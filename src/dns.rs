//! DNS sinkhole: `--allow` for clients that ignore proxy variables.
//!
//! The `--allow` proxy only helps clients that read `HTTP(S)_PROXY`. A database
//! driver, a gRPC client or a custom binary resolves the name itself and dials
//! the address. The sinkhole makes that work for allowed names, and only those:
//!
//! 1. **Resolver.** nullroute listens on `127.0.0.1:53` (UDP and TCP) inside
//!    the sandbox and bind-mounts a generated `/etc/resolv.conf` pointing at it
//!    over the real one, in the sandbox's private mount namespace. Local
//!    resolver sockets that would bypass `resolv.conf` (systemd-resolved's
//!    varlink socket used by `nss-resolve`, nscd) are masked with an empty
//!    file, so `connect` fails and glibc falls back to plain DNS.
//! 2. **Synthetic loopback pool.** An allowed name resolves to an address in
//!    `127.77.0.0/24`: each exact `--allow` host gets its own; names matching a
//!    `*.domain` wildcard share a small pool, assigned on first lookup and
//!    recycled least-recently-resolved first. Any other name gets `NXDOMAIN`
//!    and is recorded in the breach report (`Kind::Dns`). `AAAA` queries for
//!    allowed names get an empty answer, so clients use the IPv4 address.
//! 3. **Transparent relay.** For every synthetic address nullroute listens on
//!    the ports that name is allowed on (the `:port` from `--allow`, or 80 and
//!    443 by default). These listeners are created inside the sandbox and
//!    served from outside like `--port` (see forward.rs): each connection is
//!    mapped back to its host name and dialled from the host's network,
//!    applying the same rules as the proxy (allowlist, `--resolve` pins, no
//!    loopback targets).
//!
//! The resolver runs in every sandbox, not only with `--allow`: without allowed
//! names it answers every question `NXDOMAIN`. That is what lets the report (and
//! `--strict`) see lookups in a plain run, and it makes a lookup fail the same
//! way everywhere ("Name or service not known", a final answer) instead of the
//! retryable "Temporary failure in name resolution" a resolver with no route
//! gives, which clients like musl's sit out for seconds. `--no-dns` switches
//! it off.
//!
//! What is not covered: an IP literal dialled directly never asks DNS, so it
//! still fails closed with "network unreachable" (ENETUNREACH), as does a port
//! the name isn't allowed on (connection refused: nothing listens there).
//! Only TCP is relayed; UDP to a synthetic address (QUIC, for example) gets
//! nothing back.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::forward::Spec;
use crate::proxy::{self, Allowlist, DialError, Overrides, Pattern};
use crate::report::{Kind, Report};

/// Where the resolver listens inside the sandbox.
pub const PORT: u16 = 53;
/// First three octets of the synthetic address pool (127.77.0.1-254).
const POOL_PREFIX: [u8; 3] = [127, 77, 0];
/// Addresses usable in the pool.
const MAX_SLOTS: usize = 254;
/// Addresses shared by all `*.domain` names.
pub const WILDCARD_POOL: usize = 32;
/// Ports bridged for an allowed name without `:port`.
pub const DEFAULT_PORTS: [u16; 2] = [80, 443];
/// TTL of synthetic answers. Short, so a recycled wildcard address isn't
/// cached for long.
const TTL: u32 = 30;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_PTR: u16 = 12;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;

const RCODE_OK: u16 = 0;
const RCODE_FORMERR: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;
const RCODE_REFUSED: u16 = 5;

/// One synthetic address and the ports listened on there.
#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub ip: Ipv4Addr,
    pub ports: Vec<u16>,
    /// The exact host this address belongs to; None for wildcard-pool slots.
    pub fixed: Option<String>,
}

/// A listener the sandbox creates for the sinkhole.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Listener {
    Udp,
    Tcp,
    /// (slot index, port)
    Bridge(usize, u16),
}

/// The address plan, fixed before the sandbox starts.
#[derive(Debug, Clone)]
pub struct Plan {
    slots: Vec<Slot>,
    exact: BTreeMap<String, usize>,
    /// `*.domain` patterns as given (for display).
    wildcards: Vec<String>,
    /// Indices of the wildcard-pool slots.
    pool: std::ops::Range<usize>,
}

fn slot_ip(i: usize) -> Ipv4Addr {
    let [a, b, c] = POOL_PREFIX;
    Ipv4Addr::new(a, b, c, (i + 1) as u8)
}

fn add_ports(set: &mut BTreeSet<u16>, port: Option<u16>) {
    match port {
        Some(p) => {
            set.insert(p);
        }
        None => set.extend(DEFAULT_PORTS),
    }
}

impl Plan {
    /// Build the plan from the allowlist. None when it has no host names
    /// (IP literals don't go through DNS, so there is nothing to map; see
    /// [`Plan::resolver_only`]).
    pub fn new(allow: &Allowlist) -> Result<Option<Plan>, String> {
        let mut exact: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
        let mut wild_ports = BTreeSet::new();
        let mut wildcards = Vec::new();
        for e in allow.entries() {
            match &e.pattern {
                Pattern::Exact(h) if h.parse::<std::net::IpAddr>().is_ok() => {}
                Pattern::Exact(h) => add_ports(exact.entry(h.clone()).or_default(), e.port),
                Pattern::Suffix(s) => {
                    add_ports(&mut wild_ports, e.port);
                    let shown = format!("*.{s}");
                    if !wildcards.contains(&shown) {
                        wildcards.push(shown);
                    }
                }
            }
        }
        if exact.is_empty() && wildcards.is_empty() {
            return Ok(None);
        }
        let pool_size = if wildcards.is_empty() {
            0
        } else {
            WILDCARD_POOL
        };
        if exact.len() + pool_size > MAX_SLOTS {
            return Err(format!(
                "too many --allow host names for the DNS sinkhole (at most {} exact names{})",
                MAX_SLOTS - pool_size,
                if pool_size > 0 {
                    " alongside wildcards"
                } else {
                    ""
                }
            ));
        }
        let mut slots = Vec::new();
        let mut index = BTreeMap::new();
        for (host, ports) in exact {
            index.insert(host.clone(), slots.len());
            slots.push(Slot {
                ip: slot_ip(slots.len()),
                ports: ports.into_iter().collect(),
                fixed: Some(host),
            });
        }
        let start = slots.len();
        for _ in 0..pool_size {
            slots.push(Slot {
                ip: slot_ip(slots.len()),
                ports: wild_ports.iter().copied().collect(),
                fixed: None,
            });
        }
        Ok(Some(Plan {
            pool: start..slots.len(),
            slots,
            exact: index,
            wildcards,
        }))
    }

    #[cfg(test)]
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// The resolver without any allowed names: every question gets `NXDOMAIN`
    /// and is recorded. What a run without `--allow` host names gets.
    pub fn resolver_only() -> Plan {
        Plan {
            slots: Vec::new(),
            exact: BTreeMap::new(),
            wildcards: Vec::new(),
            pool: 0..0,
        }
    }

    /// Does the plan map any allowed names (as opposed to only refusing)?
    pub fn has_names(&self) -> bool {
        !self.slots.is_empty()
    }

    /// Every socket the sandbox must create for the sinkhole, in order.
    pub fn listeners(&self) -> Vec<(Listener, Spec)> {
        let dns = SocketAddr::from((Ipv4Addr::LOCALHOST, PORT));
        let mut v = vec![
            (Listener::Udp, Spec::udp(dns)),
            (Listener::Tcp, Spec::tcp(dns)),
        ];
        for (i, s) in self.slots.iter().enumerate() {
            for &p in &s.ports {
                v.push((
                    Listener::Bridge(i, p),
                    Spec::tcp(SocketAddr::from((s.ip, p))),
                ));
            }
        }
        v
    }

    /// Human-readable mapping, one line per exact host plus one for the pool.
    pub fn describe(&self) -> Vec<String> {
        let ports = |s: &Slot| {
            s.ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut v: Vec<String> = self
            .slots
            .iter()
            .filter_map(|s| {
                let h = s.fixed.as_ref()?;
                Some(format!("{h} -> {} (ports {})", s.ip, ports(s)))
            })
            .collect();
        if !self.pool.is_empty() {
            let first = &self.slots[self.pool.start];
            let last = &self.slots[self.pool.end - 1];
            v.push(format!(
                "{} -> {}-{} (pool, ports {})",
                self.wildcards.join(", "),
                first.ip,
                last.ip,
                ports(first)
            ));
        }
        v
    }

    fn matches_wildcard(&self, name: &str) -> bool {
        self.wildcards
            .iter()
            .any(|w| Pattern::Suffix(w[2..].to_string()).matches(name))
    }
}

/// Answer to one question.
#[derive(Debug, PartialEq)]
enum Answer {
    A(Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Ptr(String),
    /// The name exists but has no record of this type.
    NoData,
    NxDomain,
    Refused,
}

struct PoolState {
    names: Vec<Option<String>>,
    used: Vec<u64>,
    clock: u64,
}

/// The running sinkhole: resolver plus relays. Shared by all serving threads.
pub struct Sinkhole {
    plan: Plan,
    allow: Allowlist,
    overrides: Overrides,
    report: Arc<Report>,
    pool: Mutex<PoolState>,
    warned: Mutex<BTreeSet<String>>,
}

impl Sinkhole {
    pub fn new(
        plan: Plan,
        allow: Allowlist,
        overrides: Overrides,
        report: Arc<Report>,
    ) -> Arc<Self> {
        let n = plan.pool.len();
        Arc::new(Sinkhole {
            plan,
            allow,
            overrides,
            report,
            pool: Mutex::new(PoolState {
                names: vec![None; n],
                used: vec![0; n],
                clock: 0,
            }),
            warned: Mutex::new(BTreeSet::new()),
        })
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Pool slot for a wildcard name: its current one, a free one, or the
    /// least recently resolved one.
    fn assign(&self, name: &str) -> Option<usize> {
        let mut st = self.pool.lock().ok()?;
        st.clock += 1;
        let now = st.clock;
        let k = match st.names.iter().position(|n| n.as_deref() == Some(name)) {
            Some(k) => k,
            None => {
                let k = st
                    .names
                    .iter()
                    .position(Option::is_none)
                    .or_else(|| (0..st.used.len()).min_by_key(|&k| st.used[k]))?;
                st.names[k] = Some(name.to_string());
                k
            }
        };
        st.used[k] = now;
        Some(self.plan.pool.start + k)
    }

    /// The host name a synthetic slot currently stands for.
    fn slot_host(&self, i: usize) -> Option<String> {
        let s = self.plan.slots.get(i)?;
        if let Some(h) = &s.fixed {
            return Some(h.clone());
        }
        let st = self.pool.lock().ok()?;
        st.names.get(i - self.plan.pool.start)?.clone()
    }

    fn lookup(&self, name: &str, qtype: u16, qclass: u16) -> Answer {
        if qclass != CLASS_IN && qclass != CLASS_ANY {
            return Answer::Refused;
        }
        if let Some(rev) = name.strip_suffix(".in-addr.arpa") {
            return self.reverse(rev);
        }
        if name == "arpa" || name.ends_with(".arpa") {
            return Answer::NxDomain;
        }
        // "localhost" and friends are this machine, not a lookup (RFC 6761): a
        // client that asks DNS for them because /etc/hosts has no entry for
        // one address family must not be reported as reaching out.
        if proxy::is_localhost_name(name) {
            return match qtype {
                TYPE_A | TYPE_ANY if !name.starts_with("ip6-") => Answer::A(Ipv4Addr::LOCALHOST),
                TYPE_AAAA => Answer::Aaaa(std::net::Ipv6Addr::LOCALHOST),
                _ => Answer::NoData,
            };
        }
        let wants_addr = qtype == TYPE_A || qtype == TYPE_ANY;
        let slot = if !proxy::valid_hostname(name) {
            None
        } else if let Some(&i) = self.plan.exact.get(name) {
            Some(Some(i))
        } else if self.plan.matches_wildcard(name) {
            // Only an address query takes a pool slot.
            Some(if wants_addr { self.assign(name) } else { None })
        } else {
            None
        };
        match slot {
            None => {
                if !name.is_empty() {
                    self.report.record(Kind::Dns, name, "not in --allow", || {
                        format!("nullroute: blocked DNS lookup of {name} (not in --allow)")
                    });
                }
                Answer::NxDomain
            }
            Some(Some(i)) if wants_addr => Answer::A(self.plan.slots[i].ip),
            Some(_) => Answer::NoData,
        }
    }

    /// PTR for a synthetic address: the name it stands for.
    fn reverse(&self, rev: &str) -> Answer {
        let octets: Vec<u8> = rev.split('.').filter_map(|o| o.parse().ok()).collect();
        if octets.len() != 4 || rev.split('.').count() != 4 {
            return Answer::NxDomain;
        }
        let ip = Ipv4Addr::new(octets[3], octets[2], octets[1], octets[0]);
        match self.plan.slots.iter().position(|s| s.ip == ip) {
            Some(i) => match self.slot_host(i) {
                Some(h) => Answer::Ptr(h),
                None => Answer::NxDomain,
            },
            None => Answer::NxDomain,
        }
    }

    /// Answer one DNS message. None: not worth a reply (a response, or junk
    /// too short to carry an ID).
    pub fn handle(&self, msg: &[u8]) -> Option<Vec<u8>> {
        let q = match parse_query(msg) {
            Ok(q) => q,
            Err(reply) => return reply,
        };
        let (rcode, answers) = match self.lookup(&q.name, q.qtype, q.qclass) {
            Answer::A(ip) => (RCODE_OK, vec![(TYPE_A, ip.octets().to_vec())]),
            Answer::Aaaa(ip) => (RCODE_OK, vec![(TYPE_AAAA, ip.octets().to_vec())]),
            Answer::Ptr(h) => (RCODE_OK, vec![(TYPE_PTR, encode_name(&h))]),
            Answer::NoData => (RCODE_OK, vec![]),
            Answer::NxDomain => (RCODE_NXDOMAIN, vec![]),
            Answer::Refused => (RCODE_REFUSED, vec![]),
        };
        Some(response(q.id, q.flags, Some(&q.question), rcode, &answers))
    }

    /// Serve a listener fd received from the sandbox.
    pub fn serve(self: &Arc<Self>, listener: Listener, fd: RawFd) {
        let me = self.clone();
        match listener {
            Listener::Udp => {
                // SAFETY: fd is a bound UDP socket from the sandbox; we own it.
                let sock = unsafe { UdpSocket::from_raw_fd(fd) };
                thread::spawn(move || me.serve_udp(sock));
            }
            Listener::Tcp => {
                // SAFETY: fd is a listening TCP socket from the sandbox; we own it.
                let l = unsafe { TcpListener::from_raw_fd(fd) };
                thread::spawn(move || {
                    for c in l.incoming().flatten() {
                        let me = me.clone();
                        thread::spawn(move || me.serve_tcp(c));
                    }
                });
            }
            Listener::Bridge(slot, port) => {
                // SAFETY: as above.
                let l = unsafe { TcpListener::from_raw_fd(fd) };
                thread::spawn(move || {
                    for c in l.incoming().flatten() {
                        let me = me.clone();
                        thread::spawn(move || me.bridge(c, slot, port));
                    }
                });
            }
        }
    }

    fn serve_udp(&self, sock: UdpSocket) {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            if let Some(resp) = self.handle(&buf[..n]) {
                let _ = sock.send_to(&resp, from);
            }
        }
    }

    /// DNS over TCP: 2-byte length prefix per message, several per connection.
    fn serve_tcp(&self, mut c: TcpStream) {
        let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
        loop {
            let mut len = [0u8; 2];
            if c.read_exact(&mut len).is_err() {
                return;
            }
            let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
            if c.read_exact(&mut msg).is_err() {
                return;
            }
            let Some(resp) = self.handle(&msg) else {
                return;
            };
            let mut out = (resp.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&resp);
            if c.write_all(&out).is_err() {
                return;
            }
        }
    }

    /// Relay a connection to a synthetic address to the real host.
    fn bridge(&self, inner: TcpStream, slot: usize, port: u16) {
        let Some(host) = self.slot_host(slot) else {
            let _ = inner.shutdown(Shutdown::Both);
            return;
        };
        let target = format!("{host}:{port}");
        let block = |why: &str| {
            self.report.record(Kind::Dns, &target, why, || {
                format!("nullroute: blocked {target} ({why})")
            });
            let _ = inner.shutdown(Shutdown::Both);
        };
        if !self.allow.allows(&host, port) {
            return block("port not in --allow");
        }
        match proxy::dial(&host, port, &self.overrides) {
            Ok(outer) => crate::forward::relay(inner, outer),
            Err(DialError::Forbidden(why)) => block(why.reason()),
            Err(DialError::Io(e)) => {
                let first = self
                    .warned
                    .lock()
                    .map(|mut w| w.insert(target.clone()))
                    .unwrap_or(false);
                if first {
                    eprintln!("nullroute: could not reach {target}: {e}");
                }
                let _ = inner.shutdown(Shutdown::Both);
            }
        }
    }
}

// ---- pool address on lo ----------------------------------------------------

/// The address added to the sandbox's `lo` for the pool, as shown by --inspect.
pub const POOL_CIDR: &str = "127.77.0.1/24";

/// In the forked child, once `lo` is up: add 127.77.0.1/24 to it over
/// rtnetlink (what `ip addr add 127.77.0.1/24 dev lo` does). Raw syscalls
/// and stack buffers only.
///
/// Routing doesn't need it (all of 127/8 is local already), but glibc's
/// AI_ADDRCONFIG does: it treats a system whose only IPv4 address is
/// 127.0.0.1 as having no IPv4 at all, so `getaddrinfo(AF_INET,
/// AI_ADDRCONFIG)` would fail for every allowed name.
pub fn add_pool_address() -> io::Result<()> {
    const RTM_NEWADDR: u16 = 20;
    const NLMSG_ERROR: u16 = 2;
    const FLAGS: u16 =
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const RT_SCOPE_HOST: u8 = 254;
    // lo is always ifindex 1 in a new network namespace.
    const LO_INDEX: u32 = 1;
    let addr = slot_ip(0).octets();

    let mut msg = [0u8; 40];
    msg[0..4].copy_from_slice(&40u32.to_ne_bytes());
    msg[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
    msg[6..8].copy_from_slice(&FLAGS.to_ne_bytes());
    msg[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    // ifaddrmsg
    msg[16] = libc::AF_INET as u8;
    msg[17] = 24;
    msg[19] = RT_SCOPE_HOST;
    msg[20..24].copy_from_slice(&LO_INDEX.to_ne_bytes());
    for (off, ty) in [(24, IFA_LOCAL), (32, IFA_ADDRESS)] {
        msg[off..off + 2].copy_from_slice(&8u16.to_ne_bytes());
        msg[off + 2..off + 4].copy_from_slice(&ty.to_ne_bytes());
        msg[off + 4..off + 8].copy_from_slice(&addr);
    }
    // SAFETY: plain socket/send/recv on stack buffers of the given sizes.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            if libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut ack = [0u8; 256];
            let n = libc::recv(fd, ack.as_mut_ptr().cast(), ack.len(), 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n < 20 || u16::from_ne_bytes([ack[4], ack[5]]) != NLMSG_ERROR {
                return Err(io::Error::other("unexpected rtnetlink reply"));
            }
            match i32::from_ne_bytes([ack[16], ack[17], ack[18], ack[19]]) {
                0 => Ok(()),
                e => Err(io::Error::from_raw_os_error(-e)),
            }
        })();
        libc::close(fd);
        result
    }
}

// ---- wire format -----------------------------------------------------------

#[derive(Debug)]
struct Query {
    id: u16,
    flags: u16,
    /// The question section as received (name, type, class).
    question: Vec<u8>,
    /// Lowercase, dotted, no trailing dot; odd bytes escaped as \DDD.
    name: String,
    qtype: u16,
    qclass: u16,
}

/// Parse a standard query with one question. Err(Some(reply)) is an error
/// response to send; Err(None) means drop it.
fn parse_query(msg: &[u8]) -> Result<Query, Option<Vec<u8>>> {
    if msg.len() < 12 {
        return Err(None);
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 != 0 {
        return Err(None); // a response, not a query
    }
    let opcode = (flags >> 11) & 0xF;
    if opcode != 0 {
        return Err(Some(response(id, flags, None, RCODE_NOTIMP, &[])));
    }
    let formerr = || Some(response(id, flags, None, RCODE_FORMERR, &[]));
    if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return Err(formerr());
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = *msg.get(i).ok_or_else(formerr)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        // No compression pointers in a question; labels are at most 63.
        if len > 63 {
            return Err(formerr());
        }
        let label = msg.get(i..i + len).ok_or_else(formerr)?;
        i += len;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            match b {
                b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => name.push(b as char),
                b'A'..=b'Z' => name.push(b.to_ascii_lowercase() as char),
                _ => name.push_str(&format!("\\{b:03}")),
            }
        }
        if i - 12 > 255 {
            return Err(formerr());
        }
    }
    let tail = msg.get(i..i + 4).ok_or_else(formerr)?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    Ok(Query {
        id,
        flags,
        question: msg[12..i + 4].to_vec(),
        name,
        qtype,
        qclass,
    })
}

/// Build a response. Answers all refer to the question name (pointer 0xC00C).
fn response(
    id: u16,
    qflags: u16,
    question: Option<&[u8]>,
    rcode: u16,
    answers: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    // QR, the query's opcode and RD, authoritative, recursion available.
    let flags = 0x8000 | (qflags & 0x7800) | 0x0400 | (qflags & 0x0100) | 0x0080 | rcode;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(question.is_some() as u16).to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
    if let Some(q) = question {
        out.extend_from_slice(q);
    }
    for (ty, rdata) in answers {
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

/// A valid host name in wire format.
fn encode_name(h: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(h.len() + 2);
    for label in h.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

// ---- files mounted into the sandbox -----------------------------------------

/// Resolver sockets that would answer without going through resolv.conf.
pub const BYPASS_SOCKETS: [&str; 3] = [
    "/run/systemd/resolve/io.systemd.Resolve",
    "/run/nscd/socket",
    "/var/run/nscd/socket",
];

/// What the sandbox's /etc/resolv.conf says.
pub const RESOLV_CONF: &str = "# Generated by nullroute: names resolve through its DNS sinkhole.\n\
                               nameserver 127.0.0.1\n\
                               options timeout:2 attempts:2\n";

/// Where the sandbox's resolver configuration goes.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// The file the generated resolv.conf is mounted over: `/etc/resolv.conf`
/// with symlinks followed (systemd, WSL). None if the host has none, in which
/// case glibc already defaults to 127.0.0.1 and nothing is mounted.
pub fn resolv_conf_target() -> Option<PathBuf> {
    std::fs::canonicalize(RESOLV_CONF_PATH).ok()
}

/// The resolver bypass sockets that exist on this host (canonical paths).
/// They are masked in every sandbox, with or without `--allow`: otherwise
/// `nss-resolve` (or anything speaking varlink to systemd-resolved, or nscd)
/// would resolve names on the host's network, an out-of-band DNS leak.
pub fn bypass_targets() -> Vec<PathBuf> {
    existing(&BYPASS_SOCKETS)
}

fn existing(paths: &[&str]) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = paths
        .iter()
        .filter_map(|s| std::fs::canonicalize(s).ok())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The generated resolv.conf and the mask file, in a private temp dir, plus
/// the bind mounts that put them in place. Removes the dir on drop.
pub struct Files {
    dir: PathBuf,
    pub mounts: Vec<(CString, CString)>,
}

impl Files {
    /// Masks for the resolver bypass sockets, always; plus the sinkhole's
    /// resolv.conf when `sinkhole` is set (`--allow` without `--no-dns`).
    pub fn create(sinkhole: bool) -> io::Result<Files> {
        let resolv = sinkhole.then(|| Path::new(RESOLV_CONF_PATH));
        Self::create_for(resolv, &BYPASS_SOCKETS)
    }

    fn create_for(resolv: Option<&Path>, bypass: &[&str]) -> io::Result<Files> {
        let dir = std::env::temp_dir().join(format!(
            "nullroute-dns-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let mut files = Files {
            dir,
            mounts: Vec::new(),
        };
        let conf = files.dir.join("resolv.conf");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&conf)?
            .write_all(RESOLV_CONF.as_bytes())?;
        let mask = files.dir.join("masked");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o000)
            .open(&mask)?;
        // canonicalize follows a symlinked resolv.conf (systemd, WSL) to the
        // file that is actually read. Missing: glibc already defaults to
        // 127.0.0.1, so there is nothing to mount over.
        if let Some(target) = resolv.and_then(|r| std::fs::canonicalize(r).ok()) {
            files.mounts.push((cstring(&conf)?, cstring(&target)?));
        }
        for target in existing(bypass) {
            files.mounts.push((cstring(&mask)?, cstring(&target)?));
        }
        Ok(files)
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn cstring(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(v: &[&str]) -> Allowlist {
        Allowlist::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn sinkhole(v: &[&str]) -> Arc<Sinkhole> {
        let a = allow(v);
        let plan = Plan::new(&a).unwrap().unwrap();
        Sinkhole::new(plan, a, Overrides::new(), Report::new(true))
    }

    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        m.extend(encode_name(name));
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m
    }

    fn rcode(r: &[u8]) -> u16 {
        u16::from_be_bytes([r[2], r[3]]) & 0xF
    }
    fn ancount(r: &[u8]) -> u16 {
        u16::from_be_bytes([r[6], r[7]])
    }
    /// The A record's address in a one-answer response.
    fn a_record(r: &[u8]) -> Ipv4Addr {
        let n = r.len();
        Ipv4Addr::new(r[n - 4], r[n - 3], r[n - 2], r[n - 1])
    }

    #[test]
    fn resolver_only_refuses_and_records_every_name() {
        let plan = Plan::resolver_only();
        assert!(!plan.has_names());
        assert!(plan.describe().is_empty());
        // Just the resolver's own sockets: no address to listen on per name.
        let kinds: Vec<Listener> = plan.listeners().into_iter().map(|(l, _)| l).collect();
        assert_eq!(kinds, [Listener::Udp, Listener::Tcp]);
        let report = Report::new(true);
        let s = Sinkhole::new(plan, Allowlist::default(), Overrides::new(), report.clone());
        let r = s.handle(&query(1, "api.example.test", TYPE_A)).unwrap();
        assert_eq!(rcode(&r), RCODE_NXDOMAIN);
        assert_eq!(ancount(&r), 0);
        let e = report.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(
            (e[0].kind, e[0].target.as_str()),
            (Kind::Dns, "api.example.test")
        );
        assert!(report.has_blocks());
    }

    #[test]
    fn localhost_names_resolve_locally_and_are_not_recorded() {
        let report = Report::new(true);
        let s = Sinkhole::new(
            Plan::resolver_only(),
            Allowlist::default(),
            Overrides::new(),
            report.clone(),
        );
        let r = s.handle(&query(1, "localhost", TYPE_A)).unwrap();
        assert_eq!((rcode(&r), ancount(&r)), (RCODE_OK, 1));
        assert_eq!(a_record(&r), Ipv4Addr::LOCALHOST);
        let r = s.handle(&query(2, "localhost", TYPE_AAAA)).unwrap();
        assert_eq!((rcode(&r), ancount(&r)), (RCODE_OK, 1));
        assert_eq!(r[r.len() - 1], 1, "::1");
        let r = s.handle(&query(3, "web.localhost", TYPE_A)).unwrap();
        assert_eq!(a_record(&r), Ipv4Addr::LOCALHOST);
        // Other types: the name exists but has no such record.
        let r = s.handle(&query(4, "localhost", 16)).unwrap();
        assert_eq!((rcode(&r), ancount(&r)), (RCODE_OK, 0));
        assert!(report.is_empty(), "{:?}", report.entries());
    }

    #[test]
    fn plan_assigns_addresses_and_ports() {
        let p = Plan::new(&allow(&[
            "db.example.com:5432",
            "db.example.com:6379",
            "api.github.com",
            "10.0.0.5",
            "*.stripe.dev",
            "*.svc.test:9000",
        ]))
        .unwrap()
        .unwrap();
        let s = p.slots();
        assert_eq!(s.len(), 2 + WILDCARD_POOL);
        assert_eq!(s[0].fixed.as_deref(), Some("api.github.com"));
        assert_eq!((s[0].ip, s[0].ports.clone()), (slot_ip(0), vec![80, 443]));
        assert_eq!(s[1].fixed.as_deref(), Some("db.example.com"));
        assert_eq!(
            (s[1].ip, s[1].ports.clone()),
            (slot_ip(1), vec![5432, 6379])
        );
        assert!(
            s[2..]
                .iter()
                .all(|s| s.fixed.is_none() && s.ports == [80, 443, 9000])
        );
        assert_eq!(s[0].ip, Ipv4Addr::new(127, 77, 0, 1));
        assert_eq!(
            p.describe(),
            vec![
                "api.github.com -> 127.77.0.1 (ports 80, 443)".to_string(),
                "db.example.com -> 127.77.0.2 (ports 5432, 6379)".to_string(),
                "*.stripe.dev, *.svc.test -> 127.77.0.3-127.77.0.34 (pool, ports 80, 443, 9000)"
                    .to_string(),
            ]
        );
        let l = p.listeners();
        assert_eq!(l[0].0, Listener::Udp);
        assert_eq!(l[1].0, Listener::Tcp);
        assert_eq!(l[2].0, Listener::Bridge(0, 80));
        assert_eq!(l.len(), 2 + 2 + 2 + WILDCARD_POOL * 3);
    }

    #[test]
    fn no_plan_for_ip_only_allowlists() {
        assert!(
            Plan::new(&allow(&["10.0.0.5", "[2001:db8::1]:443"]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn too_many_names_is_an_error() {
        let names: Vec<String> = (0..300).map(|i| format!("h{i}.example.com")).collect();
        assert!(Plan::new(&Allowlist::parse(&names).unwrap()).is_err());
    }

    #[test]
    fn allowed_name_gets_its_synthetic_address() {
        let s = sinkhole(&["api.github.com"]);
        let r = s.handle(&query(0x1234, "API.GitHub.com", TYPE_A)).unwrap();
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert_eq!(rcode(&r), RCODE_OK);
        assert_eq!(ancount(&r), 1);
        assert_eq!(a_record(&r), Ipv4Addr::new(127, 77, 0, 1));
        // QR, AA, RD echoed, RA.
        assert_eq!(u16::from_be_bytes([r[2], r[3]]) & 0xFF80, 0x8580);
        assert!(s.report.is_empty());
    }

    #[test]
    fn aaaa_for_allowed_name_is_empty_not_nxdomain() {
        let s = sinkhole(&["api.github.com"]);
        let r = s.handle(&query(1, "api.github.com", 28)).unwrap();
        assert_eq!((rcode(&r), ancount(&r)), (RCODE_OK, 0));
    }

    #[test]
    fn blocked_name_is_nxdomain_and_recorded() {
        let s = sinkhole(&["api.github.com"]);
        for _ in 0..2 {
            let r = s.handle(&query(1, "evil.example", TYPE_A)).unwrap();
            assert_eq!((rcode(&r), ancount(&r)), (RCODE_NXDOMAIN, 0));
        }
        let e = s.report.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(
            (e[0].kind, e[0].target.as_str(), e[0].count),
            (Kind::Dns, "evil.example", 2)
        );
        assert_eq!(e[0].kind.label(), "dns");
    }

    #[test]
    fn odd_bytes_are_escaped_and_blocked() {
        let s = sinkhole(&["*.example.com"]);
        let mut q = query(1, "x.example.com", TYPE_A);
        q[13] = b' '; // "x" -> " "
        let r = s.handle(&q).unwrap();
        assert_eq!(rcode(&r), RCODE_NXDOMAIN);
        assert_eq!(s.report.entries()[0].target, "\\032.example.com");
    }

    #[test]
    fn wildcard_names_share_a_recycled_pool() {
        let s = sinkhole(&["*.stripe.dev"]);
        let ip = |n: &str| a_record(&s.handle(&query(1, n, TYPE_A)).unwrap());
        let a = ip("a.stripe.dev");
        assert_eq!(a, Ipv4Addr::new(127, 77, 0, 1));
        assert_eq!(ip("a.stripe.dev"), a, "sticky");
        let b = ip("b.stripe.dev");
        assert_ne!(a, b);
        // stripe.dev itself isn't covered by *.stripe.dev.
        assert_eq!(
            rcode(&s.handle(&query(1, "stripe.dev", TYPE_A)).unwrap()),
            RCODE_NXDOMAIN
        );
        // Fill the pool; "a" was refreshed after "b", so "b" is evicted first.
        ip("a.stripe.dev");
        for i in 0..WILDCARD_POOL - 2 {
            ip(&format!("n{i}.stripe.dev"));
        }
        assert_eq!(ip("a.stripe.dev"), a);
        let c = ip("c.stripe.dev");
        assert_eq!(c, b, "least recently resolved slot is recycled");
        assert_eq!(s.slot_host(1).as_deref(), Some("c.stripe.dev"));
        // AAAA matches but doesn't take a slot.
        let r = s.handle(&query(1, "d.stripe.dev", 28)).unwrap();
        assert_eq!((rcode(&r), ancount(&r)), (RCODE_OK, 0));
    }

    #[test]
    fn ptr_for_synthetic_addresses() {
        let s = sinkhole(&["api.github.com"]);
        let r = s
            .handle(&query(1, "1.0.77.127.in-addr.arpa", TYPE_PTR))
            .unwrap();
        assert_eq!((rcode(&r), ancount(&r)), (RCODE_OK, 1));
        assert!(r.ends_with(&encode_name("api.github.com")));
        let r = s
            .handle(&query(1, "9.0.77.127.in-addr.arpa", TYPE_PTR))
            .unwrap();
        assert_eq!(rcode(&r), RCODE_NXDOMAIN);
        let r = s
            .handle(&query(1, "8.8.8.8.in-addr.arpa", TYPE_PTR))
            .unwrap();
        assert_eq!(rcode(&r), RCODE_NXDOMAIN);
        assert!(s.report.is_empty(), "reverse lookups aren't breaches");
    }

    #[test]
    fn malformed_and_unsupported_messages() {
        let s = sinkhole(&["a.com"]);
        assert!(s.handle(&[0; 5]).is_none());
        let mut resp = query(7, "a.com", TYPE_A);
        resp[2] |= 0x80;
        assert!(s.handle(&resp).is_none(), "responses are ignored");
        let mut notify = query(7, "a.com", TYPE_A);
        notify[2] |= 4 << 3; // opcode NOTIFY
        assert_eq!(rcode(&s.handle(&notify).unwrap()), RCODE_NOTIMP);
        let truncated = &query(7, "a.com", TYPE_A)[..15];
        assert_eq!(rcode(&s.handle(truncated).unwrap()), RCODE_FORMERR);
        let mut ptr = query(7, "a.com", TYPE_A);
        ptr[12] = 0xC0;
        assert_eq!(rcode(&s.handle(&ptr).unwrap()), RCODE_FORMERR);
        let mut chaos = query(7, "a.com", TYPE_A);
        let n = chaos.len();
        chaos[n - 1] = 3;
        assert_eq!(rcode(&s.handle(&chaos).unwrap()), RCODE_REFUSED);
    }

    #[test]
    fn files_point_resolv_conf_at_the_sinkhole_and_mask_bypasses() {
        let tmp = std::env::temp_dir().join(format!("nr-dns-unit-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let real = tmp.join("resolv.real");
        std::fs::write(&real, "nameserver 10.0.0.1\n").unwrap();
        let link = tmp.join("resolv.conf");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let sock = tmp.join("resolve.sock");
        let _ = std::fs::remove_file(&sock);
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let missing = tmp.join("nope.sock");
        let f = Files::create_for(
            Some(&link),
            &[sock.to_str().unwrap(), missing.to_str().unwrap()],
        )
        .unwrap();
        assert_eq!(f.mounts.len(), 2);
        let (src, dst) = &f.mounts[0];
        assert_eq!(
            std::fs::read_to_string(src.to_str().unwrap()).unwrap(),
            RESOLV_CONF
        );
        let real_canon = std::fs::canonicalize(&real).unwrap();
        assert_eq!(
            dst.to_str().unwrap(),
            real_canon.to_str().unwrap(),
            "symlink followed"
        );
        assert!(f.mounts[1].1.to_str().unwrap().ends_with("resolve.sock"));
        let dir = f.dir.clone();
        drop(f);
        assert!(!dir.exists());

        // Without the sinkhole (no --allow), resolv.conf is left alone but the
        // bypass sockets are still masked.
        let f =
            Files::create_for(None, &[sock.to_str().unwrap(), missing.to_str().unwrap()]).unwrap();
        assert_eq!(f.mounts.len(), 1, "only the bypass mask");
        assert!(f.mounts[0].1.to_str().unwrap().ends_with("resolve.sock"));
        drop(f);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bypass_sockets_cover_resolved_varlink_and_nscd() {
        assert!(BYPASS_SOCKETS.contains(&"/run/systemd/resolve/io.systemd.Resolve"));
        assert!(BYPASS_SOCKETS.contains(&"/run/nscd/socket"));
        assert!(BYPASS_SOCKETS.contains(&"/var/run/nscd/socket"));
    }
}
