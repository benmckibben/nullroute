//! `--allow`: let chosen hosts through, via an HTTP proxy only nullroute can dial out of.
//!
//! The sandbox still has no route out. nullroute listens on a port inside the
//! sandbox's loopback (passed to the parent like a `--port` listener, see
//! forward.rs) and points the standard proxy variables at it (HTTP_PROXY,
//! HTTPS_PROXY, ALL_PROXY and lowercase forms). The parent, on the host's
//! network, handles each request:
//!
//! - `CONNECT host:port` (HTTPS and anything tunnelled): checked against the
//!   allowlist, then tunnelled. TLS stays end-to-end; nullroute never sees
//!   plaintext and needs no certificates.
//! - `GET http://host/...` (plain HTTP): checked, then forwarded with the
//!   request line rewritten to origin form and `Connection: close`.
//!
//! Blocked hosts get `403` with an explanation, and one warning per host on stderr.
//!
//! The allowlist is checked against the host in the request target, which a
//! client can contradict inside the request: a plain-HTTP request's `Host`
//! header must name the host it is sent to (or another allowed host), and the
//! first TLS record of a tunnel (see sni.rs) must name the tunnel's host. What
//! that can't catch (an SNI that matches with a different `Host` inside TLS)
//! is spelled out in the README.
//!
//! This only covers clients that honour proxy variables (curl, wget, pip,
//! Python requests/urllib/httpx, Go net/http, Node's fetch with
//! NODE_USE_ENV_PROXY, Java with flags...). Other clients can reach allowed
//! host names through the DNS sinkhole (dns.rs); anything else still hits the
//! sealed network and fails with "network unreachable", so the failure mode is
//! closed, never open.
//!
//! Resolution happens on the host. Addresses that resolve to loopback,
//! "unspecified", link-local (which includes the 169.254.169.254 cloud
//! metadata service) or another known metadata endpoint are refused even for
//! allowed names, so an allowed name can't be used to reach the host's
//! localhost services behind `--port`'s back or to lift cloud credentials.
//! `--allow` entries that name such addresses (or `localhost`) are rejected
//! up front.

use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;

use crate::limits;
use crate::report::{Kind, Report};
use crate::sni::{self, Refusal, Verdict};
use std::time::Duration;

/// Default port for the proxy inside the sandbox (the conventional proxy port).
/// The sandbox's loopback is private, so this only clashes with the command's
/// own listeners or with a `--port`; see pick_port.
pub const DEFAULT_PORT: u16 = 3128;

const MAX_HEAD: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// Exact host name or IP literal, lowercase, no trailing dot.
    Exact(String),
    /// `*.example.com`: any subdomain of example.com (not example.com itself).
    Suffix(String),
}

impl Pattern {
    pub(crate) fn matches(&self, h: &str) -> bool {
        match self {
            Pattern::Exact(e) => e == h,
            Pattern::Suffix(s) => {
                h.len() > s.len()
                    && h.ends_with(s.as_str())
                    && h.as_bytes()[h.len() - s.len() - 1] == b'.'
            }
        }
    }
}

/// One `--allow` entry: a pattern and, optionally, the only port it allows.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub pattern: Pattern,
    /// None: every port.
    pub port: Option<u16>,
}

#[derive(Debug, Default, Clone)]
pub struct Allowlist {
    entries: Vec<Entry>,
}

impl Allowlist {
    /// Parse `--allow` values: a host, an IP literal or `*.domain`, each
    /// optionally with `:port` (`[v6]:port` for IPv6 literals).
    pub fn parse(values: &[String]) -> Result<Self, String> {
        let mut entries = Vec::new();
        for raw in values {
            let v = raw.trim().to_ascii_lowercase();
            let bad = |why: &str| Err(format!("--allow {raw:?}: {why}"));
            if v.is_empty() {
                return bad("empty");
            }
            if v.contains("://") || v.contains('/') {
                return bad("give a host name, not a URL (e.g. api.github.com)");
            }
            // Bare IPv6 literal (has colons, no brackets): no port possible.
            if let Ok(ip) = v.parse::<IpAddr>() {
                if let Some(why) = forbidden(ip) {
                    return Err(unreachable_allow(raw, why, None));
                }
                entries.push(Entry {
                    pattern: Pattern::Exact(ip.to_string()),
                    port: None,
                });
                continue;
            }
            let (host, port) = if let Some(rest) = v.strip_prefix('[') {
                let Some((h, after)) = rest.split_once(']') else {
                    return bad("unclosed [");
                };
                if h.parse::<std::net::Ipv6Addr>().is_err() {
                    return bad("brackets are only for IPv6 literals");
                }
                match after {
                    "" => (h.to_string(), None),
                    a => match a
                        .strip_prefix(':')
                        .and_then(|p| p.parse::<u16>().ok())
                        .filter(|&p| p != 0)
                    {
                        Some(p) => (h.to_string(), Some(p)),
                        None => return bad("port must be 1-65535"),
                    },
                }
            } else {
                match v.rsplit_once(':') {
                    Some((h, p)) => match p.parse::<u16>().ok().filter(|&p| p != 0) {
                        Some(p) => (h.to_string(), Some(p)),
                        None => return bad("port must be 1-65535"),
                    },
                    None => (v.clone(), None),
                }
            };
            let host = host.trim_end_matches('.').to_string();
            if is_localhost_name(&host) {
                return Err(unreachable_allow(raw, Forbidden::Loopback, port));
            }
            // Store IpAddr's canonical form so `2001:0db8::1` matches `2001:db8::1`.
            let pattern = if let Ok(ip) = host.parse::<IpAddr>() {
                if let Some(why) = forbidden(ip) {
                    return Err(unreachable_allow(raw, why, port));
                }
                Pattern::Exact(ip.to_string())
            } else if let Some(rest) = host.strip_prefix("*.") {
                if !valid_hostname(rest) || !rest.contains('.') {
                    return bad("wildcards must look like *.example.com");
                }
                Pattern::Suffix(rest.to_string())
            } else if host.contains('*') {
                return bad("only a leading *. wildcard is supported (e.g. *.example.com)");
            } else if valid_hostname(&host) {
                Pattern::Exact(host)
            } else {
                return bad("not a valid host name");
            };
            entries.push(Entry { pattern, port });
        }
        Ok(Allowlist { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Is host allowed on at least one port?
    pub fn allows_host(&self, host: &str) -> bool {
        let h = Self::norm(host);
        self.entries.iter().any(|e| e.pattern.matches(&h))
    }

    pub(crate) fn norm(host: &str) -> String {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let h = h.trim_start_matches('[').trim_end_matches(']');
        // Same canonical IP form stored by parse, so either spelling matches.
        match h.parse::<IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => h.to_string(),
        }
    }

    /// Is host:port allowed?
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let h = Self::norm(host);
        self.entries
            .iter()
            .any(|e| e.pattern.matches(&h) && e.port.is_none_or(|p| p == port))
    }
}

/// Names that mean "this machine" (glibc/systemd resolve them to loopback
/// without asking DNS): `localhost`, `*.localhost` (RFC 6761),
/// `localhost.localdomain` and the Debian `ip6-` aliases.
pub(crate) fn is_localhost_name(h: &str) -> bool {
    let h = h.trim_start_matches("*.");
    h == "localhost"
        || h.ends_with(".localhost")
        || h == "localhost.localdomain"
        || h == "ip6-localhost"
        || h == "ip6-loopback"
}

/// The parse error for an `--allow` that could never be reached.
fn unreachable_allow(raw: &str, why: Forbidden, port: Option<u16>) -> String {
    match why {
        Forbidden::Loopback => {
            let hint = match port {
                Some(p) => format!("--port {p}"),
                None => "--port PORT".to_string(),
            };
            format!(
                "--allow {raw:?}: loopback is never reachable through --allow; \
                 to reach a service on this machine's localhost, bridge it with {hint}"
            )
        }
        other => format!(
            "--allow {raw:?}: {} addresses are always blocked",
            other.describe()
        ),
    }
}

pub(crate) fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// `--resolve HOST:IP` pins: host name (normalized) to the address nullroute
/// dials instead of resolving the name on the host.
pub type Overrides = std::collections::BTreeMap<String, IpAddr>;

/// Parse `--resolve` values (`host:ip`, `host:[v6]` or `host:v6`). Every
/// pinned host must be allowed by `allow`, so a pin can't widen the allowlist.
pub fn parse_overrides(values: &[String], allow: &Allowlist) -> Result<Overrides, String> {
    let mut out = Overrides::new();
    for raw in values {
        let v = raw.trim().to_ascii_lowercase();
        let bad = |why: &str| Err(format!("--resolve {raw:?}: {why}"));
        let Some((host, ip)) = v.split_once(':') else {
            return bad("expected HOST:IP, e.g. api.example.com:10.0.0.5");
        };
        let host = host.trim_end_matches('.');
        if !valid_hostname(host) || host.parse::<IpAddr>().is_ok() {
            return bad("not a valid host name");
        }
        let ip = ip.trim_start_matches('[').trim_end_matches(']');
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return bad("not a valid IP address");
        };
        if !allow.allows_host(host) {
            return bad("host is not in --allow");
        }
        out.insert(host.to_string(), ip);
    }
    Ok(out)
}

/// First port from DEFAULT_PORT up that isn't a `--port`.
pub fn pick_port(forwarded: &[u16]) -> u16 {
    (DEFAULT_PORT..=u16::MAX)
        .find(|p| !forwarded.contains(p))
        .unwrap_or(DEFAULT_PORT)
}

/// Environment to give the command so proxy-aware clients use us.
pub fn env_vars(port: u16) -> Vec<(&'static str, String)> {
    let url = format!("http://127.0.0.1:{port}");
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    vec![
        ("HTTP_PROXY", url.clone()),
        ("http_proxy", url.clone()),
        ("HTTPS_PROXY", url.clone()),
        ("https_proxy", url.clone()),
        ("ALL_PROXY", url.clone()),
        ("all_proxy", url),
        ("NO_PROXY", no_proxy.clone()),
        ("no_proxy", no_proxy),
        // Node 24+ only honours the variables above when this is set.
        ("NODE_USE_ENV_PROXY", "1".to_string()),
    ]
}

/// Shared state for one run: the allowlist and where blocks are recorded.
pub struct Proxy {
    allow: Allowlist,
    overrides: Overrides,
    report: Arc<Report>,
}

impl Proxy {
    pub fn new(allow: Allowlist, overrides: Overrides, report: Arc<Report>) -> Arc<Self> {
        Arc::new(Proxy {
            allow,
            overrides,
            report,
        })
    }

    /// Serve proxy connections on a listener fd received from the sandbox.
    pub fn spawn_acceptor(self: &Arc<Self>, fd: RawFd) {
        // SAFETY: fd is a listening TCP socket received from the child; we own it.
        let listener = unsafe { TcpListener::from_raw_fd(fd) };
        let me = self.clone();
        let limit = limits::Limiter::new(limits::max_connections(limits::MAX_CONNECTIONS));
        limits::spawn_service(move || {
            limits::accept_loop(
                || listener.accept().map(|(c, _)| c),
                |conn| {
                    let me = me.clone();
                    if let Some(permit) = limit.try_acquire() {
                        limits::spawn_conn(permit, move || me.handle(conn));
                    }
                },
            );
        });
    }

    fn block(&self, host: &str, port: u16, why: &str) {
        self.report
            .record(Kind::Proxy, &format!("{host}:{port}"), why, || {
                format!("nullroute: blocked {host} ({why})")
            });
    }

    fn handle(&self, mut client: TcpStream) {
        let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
        let Ok((head, rest)) = read_head(&mut client) else {
            return;
        };
        let _ = client.set_read_timeout(None);
        let Some(req) = parse_request(&head) else {
            respond(&mut client, 400, "nullroute proxy: malformed request");
            return;
        };

        if !self.allow.allows(&req.host, req.port) {
            self.block(&req.host, req.port, "not in --allow");
            respond(
                &mut client,
                403,
                &format!(
                    "nullroute blocked {}: it is not in --allow. Rerun with --allow {} to permit it.",
                    req.host, req.host
                ),
            );
            return;
        }
        let upstream = match dial(&req.host, req.port, &self.overrides) {
            Ok(s) => s,
            Err(DialError::Forbidden(why)) => {
                self.block(&req.host, req.port, why.reason());
                let msg = match why {
                    Forbidden::Loopback => format!(
                        "nullroute blocked {}: it resolves to a loopback address. Use --port for services on this machine.",
                        req.host
                    ),
                    other => format!(
                        "nullroute blocked {}: it resolves to a {} address, which is never reachable from the sandbox.",
                        req.host,
                        other.describe()
                    ),
                };
                respond(&mut client, 403, &msg);
                return;
            }
            Err(DialError::Io(e)) => {
                respond(
                    &mut client,
                    502,
                    &format!("nullroute could not reach {}:{}: {e}", req.host, req.port),
                );
                return;
            }
        };

        note_private_peer(&req.host, &upstream, self.report.quiet());
        let mut upstream = upstream;
        if req.connect {
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
            // The client's first bytes (a TLS ClientHello, usually) arrive after
            // the 200; check the server name before anything reaches the host.
            if let Err(refusal) = gate_tunnel(
                &self.allow,
                &client,
                &mut upstream,
                &req.host,
                req.port,
                rest,
            ) {
                record_refused_tunnel(&self.report, &req.host, req.port, &refusal);
                return;
            }
        } else {
            match check_host_header(&head, &req, &self.allow) {
                HostCheck::Fine => {}
                HostCheck::Malformed(why) => {
                    respond(&mut client, 400, &format!("nullroute proxy: {why}"));
                    return;
                }
                HostCheck::Differs(named) => {
                    self.block_host_header(&req, &named);
                    respond(
                        &mut client,
                        403,
                        &format!(
                            "nullroute blocked this request: its Host header names {named}, but it was sent to {}. \
                             The Host header has to name the host the request goes to; add --allow {named} to permit it.",
                            req.host
                        ),
                    );
                    return;
                }
            }
            let head = rewrite_for_origin(&head, &req);
            if upstream.write_all(&head).is_err() {
                return;
            }
            if !rest.is_empty() && upstream.write_all(&rest).is_err() {
                return;
            }
        }
        crate::forward::relay(client, upstream);
    }

    /// Record a plain-HTTP request whose Host header names another host.
    fn block_host_header(&self, req: &Request, named: &str) {
        let target = format!("{named}:{}", req.port);
        let why = format!(
            "Host header differs from the request target {}; not in --allow",
            req.host
        );
        self.report.record(Kind::Proxy, &target, &why, || {
            format!(
                "nullroute: blocked Host: {named} in a request to {} (not in --allow; the Host header must name the host the request goes to)",
                req.host
            )
        });
    }
}

/// Record a tunnel (or relayed connection) refused by [`gate_tunnel`].
pub(crate) fn record_refused_tunnel(report: &Report, host: &str, port: u16, refusal: &Refusal) {
    match refusal {
        Refusal::Name(name) => {
            let why =
                format!("TLS server name differs from the tunnel's host {host}; not in --allow");
            report.record(Kind::Proxy, &format!("{name}:{port}"), &why, || {
                format!(
                    "nullroute: blocked TLS server name {name} in a tunnel to {host}:{port} (not in --allow; the server name must be the host the tunnel goes to)"
                )
            });
        }
        Refusal::Unreadable => {
            report.record(
                Kind::Proxy,
                &format!("{host}:{port}"),
                "unreadable TLS ClientHello",
                || {
                    format!(
                        "nullroute: blocked a tunnel to {host}:{port} (unreadable TLS ClientHello)"
                    )
                },
            );
        }
    }
}

/// Look at the start of what the client sends into a tunnel to `host:port`.
/// If it is a TLS ClientHello naming a server other than `host` (and not
/// itself allowed), refuse. Otherwise the bytes read so far are written to
/// `upstream`, so the relay can carry on from there.
pub(crate) fn gate_tunnel(
    allow: &Allowlist,
    client: &TcpStream,
    upstream: &mut TcpStream,
    host: &str,
    port: u16,
    initial: Vec<u8>,
) -> Result<(), Refusal> {
    let tunnel_host = Allowlist::norm(host);
    let ok = |name: &str| Allowlist::norm(name) == tunnel_host || allow.allows(name, port);
    match sni::gate(client, upstream, initial, ok) {
        Verdict::Refuse(r) => Err(r),
        Verdict::Pass(first) => {
            // A failed write just means the tunnel is already gone.
            if !first.is_empty() {
                let _ = upstream.write_all(&first);
            }
            Ok(())
        }
    }
}

/// What the Host header of a plain-HTTP proxy request says.
#[derive(Debug, PartialEq, Eq)]
enum HostCheck {
    /// Absent, the host the request is sent to, or another allowed host.
    Fine,
    /// Names a different host that isn't allowed (as it was written).
    Differs(String),
    Malformed(&'static str),
}

/// The proxy checked the host in the request target against the allowlist, but
/// the server picks the site from the Host header. A client could ask for an
/// allowed host and name another one there (domain fronting), so the two have
/// to agree, unless the Host header names a host that is allowed too.
fn check_host_header(head: &[u8], req: &Request, allow: &Allowlist) -> HostCheck {
    let text = String::from_utf8_lossy(head);
    let mut values = text.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().to_string())
    });
    let Some(value) = values.next() else {
        return HostCheck::Fine;
    };
    if values.next().is_some() {
        return HostCheck::Malformed("more than one Host header");
    }
    let Some((host, port)) = split_host_port(&value, Some(req.port)) else {
        return HostCheck::Malformed("invalid Host header");
    };
    if Allowlist::norm(&host) == Allowlist::norm(&req.host) || allow.allows(&host, port) {
        HostCheck::Fine
    } else {
        HostCheck::Differs(Allowlist::norm(&host))
    }
}

struct Request {
    connect: bool,
    host: String,
    port: u16,
    /// For absolute-form requests: the request line with an origin-form target.
    origin_line: String,
}

/// Read until the end of the request head. Returns (head, bytes after it).
fn read_head(s: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("request head too large"));
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, None)?;
        return Some(Request {
            connect: true,
            host,
            port,
            origin_line: String::new(),
        });
    }
    // Absolute form: scheme://authority/path
    let (scheme, after) = target.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        // https:// in absolute form would mean we originate TLS; clients use CONNECT for that.
        _ => return None,
    };
    let (authority, path) = match after.find('/') {
        Some(i) => (&after[..i], &after[i..]),
        None => (after, "/"),
    };
    let authority = authority.rsplit('@').next()?; // drop userinfo
    let (host, port) = split_host_port(authority, Some(default_port))?;
    Some(Request {
        connect: false,
        host,
        port,
        origin_line: format!("{method} {path} {version}"),
    })
}

/// "host:port", "[v6]:port", or "host" when a default port is given.
fn split_host_port(s: &str, default: Option<u16>) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default?,
            None => return None,
        };
        return Some((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        Some(_) => None,
        None => Some((s.to_string(), default?)),
    }
    .filter(|(h, p)| !h.is_empty() && *p != 0)
}

/// Origin-form request line, Proxy-* headers dropped, and Connection: close so
/// each proxied connection carries one request to one host.
fn rewrite_for_origin(head: &[u8], req: &Request) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out = String::with_capacity(head.len());
    out.push_str(&req.origin_line);
    out.push_str("\r\n");
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if name.starts_with("proxy-") || name == "connection" || name == "keep-alive" {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

pub(crate) enum DialError {
    /// The target resolved to an address nullroute never dials.
    Forbidden(Forbidden),
    Io(io::Error),
}

/// Why a destination address is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Forbidden {
    /// 127.0.0.0/8, ::1, 0.0.0.0/8, ::, and v4-mapped/-compatible/NAT64 forms.
    Loopback,
    /// 169.254.0.0/16, fe80::/10.
    LinkLocal,
    /// Cloud instance metadata endpoints outside link-local.
    Metadata,
}

impl Forbidden {
    fn describe(self) -> &'static str {
        match self {
            Forbidden::Loopback => "loopback",
            Forbidden::LinkLocal => "link-local (incl. cloud metadata)",
            Forbidden::Metadata => "cloud metadata",
        }
    }

    /// The reason shown in warnings and the report.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Forbidden::Loopback => "resolves to loopback; use --port for local services",
            Forbidden::LinkLocal => {
                "resolves to a link-local address (incl. cloud metadata); always blocked"
            }
            Forbidden::Metadata => "resolves to a cloud metadata address; always blocked",
        }
    }
}

/// Is `ip` in space that belongs to a local network rather than the internet,
/// and if so which? Allowed, but worth a warning: an allowed name or address
/// there reaches machines on the host's LAN or VPN, which is easy to do by
/// accident (a corporate name, a split-horizon DNS answer).
pub(crate) fn private_range(ip: IpAddr) -> Option<&'static str> {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => {
            if v6.segments()[0] & 0xfe00 == 0xfc00 {
                return Some("unique local (fc00::/7)");
            }
            embedded_v4(v6)?
        }
    };
    let o = v4.octets();
    if o[0] == 10 || (o[0] == 172 && (16..32).contains(&o[1])) || (o[0] == 192 && o[1] == 168) {
        Some("private (RFC 1918)")
    } else if o[0] == 100 && (64..128).contains(&o[1]) {
        Some("carrier-grade NAT (100.64.0.0/10)")
    } else {
        None
    }
}

/// Warnings for `--allow` IP literals and `--resolve` pins in private space,
/// one line each: they work, but they are a hole to the local network.
pub fn private_address_warnings(allow: &Allowlist, overrides: &Overrides) -> Vec<String> {
    let mut v = Vec::new();
    for e in allow.entries() {
        if let Pattern::Exact(h) = &e.pattern
            && let Ok(ip) = h.parse::<IpAddr>()
            && let Some(range) = private_range(ip)
        {
            v.push(format!(
                "nullroute: warning: --allow {h} is a {range} address: allowing it lets the command reach that machine on your local network"
            ));
        }
    }
    for (host, ip) in overrides {
        if let Some(range) = private_range(*ip) {
            v.push(format!(
                "nullroute: warning: --resolve {host}:{ip} points at a {range} address on your local network"
            ));
        }
    }
    v
}

/// Print one warning per host the first time an allowed name is connected to
/// an address in private space (see [`private_range`]).
pub(crate) fn note_private_peer(host: &str, stream: &TcpStream, quiet: bool) {
    static SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let Ok(peer) = stream.peer_addr() else { return };
    let Some(range) = private_range(peer.ip()) else {
        return;
    };
    if host.parse::<IpAddr>().is_ok() {
        return; // an IP literal was warned about at startup
    }
    let first = match SEEN.lock() {
        Ok(mut seen) if !seen.iter().any(|h| h == host) => {
            seen.push(host.to_string());
            true
        }
        _ => false,
    };
    if first && !quiet {
        eprintln!(
            "nullroute: warning: {host} resolved to {}, a {range} address on your local network",
            peer.ip()
        );
    }
}

/// Resolve (or look up in `overrides`) and connect, refusing forbidden targets.
pub(crate) fn dial(host: &str, port: u16, overrides: &Overrides) -> Result<TcpStream, DialError> {
    let addrs: Vec<SocketAddr> = match overrides.get(&Allowlist::norm(host)) {
        Some(&ip) => vec![SocketAddr::new(ip, port)],
        None => resolve_bounded(host, port).map_err(DialError::Io)?,
    };
    if addrs.is_empty() {
        return Err(DialError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses",
        )));
    }
    if let Some(why) = addrs.iter().find_map(|a| forbidden(a.ip())) {
        return Err(DialError::Forbidden(why));
    }
    let mut last = None;
    for a in &addrs {
        match TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(DialError::Io(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no addresses")
    })))
}

/// How long a name lookup for the command may take. getaddrinfo has no
/// timeout of its own beyond the resolver's (retries across every nameserver
/// in resolv.conf can add up to minutes), and a command that hangs on a dead
/// resolver would otherwise hang with it.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Lookups that may be in flight (or stuck) at once.
const MAX_LOOKUPS: usize = 32;

/// getaddrinfo, bounded by RESOLVE_TIMEOUT and MAX_LOOKUPS.
fn resolve_bounded(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    static LOOKUPS: std::sync::OnceLock<limits::Limiter> = std::sync::OnceLock::new();
    let host = host.to_string();
    limits::run_bounded(
        LOOKUPS.get_or_init(|| limits::Limiter::new(MAX_LOOKUPS)),
        RESOLVE_TIMEOUT,
        move || Ok((host.as_str(), port).to_socket_addrs()?.collect()),
    )
}

/// Is `ip` a destination nullroute must never dial for the command, and why?
///
/// IPv6 forms that carry an IPv4 address (v4-mapped `::ffff:a.b.c.d`,
/// deprecated v4-compatible `::a.b.c.d`, NAT64 `64:ff9b::a.b.c.d`) are judged
/// by the IPv4 address inside, so `::ffff:127.0.0.1` is loopback.
pub(crate) fn forbidden(ip: IpAddr) -> Option<Forbidden> {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => embedded_v4(v6)
            .and_then(forbidden_v4)
            .or_else(|| forbidden_v6(v6)),
    }
}

fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    // NAT64 well-known prefix 64:ff9b::/96.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32));
    }
    // IPv4-compatible ::a.b.c.d (but not :: or ::1, handled as IPv6).
    if s[..6] == [0; 6] && !(s[6] == 0 && s[7] <= 1) {
        return Some(Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32));
    }
    None
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<Forbidden> {
    let o = ip.octets();
    // 0.0.0.0/8: Linux treats connect() to 0.0.0.0 (and friends) as local.
    if ip.is_loopback() || o[0] == 0 {
        Some(Forbidden::Loopback)
    } else if ip.is_link_local() {
        // 169.254.0.0/16, including 169.254.169.254 (AWS, GCP, Azure, ...)
        // and 169.254.170.2 (ECS task credentials).
        Some(Forbidden::LinkLocal)
    } else if ip == Ipv4Addr::new(100, 100, 100, 200) {
        // Alibaba Cloud metadata.
        Some(Forbidden::Metadata)
    } else {
        None
    }
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<Forbidden> {
    if ip.is_loopback() || ip.is_unspecified() {
        Some(Forbidden::Loopback)
    } else if ip.segments()[0] & 0xffc0 == 0xfe80 {
        // fe80::/10 (Ipv6Addr::is_unicast_link_local).
        Some(Forbidden::LinkLocal)
    } else if ip == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
        // AWS IMDS over IPv6.
        Some(Forbidden::Metadata)
    } else {
        None
    }
}

fn respond(s: &mut TcpStream, code: u16, msg: &str) {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Bad Gateway",
    };
    let body = format!("{msg}\n");
    let _ = write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn al(v: &[&str]) -> Allowlist {
        Allowlist::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn exact_and_case_and_trailing_dot() {
        let a = al(&["API.GitHub.com."]);
        assert!(a.allows("api.github.com", 443));
        assert!(a.allows("api.github.com.", 443));
        assert!(a.allows("Api.GitHub.Com", 443));
        assert!(!a.allows("github.com", 443));
        assert!(!a.allows("evilapi.github.com", 443));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let a = al(&["*.stripe.dev"]);
        assert!(a.allows("api.stripe.dev", 443));
        assert!(a.allows("a.b.stripe.dev", 443));
        assert!(!a.allows("stripe.dev", 443));
        assert!(!a.allows("notstripe.dev", 443));
        assert!(!a.allows("stripe.dev.evil.com", 443));
    }

    #[test]
    fn ip_literals() {
        let a = al(&["10.0.0.5", "2001:db8::1"]);
        assert!(a.allows("10.0.0.5", 443));
        assert!(a.allows("[2001:db8::1]", 443));
        assert!(!a.allows("10.0.0.6", 443));
    }

    #[test]
    fn ipv6_allow_entries_match_canonical_form() {
        // Bare literals already go through IpAddr::to_string.
        let bare = al(&["2001:0db8:0000::0001"]);
        assert!(bare.allows("2001:db8::1", 443));
        assert!(bare.allows("[2001:0db8::1]", 443));

        let bracketed = al(&["[2001:0db8::1]"]);
        assert!(bracketed.allows("2001:db8::1", 443));
        assert!(bracketed.allows("[2001:db8::1]", 80));

        // Port-qualified bracketed form must store the canonical address too.
        let ported = al(&["[2001:0DB8:0:0:0:0:0:1]:8443"]);
        assert!(ported.allows("2001:db8::1", 8443));
        assert!(ported.allows("[2001:db8::1]", 8443));
        assert!(ported.allows("2001:0db8::1", 8443));
        assert!(!ported.allows("2001:db8::1", 443));
        assert!(!ported.allows("2001:db8::2", 8443));
    }

    #[test]
    fn ports_restrict_entries() {
        let a = al(&[
            "db.example.com:5432",
            "api.example.com",
            "[2001:db8::1]:8443",
            "*.svc.test:9000",
        ]);
        assert!(a.allows("db.example.com", 5432));
        assert!(!a.allows("db.example.com", 443));
        assert!(a.allows("api.example.com", 1234));
        assert!(a.allows("2001:db8::1", 8443) && !a.allows("2001:db8::1", 443));
        assert!(a.allows("x.svc.test", 9000) && !a.allows("x.svc.test", 80));
    }

    #[test]
    fn rejects_bad_patterns() {
        for bad in [
            "",
            "*",
            "*.com",
            "https://x.com",
            "x.com/path",
            "x.com:0",
            "x.com:99999",
            "x.com:http",
            "[x.com]:443",
            "[::1",
            "a*.b.com",
            "-x.com",
            "x..com",
        ] {
            assert!(
                Allowlist::parse(&[bad.to_string()]).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn parses_connect_and_absolute_form() {
        let r = parse_request(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(r.connect && r.host == "api.github.com" && r.port == 443);
        let r = parse_request(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("2001:db8::1", 8443));
        let r = parse_request(b"GET http://user:pw@example.com/a?b=1 HTTP/1.1\r\n\r\n").unwrap();
        assert!(!r.connect && r.host == "example.com" && r.port == 80);
        assert_eq!(r.origin_line, "GET /a?b=1 HTTP/1.1");
        let r = parse_request(b"POST http://example.com:8080 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((r.port, r.origin_line.as_str()), (8080, "POST / HTTP/1.1"));
        assert!(parse_request(b"GET /relative HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"GET https://x.com/ HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"CONNECT nohost HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn rewrite_drops_proxy_headers_and_forces_close() {
        let head = b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic abc\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n";
        let req = parse_request(head).unwrap();
        let out = String::from_utf8(rewrite_for_origin(head, &req)).unwrap();
        assert_eq!(
            out,
            "GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    fn why(ip: &str) -> Option<Forbidden> {
        forbidden(ip.parse().unwrap())
    }

    #[test]
    fn loopback_targets_are_forbidden() {
        for ip in [
            "127.0.0.1",
            "127.8.9.10",
            "127.255.255.255",
            "::1",
            "0.0.0.0",
            "0.1.2.3",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
        ] {
            assert_eq!(why(ip), Some(Forbidden::Loopback), "{ip}");
        }
    }

    #[test]
    fn link_local_and_metadata_targets_are_forbidden() {
        for ip in [
            "169.254.169.254",
            "169.254.170.2",
            "169.254.0.1",
            "169.254.255.255",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "fe80::1",
            "fe80::a9fe:a9fe",
            "febf:ffff::1",
        ] {
            assert_eq!(why(ip), Some(Forbidden::LinkLocal), "{ip}");
        }
        for ip in ["100.100.100.200", "fd00:ec2::254", "::ffff:100.100.100.200"] {
            assert_eq!(why(ip), Some(Forbidden::Metadata), "{ip}");
        }
    }

    #[test]
    fn ordinary_targets_are_allowed() {
        for ip in [
            "10.0.0.1",
            "93.184.216.34",
            "169.253.255.255",
            "169.255.0.1",
            "100.100.100.201",
            "128.0.0.1",
            "2001:db8::1",
            "fec0::1",
            "fd00:ec2::253",
            "::ffff:10.0.0.1",
            "64:ff9b::5db8:d822",
        ] {
            assert_eq!(why(ip), None, "{ip}");
        }
    }

    #[test]
    fn allow_rejects_loopback_and_localhost_pointing_at_port() {
        for bad in [
            "127.0.0.1",
            "127.0.0.1:5432",
            "::1",
            "[::1]:8080",
            "::ffff:127.0.0.1",
            "0.0.0.0",
            "localhost",
            "LOCALHOST.",
            "localhost:5432",
            "db.localhost",
            "*.localhost",
            "localhost.localdomain",
            "ip6-localhost",
        ] {
            let e = Allowlist::parse(&[bad.to_string()]).unwrap_err();
            assert!(e.contains("--port"), "{bad}: {e}");
            assert!(e.contains("loopback"), "{bad}: {e}");
        }
        let e = Allowlist::parse(&["localhost:5432".to_string()]).unwrap_err();
        assert!(e.contains("--port 5432"), "{e}");
        let e = Allowlist::parse(&["127.0.0.1".to_string()]).unwrap_err();
        assert!(e.contains("--port PORT"), "{e}");
    }

    #[test]
    fn allow_rejects_link_local_and_metadata() {
        for bad in [
            "169.254.169.254",
            "169.254.169.254:80",
            "fe80::1",
            "[fe80::1]:443",
            "100.100.100.200",
            "fd00:ec2::254",
        ] {
            let e = Allowlist::parse(&[bad.to_string()]).unwrap_err();
            assert!(e.contains("always blocked"), "{bad}: {e}");
        }
        // Look-alikes are fine.
        for ok in [
            "localhost.example.com",
            "mylocalhost",
            "169.255.0.1",
            "notlocalhost.dev",
        ] {
            assert!(Allowlist::parse(&[ok.to_string()]).is_ok(), "{ok}");
        }
    }

    #[test]
    fn resolve_overrides_must_be_allowed_and_valid() {
        let a = al(&["api.example.com", "*.svc.test:9000"]);
        let o = parse_overrides(
            &[
                "API.example.com.:10.0.0.5".to_string(),
                "x.svc.test:[2001:db8::1]".to_string(),
                "y.svc.test:2001:db8::2".to_string(),
            ],
            &a,
        )
        .unwrap();
        assert_eq!(o["api.example.com"], "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(o["x.svc.test"], "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(o["y.svc.test"], "2001:db8::2".parse::<IpAddr>().unwrap());
        for bad in [
            "other.com:10.0.0.5",
            "api.example.com",
            "api.example.com:nope",
            "10.0.0.1:10.0.0.5",
            "svc.test:10.0.0.5",
        ] {
            assert!(parse_overrides(&[bad.to_string()], &a).is_err(), "{bad}");
        }
    }

    #[test]
    fn dial_uses_override_and_still_refuses_loopback() {
        let mut o = Overrides::new();
        o.insert("pinned.test".into(), "127.0.0.1".parse().unwrap());
        assert!(matches!(
            dial("Pinned.Test", 1, &o),
            Err(DialError::Forbidden(Forbidden::Loopback))
        ));
        o.insert("meta.test".into(), "169.254.169.254".parse().unwrap());
        assert!(matches!(
            dial("meta.test", 80, &o),
            Err(DialError::Forbidden(Forbidden::LinkLocal))
        ));
        o.insert("mapped.test".into(), "::ffff:127.0.0.1".parse().unwrap());
        assert!(matches!(
            dial("mapped.test", 80, &o),
            Err(DialError::Forbidden(Forbidden::Loopback))
        ));
    }

    #[test]
    fn private_ranges_are_named() {
        let r = |s: &str| private_range(s.parse().unwrap());
        for ip in [
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "::ffff:10.1.2.3",
        ] {
            assert_eq!(r(ip), Some("private (RFC 1918)"), "{ip}");
        }
        for ip in ["100.64.0.1", "100.127.255.254"] {
            assert_eq!(r(ip), Some("carrier-grade NAT (100.64.0.0/10)"), "{ip}");
        }
        for ip in ["fc00::1", "fd12:3456::1"] {
            assert_eq!(r(ip), Some("unique local (fc00::/7)"), "{ip}");
        }
        for ip in [
            "93.184.216.34",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "2001:db8::1",
            "fe00::1",
        ] {
            assert_eq!(r(ip), None, "{ip}");
        }
    }

    #[test]
    fn startup_warns_about_private_allow_entries_and_pins() {
        let a = al(&[
            "10.0.0.5",
            "93.184.216.34",
            "db.example.com",
            "fd00::1",
            "100.64.1.1:443",
        ]);
        let mut pins = Overrides::new();
        pins.insert("db.example.com".into(), "192.168.0.9".parse().unwrap());
        let w = private_address_warnings(&a, &pins);
        assert_eq!(w.len(), 4, "{w:?}");
        assert!(
            w[0].contains("--allow 10.0.0.5 is a private (RFC 1918) address"),
            "{w:?}"
        );
        assert!(w[1].contains("--allow fd00::1 is a unique local"), "{w:?}");
        assert!(
            w[2].contains("--allow 100.64.1.1 is a carrier-grade NAT"),
            "{w:?}"
        );
        assert!(
            w[3].contains("--resolve db.example.com:192.168.0.9"),
            "{w:?}"
        );
        assert!(private_address_warnings(&al(&["93.184.216.34"]), &Overrides::new()).is_empty());
    }

    #[test]
    fn host_header_must_match_the_request_target() {
        let a = al(&["api.example.com", "other.example.com"]);
        let check = |head: &str| {
            let req = parse_request(head.as_bytes()).unwrap();
            check_host_header(head.as_bytes(), &req, &a)
        };
        let get = |hdrs: &str| format!("GET http://api.example.com:8080/x HTTP/1.1\r\n{hdrs}\r\n");
        assert_eq!(check(&get("")), HostCheck::Fine);
        assert_eq!(
            check(&get("Host: api.example.com:8080\r\n")),
            HostCheck::Fine
        );
        assert_eq!(check(&get("host: API.example.com.\r\n")), HostCheck::Fine);
        assert_eq!(
            check(&get("Accept: */*\r\nHost:   api.example.com \r\n")),
            HostCheck::Fine
        );
        // Another allowed host is fine; one that isn't is not.
        assert_eq!(check(&get("Host: other.example.com\r\n")), HostCheck::Fine);
        assert_eq!(
            check(&get("Host: evil.example\r\n")),
            HostCheck::Differs("evil.example".into())
        );
        assert_eq!(
            check(&get("Host: api.example.com.evil.example\r\n")),
            HostCheck::Differs("api.example.com.evil.example".into())
        );
        assert_eq!(
            check(&get("Host: Evil.Example:81\r\n")),
            HostCheck::Differs("evil.example".into())
        );
        assert!(matches!(
            check(&get("Host: api.example.com\r\nHost: evil.example\r\n")),
            HostCheck::Malformed(_)
        ));
        assert!(matches!(check(&get("Host: \r\n")), HostCheck::Malformed(_)));
        assert!(matches!(
            check(&get("Host: [::1\r\n")),
            HostCheck::Malformed(_)
        ));
        // IP literals, bracketed or not.
        let a = al(&["2001:db8::1"]);
        let head = "GET http://[2001:db8::1]:80/ HTTP/1.1\r\nHost: [2001:0db8::1]\r\n\r\n";
        let req = parse_request(head.as_bytes()).unwrap();
        assert_eq!(
            check_host_header(head.as_bytes(), &req, &a),
            HostCheck::Fine
        );
    }

    #[test]
    fn proxy_port_avoids_forwarded_ports() {
        assert_eq!(pick_port(&[]), 3128);
        assert_eq!(pick_port(&[3128, 3129, 5432]), 3130);
    }
}
