//! Listener handover: sockets created inside the sandbox, served from outside.
//!
//! Several features need something listening *inside* the sandbox's network
//! namespace but handled by nullroute *outside* it, on the host's network:
//! `--port` bridges, the `--allow` proxy and the DNS sinkhole (dns.rs). They
//! work the same way:
//!
//! 1. Before forking, nullroute makes a Unix socketpair and a list of specs
//!    (address, required or optional).
//! 2. In the child, after entering the new network namespace, each spec is
//!    created with raw syscalls. A socket belongs to the namespace it was
//!    created in, forever.
//! 3. The child sends them to the parent over the socketpair (SCM_RIGHTS, in
//!    chunks, since the kernel caps fds per message), then execs the command.
//! 4. The parent, still in the host's namespace, accepts / receives on them.
//!
//! `--port` itself: inside, `localhost:PORT` reaches the host's `localhost:PORT`.

use crate::diag::diagln;
use crate::limits;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Most `--port` values one invocation may forward.
pub const MAX_PORTS: usize = 64;
/// Most listeners of all kinds (ports and proxy).
pub const MAX_LISTENERS: usize = 1024;
/// fds per SCM_RIGHTS message (kernel limit is 253).
const CHUNK: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    /// A bound (not connected) datagram socket, e.g. the DNS sinkhole.
    Udp,
}

#[derive(Debug, Clone, Copy)]
pub struct Spec {
    pub addr: SocketAddr,
    pub proto: Proto,
    /// Optional specs (e.g. ::1 when IPv6 is off) may fail without aborting.
    pub optional: bool,
}

impl Spec {
    pub fn tcp(addr: SocketAddr) -> Self {
        Spec {
            addr,
            proto: Proto::Tcp,
            optional: false,
        }
    }
    pub fn udp(addr: SocketAddr) -> Self {
        Spec {
            addr,
            proto: Proto::Udp,
            optional: false,
        }
    }
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

/// The `--port` specs: 127.0.0.1:PORT and (optional) [::1]:PORT.
pub fn port_specs(port: u16) -> [Spec; 2] {
    [
        Spec::tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        Spec::tcp(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).optional(),
    ]
}

/// A spec turned into raw sockaddr bytes before fork, so the child doesn't allocate.
struct RawSpec {
    family: libc::c_int,
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
    proto: Proto,
    optional: bool,
}

/// Everything the child needs, allocated before fork so the child never allocates.
pub struct ChildSide {
    /// Closed in the parent along with the Command; CLOEXEC in the child.
    sock: OwnedFd,
    specs: Vec<RawSpec>,
    /// One fd (or -1 for a skipped optional spec) per spec.
    fds: Vec<libc::c_int>,
    /// One byte per spec in the current chunk: 1 if its fd is included.
    present: Vec<u8>,
    /// cmsg buffer for one chunk, u64-backed for cmsghdr alignment.
    cmsg: Vec<u64>,
}

pub struct ParentSide {
    sock: OwnedFd,
    count: usize,
}

/// The sockets the parent received, in spec order (None for skipped optionals).
pub struct Received(Vec<Option<RawFd>>);

impl Received {
    /// Take the fd for spec `i`; the caller now owns it.
    pub fn take(&mut self, i: usize) -> Option<RawFd> {
        self.0.get_mut(i).and_then(Option::take)
    }
}

impl Drop for Received {
    fn drop(&mut self) {
        for fd in self.0.iter().flatten() {
            // SAFETY: fds nobody took are still ours.
            unsafe { libc::close(*fd) };
        }
    }
}

fn cmsg_words(n: usize) -> usize {
    // SAFETY: CMSG_SPACE is pure arithmetic.
    let space =
        unsafe { libc::CMSG_SPACE((n * std::mem::size_of::<libc::c_int>()) as u32) } as usize;
    space.div_ceil(8)
}

/// Create the socketpair and preallocate the child's buffers.
pub fn prepare(specs: &[Spec]) -> io::Result<(ParentSide, ChildSide)> {
    if specs.len() > MAX_LISTENERS {
        return Err(io::Error::other(format!(
            "too many listeners ({} > {MAX_LISTENERS})",
            specs.len()
        )));
    }
    let mut sv = [0 as libc::c_int; 2];
    // SAFETY: sv is a valid 2-element array. SEQPACKET keeps chunks as messages
    // and, unlike DGRAM, can't silently drop one.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair succeeded, so both fds are open and ours.
    let (parent_fd, child_fd) =
        unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    // A chunk of 200 sockets is far bigger than the default buffer allows for
    // in-flight fds on some kernels; make room.
    let raw: Vec<RawSpec> = specs.iter().map(to_raw).collect();
    Ok((
        ParentSide {
            sock: parent_fd,
            count: specs.len(),
        },
        ChildSide {
            sock: child_fd,
            fds: vec![-1; raw.len()],
            present: vec![0; CHUNK],
            cmsg: vec![0; cmsg_words(CHUNK)],
            specs: raw,
        },
    ))
}

fn to_raw(s: &Spec) -> RawSpec {
    // SAFETY: zeroed sockaddr_storage is valid; we write a sockaddr_in/_in6 into it.
    unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        let (family, len) = match s.addr {
            SocketAddr::V4(a) => {
                let sin = &mut *(&raw mut storage).cast::<libc::sockaddr_in>();
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = a.port().to_be();
                sin.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                (libc::AF_INET, std::mem::size_of::<libc::sockaddr_in>())
            }
            SocketAddr::V6(a) => {
                let sin6 = &mut *(&raw mut storage).cast::<libc::sockaddr_in6>();
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = a.port().to_be();
                sin6.sin6_addr.s6_addr = a.ip().octets();
                (libc::AF_INET6, std::mem::size_of::<libc::sockaddr_in6>())
            }
        };
        RawSpec {
            family,
            storage,
            len: len as libc::socklen_t,
            proto: s.proto,
            optional: s.optional,
        }
    }
}

impl ChildSide {
    /// Runs in the forked child after unshare and `lo` is up. Raw syscalls only.
    pub fn listen_and_send(&mut self) -> io::Result<()> {
        for i in 0..self.specs.len() {
            let s = &self.specs[i];
            match create(s) {
                Ok(fd) => self.fds[i] = fd,
                Err(_) if s.optional => self.fds[i] = -1,
                Err(e) => return Err(e),
            }
        }
        let mut start = 0;
        while start < self.specs.len() {
            let end = (start + CHUNK).min(self.specs.len());
            self.send_chunk(start, end)?;
            start = end;
        }
        for &fd in &self.fds {
            if fd >= 0 {
                // SAFETY: closing our own copies; the parent has its own references now.
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    fn send_chunk(&mut self, start: usize, end: usize) -> io::Result<()> {
        let n = end - start;
        let mut count = 0;
        let mut batch = [0 as libc::c_int; CHUNK];
        for i in start..end {
            let fd = self.fds[i];
            self.present[i - start] = (fd >= 0) as u8;
            if fd >= 0 {
                batch[count] = fd;
                count += 1;
            }
        }
        // SAFETY: buffers sized for CHUNK fds; msghdr points at live memory during sendmsg.
        unsafe {
            let mut iov = libc::iovec {
                iov_base: self.present.as_mut_ptr().cast(),
                iov_len: n,
            };
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if count > 0 {
                msg.msg_control = self.cmsg.as_mut_ptr().cast();
                msg.msg_controllen =
                    libc::CMSG_SPACE((count * std::mem::size_of::<libc::c_int>()) as u32) as _;
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len =
                    libc::CMSG_LEN((count * std::mem::size_of::<libc::c_int>()) as u32) as _;
                std::ptr::copy_nonoverlapping(
                    batch.as_ptr(),
                    libc::CMSG_DATA(c).cast::<libc::c_int>(),
                    count,
                );
            }
            if libc::sendmsg(self.sock.as_raw_fd(), &msg, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// socket + bind (+ listen for TCP), raw syscalls only.
fn create(s: &RawSpec) -> io::Result<libc::c_int> {
    let ty = match s.proto {
        Proto::Tcp => libc::SOCK_STREAM,
        Proto::Udp => libc::SOCK_DGRAM,
    };
    // SAFETY: storage holds a valid sockaddr of length len.
    unsafe {
        let fd = libc::socket(s.family, ty | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        if s.proto == Proto::Tcp {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&raw const one).cast(),
                std::mem::size_of_val(&one) as _,
            );
        }
        if s.family == libc::AF_INET6 {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&raw const one).cast(),
                std::mem::size_of_val(&one) as _,
            );
        }
        if libc::bind(fd, (&raw const s.storage).cast(), s.len) != 0
            || (s.proto == Proto::Tcp && libc::listen(fd, 128) != 0)
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

impl ParentSide {
    /// Receive every socket the child created. Call after spawn (which returns
    /// only once the child has exec'd, i.e. after it sent everything).
    pub fn receive(self) -> io::Result<Received> {
        let mut out = Vec::with_capacity(self.count);
        let mut cmsg = vec![0u64; cmsg_words(CHUNK)];
        let mut present = [0u8; CHUNK];
        while out.len() < self.count {
            let n = (self.count - out.len()).min(CHUNK);
            // SAFETY: buffers outlive recvmsg and are sized for one chunk.
            let fds = unsafe {
                let mut iov = libc::iovec {
                    iov_base: present.as_mut_ptr().cast(),
                    iov_len: n,
                };
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg.as_mut_ptr().cast();
                msg.msg_controllen = (cmsg.len() * 8) as _;
                let got = libc::recvmsg(
                    self.sock.as_raw_fd(),
                    &mut msg,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
                );
                if got < 0 {
                    let e = io::Error::last_os_error();
                    return Err(io::Error::new(
                        e.kind(),
                        format!("receiving sockets from the sandbox: {e}"),
                    ));
                }
                if got as usize != n {
                    return Err(io::Error::other(format!(
                        "expected a chunk of {n} specs, got {got}"
                    )));
                }
                if msg.msg_flags & libc::MSG_CTRUNC != 0 {
                    return Err(io::Error::other("sockets from the sandbox were truncated"));
                }
                let mut fds = Vec::new();
                let c = libc::CMSG_FIRSTHDR(&msg);
                if !c.is_null() && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let k = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                        / std::mem::size_of::<libc::c_int>();
                    let data = libc::CMSG_DATA(c).cast::<libc::c_int>();
                    for i in 0..k {
                        fds.push(*data.add(i));
                    }
                }
                fds
            };
            let expected = present[..n].iter().filter(|&&b| b == 1).count();
            if fds.len() != expected {
                for fd in fds {
                    // SAFETY: closing fds we just received.
                    unsafe { libc::close(fd) };
                }
                return Err(io::Error::other(format!(
                    "expected {expected} sockets from the sandbox"
                )));
            }
            let mut it = fds.into_iter();
            for &p in &present[..n] {
                out.push(if p == 1 { it.next() } else { None });
            }
        }
        Ok(Received(out))
    }
}

/// Serve a `--port` listener: relay each connection to the host's localhost:port.
pub fn serve_port(fd: RawFd, port: u16, warned: Arc<AtomicBool>) {
    spawn_acceptor(fd, port, warned);
}

fn spawn_acceptor(fd: RawFd, port: u16, warned: Arc<AtomicBool>) {
    // SAFETY: fd is a listening TCP socket we received and now own exclusively.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    let limit = limits::Limiter::new(limits::max_connections(limits::MAX_CONNECTIONS));
    limits::spawn_service(move || {
        limits::accept_loop(
            || listener.accept().map(|(c, _)| c),
            |inner| {
                let warned = warned.clone();
                let Some(permit) = limit.try_acquire() else {
                    return; // too many open: dropping it closes it
                };
                limits::spawn_conn(permit, move || match connect_host(port) {
                    Ok(outer) => relay(inner, outer),
                    Err(e) => {
                        // Once per port: a test retrying in a loop shouldn't flood stderr.
                        if !warned.swap(true, Ordering::Relaxed) {
                            diagln!(
                                "nullroute: --port {port}: {}",
                                describe_connect_error(port, &e)
                            );
                        }
                        let _ = inner.shutdown(Shutdown::Both);
                    }
                });
            },
        );
    });
}

/// Why connecting to the host's localhost:port failed, for the warning. Out
/// of file descriptors is nullroute's own problem, not "nothing is listening".
fn describe_connect_error(port: u16, e: &io::Error) -> String {
    if limits::is_out_of_fds(e) {
        format!(
            "out of file descriptors while connecting to localhost:{port} ({e}); raise the limit (ulimit -n) or open fewer connections"
        )
    } else {
        format!("nothing reachable on the host at localhost:{port} ({e})")
    }
}

/// Connect to the host's localhost:port, IPv4 first, then IPv6.
fn connect_host(port: u16) -> io::Result<TcpStream> {
    let timeout = Duration::from_secs(5);
    let v4 = SocketAddr::from(([127, 0, 0, 1], port));
    let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&v4, timeout)
        .or_else(|e4| TcpStream::connect_timeout(&v6, timeout).map_err(|_| e4))
}

/// Copy bytes both ways until each side closes, propagating half-closes.
pub(crate) fn relay(a: TcpStream, b: TcpStream) {
    let _ = a.set_nodelay(true);
    let _ = b.set_nodelay(true);
    let (Ok(mut a_read), Ok(mut b_write)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    // If the second thread can't be started, give up on this connection (it is
    // closed as the streams drop) rather than panic.
    let Ok(up) = thread::Builder::new().spawn(move || {
        let _ = io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(Shutdown::Write);
    }) else {
        return;
    };
    let (mut b_read, mut a_write) = (b, a);
    let _ = io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown(Shutdown::Write);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_out_of_descriptors_is_not_reported_as_nothing_listening() {
        let emfile = io::Error::from_raw_os_error(libc::EMFILE);
        let msg = describe_connect_error(5432, &emfile);
        assert!(msg.contains("out of file descriptors"), "{msg}");
        assert!(!msg.contains("nothing reachable"), "{msg}");
        let refused = io::Error::from_raw_os_error(libc::ECONNREFUSED);
        let msg = describe_connect_error(5432, &refused);
        assert!(
            msg.contains("nothing reachable on the host at localhost:5432"),
            "{msg}"
        );
    }
}
