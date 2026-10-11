//! Sockets the caller left open.
//!
//! The command starts in a new network namespace, but a socket is bound to the
//! namespace it was created in, not to the namespace of whoever holds it. A
//! socket that was already open in nullroute's parent (a connection a CI agent
//! or a test harness keeps, a listener handed down by a supervisor) and wasn't
//! marked close-on-exec is inherited by nullroute and then by the command, and
//! it keeps working: the command can use it to reach whatever it is connected
//! to. That is ordinary fork/exec behaviour and nullroute does not close it
//! (see the README, "Inherited file descriptors").
//!
//! This only *finds* them so that nullroute can say so. Sockets that are
//! close-on-exec never reach the command and are not reported. Nothing is
//! closed or changed.

use std::fs;
use std::os::fd::RawFd;

/// How many are named in the warning before "and N more".
const NAMED: usize = 5;

/// An inherited socket.
#[derive(Debug, PartialEq, Eq)]
pub struct Inherited {
    pub fd: RawFd,
    /// "IPv4 stream", "unix datagram", ...
    pub kind: String,
}

/// The sockets above fd 2 that this process holds without close-on-exec, in fd
/// order. Empty if `/proc/self/fd` can't be read.
pub fn sockets() -> Vec<Inherited> {
    let Ok(dir) = fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    let mut found: Vec<Inherited> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<RawFd>().ok())
        .filter(|fd| *fd > 2)
        .filter_map(|fd| inspect(fd).map(|kind| Inherited { fd, kind }))
        .collect();
    found.sort_by_key(|i| i.fd);
    found
}

/// Describe `fd` if it is an inheritable socket.
fn inspect(fd: RawFd) -> Option<String> {
    // SAFETY: these calls only read properties of an integer descriptor, which
    // may be closed again by the time they run (they then fail with EBADF); the
    // out-parameters are valid and correctly sized.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 || flags & libc::FD_CLOEXEC != 0 {
            return None;
        }
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return None;
        }
        let opt = |name: libc::c_int| -> Option<libc::c_int> {
            let mut v: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let r = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                (&mut v as *mut libc::c_int).cast(),
                &mut len,
            );
            (r == 0).then_some(v)
        };
        Some(describe(opt(libc::SO_DOMAIN), opt(libc::SO_TYPE)))
    }
}

fn describe(domain: Option<libc::c_int>, ty: Option<libc::c_int>) -> String {
    let family = match domain {
        Some(libc::AF_UNIX) => "unix".to_string(),
        Some(libc::AF_INET) => "IPv4".to_string(),
        Some(libc::AF_INET6) => "IPv6".to_string(),
        Some(libc::AF_NETLINK) => "netlink".to_string(),
        Some(libc::AF_VSOCK) => "vsock".to_string(),
        Some(d) => format!("address family {d}"),
        None => "unknown family".to_string(),
    };
    let ty = match ty.map(|t| t & 0xf) {
        Some(libc::SOCK_STREAM) => "stream",
        Some(libc::SOCK_DGRAM) => "datagram",
        Some(libc::SOCK_SEQPACKET) => "seqpacket",
        Some(libc::SOCK_RAW) => "raw",
        _ => "socket",
    };
    format!("{family} {ty}")
}

/// The warning lines for `found`, none if it is empty.
pub fn warnings(found: &[Inherited]) -> Vec<String> {
    let mut out: Vec<String> = found
        .iter()
        .take(NAMED)
        .map(|i| {
            format!(
                "nullroute: warning: fd {} is a socket inherited from the caller ({}); it is not sealed, and the command can use it to reach whatever it is connected to. Close it, or mark it close-on-exec, before starting nullroute",
                i.fd, i.kind
            )
        })
        .collect();
    if found.len() > NAMED {
        out.push(format!(
            "nullroute: warning: and {} more inherited sockets",
            found.len() - NAMED
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connected pair; `cloexec` marks both ends close-on-exec.
    fn pair(cloexec: bool) -> [RawFd; 2] {
        let mut fds = [0; 2];
        let ty = libc::SOCK_STREAM | if cloexec { libc::SOCK_CLOEXEC } else { 0 };
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, ty, 0, fds.as_mut_ptr()) },
            0
        );
        fds
    }

    fn close(fds: [RawFd; 2]) {
        for fd in fds {
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn an_inheritable_socket_is_found_and_described() {
        let fds = pair(false);
        let found = sockets();
        for fd in fds {
            let hit = found.iter().find(|i| i.fd == fd);
            assert_eq!(
                hit.map(|i| i.kind.as_str()),
                Some("unix stream"),
                "{found:?}"
            );
        }
        close(fds);
    }

    #[test]
    fn a_close_on_exec_socket_is_not_reported() {
        let fds = pair(true);
        let found = sockets();
        for fd in fds {
            assert!(found.iter().all(|i| i.fd != fd), "{fd} reported: {found:?}");
        }
        close(fds);
    }

    #[test]
    fn marking_a_socket_close_on_exec_afterwards_hides_it() {
        let fds = pair(false);
        unsafe { libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) };
        let found = sockets();
        assert!(found.iter().all(|i| i.fd != fds[0]), "{found:?}");
        assert!(found.iter().any(|i| i.fd == fds[1]), "{found:?}");
        close(fds);
    }

    #[test]
    fn files_and_pipes_are_not_sockets() {
        let mut p = [0; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        let found = sockets();
        for fd in p {
            assert!(found.iter().all(|i| i.fd != fd), "{found:?}");
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn descriptions_name_the_family_and_type() {
        assert_eq!(
            describe(Some(libc::AF_INET), Some(libc::SOCK_STREAM)),
            "IPv4 stream"
        );
        assert_eq!(
            describe(Some(libc::AF_INET6), Some(libc::SOCK_DGRAM)),
            "IPv6 datagram"
        );
        // Type flags such as SOCK_NONBLOCK don't change the name.
        assert_eq!(
            describe(
                Some(libc::AF_UNIX),
                Some(libc::SOCK_STREAM | libc::SOCK_NONBLOCK)
            ),
            "unix stream"
        );
        assert_eq!(describe(None, None), "unknown family socket");
    }

    #[test]
    fn the_warning_names_the_fd_and_caps_the_list() {
        assert!(warnings(&[]).is_empty());
        let many: Vec<Inherited> = (3..13)
            .map(|fd| Inherited {
                fd,
                kind: "IPv4 stream".into(),
            })
            .collect();
        let w = warnings(&many);
        assert_eq!(w.len(), NAMED + 1, "{w:?}");
        assert!(w[0].contains("fd 3 is a socket inherited from the caller (IPv4 stream)"));
        assert!(w[0].starts_with("nullroute: warning: "));
        assert!(w[NAMED].contains("and 5 more inherited sockets"), "{w:?}");
    }
}
