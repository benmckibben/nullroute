//! Hermetic mode: run a command in a fresh, empty network namespace.
//!
//! How it works (Linux only):
//! 1. Fork. In the child, before exec:
//!    - unshare(CLONE_NEWUSER | CLONE_NEWNET): a new user namespace (so no root
//!      is needed) and a new network namespace that has only a loopback device.
//!    - map our real uid/gid into the user namespace, so the command still runs
//!      as "you", not as a fake root.
//!    - bring `lo` up (it starts DOWN), so 127.0.0.1 works inside.
//! 2. exec the command. It keeps no capabilities after exec (it isn't root in
//!    the namespace), so it can't add interfaces or routes to get back out.
//!
//! Inside, there is no route to anything but loopback: connections to other
//! hosts fail immediately with "network unreachable", and DNS fails.
//!
//! Loopback inside is the namespace's own, so services on the host's 127.0.0.1
//! (a local Postgres, a published Docker port) are only reachable through
//! `--port` forwarding; see forward.rs. With `--allow`, names resolve through
//! the DNS sinkhole instead (dns.rs), which needs the mount namespace too.

use std::ffi::CString;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};

use crate::report::Report;
use crate::{dns, forward, hide, proxy, signals};
use std::sync::Arc;

/// What a listener created inside the sandbox is for.
enum Role {
    Port(u16),
    Proxy,
    Dns(dns::Listener),
}

/// Run `argv` inside a hermetic network namespace and wait for it. Each port in
/// `ports` is bridged from the sandbox's localhost to the host's.
pub fn run_hermetic(
    argv: &[String],
    ports: &[u16],
    hide: Option<&hide::Plan>,
    proxy: Option<(u16, Arc<proxy::Proxy>)>,
    dns: Option<&Arc<dns::Sinkhole>>,
    report: &Arc<Report>,
) -> io::Result<ExitStatus> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no command given"))?;

    // Prepare everything that allocates *before* fork. The pre_exec closure runs
    // in the forked child, where allocating is not guaranteed safe.
    // SAFETY: getuid/getgid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let uid_map = format!("{uid} {uid} 1\n");
    let gid_map = format!("{gid} {gid} 1\n");
    let paths = (
        CString::new("/proc/self/setgroups").unwrap(),
        CString::new("/proc/self/uid_map").unwrap(),
        CString::new("/proc/self/gid_map").unwrap(),
    );

    // Every listener the parent will serve is created inside the sandbox and
    // handed over in one batch: --port bridges, the --allow proxy, then the
    // DNS sinkhole (resolver + one listener per synthetic address and port).
    let mut roles: Vec<(Role, forward::Spec)> = Vec::new();
    for &p in ports {
        roles.extend(forward::port_specs(p).map(|s| (Role::Port(p), s)));
    }
    if let Some((pp, _)) = &proxy {
        roles.extend(forward::port_specs(*pp).map(|s| (Role::Proxy, s)));
    }
    if let Some(d) = dns {
        roles.extend(
            d.plan()
                .listeners()
                .into_iter()
                .map(|(l, s)| (Role::Dns(l), s)),
        );
    }
    let specs: Vec<forward::Spec> = roles.iter().map(|(_, s)| *s).collect();
    let (parent_side, mut child_side) = if specs.is_empty() {
        (None, None)
    } else {
        let (p, c) = forward::prepare(&specs)?;
        (Some(p), Some(c))
    };

    // Bind mounts for the private mount namespace: socket decoys, then the
    // sinkhole's resolv.conf and resolver-socket masks. dns_files must outlive
    // the child (it deletes the sources on drop).
    let dns_files = dns.map(|_| dns::Files::create()).transpose()?;
    let need_mount_ns = hide.is_some() || dns.is_some();
    let mounts = if need_mount_ns {
        let mut m = hide
            .map(|h| h.mount_list())
            .transpose()?
            .unwrap_or_default();
        if let Some(f) = &dns_files {
            m.extend(f.mounts.iter().cloned());
        }
        Some(m)
    } else {
        None
    };
    let flags = namespace_flags(need_mount_ns);
    let pool_address = dns.is_some();

    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some((pp, _)) = &proxy {
        cmd.envs(proxy::env_vars(*pp));
    }
    // SAFETY: the closure only makes raw syscalls (no allocation, no locks),
    // which is what pre_exec requires.
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(flags) != 0 {
                return Err(io::Error::last_os_error());
            }
            // An unprivileged process must deny setgroups before writing gid_map.
            write_file(&paths.0, b"deny")?;
            write_file(&paths.1, uid_map.as_bytes())?;
            write_file(&paths.2, gid_map.as_bytes())?;
            if let Some(m) = mounts.as_ref() {
                hide::apply_in_child(m)?;
            }
            loopback_up()?;
            if pool_address {
                dns::add_pool_address()?;
            }
            if let Some(c) = child_side.as_mut() {
                c.listen_and_send()?;
            }
            Ok(())
        });
    }

    let spawned = cmd.spawn().map_err(explain_spawn_error);
    // Dropping cmd drops the pre_exec closure and with it the parent's copy of
    // the child's socket end.
    drop(cmd);
    let mut child = spawned?;
    signals::install(child.id());
    if let Some(h) = hide
        && let Err(e) = h.start(report)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    if let Some(parent) = parent_side {
        let mut got = match parent.receive() {
            Ok(g) => g,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        // One "nothing listening" warning per --port, shared by its v4/v6 sockets.
        let mut warned = std::collections::HashMap::new();
        for (i, (role, _)) in roles.iter().enumerate() {
            let Some(fd) = got.take(i) else { continue };
            match role {
                Role::Port(port) => {
                    let w = warned
                        .entry(*port)
                        .or_insert_with(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));
                    forward::serve_port(fd, *port, w.clone());
                }
                Role::Proxy => match &proxy {
                    Some((_, p)) => p.spawn_acceptor(fd),
                    // SAFETY: unreachable in practice; don't leak the fd.
                    None => unsafe {
                        libc::close(fd);
                    },
                },
                Role::Dns(l) => match dns {
                    Some(d) => d.serve(*l, fd),
                    // SAFETY: as above.
                    None => unsafe {
                        libc::close(fd);
                    },
                },
            }
        }
    }
    let status = child.wait();
    drop(dns_files);
    status
}

/// The namespaces the child unshares: always user + net, plus a mount
/// namespace when there are sockets to hide or the DNS sinkhole needs its
/// resolv.conf. Shared with `--inspect`.
pub fn namespace_flags(mount_ns: bool) -> libc::c_int {
    libc::CLONE_NEWUSER | libc::CLONE_NEWNET | if mount_ns { libc::CLONE_NEWNS } else { 0 }
}

/// open + write + close with raw syscalls (safe to call in pre_exec).
fn write_file(path: &CString, data: &[u8]) -> io::Result<()> {
    // SAFETY: path is a valid NUL-terminated string; data is a valid slice.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = libc::write(fd, data.as_ptr().cast(), data.len());
        let err = io::Error::last_os_error();
        libc::close(fd);
        if n < 0 || n as usize != data.len() {
            return Err(err);
        }
    }
    Ok(())
}

/// Set IFF_UP on "lo" via ioctl, the same thing `ip link set lo up` does.
fn loopback_up() -> io::Result<()> {
    // SAFETY: plain socket/ioctl calls on a zeroed, correctly sized ifreq.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (dst, src) in ifr.ifr_name.iter_mut().zip(b"lo\0") {
            *dst = *src as libc::c_char;
        }
        let result = (|| {
            if libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) < 0 {
                return Err(io::Error::last_os_error());
            }
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(sock, libc::SIOCSIFFLAGS, &ifr) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        libc::close(sock);
        result
    }
}

/// Turn the common "namespaces are disabled" failure into an actionable message.
fn explain_spawn_error(e: io::Error) -> io::Error {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) | Some(libc::ENOSPC) => io::Error::new(
            e.kind(),
            format!(
                "{e}: could not create an unprivileged user namespace. \
                 On Ubuntu 23.10+ this is usually AppArmor \
                 (sysctl kernel.apparmor_restrict_unprivileged_userns); \
                 elsewhere check kernel.unprivileged_userns_clone and user.max_user_namespaces"
            ),
        ),
        _ => e,
    }
}
