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
//! hosts fail immediately with "network unreachable", and DNS fails. Local
//! resolver sockets that would resolve on the host's behalf (systemd-resolved's
//! varlink socket, nscd, the system D-Bus) are masked in a private mount
//! namespace; see dns.rs and hide.rs.
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
use crate::{dns, forward, hide, lifecycle, limits, proxy, signals};
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
    mut hide: Option<&mut hide::Plan>,
    proxy: Option<(u16, Arc<proxy::Proxy>)>,
    dns: Option<&Arc<dns::Sinkhole>>,
    report: &Arc<Report>,
) -> io::Result<ExitStatus> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no command given"))?;

    // From here until the signal thread is running, SIGINT/SIGQUIT/SIGTERM/SIGHUP
    // stay pending instead of hitting nullroute's default action (see
    // signals.rs). Blocking comes first, before anything is created on disk,
    // so a signal during setup can't kill nullroute and leave files behind.
    // Whatever the command orphans is reparented to nullroute, which kills it
    // once the command is done (lifecycle.rs).
    lifecycle::become_subreaper();
    let blocked = signals::block()?;
    // Relaying uses two descriptors per connection: lift the soft descriptor
    // limit to the hard one for nullroute itself. The command gets the original
    // back before exec (below).
    let nofile_original = limits::raise_nofile_limit();

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
    // sinkhole's resolv.conf (with --allow) and the resolver-socket masks
    // (always: systemd-resolved's varlink socket and nscd would otherwise
    // resolve names on the host's network). Their source files live in private
    // temp dirs that are removed right after spawn (tmpdir.rs).
    if let Some(h) = hide.as_deref_mut() {
        h.prepare()?;
    }
    let dns_files = Some(dns::Files::create(dns.is_some())?).filter(|f| !f.mounts.is_empty());
    let need_mount_ns = hide.is_some() || dns_files.is_some();
    let mounts = if need_mount_ns {
        let mut m = hide
            .as_deref()
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

    let child_mask = blocked.child_mask()?;
    hold_for_test();
    // The parent-death signal is tied to the forking thread (lifecycle.rs).
    debug_assert!(
        lifecycle::on_main_thread(),
        "spawn the command from the main thread"
    );
    // SAFETY: getpid has no preconditions.
    let parent = unsafe { libc::getpid() };
    // A bystander in our process group, to tell group-directed signals from
    // pid-directed ones (signals.rs). Forked while we are still single-threaded.
    let sentinel = blocked.spawn_sentinel(parent);

    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some((pp, _)) = &proxy {
        cmd.envs(proxy::env_vars(*pp));
    }
    // SAFETY: the closure only makes raw syscalls (no allocation, no locks),
    // which is what pre_exec requires.
    unsafe {
        cmd.pre_exec(move || {
            let mut setup = || -> io::Result<()> {
                // First, so the child can't outlive nullroute even during setup.
                lifecycle::die_with_parent(parent)?;
                // Opened now, read at the end: the namespace changes below may
                // change what the child can open (signals.rs).
                let parent_status = child_mask.open_parent_status()?;
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
                if let Some(original) = &nofile_original
                    && libc::setrlimit(libc::RLIMIT_NOFILE, original) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                // Re-arm after the user-namespace credential change (lifecycle.rs).
                lifecycle::die_with_parent(parent)?;
                // Last: unblock, so nothing is delivered before setup is done. A
                // SIGINT/SIGQUIT that reached only nullroute is passed on here.
                child_mask.restore(parent_status)?;
                Ok(())
            };
            // Tag setup failures so they can be told apart from exec failures
            // (ENOENT/EACCES from the command itself). from_raw_os_error does
            // not allocate, so this stays async-signal-safe.
            setup().map_err(|e| {
                io::Error::from_raw_os_error(
                    e.raw_os_error().unwrap_or(libc::EIO) | SETUP_ERROR_TAG,
                )
            })
        });
    }

    let spawned = cmd.spawn().map_err(classify_spawn_error);
    // Dropping cmd drops the pre_exec closure and with it the parent's copy of
    // the child's socket end.
    drop(cmd);
    // Spawn returns once the command has exec'd, i.e. after the child made its
    // bind mounts: the files they came from can go now, so nothing is left in
    // the temp dir whatever happens to nullroute from here on.
    if let Some(f) = &dns_files {
        f.cleanup();
    }
    if let Some(h) = hide.as_deref() {
        h.cleanup();
    }
    let mut child = spawned?;
    let fwd = match blocked.start(child.id(), sentinel) {
        Ok(f) => f,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            lifecycle::kill_leftovers();
            return Err(io::Error::new(
                e.kind(),
                format!("starting the signal forwarder: {e}"),
            ));
        }
    };
    if let Some(h) = hide.as_deref()
        && let Err(e) = h.start(report)
    {
        let _ = child.kill();
        let _ = signals::wait_for_exit(&mut child, &fwd);
        lifecycle::kill_leftovers();
        return Err(e);
    }
    if let Some(parent) = parent_side {
        let mut got = match parent.receive() {
            Ok(g) => g,
            Err(e) => {
                let _ = child.kill();
                let _ = signals::wait_for_exit(&mut child, &fwd);
                lifecycle::kill_leftovers();
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
    let status = signals::wait_for_exit(&mut child, &fwd);
    // The command is done; don't leave anything it started running in a
    // sandbox whose relays are about to go away.
    lifecycle::kill_leftovers();
    status
}

/// Test hook (debug builds only): with NULLROUTE_TEST_HOLD_BEFORE_SPAWN=PATH,
/// create PATH and wait until it is removed (at most 10 s), right after the
/// signals are blocked and before the command is forked. Lets a test land a
/// signal in that window deterministically instead of racing for it.
#[cfg(debug_assertions)]
fn hold_for_test() {
    let Some(path) = std::env::var_os("NULLROUTE_TEST_HOLD_BEFORE_SPAWN") else {
        return;
    };
    let path = std::path::Path::new(&path);
    if std::fs::write(path, b"holding\n").is_err() {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

#[cfg(not(debug_assertions))]
fn hold_for_test() {}

/// The namespaces the child unshares: always user + net, plus a mount
/// namespace when there are sockets to hide or resolver sockets to mask, or
/// the DNS sinkhole needs its resolv.conf. Shared with `--inspect`.
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
        // `as _`: the request argument is c_ulong on glibc but c_int on musl.
        let result = (|| {
            if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
                return Err(io::Error::last_os_error());
            }
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        libc::close(sock);
        result
    }
}

/// Set on the errno of a failure inside the forked child's setup (pre_exec),
/// so it can be told apart from the exec of the command itself failing.
const SETUP_ERROR_TAG: i32 = 1 << 24;

/// The command itself could not be started: not found (127) or not
/// executable (126), the codes shells and `docker run` use. Carried inside the
/// `io::Error` returned by `run_hermetic`; see [`command_exit_code`].
#[derive(Debug)]
struct CommandNotStarted {
    code: u8,
    source: io::Error,
}

impl std::fmt::Display for CommandNotStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for CommandNotStarted {}

/// 127 or 126 if `e` says the command could not be found or executed, else None.
pub fn command_exit_code(e: &io::Error) -> Option<u8> {
    e.get_ref()?
        .downcast_ref::<CommandNotStarted>()
        .map(|c| c.code)
}

fn classify_spawn_error(e: io::Error) -> io::Error {
    let Some(errno) = e.raw_os_error() else {
        return e;
    };
    if errno & SETUP_ERROR_TAG != 0 {
        return explain_spawn_error(io::Error::from_raw_os_error(errno & !SETUP_ERROR_TAG));
    }
    let code = match errno {
        libc::ENOENT | libc::ENOTDIR => 127,
        libc::EACCES | libc::ENOEXEC | libc::EISDIR | libc::ETXTBSY | libc::ELOOP => 126,
        // fork/pipe failures and the like: nullroute's problem, not the command's.
        _ => return e,
    };
    io::Error::new(e.kind(), CommandNotStarted { code, source: e })
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
