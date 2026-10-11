//! Socket hiding: close the Unix-socket side door out of the sandbox.
//!
//! A network namespace only scopes network sockets. Unix socket *files* (like
//! /var/run/docker.sock) are reached through the filesystem, so a sandboxed
//! command could still ask the Docker daemon, which runs outside with full
//! network access, to start a container for it.
//!
//! To close that, nullroute also gives the command its own mount namespace and
//! bind-mounts a decoy socket over each hidden path. The decoys are Unix
//! listeners nullroute owns (in a private temp dir); connecting to a hidden
//! path reaches the decoy, which:
//!   - answers HTTP requests with `403` and a JSON `{"message": ...}`, which
//!     the Docker and Podman CLIs print as "Error response from daemon: ...";
//!   - makes nullroute print one warning per path on stderr saying how to allow it.
//!
//! The command can't remove the decoys: after exec it holds no capabilities, and
//! unmounting needs CAP_SYS_ADMIN. Mounts are only changed inside the new mount
//! namespace; the host's filesystem is untouched.
//!
//! By default these are hidden (the ones that exist; see [`SocketEnv::default_sockets`]):
//! container runtimes, the system D-Bus, the user's session D-Bus and systemd
//! user manager, snapd, SSH/keyring agents (`$SSH_AUTH_SOCK`), gpg-agent /
//! dirmngr and, under WSL, the interop socket. `--hide-socket` adds more and
//! `--allow-socket` keeps one visible.
//!
//! Each of these is a service that lives outside the network namespace and
//! will do things on the command's behalf. The system bus reaches
//! systemd-resolved (`org.freedesktop.resolve1`), which resolves any name for
//! whoever asks: a DNS side channel straight past the sandbox. The session bus
//! and the systemd user manager start processes on the host (`systemd-run
//! --user` runs a command in the host's network namespace). dirmngr fetches
//! keys over the host's network, snapd installs snaps, container runtimes
//! start containers with a network.
//!
//! Abstract sockets (`@name`, a D-Bus session bus address of the form
//! `unix:abstract=...`, the X11 `@/tmp/.X11-unix/X0` name) live in the network
//! namespace, so the sandbox's own empty one hides the host's: nothing to do.
//! Display servers (X11, Wayland) are not hidden by default: they can inject
//! input and read the screen, but that is not a way to the network, and hiding
//! them would break GUI tests. Hide one with `--hide-socket` if that matters.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::diag::diagln;
use crate::limits::{self, Limiter};
use crate::report::{Kind, Report, json_string};
use crate::tmpdir::PrivateDir;

/// What the default list of hidden sockets is derived from: the places a user's session
/// services listen, which depend on the environment. Separate from the process
/// environment so tests can build one without touching it.
#[derive(Debug, Default, Clone)]
pub struct SocketEnv {
    pub uid: u32,
    /// `$XDG_RUNTIME_DIR`.
    pub xdg_runtime_dir: Option<PathBuf>,
    /// `$HOME`.
    pub home: Option<PathBuf>,
    /// `$GNUPGHOME`.
    pub gnupg_home: Option<PathBuf>,
    /// `$DBUS_SESSION_BUS_ADDRESS`.
    pub dbus_session: Option<String>,
    /// `$DBUS_SYSTEM_BUS_ADDRESS`.
    pub dbus_system: Option<String>,
    /// `$SSH_AUTH_SOCK`.
    pub ssh_auth_sock: Option<PathBuf>,
    /// `$DOCKER_HOST`.
    pub docker_host: Option<String>,
    /// `$WSL_INTEROP`.
    pub wsl_interop: Option<PathBuf>,
}

impl SocketEnv {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
        SocketEnv {
            // SAFETY: getuid has no preconditions and cannot fail.
            uid: unsafe { libc::getuid() },
            xdg_runtime_dir: var("XDG_RUNTIME_DIR").map(PathBuf::from),
            home: var("HOME").map(PathBuf::from),
            gnupg_home: var("GNUPGHOME").map(PathBuf::from),
            dbus_session: var("DBUS_SESSION_BUS_ADDRESS").and_then(|v| v.into_string().ok()),
            dbus_system: var("DBUS_SYSTEM_BUS_ADDRESS").and_then(|v| v.into_string().ok()),
            ssh_auth_sock: var("SSH_AUTH_SOCK").map(PathBuf::from),
            docker_host: var("DOCKER_HOST").and_then(|v| v.into_string().ok()),
            wsl_interop: var("WSL_INTEROP").map(PathBuf::from),
        }
    }

    /// The directories a session's runtime sockets live in: `$XDG_RUNTIME_DIR`
    /// and the conventional `/run/user/UID` (which is where a user's session
    /// bus is even when the variable isn't set, as in cron and some CI shells).
    fn runtime_dirs(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.xdg_runtime_dir.iter().cloned().collect();
        let conventional = PathBuf::from(format!("/run/user/{}", self.uid));
        if !v.contains(&conventional) {
            v.push(conventional);
        }
        v
    }

    /// Container-runtime sockets, at their standard paths and wherever
    /// `DOCKER_HOST` points.
    fn runtime_sockets(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/podman/podman.sock",
            "/run/containerd/containerd.sock",
            "/run/buildkit/buildkitd.sock",
            "/run/k3s/containerd/containerd.sock",
            "/run/crio/crio.sock",
            "/run/libvirt/libvirt-sock",
            "/var/lib/lxd/unix.socket",
            "/var/snap/lxd/common/lxd/unix.socket",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        for dir in self.runtime_dirs() {
            for rel in [
                "docker.sock", // rootless Docker
                "docker/containerd/containerd.sock",
                "podman/podman.sock", // rootless Podman
                "buildkit/buildkitd.sock",
                "libvirt/libvirt-sock",
            ] {
                v.push(dir.join(rel));
            }
        }
        v.extend(self.docker_api_home_sockets());
        // An explicit DOCKER_HOST=unix:///path is where the CLI will actually go.
        if let Some(p) = self
            .docker_host
            .as_deref()
            .and_then(|h| h.strip_prefix("unix://"))
        {
            v.push(PathBuf::from(p));
        }
        v
    }

    /// Sockets that speak the Docker HTTP API, the ones `--seal-docker` can
    /// seal: the system and rootless Docker sockets, `DOCKER_HOST` and the
    /// home-directory ones. (containerd and BuildKit speak gRPC and are only
    /// hidden.)
    pub fn docker_api_sockets(&self) -> Vec<PathBuf> {
        let mut v = vec![
            PathBuf::from("/var/run/docker.sock"),
            PathBuf::from("/run/docker.sock"),
        ];
        v.extend(
            self.runtime_dirs()
                .into_iter()
                .map(|d| d.join("docker.sock")),
        );
        v.extend(self.docker_api_home_sockets());
        if let Some(p) = self
            .docker_host
            .as_deref()
            .and_then(|h| h.strip_prefix("unix://"))
        {
            v.push(PathBuf::from(p));
        }
        v
    }

    /// Docker API sockets that Docker Desktop and the VM-based runtimes
    /// (Colima, Rancher Desktop, Lima, OrbStack) keep in the home directory.
    /// Wildcards are expanded against what exists.
    pub fn docker_api_home_sockets(&self) -> Vec<PathBuf> {
        let Some(home) = &self.home else {
            return Vec::new();
        };
        [
            ".docker/run/docker.sock", // Docker Desktop
            ".docker/desktop/*.sock",
            ".colima/*/docker.sock",
            ".rd/docker.sock", // Rancher Desktop
            ".lima/*/sock/docker.sock",
            ".orbstack/run/docker.sock",
        ]
        .iter()
        .flat_map(|rel| expand(&home.join(rel)))
        .collect()
    }

    /// Everything hidden unless `--allow-socket`ed, each with why. Only sockets
    /// that exist are hidden by [`plan`]; a path that isn't there is skipped
    /// silently.
    pub fn default_sockets(&self) -> Vec<(PathBuf, &'static str)> {
        let mut v: Vec<(PathBuf, &'static str)> = Vec::new();
        let mut add = |paths: Vec<PathBuf>, why: &'static str| {
            v.extend(paths.into_iter().map(|p| (p, why)));
        };
        add(self.runtime_sockets(), RUNTIME_REASON);
        add(self.system_bus_sockets(), DBUS_REASON);

        let mut session: Vec<PathBuf> = self
            .dbus_session
            .as_deref()
            .map(dbus_address_paths)
            .unwrap_or_default();
        let mut manager = Vec::new();
        let mut snapd = vec![
            PathBuf::from("/run/snapd.socket"),
            PathBuf::from("/run/snapd-snap.socket"),
        ];
        let mut agents: Vec<PathBuf> = self.ssh_auth_sock.iter().cloned().collect();
        let mut gpg = Vec::new();
        for dir in self.runtime_dirs() {
            session.push(dir.join("bus"));
            manager.push(dir.join("systemd/private"));
            snapd.push(dir.join("snapd-session-agent.socket"));
            agents.extend(
                ["ssh-agent.socket", "openssh_agent", "gcr/ssh", "keyring/*"]
                    .iter()
                    .flat_map(|rel| expand(&dir.join(rel))),
            );
            gpg.extend(
                ["gnupg/S.*", "gnupg/d.*/S.*"]
                    .iter()
                    .flat_map(|rel| expand(&dir.join(rel))),
            );
        }
        let gnupg_homes = self.home.iter().map(|h| h.join(".gnupg"));
        for dir in gnupg_homes.chain(self.gnupg_home.clone()) {
            gpg.extend(expand(&dir.join("S.*")));
        }
        add(session, SESSION_BUS_REASON);
        add(manager, USER_MANAGER_REASON);
        add(snapd, SNAPD_REASON);
        add(agents, AGENT_REASON);
        add(gpg, GPG_REASON);
        add(self.wsl_interop_sockets(Path::new("/run/WSL")), WSL_REASON);
        v
    }

    /// The WSL interop sockets: `<dir>/<N>_interop` (`/run/WSL`; some are
    /// symlinks to one another) and wherever `$WSL_INTEROP` points. A process
    /// that can reach one can have WSL start a Windows program, which is not in
    /// the sandbox's network namespace.
    fn wsl_interop_sockets(&self, dir: &Path) -> Vec<PathBuf> {
        let mut v = expand(&dir.join("*_interop"));
        v.extend(self.wsl_interop.iter().cloned());
        v
    }

    /// The system bus socket, at its standard paths and wherever
    /// DBUS_SYSTEM_BUS_ADDRESS points (`unix:path=...`).
    fn system_bus_sockets(&self) -> Vec<PathBuf> {
        let mut v = vec![
            PathBuf::from(DBUS_SYSTEM_SOCKET),
            PathBuf::from("/var/run/dbus/system_bus_socket"),
        ];
        if let Some(addr) = &self.dbus_system {
            v.extend(dbus_address_paths(addr));
        }
        v
    }
}

/// Socket paths in a D-Bus address: a ;-separated list of
/// `transport:key=value,...`, of which `unix:path=...` names a file.
/// Abstract sockets (`unix:abstract=...`) are skipped on purpose: they are
/// scoped to the network namespace, so the sandbox can't reach the host's.
fn dbus_address_paths(addr: &str) -> Vec<PathBuf> {
    addr.split(';')
        .filter_map(|t| t.strip_prefix("unix:"))
        .flat_map(|params| params.split(','))
        .filter_map(|kv| kv.strip_prefix("path="))
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Where the system D-Bus listens on practically every distribution.
pub const DBUS_SYSTEM_SOCKET: &str = "/run/dbus/system_bus_socket";

/// Expand `*` wildcards in a path, one path component at a time (a component
/// like `S.*` or `*.sock` matches directory entries; `*` doesn't match a
/// leading dot or cross a `/`). Wildcard-free paths come back unchanged
/// whether or not they exist; wildcard ones only yield what exists.
pub fn expand(pattern: &Path) -> Vec<PathBuf> {
    use std::path::Component;
    let mut paths = vec![PathBuf::new()];
    for comp in pattern.components() {
        let name = match comp {
            Component::Normal(n) => n,
            other => {
                paths.iter_mut().for_each(|p| p.push(other.as_os_str()));
                continue;
            }
        };
        let Some(pat) = name.to_str().filter(|n| n.contains('*')) else {
            paths.iter_mut().for_each(|p| p.push(name));
            continue;
        };
        let mut next = Vec::new();
        for dir in &paths {
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut names: Vec<_> = rd
                .flatten()
                .map(|e| e.file_name())
                .filter(|n| {
                    n.to_str().is_some_and(|n| {
                        (!n.starts_with('.') || pat.starts_with('.')) && wildcard_match(pat, n)
                    })
                })
                .collect();
            names.sort();
            next.extend(names.into_iter().map(|n| dir.join(n)));
        }
        paths = next;
    }
    paths
}

/// Match `s` against a pattern where `*` stands for any run of characters.
fn wildcard_match(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// What a decoy does with connections.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Answer 403: the command can't use this socket at all.
    Block,
    /// Proxy to the real socket, forcing created containers onto no network.
    SealDocker,
}

struct Decoy {
    /// Canonical path being hidden (what the user will see in warnings).
    target: PathBuf,
    /// Bound by [`Plan::prepare`]; None until then (--dry-run never gets there).
    listener: Option<UnixListener>,
    mode: Mode,
    /// Why it's hidden, for the messages.
    reason: &'static str,
}

const RUNTIME_REASON: &str = "container runtimes can start containers with full network access";
const DBUS_REASON: &str = "the system D-Bus reaches host services such as systemd-resolved, which resolve names outside the sandbox";
const SESSION_BUS_REASON: &str = "the session D-Bus can start processes on the host with full network access, for example through systemd-run --user";
const USER_MANAGER_REASON: &str =
    "the systemd user manager can start processes on the host with full network access";
const SNAPD_REASON: &str = "snapd installs and runs snaps outside the sandbox, with network access";
const AGENT_REASON: &str =
    "an SSH or keyring agent signs with your keys for anything the command can reach";
const GPG_REASON: &str =
    "gpg-agent holds your keys and dirmngr looks keys up on the host's network";
const WSL_REASON: &str =
    "WSL interop starts Windows programs, which are not bound by the sandbox's network namespace";
const EXPLICIT_REASON: &str = "hidden with --hide-socket";

/// What to hide. [`Plan::prepare`] makes the decoys listen, in a private temp
/// dir that is removed again as soon as the sandbox is up (tmpdir.rs).
pub struct Plan {
    scratch: Option<PrivateDir>,
    decoys: Vec<Decoy>,
    /// --seal-docker-pulls and what it checks against, for sealed sockets.
    docker: Arc<crate::docker::Policy>,
}

/// (decoy path, target path) pairs for the child, allocated before fork.
pub type MountList = Vec<(CString, CString)>;

/// Work out which sockets to hide. Defaults that don't exist (or aren't
/// sockets) are skipped silently; so are the standard Docker sockets under
/// `--seal-docker` (`seal_defaults`). Paths the user named (`--hide-socket`,
/// `--seal-docker-socket`) get a warning if they can't be used.
/// Returns None when there is nothing to hide, so no mount namespace is needed.
pub fn plan(
    extra: &[PathBuf],
    allow: &[PathBuf],
    seal: &[PathBuf],
    seal_defaults: &[PathBuf],
) -> io::Result<Option<Plan>> {
    plan_for(&SocketEnv::from_env(), extra, allow, seal, seal_defaults)
}

fn plan_for(
    env: &SocketEnv,
    extra: &[PathBuf],
    allow: &[PathBuf],
    seal: &[PathBuf],
    seal_defaults: &[PathBuf],
) -> io::Result<Option<Plan>> {
    let allowed: BTreeSet<PathBuf> = allow.iter().map(|p| canonical_or_same(p)).collect();
    // Docker sockets to seal (proxy + force no-network) rather than block.
    let sealed: BTreeSet<PathBuf> = seal
        .iter()
        .chain(seal_defaults)
        .map(|p| canonical_or_same(p))
        .collect();
    // BTreeMap keeps output stable; (Mode, reason) per target. Sealing wins.
    let mut targets: std::collections::BTreeMap<PathBuf, (Mode, &'static str)> =
        std::collections::BTreeMap::new();
    let candidates = env
        .default_sockets()
        .into_iter()
        .map(|(p, why)| (p, why, false))
        .chain(extra.iter().cloned().map(|p| (p, EXPLICIT_REASON, true)));
    for (path, default_reason, explicit) in candidates {
        let Ok(canon) = std::fs::canonicalize(&path) else {
            if explicit {
                diagln!(
                    "nullroute: --hide-socket {}: no such file, ignoring",
                    path.display()
                );
            }
            continue;
        };
        match std::fs::metadata(&canon) {
            Ok(m) if m.file_type().is_socket() => {}
            _ => {
                if explicit {
                    diagln!(
                        "nullroute: --hide-socket {}: not a Unix socket, ignoring",
                        path.display()
                    );
                }
                continue;
            }
        }
        if sealed.contains(&canon) || allowed.contains(&canon) {
            continue; // sealed ones are added below; allowed ones stay visible
        }
        let r = targets
            .entry(canon)
            .or_insert((Mode::Block, default_reason));
        if explicit {
            *r = (Mode::Block, EXPLICIT_REASON);
        }
    }
    let requested = seal.iter().map(|p| (p, true));
    let standard = seal_defaults.iter().map(|p| (p, false));
    let mut sealed_any = false;
    for (path, explicit) in requested.chain(standard) {
        let Ok(canon) = std::fs::canonicalize(path) else {
            if explicit {
                diagln!(
                    "nullroute: --seal-docker-socket {}: not found, ignoring",
                    path.display()
                );
            }
            continue;
        };
        if std::fs::metadata(&canon).is_ok_and(|m| m.file_type().is_socket()) {
            targets.insert(canon, (Mode::SealDocker, crate::docker::SEAL_REASON));
            sealed_any = true;
        } else if explicit {
            diagln!(
                "nullroute: --seal-docker-socket {}: not a Unix socket, ignoring",
                path.display()
            );
        }
    }
    if !seal_defaults.is_empty() && !sealed_any {
        diagln!(
            "nullroute: --seal-docker: no Docker socket found at the standard paths; \
             use --seal-docker-socket PATH for a non-standard one"
        );
    }
    if targets.is_empty() {
        return Ok(None);
    }

    Ok(Some(Plan {
        scratch: None,
        decoys: targets
            .into_iter()
            .map(|(target, (mode, reason))| Decoy {
                target,
                listener: None,
                mode,
                reason,
            })
            .collect(),
        docker: Arc::default(),
    }))
}

impl Plan {
    /// Create the private temp dir and bind a listening decoy socket for each
    /// target in it. Call right before spawning the command (nothing is
    /// created by merely planning, so --dry-run and --inspect leave no
    /// files).
    pub fn prepare(&mut self) -> io::Result<()> {
        if self.scratch.is_some() {
            return Ok(());
        }
        let scratch = PrivateDir::create("nullroute")?;
        for (i, d) in self.decoys.iter_mut().enumerate() {
            d.listener = Some(UnixListener::bind(
                scratch.path().join(format!("decoy-{i}.sock")),
            )?);
        }
        self.scratch = Some(scratch);
        Ok(())
    }

    pub fn mount_list(&self) -> io::Result<MountList> {
        let Some(scratch) = &self.scratch else {
            return Err(io::Error::other("socket decoys were not prepared"));
        };
        self.decoys
            .iter()
            .enumerate()
            .map(|(i, d)| {
                Ok((
                    cstring(&scratch.path().join(format!("decoy-{i}.sock")))?,
                    cstring(&d.target)?,
                ))
            })
            .collect()
    }

    pub fn blocked_targets(&self) -> impl Iterator<Item = &Path> {
        self.decoys
            .iter()
            .filter(|d| d.mode == Mode::Block)
            .map(|d| d.target.as_path())
    }

    pub fn sealed_targets(&self) -> impl Iterator<Item = &Path> {
        self.decoys
            .iter()
            .filter(|d| d.mode == Mode::SealDocker)
            .map(|d| d.target.as_path())
    }

    /// Set the --seal-docker-pulls policy sealed sockets apply.
    pub fn set_docker_policy(&mut self, policy: crate::docker::Policy) {
        self.docker = Arc::new(policy);
    }

    /// Start answering connections on the decoys. Call after spawn.
    pub fn start(&self, report: &Arc<Report>) -> io::Result<()> {
        for d in &self.decoys {
            let Some(listener) = &d.listener else {
                continue;
            };
            let listener = listener.try_clone()?;
            let target = d.target.clone();
            let reason = d.reason;
            let mode = d.mode;
            let report = report.clone();
            let docker = self.docker.clone();
            let limit = Limiter::new(limits::max_connections(limits::MAX_DECOY_CONNECTIONS));
            thread::Builder::new().name("decoy".into()).spawn(move || {
                limits::accept_loop(
                    || listener.accept().map(|(c, _)| c),
                    |conn| {
                        let target = target.clone();
                        let report = report.clone();
                        let docker = docker.clone();
                        match mode {
                            Mode::Block => {
                                let t = target.display().to_string();
                                report.record(Kind::Socket, &t, reason, || {
                                    format!("nullroute: blocked a connection to {t} ({reason}). Rerun with --allow-socket {t} to permit it.")
                                });
                                if let Some(permit) = limit.try_acquire() {
                                    limits::spawn_conn(permit, move || answer(conn, &target, reason));
                                }
                            }
                            Mode::SealDocker => {
                                if let Some(permit) = limit.try_acquire() {
                                    limits::spawn_conn(permit, move || {
                                        crate::docker::handle(conn, &target, &report, &docker)
                                    });
                                }
                            }
                        }
                    },
                );
            })?;
        }
        Ok(())
    }
}

/// Reply to whatever was sent with an HTTP 403 the Docker/Podman CLIs display.
fn answer(mut conn: UnixStream, target: &Path, reason: &str) {
    let _ = conn.set_read_timeout(Some(Duration::from_millis(300)));
    let mut buf = [0u8; 4096];
    let n = conn.read(&mut buf).unwrap_or(0);
    let is_head = buf[..n].starts_with(b"HEAD ");
    let msg = format!(
        "nullroute blocked access to {t} ({reason}). Rerun with --allow-socket {t} to permit it.",
        t = target.display()
    );
    let body = format!("{{\"message\":{}}}", json_string(&msg));
    let mut resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if !is_head {
        resp.push_str(&body);
    }
    let _ = conn.write_all(resp.as_bytes());
    let _ = conn.shutdown(std::net::Shutdown::Both);
}

fn canonical_or_same(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn cstring(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// In the forked child, after unshare(CLONE_NEWNS): stop mount events leaking
/// back to the host, then bind each decoy over its target. Raw syscalls only.
pub fn apply_in_child(mounts: &MountList) -> io::Result<()> {
    // SAFETY: valid NUL-terminated strings; null pointers where the API allows.
    unsafe {
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        for (decoy, target) in mounts {
            if libc::mount(
                decoy.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_dbus_is_hidden_by_default_with_its_own_reason() {
        let d = SocketEnv::from_env().default_sockets();
        assert!(
            d.iter()
                .any(|(p, why)| p == Path::new(DBUS_SYSTEM_SOCKET) && *why == DBUS_REASON),
            "{d:?}"
        );
        assert!(
            d.iter()
                .any(|(p, why)| p == Path::new("/var/run/docker.sock") && *why == RUNTIME_REASON)
        );
    }

    #[test]
    fn dbus_address_paths_are_parsed() {
        assert_eq!(
            dbus_address_paths("unix:path=/run/dbus/system_bus_socket"),
            vec![PathBuf::from("/run/dbus/system_bus_socket")]
        );
        assert_eq!(
            dbus_address_paths("unix:abstract=/tmp/x;unix:guid=1,path=/a/b;tcp:host=x,port=1"),
            vec![PathBuf::from("/a/b")]
        );
        assert!(dbus_address_paths("").is_empty());
        assert!(dbus_address_paths("unix:path=").is_empty());
    }

    /// A temp directory laid out like a user's runtime dir, with real sockets.
    struct Session {
        root: PathBuf,
        env: SocketEnv,
        _listeners: Vec<std::os::unix::net::UnixListener>,
    }

    impl Session {
        fn new(tag: &str) -> Session {
            let root = std::env::temp_dir().join(format!("nr-hide-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let xdg = root.join("run");
            std::fs::create_dir_all(&xdg).unwrap();
            let env = SocketEnv {
                uid: u32::MAX - 1, // so /run/user/UID is never a real directory
                xdg_runtime_dir: Some(xdg),
                home: Some(root.join("home")),
                ..SocketEnv::default()
            };
            Session {
                root,
                env,
                _listeners: Vec::new(),
            }
        }

        fn sock(&mut self, path: &Path) -> PathBuf {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            self._listeners
                .push(std::os::unix::net::UnixListener::bind(path).unwrap());
            std::fs::canonicalize(path).unwrap()
        }

        fn xdg(&self) -> PathBuf {
            self.env.xdg_runtime_dir.clone().unwrap()
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn blocked(env: &SocketEnv) -> Vec<PathBuf> {
        plan_for(env, &[], &[], &[], &[])
            .unwrap()
            .map(|p| p.blocked_targets().map(Path::to_path_buf).collect())
            .unwrap_or_default()
    }

    #[test]
    fn wsl_interop_sockets_are_found_by_directory_and_by_variable() {
        let mut s = Session::new("wsl");
        let run = s.root.join("run-wsl");
        let a = s.sock(&run.join("2_interop"));
        // WSL keeps a symlink per session pointing at the real socket.
        std::os::unix::fs::symlink(&a, run.join("1_interop")).unwrap();
        let named = s.sock(&s.root.join("elsewhere/wsl.sock"));
        s.env.wsl_interop = Some(named.clone());
        let got = s.env.wsl_interop_sockets(&run);
        for want in [run.join("2_interop"), run.join("1_interop"), named] {
            assert!(got.contains(&want), "{want:?} missing from {got:?}");
        }
        // Without the directory or the variable there is nothing to hide.
        let none = SocketEnv::default().wsl_interop_sockets(&s.root.join("no-such-dir"));
        assert!(none.is_empty(), "{none:?}");
    }

    #[test]
    fn a_socket_named_by_wsl_interop_is_hidden_by_default() {
        let mut s = Session::new("wslvar");
        let sock = s.sock(&s.root.join("elsewhere/9_interop"));
        s.env.wsl_interop = Some(sock.clone());
        let got = blocked(&s.env);
        assert!(got.contains(&sock), "{sock:?} not hidden; hidden: {got:?}");
        assert!(
            s.env
                .default_sockets()
                .iter()
                .any(|(p, why)| p == &sock && *why == WSL_REASON),
            "{sock:?} is not on the default list with the WSL reason"
        );
    }

    #[test]
    fn session_sockets_are_hidden_by_default_when_they_exist() {
        let mut s = Session::new("session");
        let xdg = s.xdg();
        let want = [
            s.sock(&xdg.join("bus")),
            s.sock(&xdg.join("systemd/private")),
            s.sock(&xdg.join("snapd-session-agent.socket")),
            s.sock(&xdg.join("gnupg/S.gpg-agent")),
            s.sock(&xdg.join("gnupg/S.dirmngr")),
            s.sock(&xdg.join("gnupg/d.abc123/S.gpg-agent")),
            s.sock(&xdg.join("keyring/ssh")),
            s.sock(&xdg.join("docker.sock")),
            s.sock(&xdg.join("podman/podman.sock")),
            s.sock(&s.root.join("home/.gnupg/S.gpg-agent.ssh")),
            s.sock(&s.root.join("home/.docker/desktop/docker.sock")),
            s.sock(&s.root.join("home/.colima/default/docker.sock")),
            s.sock(&s.root.join("home/.rd/docker.sock")),
        ];
        let got = blocked(&s.env);
        for w in &want {
            assert!(got.contains(w), "{w:?} not hidden; hidden: {got:?}");
        }
        // Sockets that are not on the list stay visible.
        let other = s.sock(&xdg.join("pulse/native"));
        let other2 = s.sock(&xdg.join("systemd/notify"));
        let got = blocked(&s.env);
        assert!(!got.contains(&other) && !got.contains(&other2), "{got:?}");
    }

    #[test]
    fn env_variables_name_more_sockets() {
        let mut s = Session::new("envvars");
        let agent = s.sock(&s.root.join("elsewhere/agent.1234"));
        let bus = s.sock(&s.root.join("elsewhere/mybus"));
        let docker = s.sock(&s.root.join("elsewhere/dock.sock"));
        let gnupg = s.sock(&s.root.join("gnupghome/S.gpg-agent"));
        s.env.ssh_auth_sock = Some(agent.clone());
        s.env.dbus_session = Some(format!(
            "unix:abstract=/tmp/dbus-nope,guid=1;unix:path={},guid=2",
            bus.display()
        ));
        s.env.docker_host = Some(format!("unix://{}", docker.display()));
        s.env.gnupg_home = Some(s.root.join("gnupghome"));
        let got = blocked(&s.env);
        for w in [&agent, &bus, &docker, &gnupg] {
            assert!(got.contains(w), "{w:?} not hidden; hidden: {got:?}");
        }
    }

    #[test]
    fn missing_default_sockets_are_skipped_silently() {
        // Nothing exists below the session's directories: plan() finds nothing
        // there (and prints nothing; it only warns about paths the user named).
        let s = Session::new("missing");
        let listed: Vec<_> = s
            .env
            .default_sockets()
            .into_iter()
            .filter(|(p, _)| p.starts_with(&s.root))
            .collect();
        assert!(listed.iter().any(|(p, _)| p.ends_with("bus")), "{listed:?}");
        assert!(blocked(&s.env).iter().all(|p| !p.starts_with(&s.root)));
    }

    #[test]
    fn allow_socket_keeps_a_default_hidden_socket_visible() {
        let mut s = Session::new("allow");
        let bus = s.sock(&s.xdg().join("bus"));
        let agent = s.sock(&s.root.join("agent"));
        s.env.ssh_auth_sock = Some(agent.clone());
        let p = plan_for(&s.env, &[], std::slice::from_ref(&bus), &[], &[])
            .unwrap()
            .unwrap();
        let hidden: Vec<_> = p.blocked_targets().collect();
        assert!(!hidden.contains(&bus.as_path()), "{hidden:?}");
        assert!(hidden.contains(&agent.as_path()), "{hidden:?}");
    }

    #[test]
    fn abstract_bus_addresses_name_no_file() {
        assert!(dbus_address_paths("unix:abstract=/tmp/dbus-abc,guid=1").is_empty());
    }

    #[test]
    fn wildcards_expand_one_component_at_a_time() {
        let mut s = Session::new("glob");
        let a = s.sock(&s.root.join("d/one.sock"));
        let b = s.sock(&s.root.join("d/two.sock"));
        s.sock(&s.root.join("d/three.txt"));
        s.sock(&s.root.join("d/.hidden.sock"));
        s.sock(&s.root.join("x/deep/one.sock"));
        assert_eq!(expand(&s.root.join("d/*.sock")), vec![a.clone(), b.clone()]);
        assert_eq!(expand(&s.root.join("d/t*")).len(), 2);
        assert_eq!(expand(&s.root.join("x/*/one.sock")).len(), 1);
        assert!(expand(&s.root.join("nope/*.sock")).is_empty());
        // No wildcard: returned as given, existing or not.
        assert_eq!(
            expand(&s.root.join("nope/plain")),
            vec![s.root.join("nope/plain")]
        );
        assert!(wildcard_match("S.*", "S.gpg-agent"));
        assert!(wildcard_match("*.sock", "a.sock"));
        assert!(!wildcard_match("*.sock", "a.sockx"));
        assert!(wildcard_match("a*b*c", "aXXbYYc"));
        assert!(!wildcard_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn explicit_seal_paths_warn_but_standard_ones_do_not_matter() {
        let mut s = Session::new("seal");
        let sock = s.sock(&s.xdg().join("docker.sock"));
        let p = plan_for(&s.env, &[], &[], &[], std::slice::from_ref(&sock))
            .unwrap()
            .unwrap();
        assert_eq!(p.sealed_targets().collect::<Vec<_>>(), vec![sock.as_path()]);
        assert!(p.blocked_targets().all(|t| t != sock));
    }

    #[test]
    fn allow_socket_keeps_the_system_bus_visible() {
        let Ok(canon) = std::fs::canonicalize(DBUS_SYSTEM_SOCKET) else {
            return eprintln!("skipping: no system D-Bus socket");
        };
        let hidden = plan(&[], &[], &[], &[]).unwrap();
        assert!(
            hidden
                .as_ref()
                .is_some_and(|p| p.blocked_targets().any(|t| t == canon))
        );
        let allowed = plan(&[], &[PathBuf::from(DBUS_SYSTEM_SOCKET)], &[], &[]).unwrap();
        assert!(
            allowed
                .as_ref()
                .is_none_or(|p| p.blocked_targets().all(|t| t != canon))
        );
    }
}
