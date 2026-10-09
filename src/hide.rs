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
//! By default the well-known container-runtime sockets and the system D-Bus
//! socket are hidden. `--hide-socket` adds more and `--allow-socket` keeps one
//! visible.
//!
//! D-Bus is hidden because the system bus reaches host services that live
//! outside the network namespace. The obvious one is systemd-resolved
//! (`org.freedesktop.resolve1`), which would happily resolve any name on the
//! command's behalf: a DNS side channel straight past the sandbox.

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

/// Sockets hidden unless `--allow-socket`ed, each with why: container
/// runtimes, whose daemons can start network-connected containers on the
/// command's behalf, and the system D-Bus, whose services (systemd-resolved)
/// can resolve names outside the sandbox.
pub fn default_sockets() -> Vec<(PathBuf, &'static str)> {
    let mut v: Vec<(PathBuf, &'static str)> = runtime_sockets()
        .into_iter()
        .map(|p| (p, RUNTIME_REASON))
        .collect();
    v.extend(dbus_system_sockets().into_iter().map(|p| (p, DBUS_REASON)));
    v
}

/// The system bus socket, at its standard paths and wherever
/// DBUS_SYSTEM_BUS_ADDRESS points (`unix:path=...`).
pub fn dbus_system_sockets() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from(DBUS_SYSTEM_SOCKET),
        PathBuf::from("/var/run/dbus/system_bus_socket"),
    ];
    if let Ok(addr) = std::env::var("DBUS_SYSTEM_BUS_ADDRESS") {
        v.extend(dbus_address_paths(&addr));
    }
    v
}

/// Socket paths in a D-Bus address: a ;-separated list of
/// `transport:key=value,...`, of which `unix:path=...` names a file.
/// (Abstract sockets are scoped to the network namespace, so they don't matter.)
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

fn runtime_sockets() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/containerd/containerd.sock",
        "/run/buildkit/buildkitd.sock",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        let xdg = PathBuf::from(xdg);
        v.push(xdg.join("docker.sock")); // rootless Docker
        v.push(xdg.join("podman/podman.sock")); // rootless Podman
    }
    if let Some(home) = std::env::var_os("HOME") {
        v.push(PathBuf::from(home).join(".docker/run/docker.sock")); // Docker Desktop for Linux
    }
    // An explicit DOCKER_HOST=unix:///path is where the CLI will actually go.
    if let Ok(h) = std::env::var("DOCKER_HOST")
        && let Some(p) = h.strip_prefix("unix://")
    {
        v.push(PathBuf::from(p));
    }
    v
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

/// Work out which sockets to hide. Defaults and `--hide-socket` paths that don't
/// exist (or aren't sockets) are skipped; explicit ones with a warning.
/// Returns None when there is nothing to hide, so no mount namespace is needed.
pub fn plan(extra: &[PathBuf], allow: &[PathBuf], seal: &[PathBuf]) -> io::Result<Option<Plan>> {
    let allowed: BTreeSet<PathBuf> = allow.iter().map(|p| canonical_or_same(p)).collect();
    // Docker sockets to seal (proxy + force no-network) rather than block.
    let sealed: BTreeSet<PathBuf> = seal.iter().map(|p| canonical_or_same(p)).collect();
    // BTreeMap keeps output stable; (Mode, reason) per target. Sealing wins.
    let mut targets: std::collections::BTreeMap<PathBuf, (Mode, &'static str)> =
        std::collections::BTreeMap::new();
    let candidates = default_sockets()
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
    for path in seal {
        let Ok(canon) = std::fs::canonicalize(path) else {
            diagln!(
                "nullroute: --seal-docker: {} not found, ignoring",
                path.display()
            );
            continue;
        };
        if std::fs::metadata(&canon)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
        {
            targets.insert(canon, (Mode::SealDocker, crate::docker::SEAL_REASON));
        }
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

    /// What the forked child deletes after its bind mounts (tmpdir.rs).
    pub fn child_cleanup(&self) -> io::Result<Option<crate::tmpdir::ChildCleanup>> {
        self.scratch
            .as_ref()
            .map(PrivateDir::child_cleanup)
            .transpose()
    }

    /// Remove the temp dir. Call once the command has been spawned: the
    /// bind mounts keep the sockets alive and the listeners are open fds.
    pub fn cleanup(&self) {
        if let Some(s) = &self.scratch {
            s.remove();
        }
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
        let d = default_sockets();
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

    #[test]
    fn allow_socket_keeps_the_system_bus_visible() {
        let Ok(canon) = std::fs::canonicalize(DBUS_SYSTEM_SOCKET) else {
            return eprintln!("skipping: no system D-Bus socket");
        };
        let hidden = plan(&[], &[], &[]).unwrap();
        assert!(
            hidden
                .as_ref()
                .is_some_and(|p| p.blocked_targets().any(|t| t == canon))
        );
        let allowed = plan(&[], &[PathBuf::from(DBUS_SYSTEM_SOCKET)], &[]).unwrap();
        assert!(
            allowed
                .as_ref()
                .is_none_or(|p| p.blocked_targets().all(|t| t != canon))
        );
    }
}
