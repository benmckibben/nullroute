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
//! By default the well-known container-runtime sockets are hidden. `--hide-socket`
//! adds more and `--allow-socket` keeps one visible.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::report::{Kind, Report, json_string};

/// Sockets hidden unless `--allow-socket`ed: container runtimes, whose
/// daemons can start network-connected containers on the command's behalf.
pub fn default_sockets() -> Vec<PathBuf> {
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
    listener: UnixListener,
    mode: Mode,
    /// Why it's hidden, for the messages.
    reason: &'static str,
}

const RUNTIME_REASON: &str = "container runtimes can start containers with full network access";
const EXPLICIT_REASON: &str = "hidden with --hide-socket";

/// What to hide, with decoys already listening. Removes its temp dir on drop.
pub struct Plan {
    dir: PathBuf,
    decoys: Vec<Decoy>,
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
        .map(|p| (p, false))
        .chain(extra.iter().cloned().map(|p| (p, true)));
    for (path, explicit) in candidates {
        let Ok(canon) = std::fs::canonicalize(&path) else {
            if explicit {
                eprintln!(
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
                    eprintln!(
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
        let reason = if explicit {
            EXPLICIT_REASON
        } else {
            RUNTIME_REASON
        };
        let r = targets.entry(canon).or_insert((Mode::Block, reason));
        if explicit {
            *r = (Mode::Block, EXPLICIT_REASON);
        }
    }
    for path in seal {
        let Ok(canon) = std::fs::canonicalize(path) else {
            eprintln!(
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

    let dir = std::env::temp_dir().join(format!("nullroute-{}-{}", std::process::id(), nonce()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let mut plan = Plan {
        dir,
        decoys: Vec::new(),
    };
    for (i, (target, (mode, reason))) in targets.into_iter().enumerate() {
        let listener = UnixListener::bind(plan.dir.join(format!("decoy-{i}.sock")))?;
        plan.decoys.push(Decoy {
            target,
            listener,
            mode,
            reason,
        });
    }
    Ok(Some(plan))
}

impl Plan {
    pub fn mount_list(&self) -> io::Result<MountList> {
        self.decoys
            .iter()
            .enumerate()
            .map(|(i, d)| {
                Ok((
                    cstring(&self.dir.join(format!("decoy-{i}.sock")))?,
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

    /// Start answering connections on the decoys. Call after spawn.
    pub fn start(&self, report: &Arc<Report>) -> io::Result<()> {
        for d in &self.decoys {
            let listener = d.listener.try_clone()?;
            let target = d.target.clone();
            let reason = d.reason;
            let mode = d.mode;
            let report = report.clone();
            thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(conn) = conn else { continue };
                    let target = target.clone();
                    let report = report.clone();
                    match mode {
                        Mode::Block => {
                            let t = target.display().to_string();
                            report.record(Kind::Socket, &t, reason, || {
                                format!("nullroute: blocked a connection to {t} ({reason}). Rerun with --allow-socket {t} to permit it.")
                            });
                            thread::spawn(move || answer(conn, &target, reason));
                        }
                        Mode::SealDocker => {
                            thread::spawn(move || crate::docker::handle(conn, &target, &report));
                        }
                    }
                }
            });
        }
        Ok(())
    }
}

impl Drop for Plan {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
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

fn nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
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
