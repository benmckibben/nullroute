//! Socket hiding: Unix sockets can't be used as a side door out of the sandbox.
//!
//! These tests use their own sockets via --hide-socket, so they don't depend on
//! Docker. The Docker test at the end is skipped when there's no Docker daemon.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("nr-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A Unix socket service that replies "real:" + whatever it receives.
fn service(path: &Path) {
    let l = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap_or(0);
            let _ = c.write_all(&[b"real:", &buf[..n]].concat());
        }
    });
}

fn nullroute(args: &[&str], tmpdir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .env("TMPDIR", tmpdir) // where nullroute puts its decoys
        .output()
        .expect("failed to launch nullroute")
}

/// Python: connect to a Unix socket, send "hi", print the first line back.
fn talk(path: &Path) -> String {
    format!(
        "import socket\nc = socket.socket(socket.AF_UNIX); c.connect({:?}); c.sendall(b'hi')\n\
         print(c.recv(200).decode().splitlines()[0])",
        path.to_str().unwrap()
    )
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

#[test]
fn unhidden_socket_is_reachable() {
    let t = TmpDir::new("unhidden");
    let sock = t.0.join("svc.sock");
    service(&sock);
    let o = nullroute(&["--", "python3", "-c", &talk(&sock)], &t.0);
    assert_eq!(out(&o), "real:hi", "{o:?}");
}

#[test]
fn hidden_socket_gets_the_decoy_and_one_warning() {
    let t = TmpDir::new("hidden");
    let sock = t.0.join("svc.sock");
    service(&sock);
    let script = format!("{0}\n{0}\n{0}", talk(&sock));
    let o = nullroute(
        &[
            "--hide-socket",
            sock.to_str().unwrap(),
            "--",
            "python3",
            "-c",
            &script,
        ],
        &t.0,
    );
    assert_eq!(
        out(&o),
        "HTTP/1.1 403 Forbidden\n".repeat(3).trim(),
        "{o:?}"
    );
    assert_eq!(
        err(&o).matches("blocked a connection to").count(),
        1,
        "{}",
        err(&o)
    );
    assert!(err(&o).contains("--allow-socket"), "{}", err(&o));
}

#[test]
fn decoy_body_is_docker_style_json() {
    let t = TmpDir::new("json");
    let sock = t.0.join("svc.sock");
    service(&sock);
    let script = format!(
        "import socket, json\nc = socket.socket(socket.AF_UNIX); c.connect({:?})\n\
         c.sendall(b'GET /_ping HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')\n\
         data = b''\nwhile (d := c.recv(4096)): data += d\n\
         print(json.loads(data.split(b'\\r\\n\\r\\n', 1)[1])['message'])",
        sock.to_str().unwrap()
    );
    let o = nullroute(
        &[
            "--hide-socket",
            sock.to_str().unwrap(),
            "--",
            "python3",
            "-c",
            &script,
        ],
        &t.0,
    );
    assert!(out(&o).starts_with("nullroute blocked access to"), "{o:?}");
}

#[test]
fn hiding_follows_symlinks() {
    let t = TmpDir::new("symlink");
    let sock = t.0.join("svc.sock");
    let link = t.0.join("link.sock");
    service(&sock);
    std::os::unix::fs::symlink(&sock, &link).unwrap();
    // Hide via the link; connecting via the real path must still hit the decoy.
    let o = nullroute(
        &[
            "--hide-socket",
            link.to_str().unwrap(),
            "--",
            "python3",
            "-c",
            &talk(&sock),
        ],
        &t.0,
    );
    assert_eq!(out(&o), "HTTP/1.1 403 Forbidden", "{o:?}");
}

#[test]
fn allow_socket_overrides_hide() {
    let t = TmpDir::new("allow");
    let sock = t.0.join("svc.sock");
    service(&sock);
    let s = sock.to_str().unwrap();
    let o = nullroute(
        &[
            "--hide-socket",
            s,
            "--allow-socket",
            s,
            "--",
            "python3",
            "-c",
            &talk(&sock),
        ],
        &t.0,
    );
    assert_eq!(out(&o), "real:hi", "{o:?}");
}

#[test]
fn command_cannot_unmount_the_decoy() {
    let t = TmpDir::new("umount");
    let sock = t.0.join("svc.sock");
    service(&sock);
    let s = sock.to_str().unwrap();
    let o = nullroute(
        &["--hide-socket", s, "--", "sh", "-c", &format!("umount {s}")],
        &t.0,
    );
    assert!(!o.status.success(), "umount succeeded: {o:?}");
}

#[test]
fn decoy_temp_dir_is_cleaned_up() {
    let t = TmpDir::new("cleanup");
    let sock = t.0.join("svc.sock");
    service(&sock);
    let o = nullroute(
        &["--hide-socket", sock.to_str().unwrap(), "--", "true"],
        &t.0,
    );
    assert!(o.status.success(), "{o:?}");
    let leftovers: Vec<_> = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("nullroute-"))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

#[test]
fn bad_hide_paths_warn_and_still_run() {
    let t = TmpDir::new("bad");
    let o = nullroute(
        &[
            "--hide-socket",
            "/definitely/missing.sock",
            "--hide-socket",
            "/etc/hostname",
            "--",
            "sh",
            "-c",
            "exit 3",
        ],
        &t.0,
    );
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(err(&o).contains("no such file"), "{}", err(&o));
    assert!(err(&o).contains("not a Unix socket"), "{}", err(&o));
}

#[test]
fn dry_run_lists_hidden_sockets_and_ports() {
    let t = TmpDir::new("dry");
    let sock = t.0.join("svc.sock");
    service(&sock);
    let canon = std::fs::canonicalize(&sock).unwrap();
    let o = nullroute(
        &[
            "--hide-socket",
            sock.to_str().unwrap(),
            "--port",
            "5432",
            "--dry-run",
            "--",
            "false",
        ],
        &t.0,
    );
    assert!(
        o.status.success(),
        "dry run must not run the command: {o:?}"
    );
    assert!(
        out(&o).contains(&format!("hidden socket: {}", canon.display())),
        "{o:?}"
    );
    assert!(out(&o).contains("forwarded port: 5432"), "{o:?}");
}

#[test]
fn docker_is_blocked_by_default_when_present() {
    let reachable = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output();
    if !matches!(&reachable, Ok(o) if o.status.success()) {
        eprintln!("skipping: no reachable Docker daemon");
        return;
    }
    let t = TmpDir::new("docker");
    let o = nullroute(
        &["--", "docker", "version", "--format", "{{.Server.Version}}"],
        &t.0,
    );
    assert!(
        !o.status.success(),
        "docker reached the daemon from inside: {o:?}"
    );
    assert!(
        err(&o).contains("Error response from daemon: nullroute blocked access to"),
        "{}",
        err(&o)
    );

    // And the escape hatch works.
    let sock = std::fs::canonicalize("/var/run/docker.sock").unwrap();
    let o = nullroute(
        &[
            "--allow-socket",
            sock.to_str().unwrap(),
            "--",
            "docker",
            "version",
            "--format",
            "{{.Server.Version}}",
        ],
        &t.0,
    );
    assert!(o.status.success(), "{o:?}");
}
