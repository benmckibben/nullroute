//! --inspect: the sandbox topology is printed to stderr before the command runs,
//! and with --dry-run nothing is run at all.
//!
//! These tests use their own sockets via --hide-socket / --seal-docker-socket,
//! so they don't depend on Docker. The Docker check is skipped without a daemon.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HEADER: &str = "nullroute: inspect: sandbox topology";

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("nr-inspect-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        // Canonical, so paths match what nullroute prints.
        TmpDir(std::fs::canonicalize(&p).unwrap())
    }
    fn socket(&self, name: &str) -> (PathBuf, UnixListener) {
        let p = self.0.join(name);
        let l = UnixListener::bind(&p).unwrap();
        (p, l)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn nr(args: &[&str], tmp: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .env("TMPDIR", tmp) // where nullroute puts its decoys
        .output()
        .expect("failed to launch nullroute")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// The value after "  <key>:" on its own line, e.g. field(s, "bridged ports").
fn field(stderr: &str, key: &str) -> String {
    let prefix = format!("  {key}:");
    stderr
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {key:?} line in:\n{stderr}"))
        .trim()
        .to_string()
}

/// Paths listed under a socket section header ("blocked" or "sealed").
fn section(stderr: &str, which: &str) -> Vec<PathBuf> {
    let mut lines = stderr
        .lines()
        .skip_while(|l| !l.starts_with(&format!("    {which} (")));
    let head = lines
        .next()
        .unwrap_or_else(|| panic!("no {which} section in:\n{stderr}"));
    if head.ends_with(": none") {
        return vec![];
    }
    lines
        .take_while(|l| l.starts_with("      "))
        .map(|l| PathBuf::from(l.trim()))
        .collect()
}

#[test]
fn dry_run_prints_topology_and_does_not_run_the_command() {
    let t = TmpDir::new("dry");
    let marker = t.0.join("ran");
    let script = format!("touch {}", marker.display());
    let o = nr(&["--inspect", "--dry-run", "--", "sh", "-c", &script], &t.0);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(!marker.exists(), "--inspect --dry-run must not run: {o:?}");
    let e = err(&o);
    assert!(e.contains(HEADER), "{e}");
    for key in [
        "namespaces",
        "loopback",
        "bridged ports",
        "unix sockets",
        "upstream proxy",
    ] {
        field(&e, key);
    }
    assert!(
        !out(&o).contains(HEADER),
        "topology goes to stderr, not stdout"
    );
}

#[test]
fn inspect_prints_topology_then_runs_the_command() {
    let t = TmpDir::new("run");
    let o = nr(
        &[
            "--inspect",
            "--",
            "sh",
            "-c",
            "echo CMD-STDOUT; echo CMD-STDERR >&2; exit 3",
        ],
        &t.0,
    );
    assert_eq!(
        o.status.code(),
        Some(3),
        "exit code still passes through: {o:?}"
    );
    assert_eq!(out(&o).trim(), "CMD-STDOUT", "stdout stays clean: {o:?}");
    let e = err(&o);
    let topo = e.find(HEADER).expect("topology printed");
    let cmd = e.find("CMD-STDERR").expect("command ran");
    assert!(
        topo < cmd,
        "topology must come before the command runs:\n{e}"
    );
}

#[test]
fn without_inspect_nothing_is_printed() {
    let t = TmpDir::new("off");
    let o = nr(&["--", "true"], &t.0);
    assert!(o.status.success(), "{o:?}");
    assert!(!err(&o).contains(HEADER), "{o:?}");
    let o = nr(&["--dry-run", "--", "true"], &t.0);
    assert!(!err(&o).contains(HEADER), "{o:?}");
}

#[test]
fn base_topology_has_user_and_net_namespaces_and_loopback() {
    let t = TmpDir::new("base");
    let e = err(&nr(&["--inspect", "--dry-run", "--", "true"], &t.0));
    let ns = field(&e, "namespaces");
    let ns: Vec<&str> = ns.split(", ").collect();
    assert_eq!(&ns[..2], ["user", "net"], "{e}");
    // The resolver's pool address is on lo in every sandbox.
    assert_eq!(
        field(&e, "loopback"),
        "lo: UP (127.0.0.1, ::1, 127.77.0.1/24)"
    );
    assert_eq!(field(&e, "bridged ports"), "none");
    assert_eq!(field(&e, "upstream proxy"), "none");
    // The mount namespace is there exactly when some socket is hidden, sealed
    // or masked, or the resolver has a resolv.conf to mount.
    let any_mounts = !section(&e, "blocked").is_empty()
        || !section(&e, "sealed").is_empty()
        || !section(&e, "masked").is_empty()
        || std::fs::canonicalize("/etc/resolv.conf").is_ok();
    assert_eq!(ns.contains(&"mount"), any_mounts, "{e}");

    // Without the resolver (--no-dns) the loopback is just lo's own addresses.
    let e = err(&nr(
        &["--inspect", "--dry-run", "--no-dns", "--", "true"],
        &t.0,
    ));
    assert_eq!(field(&e, "loopback"), "lo: UP (127.0.0.1, ::1)");
}

#[test]
fn ports_are_listed_sorted_and_deduplicated() {
    let t = TmpDir::new("ports");
    let o = nr(
        &[
            "--inspect",
            "--dry-run",
            "--port",
            "6379,5432",
            "--port",
            "5432",
            "--",
            "true",
        ],
        &t.0,
    );
    assert_eq!(field(&err(&o), "bridged ports"), "5432, 6379", "{o:?}");
}

#[test]
fn hidden_socket_is_listed_as_blocked_with_a_mount_namespace() {
    let t = TmpDir::new("hide");
    let (sock, _l) = t.socket("svc.sock");
    let o = nr(
        &[
            "--inspect",
            "--dry-run",
            "--hide-socket",
            sock.to_str().unwrap(),
            "--",
            "true",
        ],
        &t.0,
    );
    let e = err(&o);
    assert!(section(&e, "blocked").contains(&sock), "{e}");
    assert!(!section(&e, "sealed").contains(&sock), "{e}");
    assert!(field(&e, "namespaces").ends_with("mount"), "{e}");
}

#[test]
fn sealed_socket_is_listed_as_sealed_not_blocked() {
    let t = TmpDir::new("seal");
    let (sock, _l) = t.socket("docker.sock");
    let o = nr(
        &[
            "--inspect",
            "--dry-run",
            "--seal-docker-socket",
            sock.to_str().unwrap(),
            "--",
            "true",
        ],
        &t.0,
    );
    let e = err(&o);
    assert!(section(&e, "sealed").contains(&sock), "{e}");
    assert!(!section(&e, "blocked").contains(&sock), "{e}");
}

#[test]
fn allowed_socket_is_in_neither_list() {
    let t = TmpDir::new("allowsock");
    let (sock, _l) = t.socket("svc.sock");
    let s = sock.to_str().unwrap();
    let o = nr(
        &[
            "--inspect",
            "--dry-run",
            "--hide-socket",
            s,
            "--allow-socket",
            s,
            "--",
            "true",
        ],
        &t.0,
    );
    let e = err(&o);
    assert!(!section(&e, "blocked").contains(&sock), "{e}");
    assert!(!section(&e, "sealed").contains(&sock), "{e}");
}

#[test]
fn allowlist_shows_the_proxy_binding() {
    let t = TmpDir::new("proxy");
    let o = nr(
        &[
            "--inspect",
            "--dry-run",
            "--allow",
            "API.GitHub.com.,*.stripe.dev",
            "--",
            "true",
        ],
        &t.0,
    );
    assert_eq!(
        field(&err(&o), "upstream proxy"),
        "http://127.0.0.1:3128 (allow: api.github.com, *.stripe.dev)",
        "{o:?}"
    );
    // The proxy steps aside for a --port that takes its default.
    let o = nr(
        &[
            "--inspect",
            "--dry-run",
            "--port",
            "3128",
            "--allow",
            "example.com",
            "--",
            "true",
        ],
        &t.0,
    );
    assert_eq!(
        field(&err(&o), "upstream proxy"),
        "http://127.0.0.1:3129 (allow: example.com)",
        "{o:?}"
    );
}

#[test]
fn dry_run_stdout_is_unchanged_by_inspect() {
    let t = TmpDir::new("stdout");
    let (sock, _l) = t.socket("svc.sock");
    let args = [
        "--dry-run",
        "--port",
        "5432",
        "--hide-socket",
        sock.to_str().unwrap(),
    ];
    let plain = nr(&[&args[..], &["--", "true"]].concat(), &t.0);
    let inspected = nr(&[&["--inspect"], &args[..], &["--", "true"]].concat(), &t.0);
    assert_eq!(out(&plain), out(&inspected));
}

#[test]
fn reported_namespaces_match_the_live_sandbox() {
    let t = TmpDir::new("live");
    let (sock, _l) = t.socket("svc.sock");
    let o = nr(
        &[
            "--inspect",
            "--hide-socket",
            sock.to_str().unwrap(),
            "--",
            "readlink",
            "/proc/self/ns/user",
            "/proc/self/ns/net",
            "/proc/self/ns/mnt",
        ],
        &t.0,
    );
    assert!(o.status.success(), "{o:?}");
    let inside: Vec<String> = out(&o).lines().map(str::to_string).collect();
    let host: Vec<String> = ["user", "net", "mnt"]
        .iter()
        .map(|n| {
            std::fs::read_link(format!("/proc/self/ns/{n}"))
                .unwrap()
                .display()
                .to_string()
        })
        .collect();
    assert_eq!(inside.len(), 3, "{o:?}");
    for (i, name) in ["user", "net", "mount"].iter().enumerate() {
        assert_ne!(inside[i], host[i], "{name} namespace should be fresh");
    }
    assert_eq!(field(&err(&o), "namespaces"), "user, net, mount");
}

#[test]
fn live_docker_socket_is_reported_as_sealed() {
    let docker_ok = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let Ok(real) = std::fs::canonicalize("/var/run/docker.sock") else {
        return eprintln!("skipping: no /var/run/docker.sock");
    };
    if !docker_ok {
        return eprintln!("skipping: docker unavailable");
    }
    let t = TmpDir::new("docker");
    let o = nr(
        &[
            "--inspect",
            "--seal-docker",
            "--",
            "docker",
            "version",
            "--format",
            "ok",
        ],
        &t.0,
    );
    let e = err(&o);
    assert!(section(&e, "sealed").contains(&real), "{e}");
    assert!(!section(&e, "blocked").contains(&real), "{e}");
    assert_eq!(out(&o).trim(), "ok", "sealed docker still usable: {o:?}");
}

#[test]
fn dry_run_lists_everything_inspect_does() {
    // --dry-run promises what would be hidden, masked, forwarded and allowed:
    // the masked resolver sockets and the namespaces must be in its stdout,
    // not only in --inspect's topology.
    let t = TmpDir::new("dry-complete");
    let o = nr(
        &["--inspect", "--dry-run", "--port", "5432", "--", "true"],
        &t.0,
    );
    let (stdout, topology) = (out(&o), err(&o));
    let masked: Vec<String> = section(&topology, "masked")
        .iter()
        .map(|p| format!("masked resolver socket: {}", p.display()))
        .collect();
    let listed: Vec<String> = stdout
        .lines()
        .filter(|l| l.starts_with("masked resolver socket:"))
        .map(String::from)
        .collect();
    assert_eq!(listed, masked, "{stdout}");
    let ns = field(&topology, "namespaces");
    assert!(
        stdout.lines().any(|l| l == format!("namespaces: {ns}")),
        "{stdout}"
    );
    assert!(
        stdout.lines().any(|l| l == "forwarded port: 5432"),
        "{stdout}"
    );
}
