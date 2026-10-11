//! Sockets hidden by default: the user's session services (D-Bus, systemd
//! user manager, snapd, SSH/GPG agents) are reachable from the host's network
//! namespace through the filesystem, so they would be a way out of the sandbox.
//!
//! The sockets here are real Unix sockets in a temporary XDG_RUNTIME_DIR that
//! the tests point nullroute at through the environment, so nothing depends on
//! what the machine running them has installed. The last tests use the real
//! session bus and are skipped (loudly) without one.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("nr-defsock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A Unix socket service replying "real:" + what it receives. The counter says
/// how many connections reached it.
fn service(path: &Path) -> Arc<AtomicUsize> {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let l = UnixListener::bind(path).unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap_or(0);
            if n > 0 {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            let _ = c.write_all(&[b"real:", &buf[..n]].concat());
        }
    });
    hits
}

/// Run nullroute with a controlled environment: the session directories are
/// under `root` and none of the variables that name sockets leak in from the
/// machine running the tests.
fn run(root: &TmpDir, envs: &[(&str, String)], args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    c.arg("run").args(args);
    for k in [
        "DBUS_SESSION_BUS_ADDRESS",
        "DBUS_SYSTEM_BUS_ADDRESS",
        "SSH_AUTH_SOCK",
        "GNUPGHOME",
        "DOCKER_HOST",
        "WSL_INTEROP",
    ] {
        c.env_remove(k);
    }
    c.env("XDG_RUNTIME_DIR", root.path("run"))
        .env("HOME", root.path("home"))
        .env("TMPDIR", root.path("tmp"));
    for (k, v) in envs {
        c.env(k, v);
    }
    std::fs::create_dir_all(root.path("tmp")).unwrap();
    c.output().expect("launch nullroute")
}

/// Python: connect to a Unix socket, send "hi", print the first line back (or
/// the error).
fn talk(path: &Path) -> String {
    format!(
        "import socket\n\
         c = socket.socket(socket.AF_UNIX)\n\
         try:\n    c.connect({:?}); c.sendall(b'hi'); print(c.recv(200).decode().splitlines()[0])\n\
         except OSError as e:\n    print('error', e.errno)",
        path.to_str().unwrap()
    )
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// Every socket the default list is documented to cover, below one fake
/// session. (name, path relative to the temp root, environment variables).
fn session_sockets(root: &TmpDir) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("session bus", root.path("run/bus")),
        ("systemd user manager", root.path("run/systemd/private")),
        (
            "snapd session agent",
            root.path("run/snapd-session-agent.socket"),
        ),
        ("gpg-agent", root.path("run/gnupg/S.gpg-agent")),
        ("dirmngr", root.path("run/gnupg/S.dirmngr")),
        ("gnome-keyring ssh", root.path("run/keyring/ssh")),
        ("rootless docker", root.path("run/docker.sock")),
        ("rootless podman", root.path("run/podman/podman.sock")),
        ("home gnupg", root.path("home/.gnupg/S.gpg-agent.ssh")),
        (
            "docker desktop",
            root.path("home/.docker/desktop/docker.sock"),
        ),
        ("colima", root.path("home/.colima/default/docker.sock")),
    ]
}

#[test]
fn session_sockets_are_hidden_inside_and_reachable_outside() {
    let t = TmpDir::new("hidden");
    let mut cases = Vec::new();
    for (name, path) in session_sockets(&t) {
        cases.push((name, path.clone(), service(&path)));
    }
    // Named by environment variables instead of a fixed location.
    let agent = t.path("elsewhere/agent.4242");
    let bus = t.path("elsewhere/custom-bus");
    cases.push(("$SSH_AUTH_SOCK", agent.clone(), service(&agent)));
    cases.push(("$DBUS_SESSION_BUS_ADDRESS", bus.clone(), service(&bus)));
    let wsl = t.path("elsewhere/7_interop");
    cases.push(("$WSL_INTEROP", wsl.clone(), service(&wsl)));
    let envs = [
        ("WSL_INTEROP", wsl.display().to_string()),
        ("SSH_AUTH_SOCK", agent.display().to_string()),
        (
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={},guid=0123", bus.display()),
        ),
    ];

    for (name, path, hits) in &cases {
        // Outside, the service answers.
        let me = Command::new("python3")
            .args(["-c", &talk(path)])
            .output()
            .unwrap();
        assert_eq!(out(&me), "real:hi", "{name} should work outside: {me:?}");
        let before = hits.load(Ordering::SeqCst);

        // Inside, connecting reaches the decoy, never the service.
        let o = run(&t, &envs, &["--", "python3", "-c", &talk(path)]);
        assert_eq!(
            out(&o),
            "HTTP/1.1 403 Forbidden",
            "{name} reachable inside: {o:?}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before,
            "{name}: the real service received data from inside the sandbox"
        );
        assert!(
            err(&o).contains("blocked a connection to") && err(&o).contains("--allow-socket"),
            "{name}: {}",
            err(&o)
        );
    }
}

#[test]
fn allow_socket_reopens_one_default_hidden_socket_only() {
    let t = TmpDir::new("allow");
    let bus = t.path("run/bus");
    let manager = t.path("run/systemd/private");
    service(&bus);
    service(&manager);
    let script = format!("{}\n{}", talk(&bus), talk(&manager));
    let o = run(
        &t,
        &[],
        &[
            "--allow-socket",
            bus.to_str().unwrap(),
            "--",
            "python3",
            "-c",
            &script,
        ],
    );
    assert_eq!(out(&o), "real:hi\nHTTP/1.1 403 Forbidden", "{o:?}");
}

#[test]
fn dry_run_and_inspect_list_the_default_hidden_sockets() {
    let t = TmpDir::new("list");
    let bus = t.path("run/bus");
    service(&bus);
    let bus = std::fs::canonicalize(bus).unwrap();
    let o = run(&t, &[], &["--dry-run", "--inspect", "--", "true"]);
    assert!(o.status.success(), "{o:?}");
    assert!(
        out(&o).contains(&format!("hidden socket: {}", bus.display())),
        "{o:?}"
    );
    assert!(
        err(&o).contains(&format!("blocked (403 decoy):\n      {}", bus.display()))
            || err(&o).contains(&format!("      {}\n", bus.display())),
        "{}",
        err(&o)
    );
}

#[test]
fn sockets_that_do_not_exist_are_skipped_without_a_word() {
    let t = TmpDir::new("quiet");
    // Neither the session directory nor the home directory has anything in it.
    std::fs::create_dir_all(t.path("run")).unwrap();
    std::fs::create_dir_all(t.path("home")).unwrap();
    let o = run(&t, &[], &["--", "sh", "-c", "exit 7"]);
    assert_eq!(o.status.code(), Some(7), "{o:?}");
    // Whatever system sockets this machine has may be hidden (and listed in
    // --dry-run), but no path that simply isn't there is mentioned.
    assert!(
        !err(&o).contains("not found") && !err(&o).contains("no such file"),
        "{}",
        err(&o)
    );
    let o = run(&t, &[], &["--seal-docker", "--", "true"]);
    assert!(
        !err(&o).contains("not found, ignoring"),
        "a missing standard Docker socket is not worth a warning: {}",
        err(&o)
    );
}

#[test]
fn abstract_sockets_of_the_host_are_not_reachable() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;
    let name = format!("nr-abstract-{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(&name).unwrap();
    let l = UnixListener::bind_addr(&addr).unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let n = accepted.clone();
    thread::spawn(move || {
        for _ in l.incoming().flatten() {
            n.fetch_add(1, Ordering::SeqCst);
        }
    });
    let script = format!(
        "import socket\nc = socket.socket(socket.AF_UNIX)\n\
         try:\n    c.connect('\\0{name}'); print('connected')\n\
         except OSError as e:\n    print('error', e.errno)"
    );
    let outside = Command::new("python3")
        .args(["-c", &script])
        .output()
        .unwrap();
    assert_eq!(out(&outside), "connected", "{outside:?}");
    let before = accepted.load(Ordering::SeqCst);
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--", "python3", "-c", &script])
        .output()
        .unwrap();
    assert_eq!(out(&o), format!("error {}", libc::ECONNREFUSED), "{o:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), before);
}

/// The reproduction from the field: a command inside could list the host's
/// session bus (and from there start processes on the host). Needs a session
/// bus and busctl; skipped otherwise.
#[test]
fn real_session_bus_is_not_reachable_from_inside() {
    let Ok(outside) = Command::new("busctl")
        .args(["--user", "--no-pager", "list"])
        .output()
    else {
        return eprintln!("skipping real_session_bus_is_not_reachable_from_inside: no busctl");
    };
    if !outside.status.success() {
        return eprintln!(
            "skipping real_session_bus_is_not_reachable_from_inside: no session bus here"
        );
    }
    let inside = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--", "busctl", "--user", "--no-pager", "list"])
        .output()
        .unwrap();
    assert!(
        !inside.status.success(),
        "busctl --user worked inside the sandbox: {}",
        out(&inside)
    );
    assert!(
        err(&inside).contains("blocked a connection to"),
        "{}",
        err(&inside)
    );
}
