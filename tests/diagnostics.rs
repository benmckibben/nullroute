//! Diagnostics (warnings, live "blocked" lines, the summary) must never change
//! what a run does: not its exit code, not whether the proxy/DNS/decoy threads
//! keep serving. stderr or stdout can be a pipe whose reader is gone, a full
//! disk (/dev/full) or closed; Rust's own `eprintln!` panics on all of those.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("nr-diag-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A Unix socket we hide, so a "blocked attempt" needs no network or Docker.
/// Returns the listener too: it must stay alive for the test.
fn hidden_socket(tmp: &Tmp) -> (UnixListener, String) {
    let p = tmp.0.join("svc.sock");
    let l = UnixListener::bind(&p).unwrap();
    let path = std::fs::canonicalize(&p)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    (l, path)
}

/// Connect to the (hidden) socket `times` times, print one line per reply that
/// says nullroute blocked it, then exit with `code`.
fn poke_then_exit(path: &str, times: usize, code: i32) -> String {
    format!(
        r#"import socket, sys
for _ in range({times}):
    c = socket.socket(socket.AF_UNIX); c.connect({path:?}); c.sendall(b'x')
    print('blocked' if b'403' in c.recv(256) else 'passed', flush=True)
sys.exit({code})
"#
    )
}

fn run(tmp: &Tmp, args: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .env("TMPDIR", &tmp.0)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .unwrap()
}

/// A pipe whose reader has gone away: every write fails with EPIPE.
fn broken_pipe() -> Stdio {
    let (r, w) = std::io::pipe().unwrap();
    drop(r);
    Stdio::from(w)
}

/// /dev/full: every write fails with ENOSPC.
fn full_disk() -> Stdio {
    Stdio::from(
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap(),
    )
}

fn assert_exit_7_after_three_blocks(o: &Output) {
    assert_eq!(o.status.code(), Some(7), "{o:?}");
    // The decoy kept answering after its first (unprintable) warning.
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "blocked\nblocked\nblocked\n",
        "{o:?}"
    );
}

#[test]
fn closed_stderr_pipe_keeps_the_commands_exit_code() {
    let t = Tmp::new("stderr-pipe");
    let (_l, s) = hidden_socket(&t);
    let script = poke_then_exit(&s, 3, 7);
    let o = run(
        &t,
        &["--hide-socket", &s, "--", "python3", "-c", &script],
        Stdio::piped(),
        broken_pipe(),
    );
    assert_exit_7_after_three_blocks(&o);
}

#[test]
fn full_stderr_keeps_the_commands_exit_code() {
    let t = Tmp::new("stderr-full");
    let (_l, s) = hidden_socket(&t);
    let script = poke_then_exit(&s, 3, 7);
    let o = run(
        &t,
        &["--hide-socket", &s, "--", "python3", "-c", &script],
        Stdio::piped(),
        full_disk(),
    );
    assert_exit_7_after_three_blocks(&o);
}

#[test]
fn closed_stderr_keeps_exit_code_with_strict_and_the_dns_sinkhole() {
    // The DNS sinkhole's thread prints "blocked DNS lookup" too, and --strict's
    // own failure message goes to the same stderr: exit 1, not 101.
    let t = Tmp::new("stderr-strict");
    let o = run(
        &t,
        &[
            "--strict",
            "--allow",
            "example.com",
            "--",
            "sh",
            "-c",
            "getent hosts blocked.example.org >/dev/null 2>&1; exit 0",
        ],
        Stdio::piped(),
        broken_pipe(),
    );
    assert_eq!(o.status.code(), Some(1), "{o:?}");
}

#[test]
fn closed_stdout_does_not_make_nullroute_panic() {
    let t = Tmp::new("stdout-pipe");
    let (_l, s) = hidden_socket(&t);
    let script = poke_then_exit(&s, 1, 7);
    let o = run(
        &t,
        &["--hide-socket", &s, "--", "python3", "-c", &script],
        broken_pipe(),
        Stdio::piped(),
    );
    // The command's own stdout is the broken pipe (python fails to flush and
    // exits with its own code); nullroute passes the code through, still
    // prints its report, and doesn't turn anything into a panic (101).
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("panicked"), "{err}");
    assert!(err.contains("blocked 1 attempt"), "{err}");
    assert_ne!(o.status.code(), Some(101), "{o:?}");
}

#[test]
fn dry_run_to_a_full_stdout_fails_with_a_message_not_a_panic() {
    let t = Tmp::new("dry-run-full");
    let o = run(
        &t,
        &["--dry-run", "--port", "5432", "--", "true"],
        full_disk(),
        Stdio::piped(),
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(o.status.code(), Some(74), "{o:?}");
    assert!(err.contains("writing the --dry-run listing"), "{err}");
}
