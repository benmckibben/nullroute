//! Breach report, --strict, --quiet, --report-json, and signal behaviour.

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("nr-report-{tag}-{}", std::process::id()));
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

fn nr(args: &[&str], tmp: &Tmp) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .env("TMPDIR", &tmp.0)
        .output()
        .unwrap()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// A Unix socket we hide, so a "blocked attempt" needs no network or Docker.
fn hidden_socket(tmp: &Tmp) -> String {
    let p = tmp.0.join("svc.sock");
    let l = UnixListener::bind(&p).unwrap();
    std::mem::forget(l); // keep it listening for the test's lifetime
    std::fs::canonicalize(&p)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn poke(path: &str, times: usize) -> String {
    format!(
        "import socket\nfor _ in range({times}):\n    c = socket.socket(socket.AF_UNIX); c.connect({path:?}); c.sendall(b'x'); c.recv(64)"
    )
}

#[test]
fn summary_lists_blocked_targets_with_counts() {
    let t = Tmp::new("summary");
    let s = hidden_socket(&t);
    let o = nr(
        &["--hide-socket", &s, "--", "python3", "-c", &poke(&s, 3)],
        &t,
    );
    assert!(o.status.success(), "{o:?}");
    let e = err(&o);
    assert!(
        e.contains("nullroute: blocked 3 attempts to reach 1 target:"),
        "{e}"
    );
    assert!(e.contains(&format!("socket  {s}")), "{e}");
    assert!(e.contains("3x"), "{e}");
}

#[test]
fn no_summary_when_nothing_blocked() {
    let t = Tmp::new("clean");
    let o = nr(&["--", "true"], &t);
    assert!(o.status.success());
    assert!(!err(&o).contains("nullroute: blocked"), "{}", err(&o));
}

#[test]
fn strict_fails_a_successful_command_that_was_blocked() {
    let t = Tmp::new("strict");
    let s = hidden_socket(&t);
    let o = nr(
        &[
            "--strict",
            "--hide-socket",
            &s,
            "--",
            "python3",
            "-c",
            &poke(&s, 1),
        ],
        &t,
    );
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(err(&o).contains("--strict: failing"), "{}", err(&o));
}

#[test]
fn strict_keeps_the_commands_own_failure_code() {
    let t = Tmp::new("strict-fail");
    let s = hidden_socket(&t);
    let script = format!("{}\nraise SystemExit(7)", poke(&s, 1));
    let o = nr(
        &[
            "--strict",
            "--hide-socket",
            &s,
            "--",
            "python3",
            "-c",
            &script,
        ],
        &t,
    );
    assert_eq!(o.status.code(), Some(7), "{o:?}");
}

#[test]
fn strict_passes_when_nothing_was_blocked() {
    let t = Tmp::new("strict-clean");
    assert_eq!(nr(&["--strict", "--", "true"], &t).status.code(), Some(0));
}

#[test]
fn quiet_drops_live_lines_but_keeps_summary() {
    let t = Tmp::new("quiet");
    let s = hidden_socket(&t);
    let o = nr(
        &[
            "-q",
            "--hide-socket",
            &s,
            "--",
            "python3",
            "-c",
            &poke(&s, 2),
        ],
        &t,
    );
    let e = err(&o);
    assert!(!e.contains("blocked a connection to"), "{e}");
    assert!(e.contains("nullroute: blocked 2 attempts"), "{e}");
}

#[test]
fn report_json_is_written_and_parseable() {
    let t = Tmp::new("json");
    let s = hidden_socket(&t);
    let out = t.0.join("report.json");
    let o = nr(
        &[
            "--strict",
            "--report-json",
            out.to_str().unwrap(),
            "--hide-socket",
            &s,
            "--",
            "python3",
            "-c",
            &poke(&s, 2),
        ],
        &t,
    );
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    let check = format!(
        "import json; r = json.load(open({:?})); b = r['blocked'][0]\n\
         print(r['exit_code'], r['strict_failed'], r['command'][0], b['kind'], b['target'] == {s:?}, b['count'])",
        out.to_str().unwrap()
    );
    let v = Command::new("python3")
        .args(["-c", &check])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&v.stdout).trim(),
        "1 True python3 socket True 2",
        "{v:?}"
    );
}

#[test]
fn report_json_written_when_clean() {
    let t = Tmp::new("json-clean");
    let out = t.0.join("r.json");
    nr(&["--report-json", out.to_str().unwrap(), "--", "true"], &t);
    let body = std::fs::read_to_string(&out).unwrap();
    assert!(
        body.contains("\"blocked\": []") && body.contains("\"exit_code\": 0"),
        "{body}"
    );
}

#[test]
fn report_survives_sigint_to_the_process_group() {
    // Like Ctrl-C: SIGINT to nullroute and the command. The command dies (130),
    // nullroute ignores it, prints the summary and exits with the command's status.
    let t = Tmp::new("sigint");
    let s = hidden_socket(&t);
    let script = format!(
        "{}\nimport time\nprint('ready', flush=True)\ntime.sleep(30)",
        poke(&s, 1)
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--hide-socket", &s, "--", "python3", "-c", &script])
        .env("TMPDIR", &t.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().unwrap()),
        &mut line,
    )
    .unwrap();
    assert_eq!(line.trim(), "ready");
    unsafe { libc::kill(-(child.id() as i32), libc::SIGINT) };
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(130), "{o:?}");
    assert!(
        err(&o).contains("nullroute: blocked 1 attempt to reach 1 target:"),
        "{}",
        err(&o)
    );
}

#[test]
fn sigterm_is_forwarded_to_the_command() {
    let t = Tmp::new("sigterm");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "trap 'echo got-term; exit 42' TERM; echo ready; while :; do sleep 0.05; done",
        ])
        .env("TMPDIR", &t.0)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut buf = [0u8; 6];
    std::io::Read::read_exact(&mut out, &mut buf).unwrap();
    thread::sleep(Duration::from_millis(100));
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let status = child.wait().unwrap();
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    assert!(
        rest.contains("got-term"),
        "command didn't see SIGTERM: {rest:?}"
    );
    assert_eq!(status.code(), Some(42));
    let _ = std::io::stdout().flush();
}
