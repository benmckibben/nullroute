//! Caps on what nullroute does for a command: connections served at once,
//! live output, the report, descriptor limits. The numbers are lowered with
//! debug-build-only environment variables (NULLROUTE_TEST_MAX_CONNECTIONS,
//! NULLROUTE_TEST_REPORT_LIMITS), so those tests are ignored in release
//! builds; the descriptor-limit test is not.

use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

fn nullroute() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    c.arg("run").stdin(Stdio::null());
    c
}

fn python(c: &mut Command, script: &str) -> Output {
    c.arg("--")
        .args(["python3", "-c", script])
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Opens §n§ idle connections to §addr§, waits (polling, up to 15 s) until the
/// number that nullroute has closed stops being at least §expect_closed§, and
/// prints "closed=C open=O threads=T" (T: nullroute's threads).
fn idle_connections(addr: &str, n: usize, expect_closed: usize) -> String {
    format!(
        r#"
import select, socket, os, time
host, port = "{}".split(":")
socks = []
for i in range({n}):
    s = socket.create_connection((host, int(port)), timeout=5)
    socks.append(s)
    time.sleep(0.005)
closed = 0
alive = list(socks)
deadline = time.time() + 15
while closed < {expect_closed} and time.time() < deadline:
    readable, _, _ = select.select(alive, [], [], 0.1)
    for s in readable:
        try:
            gone = s.recv(1) == b""
        except OSError:
            gone = True
        if gone:
            closed += 1
            alive.remove(s)
# a little longer, to see whether nullroute closes more than it should
end = time.time() + 0.5
while time.time() < end:
    readable, _, _ = select.select(alive, [], [], 0.1)
    for s in readable:
        try:
            gone = s.recv(1) == b""
        except OSError:
            gone = True
        if gone:
            closed += 1
            alive.remove(s)
threads = [int(l.split(":")[1]) for l in open("/proc/%d/status" % os.getppid()) if l.startswith("Threads")][0]
print("closed=%d open=%d threads=%d" % (closed, len(alive), threads))
"#,
        addr
    )
}

fn parse_idle(output: &str) -> (usize, usize, usize) {
    let line = output.lines().last().unwrap_or_default();
    let field = |name: &str| -> usize {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(name))
            .and_then(|v| v.strip_prefix('='))
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("no {name} in {output:?}"))
    };
    (field("closed"), field("open"), field("threads"))
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only limit override")]
fn port_forward_connections_beyond_the_cap_are_closed_and_cost_no_threads() {
    // A host service that accepts and holds every connection.
    let host = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = host.local_addr().unwrap().port();
    let held = Arc::new(Mutex::new(Vec::new()));
    let keep = held.clone();
    std::thread::spawn(move || {
        for c in host.incoming().flatten() {
            keep.lock().unwrap().push(c);
        }
    });
    let o = python(
        nullroute()
            .env("NULLROUTE_TEST_MAX_CONNECTIONS", "4")
            .args(["--port", &port.to_string()]),
        &idle_connections(&format!("127.0.0.1:{port}"), 12, 8),
    );
    assert!(o.status.success(), "{}", err(&o));
    let (closed, open, threads) = parse_idle(&out(&o));
    assert_eq!((closed, open), (8, 4), "{}", out(&o));
    // 4 relayed connections = 8 threads, plus nullroute's own handful.
    assert!(threads < 30, "{threads} threads for 4 connections");
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only limit override")]
fn dns_tcp_connections_beyond_the_cap_are_closed() {
    let o = python(
        nullroute()
            .env("NULLROUTE_TEST_MAX_CONNECTIONS", "4")
            .args(["--allow", "example.com"]),
        &idle_connections("127.0.0.1:53", 12, 8),
    );
    assert!(o.status.success(), "{}", err(&o));
    let (closed, open, threads) = parse_idle(&out(&o));
    assert_eq!((closed, open), (8, 4), "{}", out(&o));
    assert!(threads < 30, "{threads} threads for 4 connections");
}

/// A command sends §n§ DNS queries for distinct names that aren't allowed.
fn lookups(n: usize) -> String {
    format!(
        r#"
import socket, struct
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(5)
for i in range({n}):
    labels = ("gen%d.example.org" % i).split(".")
    q = struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\0" + struct.pack(">HH", 1, 1)
    u.sendto(q, ("127.0.0.1", 53))
    u.recvfrom(512)
"#
    )
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only limit override")]
fn a_flood_of_distinct_names_is_capped_but_still_fails_strict_and_is_counted() {
    let dir = std::env::temp_dir().join(format!("nr-limits-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let json = dir.join("report.json");
    let started = Instant::now();
    let o = python(
        nullroute()
            .env("NULLROUTE_TEST_REPORT_LIMITS", "5,3")
            .args(["--strict", "--allow", "example.com", "--report-json"])
            .arg(&json),
        &lookups(60),
    );
    let seconds = started.elapsed().as_secs() + 1;
    let stderr = err(&o);
    let live = stderr
        .lines()
        .filter(|l| l.starts_with("nullroute: blocked DNS lookup of"))
        .count();
    // At most 3 live lines in each second, whatever the machine's speed.
    assert!(
        live as u64 <= 3 * seconds,
        "{live} live lines in {seconds}s\n{stderr}"
    );
    assert!(live < 60, "{stderr}");
    // Only the first 5 targets are listed in the summary; the rest are counted.
    let listed = stderr.lines().filter(|l| l.starts_with("  dns ")).count();
    assert_eq!(listed, 5, "{stderr}");
    assert!(stderr.contains("to reach at least 5 targets"), "{stderr}");
    assert!(
        stderr.contains("more attempts at other targets (only the first 5 targets are listed)"),
        "{stderr}"
    );
    assert!(stderr.contains("live messages were held back"), "{stderr}");
    // The suppressed attempts are still blocks: --strict fails (exit 1).
    assert_eq!(o.status.code(), Some(1), "{stderr}");
    let report = std::fs::read_to_string(&json).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        report.contains("\"not_listed\": {\"blocked_attempts\": "),
        "{report}"
    );
    assert!(!report.contains("\"blocked_attempts\": 0"), "{report}");
}

#[test]
fn the_command_gets_its_original_descriptor_limit_while_nullroute_raises_its_own() {
    // soft 256 / hard 4096 for nullroute and the command, as a shell's
    // default soft limit with a higher hard limit.
    let mut c = nullroute();
    unsafe {
        c.pre_exec(|| {
            let l = libc::rlimit {
                rlim_cur: 256,
                rlim_max: 4096,
            };
            libc::setrlimit(libc::RLIMIT_NOFILE, &l);
            Ok(())
        });
    }
    let o = python(
        &mut c,
        r#"
import os
def soft_hard(path):
    for l in open(path):
        if l.startswith("Max open files"):
            return l.split()[3:5]
print(" ".join(soft_hard("/proc/self/limits") + soft_hard("/proc/%d/limits" % os.getppid())))
"#,
    );
    assert!(o.status.success(), "{}", err(&o));
    // command: soft 256 hard 4096; nullroute: soft 4096 hard 4096.
    assert_eq!(out(&o).trim(), "256 4096 4096 4096", "{}", err(&o));
}
