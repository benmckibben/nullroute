//! SIGTERM / SIGHUP forwarding: the command gets each signal exactly once,
//! however it was sent (to nullroute's pid, to its process group as `timeout`
//! and `kill -SIGNAL -PGID` do, or both), and nullroute still exits with
//! 128+N when the signal kills the command.
//!
//! The command is this test binary itself, run as a signal counter (see
//! `signal_counter_helper`): its handler takes 150 ms, so a second copy of the
//! signal arriving while the first is being handled is counted separately
//! instead of coalescing with it, which is what makes a duplicate visible
//! deterministically. The helper exits with the number of signals it handled,
//! and nullroute passes that on.

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(20);

static HANDLED: AtomicI32 = AtomicI32::new(0);

extern "C" fn count_signal(_sig: libc::c_int) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
    // Long enough for a duplicate to arrive while the signal is blocked by
    // the running handler. nanosleep is async-signal-safe.
    let t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 150_000_000,
    };
    unsafe { libc::nanosleep(&t, std::ptr::null_mut()) };
}

/// Not a test: the command the tests below run under nullroute. Does nothing
/// unless NULLROUTE_TEST_SIGNAL_COUNTER names the file to announce itself in.
#[test]
fn signal_counter_helper() {
    let Some(announce) = std::env::var_os("NULLROUTE_TEST_SIGNAL_COUNTER") else {
        return;
    };
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = count_signal as extern "C" fn(libc::c_int) as usize;
        for sig in [libc::SIGTERM, libc::SIGHUP] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    std::fs::write(&announce, b"ready\n").unwrap();
    let deadline = Instant::now() + TIMEOUT;
    while HANDLED.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    // Wait for late duplicates, then report how many signals were handled.
    std::thread::sleep(Duration::from_millis(600));
    let count = HANDLED.load(Ordering::SeqCst);
    let mut counted = announce.clone();
    counted.push(".count");
    let _ = std::fs::write(counted, format!("{count}\n"));
    std::process::exit(count);
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("nr-sigdel-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// nullroute in its own process group (like a foreground job or `timeout`'s),
/// running the command; waits until the command says it is ready.
struct Running {
    child: Child,
    _scratch: Scratch,
}

impl Running {
    fn pid(&self) -> libc::pid_t {
        self.child.id() as libc::pid_t
    }

    fn wait(mut self) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(Instant::now() < deadline, "nullroute didn't exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // The test failed or finished: don't leave the process group behind.
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
        let _ = self.child.wait();
    }
}

fn wait_for(what: &str, path: &Path) {
    let deadline = Instant::now() + TIMEOUT;
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn start(tag: &str, command: &[&str], announce_env: bool) -> Running {
    let scratch = Scratch::new(tag);
    let ready = scratch.0.join("ready");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    cmd.args(["run", "--"]).args(command);
    if announce_env {
        cmd.env("NULLROUTE_TEST_SIGNAL_COUNTER", &ready);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .process_group(0);
    let child = cmd.spawn().unwrap();
    let running = Running {
        child,
        _scratch: scratch,
    };
    if announce_env {
        wait_for("the command to start", &ready);
    }
    running
}

fn counter() -> Vec<String> {
    let exe = std::env::current_exe()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    [
        exe.as_str(),
        "--exact",
        "signal_counter_helper",
        "--test-threads=1",
        "--nocapture",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Clone, Copy, Debug)]
enum How {
    /// kill(nullroute_pid): only nullroute is addressed.
    Pid,
    /// kill(-pgid): nullroute and the command, as `kill -TERM -PGID` does.
    Group,
    /// What `timeout` does: the child's pid, then its whole group.
    Both,
}

fn send(pid: libc::pid_t, sig: libc::c_int, how: How) {
    unsafe {
        match how {
            How::Pid => libc::kill(pid, sig),
            How::Group => libc::kill(-pid, sig),
            How::Both => {
                libc::kill(pid, sig);
                libc::kill(-pid, sig)
            }
        };
    }
}

/// The command must see the signal exactly once; its exit status says how
/// many it handled.
fn exactly_once(tag: &str, sig: libc::c_int, how: How) {
    for round in 0..4 {
        let argv = counter();
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let run = start(&format!("{tag}-{round}"), &argv, true);
        send(run.pid(), sig, how);
        let status = run.wait();
        assert_eq!(
            status.code(),
            Some(1),
            "round {round}: SIGNAL {sig} sent as {how:?} was handled by the command (exit status) {status:?} times, not exactly once"
        );
    }
}

#[test]
fn sigterm_to_nullroutes_pid_is_forwarded_once() {
    exactly_once("term-pid", libc::SIGTERM, How::Pid);
}

#[test]
fn sigterm_to_the_process_group_reaches_the_command_once() {
    exactly_once("term-group", libc::SIGTERM, How::Group);
}

#[test]
fn sigterm_to_the_pid_and_the_group_like_timeout_reaches_the_command_once() {
    exactly_once("term-both", libc::SIGTERM, How::Both);
}

#[test]
fn sighup_to_nullroutes_pid_is_forwarded_once() {
    exactly_once("hup-pid", libc::SIGHUP, How::Pid);
}

#[test]
fn sighup_to_the_process_group_reaches_the_command_once() {
    exactly_once("hup-group", libc::SIGHUP, How::Group);
}

#[test]
fn real_timeout_delivers_sigterm_once() {
    // `timeout` itself (GNU coreutils): signals its child, then its group.
    let scratch = Scratch::new("timeout");
    let ready = scratch.0.join("ready");
    let argv = counter();
    let status = Command::new("timeout")
        .args([
            "--signal=TERM",
            "1",
            env!("CARGO_BIN_EXE_nullroute"),
            "run",
            "--",
        ])
        .args(&argv)
        .env("NULLROUTE_TEST_SIGNAL_COUNTER", &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status();
    let Ok(status) = status else {
        eprintln!("skipping: no timeout(1) on this machine");
        return;
    };
    // timeout reports 124 when it had to stop the command and hides the
    // command's own status, so the helper leaves its count in a file.
    assert_eq!(status.code(), Some(124), "{status:?}");
    let count = std::fs::read_to_string(scratch.0.join("ready.count")).unwrap();
    assert_eq!(
        count.trim(),
        "1",
        "the command handled SIGTERM {count} times"
    );
}

#[test]
fn a_signal_that_kills_the_command_exits_128_plus_n_however_it_was_sent() {
    for how in [How::Pid, How::Group, How::Both] {
        let run = start(
            &format!("kill-{how:?}"),
            &["sh", "-c", "exec sleep 300"],
            false,
        );
        let pid = run.pid();
        // Poll for the command to be running instead of sleeping.
        let deadline = Instant::now() + TIMEOUT;
        while !has_child_named(pid, "sleep") {
            assert!(Instant::now() < deadline, "the command never started");
            std::thread::sleep(Duration::from_millis(5));
        }
        send(pid, libc::SIGTERM, how);
        let status = run.wait();
        assert_eq!(
            status.code(),
            Some(128 + libc::SIGTERM),
            "{how:?}: {status:?}"
        );
        assert_eq!(status.signal(), None);
    }
}

/// Does `pid` have a child process called `name` (by now)?
fn has_child_named(pid: libc::pid_t, name: &str) -> bool {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    tasks.flatten().any(|t| {
        std::fs::read_to_string(t.path().join("children"))
            .unwrap_or_default()
            .split_whitespace()
            .any(|c| {
                std::fs::read_to_string(format!("/proc/{c}/comm")).is_ok_and(|n| n.trim() == name)
            })
    })
}
