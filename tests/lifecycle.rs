//! End-to-end tests for the command's lifetime: it must not outlive nullroute,
//! and signals sent right after launch must reach it rather than being lost.
//! Every test runs the real binary and kills whatever it started, even when an
//! assertion fails (see Cleanup).

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Generous: CI runners can be slow, and polling returns as soon as it can.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A scratch directory and the processes a test started; on drop (including
/// a panic), SIGKILLs every pid written into the directory's *.pid files and
/// the nullroute processes, then removes the directory.
struct Cleanup {
    dir: PathBuf,
    nullroutes: Vec<Child>,
}

impl Cleanup {
    fn new(name: &str) -> Cleanup {
        let dir = std::env::temp_dir().join(format!("nr-lifecycle-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Cleanup {
            dir,
            nullroutes: Vec::new(),
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &mut self.nullroutes {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                if e.path().extension().is_some_and(|x| x == "pid")
                    && let Some(pid) = read_pid(&e.path())
                    && is_alive(pid)
                {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn nullroute(argv: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    c.arg("run").arg("--").args(argv);
    c.stdin(Stdio::null());
    c
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Running, i.e. it exists and isn't a zombie waiting for its new parent to
/// reap it.
fn is_alive(pid: libc::pid_t) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // The state is the first field after the ")" that ends the name.
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state != "Z" && state != "X"),
        Err(_) => false,
    }
}

fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_with_timeout(child: &mut Child) -> ExitStatus {
    poll("nullroute to exit", || child.try_wait().unwrap())
}

#[test]
fn command_dies_when_nullroute_is_sigkilled() {
    let mut cl = Cleanup::new("sigkill");
    let pidfile = cl.file("command.pid");
    // exec: the pid written is the sleep's.
    let script = format!("echo $$ > {}; exec sleep 300", pidfile.display());
    cl.nullroutes
        .push(nullroute(&["sh", "-c", &script]).spawn().unwrap());
    let pid = poll("the command to start", || read_pid(&pidfile));
    assert!(is_alive(pid));

    let nr = &mut cl.nullroutes[0];
    nr.kill().unwrap(); // SIGKILL: nullroute gets no chance to clean up
    let status = nr.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));

    poll("the orphaned command to die", || {
        (!is_alive(pid)).then_some(())
    });
}

#[test]
fn processes_the_command_leaves_behind_are_killed_when_it_exits() {
    let cl = Cleanup::new("leftovers");
    let bg = cl.file("background.pid");
    let detached = cl.file("detached.pid");
    // One plain background job, and one that left the session and ignores
    // the usual signals; the command itself exits right away.
    let script = format!(
        "sleep 300 & echo $! > {}; \
         setsid sh -c 'trap \"\" TERM HUP INT; echo $$ > {}; exec sleep 300' & \
         while [ ! -s {} ]; do sleep 0.01; done; exit 3",
        bg.display(),
        detached.display(),
        detached.display(),
    );
    let mut nr = nullroute(&["sh", "-c", &script]).spawn().unwrap();
    let status = wait_with_timeout(&mut nr);
    assert_eq!(status.code(), Some(3), "exit code still the command's");
    for f in [&bg, &detached] {
        let pid = read_pid(f).unwrap_or_else(|| panic!("{} not written", f.display()));
        assert!(
            !is_alive(pid),
            "{} (pid {pid}) outlived nullroute",
            f.display()
        );
    }
}

#[test]
fn command_starts_with_no_signals_blocked() {
    // nullroute blocks signals around spawn; the command must not inherit that.
    let o = nullroute(&["grep", "^SigBlk:", "/proc/self/status"])
        .output()
        .unwrap();
    let mine = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    let expected = mine.lines().find(|l| l.starts_with("SigBlk:")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        expected.trim(),
        "{o:?}"
    );
}

/// Send `sig` (to nullroute, or to its process group when `group`) a few
/// milliseconds after launch, many times with varying delays so it lands in
/// every startup phase. Either nullroute had not started the command yet and
/// died of the signal (nothing else running), or the command got it: exit
/// `trapped` from its trap, or 128+sig if it hadn't set the trap yet.
fn signal_right_after_launch(name: &str, sig: libc::c_int, group: bool, trapped: i32) {
    let trap = match sig {
        libc::SIGTERM => "TERM",
        libc::SIGINT => "INT",
        _ => unreachable!(),
    };
    for i in 0..40 {
        let mut cl = Cleanup::new(&format!("{name}-{i}"));
        let pidfile = cl.file("command.pid");
        let script = format!(
            "echo $$ > {}; trap 'exit {trapped}' {trap}; while :; do sleep 0.02; done",
            pidfile.display()
        );
        let mut cmd = nullroute(&["sh", "-c", &script]);
        if group {
            // Its own process group, like a foreground job: the signal goes to
            // nullroute and the command together, as from a terminal.
            cmd.process_group(0);
        }
        cl.nullroutes.push(cmd.spawn().unwrap());
        let nr = &mut cl.nullroutes[0];
        let pid = nr.id() as libc::pid_t;
        thread::sleep(Duration::from_micros(250 * (i % 20)));
        unsafe { libc::kill(if group { -pid } else { pid }, sig) };
        let status = wait_with_timeout(nr);

        if status.signal() == Some(sig) {
            // Only acceptable before the command was spawned.
            let started = read_pid(&pidfile);
            assert!(
                started.is_none(),
                "run {i}: nullroute died of signal {sig} after starting the command (pid {started:?}); \
                 the signal was lost to the command"
            );
        } else {
            assert!(
                status.code() == Some(trapped) || status.code() == Some(128 + sig),
                "run {i}: signal {sig} didn't reach the command: {status:?}"
            );
        }
        if let Some(p) = read_pid(&pidfile) {
            poll("the command to be gone", || (!is_alive(p)).then_some(()));
        }
    }
}

#[test]
fn sigterm_right_after_launch_reaches_the_command() {
    signal_right_after_launch("term", libc::SIGTERM, false, 42);
}

#[test]
fn sigint_to_the_group_right_after_launch_reaches_the_command() {
    signal_right_after_launch("int", libc::SIGINT, true, 43);
}

#[test]
fn sigterm_while_running_is_forwarded() {
    let mut cl = Cleanup::new("forward");
    let pidfile = cl.file("command.pid");
    let script = format!(
        "trap 'exit 42' TERM; echo $$ > {}; while :; do sleep 0.02; done",
        pidfile.display()
    );
    cl.nullroutes
        .push(nullroute(&["sh", "-c", &script]).spawn().unwrap());
    poll("the command to start", || read_pid(&pidfile));
    let nr = &mut cl.nullroutes[0];
    unsafe { libc::kill(nr.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(wait_with_timeout(nr).code(), Some(42));
}
