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

/// Like [`nullroute`], with flags for `run` before the command.
fn nullroute_with(flags: &[&str], argv: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    c.arg("run").args(flags).arg("--").args(argv);
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
/// every startup phase. Whichever phase it lands in, it must have the effect
/// it would have had on the command run without nullroute, never silently
/// vanish, and never leave the command running:
/// - before nullroute blocks its signals: nullroute dies of it (the command
///   doesn't exist yet, `command.pid` is never written);
/// - while the command is being set up (SIGINT: also if it landed before the
///   command was forked, see `signal_before_the_command_exists`):
///   the child dies of it before running anything, nullroute exits 128+sig,
///   again without `command.pid`;
/// - once the command runs: it gets the signal, exiting `trapped` from its
///   trap, or 128+sig if it hadn't installed the trap yet.
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

        let started = read_pid(&pidfile);
        if status.signal() == Some(sig) {
            assert!(
                started.is_none(),
                "run {i}: nullroute died of signal {sig} after starting the command (pid {started:?}); \
                 the signal was lost to the command"
            );
        } else if started.is_some() {
            assert!(
                status.code() == Some(trapped) || status.code() == Some(128 + sig),
                "run {i}: signal {sig} didn't reach the command: {status:?}"
            );
        } else {
            // The command never ran: its child was stopped by the signal first.
            assert_eq!(
                status.code(),
                Some(128 + sig),
                "run {i}: the command never started, yet nullroute didn't report the signal: {status:?}"
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

/// Run nullroute (in its own process group, with core dumps off so a SIGQUIT
/// doesn't leave a core file) held right after it blocked its signals and
/// before it forks the command (debug-only test hook, see sandbox.rs). Returns
/// once it is held, with the path to release it by removing.
#[cfg(debug_assertions)]
fn held_before_spawn(cl: &mut Cleanup, script: &str) -> PathBuf {
    let hold = cl.file("hold");
    let mut cmd = nullroute(&["sh", "-c", script]);
    cmd.env("NULLROUTE_TEST_HOLD_BEFORE_SPAWN", &hold);
    cmd.process_group(0);
    // SAFETY: only setrlimit, which is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            let none = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            Ok(())
        });
    }
    cl.nullroutes.push(cmd.spawn().unwrap());
    poll("nullroute to reach the hold", || {
        hold.exists().then_some(())
    });
    hold
}

/// The window the sweep above can only hit by luck, made certain: the signal
/// reaches nullroute while the command does not exist yet (so only nullroute is
/// in the process group to get it). It used to be dropped, and the command that
/// started afterwards never saw it: Ctrl-C during startup was lost and the
/// command ran on, with nullroute waiting for it forever.
#[cfg(debug_assertions)]
fn signal_before_the_command_exists(sig: libc::c_int, group: bool) {
    let mut cl = Cleanup::new(&format!("early-{sig}-{group}"));
    let pidfile = cl.file("command.pid");
    let script = format!(
        "echo $$ > {}; while :; do sleep 0.02; done",
        pidfile.display()
    );
    let hold = held_before_spawn(&mut cl, &script);
    let nr = &mut cl.nullroutes[0];
    let pid = nr.id() as libc::pid_t;
    unsafe { libc::kill(if group { -pid } else { pid }, sig) };
    std::fs::remove_file(&hold).unwrap();

    let status = wait_with_timeout(nr);
    assert_eq!(
        status.code(),
        Some(128 + sig),
        "the signal sent before the command existed was lost: {status:?}"
    );
    assert!(
        read_pid(&pidfile).is_none(),
        "the command ran although it was interrupted before it started"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only test hook")]
fn sigint_to_the_group_before_the_command_exists_stops_it_from_running() {
    #[cfg(debug_assertions)]
    signal_before_the_command_exists(libc::SIGINT, true);
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only test hook")]
fn sigquit_to_the_group_before_the_command_exists_stops_it_from_running() {
    #[cfg(debug_assertions)]
    signal_before_the_command_exists(libc::SIGQUIT, true);
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only test hook")]
fn sigint_to_nullroute_alone_before_the_command_exists_is_treated_the_same() {
    // Indistinguishable from the group case at that point (signals.rs).
    #[cfg(debug_assertions)]
    signal_before_the_command_exists(libc::SIGINT, false);
}

#[test]
fn sigint_to_the_group_while_running_reaches_the_command_once() {
    // Once the command exists the terminal's group delivery is all it needs:
    // nullroute must not add a second copy, and a SIGINT sent to nullroute
    // alone stays ignored (README, "Signals and process lifetime").
    let mut cl = Cleanup::new("int-once");
    let pidfile = cl.file("command.pid");
    let hits = cl.file("hits");
    let script = format!(
        "trap 'echo x >> {}' INT; trap 'exit 42' TERM; echo $$ > {}; while :; do sleep 0.02; done",
        hits.display(),
        pidfile.display()
    );
    let mut cmd = nullroute(&["sh", "-c", &script]);
    cmd.process_group(0);
    cl.nullroutes.push(cmd.spawn().unwrap());
    poll("the command to start", || read_pid(&pidfile));
    let nr = &mut cl.nullroutes[0];
    let pid = nr.id() as libc::pid_t;
    let count = || std::fs::read_to_string(&hits).map_or(0, |s| s.lines().count());

    unsafe { libc::kill(-pid, libc::SIGINT) };
    poll("the command to see the SIGINT", || {
        (count() >= 1).then_some(())
    });
    unsafe { libc::kill(pid, libc::SIGINT) }; // nullroute alone: ignored
    // Instead of sleeping and hoping the ignored signal had time to do harm,
    // order the checks: signals sent to nullroute are handled in order, so by
    // the time the SIGTERM that follows has been forwarded and the command
    // has exited with its TERM status (nullroute itself survived the SIGINT),
    // the SIGINT has been dealt with, and the command saw no second one.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(wait_with_timeout(nr).code(), Some(42));
    assert_eq!(count(), 1, "the command saw a different number of SIGINTs");
}

/// A command that ignores SIGTERM and a background child of its own.
fn stubborn_script(pidfile: &Path, childfile: &Path) -> String {
    format!(
        "trap '' TERM; echo $$ > {}; sleep 600 & echo $! > {}; wait; while :; do sleep 0.05; done",
        pidfile.display(),
        childfile.display()
    )
}

#[test]
fn a_command_that_ignores_sigterm_keeps_nullroute_waiting_without_kill_after() {
    let mut cl = Cleanup::new("stubborn-default");
    let (pidfile, childfile) = (cl.file("command.pid"), cl.file("child.pid"));
    let script = stubborn_script(&pidfile, &childfile);
    cl.nullroutes
        .push(nullroute(&["sh", "-c", &script]).spawn().unwrap());
    poll("the command to start", || read_pid(&pidfile));
    let nr = &mut cl.nullroutes[0];
    unsafe { libc::kill(nr.id() as libc::pid_t, libc::SIGTERM) };
    thread::sleep(Duration::from_secs(3));
    assert!(
        nr.try_wait().unwrap().is_none(),
        "nullroute gave up on a command that ignores SIGTERM without --kill-after"
    );
    assert!(is_alive(read_pid(&pidfile).unwrap()));
    // Cleanup kills it.
}

#[test]
fn kill_after_sigkills_a_command_that_ignores_sigterm() {
    let mut cl = Cleanup::new("stubborn-kill-after");
    let (pidfile, childfile) = (cl.file("command.pid"), cl.file("child.pid"));
    let script = stubborn_script(&pidfile, &childfile);
    cl.nullroutes.push(
        nullroute_with(&["--kill-after", "1"], &["sh", "-c", &script])
            .spawn()
            .unwrap(),
    );
    let command = poll("the command to start", || read_pid(&pidfile));
    let child = poll("its child to start", || read_pid(&childfile));
    let nr = &mut cl.nullroutes[0];
    let sent = Instant::now();
    unsafe { libc::kill(nr.id() as libc::pid_t, libc::SIGTERM) };
    let status = wait_with_timeout(nr);
    let took = sent.elapsed();
    assert_eq!(
        status.signal().or(status.code().map(|c| c - 128)),
        Some(libc::SIGKILL),
        "exit status {status:?}"
    );
    assert!(
        took >= Duration::from_millis(900),
        "escalated before the delay: {took:?}"
    );
    assert!(!is_alive(command), "the command survived");
    poll("the command's child to be killed", || {
        (!is_alive(child)).then_some(())
    });
}

#[test]
fn kill_after_leaves_a_command_that_exits_in_time_alone() {
    let mut cl = Cleanup::new("kill-after-polite");
    let pidfile = cl.file("command.pid");
    let script = format!(
        "trap 'exit 42' TERM; echo $$ > {}; while :; do sleep 0.02; done",
        pidfile.display()
    );
    cl.nullroutes.push(
        nullroute_with(&["--kill-after", "5"], &["sh", "-c", &script])
            .spawn()
            .unwrap(),
    );
    poll("the command to start", || read_pid(&pidfile));
    let nr = &mut cl.nullroutes[0];
    let sent = Instant::now();
    unsafe { libc::kill(nr.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(wait_with_timeout(nr).code(), Some(42));
    assert!(
        sent.elapsed() < Duration::from_secs(4),
        "waited for the delay"
    );
}

#[test]
fn kill_after_rejects_zero_and_non_numbers() {
    for bad in ["0", "-1", "soon", "1.5"] {
        let o = nullroute_with(&["--kill-after", bad], &["true"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "--kill-after {bad}: {o:?}");
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("error:"),
            "--kill-after {bad}: {o:?}"
        );
    }
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
