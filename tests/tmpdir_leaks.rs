//! nullroute's scratch directories (decoy sockets, generated resolv.conf) must
//! not outlive a run, however it ends: they only exist while the sandbox is
//! being set up, and what a kill in that window leaves is swept by the next
//! run. Every test gives nullroute its own TMPDIR and looks inside it.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(15);

/// A scratch TMPDIR (and a socket to hide in it); removed on drop, and the
/// processes of a test are killed.
struct Env {
    dir: PathBuf,
    kids: Vec<Child>,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("nr-tmpleak-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tmp")).unwrap();
        Env {
            dir,
            kids: Vec::new(),
        }
    }

    fn tmp(&self) -> PathBuf {
        self.dir.join("tmp")
    }

    /// A socket to hide (an explicit --hide-socket, so the test doesn't depend
    /// on what is installed on the machine) and the file that will exist in
    /// the sandbox when the command is up.
    fn socket(&self) -> String {
        let p = self.dir.join("svc.sock");
        if !p.exists() {
            std::mem::forget(std::os::unix::net::UnixListener::bind(&p).unwrap());
        }
        p.to_str().unwrap().to_string()
    }

    fn nullroute(&self, extra: &[&str], command: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
        c.arg("run")
            .args(["--hide-socket", &self.socket(), "--allow", "example.com"])
            .args(extra)
            .arg("--")
            .args(command)
            .env("TMPDIR", self.tmp())
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        // No core dumps from the deliberate crashes below.
        // SAFETY: only setrlimit, which is async-signal-safe.
        unsafe {
            c.pre_exec(|| {
                let none = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &none);
                Ok(())
            });
        }
        c
    }

    /// What nullroute left in its TMPDIR.
    fn leftovers(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.tmp())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        for k in &mut self.kids {
            // The whole group: nullroute, its command and helper.
            unsafe { libc::kill(-(k.id() as libc::pid_t), libc::SIGKILL) };
            let _ = k.kill();
            let _ = k.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn children_of(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    tasks
        .flatten()
        .filter_map(|t| std::fs::read_to_string(t.path().join("children")).ok())
        .flat_map(|s| {
            s.split_whitespace()
                .filter_map(|p| p.parse().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn comm(pid: libc::pid_t) -> Option<String> {
    Some(
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()?
            .trim()
            .to_string(),
    )
}

fn alive(pid: libc::pid_t) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .and_then(|(_, r)| r.split_whitespace().next().map(|st| st != "Z" && st != "X"))
            .unwrap_or(false)
    })
}

/// Start nullroute running `sleep 300`, wait until the command is up, hit
/// nullroute with `sig` and wait for the command to be gone. The scratch
/// directories have to stay while the command runs (a nullroute started inside
/// the sandbox mounts over them), so a kill leaves them behind: the next run
/// must sweep them once they are old enough.
fn kill_then_the_next_run_sweeps(tag: &str, sig: libc::c_int) {
    let mut env = Env::new(tag);
    let child = env
        .nullroute(&[], &["sleep", "300"])
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    env.kids.push(child);
    let sleeper = poll("the command to start", || {
        children_of(pid)
            .into_iter()
            .find(|&c| comm(c).as_deref() == Some("sleep"))
    });
    unsafe { libc::kill(pid, sig) };
    env.kids[0].wait().unwrap();
    poll("the command to die with nullroute", || {
        (!alive(sleeper)).then_some(())
    });
    // Nobody holds the locks any more; make the leftovers old enough.
    let left = env.leftovers();
    for d in &left {
        backdate(&env.tmp().join(d));
    }
    assert!(env.nullroute(&[], &["true"]).status().unwrap().success());
    assert_eq!(
        env.leftovers(),
        Vec::<String>::new(),
        "left after the next run (there were {left:?})"
    );
}

#[test]
fn sigkill_while_the_command_runs_is_swept_by_the_next_run() {
    kill_then_the_next_run_sweeps("kill", libc::SIGKILL);
}

#[test]
fn a_crash_while_the_command_runs_is_swept_by_the_next_run() {
    // SIGUSR1 and SIGABRT terminate with no chance to clean up, like a crash
    // (SIGSEGV can't stand in: Rust handles it for stack overflow detection).
    kill_then_the_next_run_sweeps("usr1", libc::SIGUSR1);
    kill_then_the_next_run_sweeps("abrt", libc::SIGABRT);
}

#[test]
fn ordinary_exits_leave_no_temp_dirs() {
    let env = Env::new("exits");
    for command in [
        &["true"][..],
        &["sh", "-c", "exit 7"],
        &["no-such-command-here"],
    ] {
        let status = env.nullroute(&[], command).status().unwrap();
        assert!(status.code().is_some(), "{status:?}");
        assert_eq!(env.leftovers(), Vec::<String>::new(), "after {command:?}");
    }
}

#[test]
fn dry_run_and_inspect_create_nothing() {
    let env = Env::new("dry");
    for extra in [&["--dry-run"][..], &["--inspect", "--dry-run"]] {
        let status = env
            .nullroute(extra, &["true"])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "{status:?}");
        assert_eq!(env.leftovers(), Vec::<String>::new(), "after {extra:?}");
    }
}

/// Start nullroute held right after it created its scratch directories and
/// before it forks the command (debug-only test hook, see sandbox.rs).
#[cfg(debug_assertions)]
fn held_during_setup(env: &mut Env, command: &[&str]) -> (libc::pid_t, PathBuf) {
    let hold = env.dir.join("hold");
    let mut cmd = env.nullroute(&[], command);
    cmd.env("NULLROUTE_TEST_HOLD_BEFORE_SPAWN", &hold)
        .process_group(0);
    let child = cmd.spawn().unwrap();
    let pid = child.id() as libc::pid_t;
    env.kids.push(child);
    poll("nullroute to reach the hold", || {
        hold.exists().then_some(())
    });
    (pid, hold)
}

fn backdate(path: &Path) {
    let t = libc::timespec {
        tv_sec: 1_000_000_000,
        tv_nsec: 0,
    };
    let c =
        std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())).unwrap();
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [t, t].as_ptr(), 0) };
    assert_eq!(rc, 0);
}

/// Make the directory's mtime "now" again.
#[cfg(debug_assertions)]
fn touch(path: &Path) {
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_NOW,
    };
    let c =
        std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())).unwrap();
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [now, now].as_ptr(), 0) };
    assert_eq!(rc, 0);
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only test hook")]
fn a_kill_during_setup_is_cleaned_up_by_the_next_run_but_a_live_run_is_not() {
    #[cfg(debug_assertions)]
    {
        let mut env = Env::new("setup");
        // A live run, held during setup: its directories exist and are locked.
        let (live, live_hold) = held_during_setup(&mut env, &["true"]);
        let live_dirs = env.leftovers();
        assert_eq!(live_dirs.len(), 2, "{live_dirs:?}");
        // Old enough to be swept, were it not in use.
        for d in &live_dirs {
            backdate(&env.tmp().join(d));
        }
        // Another run starts: it must leave the live run's directories alone.
        assert!(env.nullroute(&[], &["true"]).status().unwrap().success());
        assert_eq!(
            env.leftovers(),
            live_dirs,
            "a run in progress lost its directories"
        );

        // Killed in that window: nothing can clean up.
        unsafe { libc::kill(live, libc::SIGKILL) };
        env.kids[0].wait().unwrap();
        let _ = std::fs::remove_file(&live_hold);
        assert_eq!(
            env.leftovers(),
            live_dirs,
            "the kill left no directories to sweep"
        );
        // Still young: kept (a nullroute from before the locks may own it).
        for d in &live_dirs {
            touch(&env.tmp().join(d));
        }
        assert!(env.nullroute(&[], &["true"]).status().unwrap().success());
        assert_eq!(env.leftovers(), live_dirs);
        // Old and unlocked: swept by the next run.
        for d in &live_dirs {
            backdate(&env.tmp().join(d));
        }
        assert!(env.nullroute(&[], &["true"]).status().unwrap().success());
        assert_eq!(env.leftovers(), Vec::<String>::new());
    }
}

#[test]
fn nothing_outside_our_own_names_is_swept() {
    let env = Env::new("names");
    let others = [
        "important",
        "nullroute-notes",
        "nullroute-1-2-3",
        "nr-lifecycle-1-x",
    ];
    for name in others {
        let p = env.tmp().join(name);
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("keep"), b"x").unwrap();
    }
    assert!(env.nullroute(&[], &["true"]).status().unwrap().success());
    for name in others {
        assert!(
            env.tmp().join(name).join("keep").exists(),
            "{name} was removed"
        );
    }
}
