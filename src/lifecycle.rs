//! Tie the command's lifetime to nullroute's.
//!
//! If nullroute dies without getting to clean up (SIGKILL, the OOM killer, a
//! crash), the command must not keep running on its own: it would sit in a
//! sandbox whose port relays, proxy and DNS sinkhole are gone, and a CI job
//! that killed nullroute would leak it. The child asks the kernel for SIGKILL
//! when its parent dies (`PR_SET_PDEATHSIG`) before exec.
//!
//! Details that matter:
//! - The parent-death signal fires when the *thread* that forked the child
//!   exits, not the process. nullroute forks from its main thread (std's
//!   `Command::spawn` forks on the calling thread, and `run_hermetic` runs on
//!   main), which lives until the process exits.
//! - The kernel clears the setting when credentials change in a way that isn't
//!   a subset of the old ones (and on exec of a set-user-ID, set-group-ID or
//!   file-capability binary). Creating the user namespace and writing the
//!   uid/gid maps keeps it on current kernels, but it is re-armed as the last
//!   setup step anyway so the exec'd command always starts with it.
//! - It isn't inherited across fork: it covers the command itself. When the
//!   command is SIGKILLed its own children are orphaned, not killed (see the
//!   README's "Signals and process lifetime").
//!
//! For the case where nullroute does get to finish (the command exited, or a
//! forwarded SIGTERM ended it), nullroute is the command's child subreaper:
//! whatever the command leaves running is reparented to nullroute instead of
//! init, and [`kill_leftovers`] SIGKILLs it before nullroute exits.
//! - SIGKILL rather than SIGTERM: this only fires when nullroute is already
//!   gone, and a command that ignores or mishandles SIGTERM would otherwise
//!   live on.

use std::io;
use std::time::{Duration, Instant};

/// How long [`kill_leftovers`] keeps trying before it gives up on processes
/// that can't die yet (uninterruptible sleep).
const LEFTOVER_DEADLINE: Duration = Duration::from_secs(5);

/// In the forked child (pre_exec; raw syscalls only): get SIGKILL when the
/// parent dies, and die now if `parent` already has (the child was reparented
/// before the prctl ran). Safe to call more than once.
pub fn die_with_parent(parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: plain syscalls with integer arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::getppid() != parent {
            // nullroute is gone; do what the parent-death signal would have.
            libc::kill(libc::getpid(), libc::SIGKILL);
            libc::_exit(128 + libc::SIGKILL);
        }
    }
    Ok(())
}

/// How many threads this process has, from /proc/self/task; None if that
/// can't be read. nullroute starts its worker threads only after the command
/// has been forked, so before that it must be 1: the child of a fork in a
/// multi-threaded process may only call async-signal-safe functions.
pub fn thread_count() -> Option<usize> {
    Some(std::fs::read_dir("/proc/self/task").ok()?.count())
}

/// Make nullroute the reaper of whatever the command orphans, so
/// [`kill_leftovers`] can find it. Call before spawning. Best effort.
pub fn become_subreaper() {
    // SAFETY: plain syscall with integer arguments.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong) };
}

/// After the command has exited (and been waited for): SIGKILL every process
/// it left behind, which [`become_subreaper`] made nullroute's children, and
/// reap them. Loops because killing one orphans its own children onto
/// nullroute. Returns how many were killed.
pub fn kill_leftovers() -> usize {
    let deadline = Instant::now() + LEFTOVER_DEADLINE;
    let mut killed = std::collections::HashSet::new();
    loop {
        reap_exited();
        let pids = children();
        if pids.is_empty() || Instant::now() >= deadline {
            break;
        }
        for pid in pids {
            // SAFETY: pid is a child of ours; it can't be recycled to an
            // unrelated process until we reap it.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                killed.insert(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    killed.len()
}

/// waitpid(-1, WNOHANG) until nothing more has exited. The command itself was
/// already waited for; nullroute starts no other child processes.
fn reap_exited() {
    loop {
        // SAFETY: a null status pointer is allowed.
        let r = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if r <= 0 {
            break;
        }
    }
}

/// nullroute's current child processes, from /proc/self/task/*/children (an
/// orphan can be reparented to any of its threads). Empty if /proc doesn't
/// expose it (CONFIG_PROC_CHILDREN).
fn children() -> Vec<libc::pid_t> {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for task in tasks.flatten() {
        if let Ok(s) = std::fs::read_to_string(task.path().join("children")) {
            pids.extend(
                s.split_whitespace()
                    .filter_map(|p| p.parse::<libc::pid_t>().ok()),
            );
        }
    }
    pids
}

/// True on the process's main thread, the only one that may spawn the command
/// (see the module docs).
pub fn on_main_thread() -> bool {
    // SAFETY: gettid/getpid have no preconditions.
    unsafe { libc::syscall(libc::SYS_gettid) == libc::getpid() as libc::c_long }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_count_sees_other_threads() {
        let (stop, hold) = std::sync::mpsc::channel::<()>();
        let before = thread_count().unwrap();
        let t = std::thread::spawn(move || {
            let _ = hold.recv();
        });
        assert!(thread_count().unwrap() > before);
        drop(stop);
        t.join().unwrap();
    }
}
