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
//! - SIGKILL rather than SIGTERM: this only fires when nullroute is already
//!   gone, and a command that ignores or mishandles SIGTERM would otherwise
//!   live on.

use std::io;

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

/// True on the process's main thread, the only one that may spawn the command
/// (see the module docs).
pub fn on_main_thread() -> bool {
    // SAFETY: gettid/getpid have no preconditions.
    unsafe { libc::syscall(libc::SYS_gettid) == libc::getpid() as libc::c_long }
}
