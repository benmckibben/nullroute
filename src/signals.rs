//! Signals while the command runs, so the breach report survives Ctrl-C.
//!
//! - SIGINT / SIGQUIT are ignored by nullroute. A terminal sends them to the
//!   whole foreground process group, so the command still gets them and decides
//!   what to do; nullroute just waits, prints its report and exits with the
//!   command's status (130 for an interrupted command). Shells, `time` and
//!   `cargo run` behave the same way.
//! - SIGTERM / SIGHUP sent to nullroute (a CI timeout, a closed terminal) are
//!   forwarded to the command, which otherwise wouldn't see them.
//!
//! Around spawn these four signals are blocked ([`block`]): one that arrives
//! while the child is being set up stays pending instead of killing nullroute
//! with its default action (which used to leave the just-started command
//! running on its own), and is handled once the handlers are in place. The
//! child gets the original mask back right before exec
//! ([`ChildMask::restore`]).
//!
//! Dispositions are not changed before fork, so the command inherits the ones
//! nullroute itself inherited (SIGHUP ignored under `nohup`, SIGINT ignored for a
//! background job of a non-interactive shell), as before. Caught handlers would
//! be reset by exec anyway; ignored ones carry over, which is the point.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD: AtomicI32 = AtomicI32::new(0);

/// The signals nullroute handles while the command runs.
const HANDLED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe { libc::kill(pid, sig) };
    }
}

/// The handled signals, blocked on the spawning thread. [`Blocked::install`] (or
/// dropping it, on an error path) restores the previous mask.
pub struct Blocked {
    old: libc::sigset_t,
}

/// The mask to give the child back before exec; see [`Blocked::child_mask`].
#[derive(Clone, Copy)]
pub struct ChildMask(libc::sigset_t);

/// Block the handled signals on the calling thread. Call right before spawning
/// the command, on the thread that spawns it.
///
/// nullroute has no other threads until the command is running (the relay,
/// proxy and DNS threads start after spawn), so this keeps a process-directed
/// signal pending rather than letting another thread take it with the default
/// action.
pub fn block() -> io::Result<Blocked> {
    // SAFETY: sigset_t is plain data; the libc calls get valid pointers.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in HANDLED {
            libc::sigaddset(&mut set, sig);
        }
        let mut old: libc::sigset_t = std::mem::zeroed();
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(Blocked { old })
    }
}

impl Blocked {
    /// The mask nullroute had before [`block`], for the child to restore with
    /// [`ChildMask::restore`]. Copied before fork so the child doesn't allocate.
    pub fn child_mask(&self) -> ChildMask {
        ChildMask(self.old)
    }

    /// Call right after the command has been spawned: install the handlers,
    /// then unblock, so whatever arrived in between is handled (SIGTERM /
    /// SIGHUP forwarded, SIGINT / SIGQUIT dropped, as always).
    pub fn install(self, child_pid: u32) {
        CHILD.store(child_pid as i32, Ordering::Relaxed);
        // SAFETY: installing handlers; `forward` only does async-signal-safe work.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGQUIT, libc::SIG_IGN);
            let handler = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::signal(libc::SIGTERM, handler);
            libc::signal(libc::SIGHUP, handler);
        }
        // Dropping self unblocks.
    }
}

impl ChildMask {
    /// In the forked child, as the last step before exec: put back the mask
    /// nullroute had before [`block`], so the command starts with the mask it
    /// always had. A signal that reached the child during setup (Ctrl-C to the
    /// process group) is delivered now, with the inherited disposition, so it
    /// isn't lost.
    ///
    /// Raw syscall only, so it's safe in `pre_exec`. Rust's std leaves the
    /// child with the parent's mask, so without this the command would start
    /// with these signals blocked.
    pub fn restore(&self) -> io::Result<()> {
        // SAFETY: valid pointer to a sigset_t captured before fork.
        let rc = unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Blocked {
    fn drop(&mut self) {
        // SAFETY: valid pointer to the saved mask.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) };
    }
}
