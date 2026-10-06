//! Signals while the command runs, so the breach report survives Ctrl-C.
//!
//! - SIGINT / SIGQUIT are ignored by nullroute. A terminal sends them to the
//!   whole foreground process group, so the command still gets them and decides
//!   what to do; nullroute just waits, prints its report and exits with the
//!   command's status (130 for an interrupted command). Shells, `time` and
//!   `cargo run` behave the same way.
//! - SIGTERM / SIGHUP sent to nullroute (a CI timeout, a closed terminal) are
//!   forwarded to the command, which otherwise wouldn't see them.

use std::sync::atomic::{AtomicI32, Ordering};

static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe { libc::kill(pid, sig) };
    }
}

/// Call right after the command has been spawned.
pub fn install(child_pid: u32) {
    CHILD.store(child_pid as i32, Ordering::Relaxed);
    // SAFETY: installing handlers; `forward` only does async-signal-safe work.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
        let handler = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGHUP, handler);
    }
}
