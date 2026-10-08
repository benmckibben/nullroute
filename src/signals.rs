//! Signals while the command runs, so the breach report survives Ctrl-C.
//!
//! - SIGINT / SIGQUIT are ignored by nullroute once the command is running. A
//!   terminal sends them to the whole foreground process group, so the command
//!   still gets them and decides what to do; nullroute just waits, prints its
//!   report and exits with the command's status (130 for an interrupted
//!   command). Shells, `time` and `cargo run` behave the same way.
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
//! SIGINT / SIGQUIT that arrive in that window need care. Sent to the process
//! group (Ctrl-C, `kill -INT -PGID`), they reach nullroute and, if it already
//! exists, the child, which has them pending until its mask is restored. But
//! one that lands before the fork reaches only nullroute: the child isn't in
//! the group yet and never sees it, and with the "ignore" rule above the user's
//! Ctrl-C would vanish and the command would run anyway. So the child asks the
//! kernel what is pending on nullroute right before it restores its mask
//! ([`ChildMask::open_parent_status`]) and sends itself whatever of SIGINT /
//! SIGQUIT it finds. The child still has them blocked at that point, so a
//! signal that it also received directly stays one pending signal (standard
//! signals coalesce): delivered once, never twice. It is delivered with the
//! disposition the command inherited, so it normally ends the child before the
//! command's first instruction, as Ctrl-C would have just before the launch;
//! if the inherited disposition is "ignore" (a background job of a
//! non-interactive shell), it is ignored as usual. A SIGINT / SIGQUIT sent to
//! nullroute's own pid only is indistinguishable from a group one at that
//! point, so it is treated the same during startup; once the command is
//! running such a signal is ignored, as documented.
//!
//! Dispositions are not changed before fork, so the command inherits the ones
//! nullroute itself inherited (SIGHUP ignored under `nohup`, SIGINT ignored for a
//! background job of a non-interactive shell), as before. Caught handlers would
//! be reset by exec anyway; ignored ones carry over, which is the point.

use std::ffi::CString;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD: AtomicI32 = AtomicI32::new(0);

/// The signals nullroute handles while the command runs.
const HANDLED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// The ones nullroute drops while the command runs, because the terminal's
/// process-group delivery already reaches it; before it exists they have to be
/// handed on (see the module docs).
const GROUP_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGQUIT];

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

/// What the child needs before exec, prepared before fork so the child doesn't
/// allocate; see [`Blocked::child_mask`]: the mask to restore, and the path
/// of the parent's /proc status file, which lists its pending signals.
pub struct ChildMask {
    mask: libc::sigset_t,
    parent_status: CString,
}

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
    /// [`ChildMask::restore`], and the file it reads nullroute's pending
    /// signals from. Built before fork so the child doesn't allocate.
    pub fn child_mask(&self) -> ChildMask {
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        ChildMask {
            mask: self.old,
            parent_status: CString::new(format!("/proc/{pid}/status"))
                .expect("a path made of digits has no NUL"),
        }
    }

    /// Call right after the command has been spawned: install the handlers,
    /// then unblock, so whatever arrived in between is handled (SIGTERM /
    /// SIGHUP forwarded; SIGINT / SIGQUIT dropped, as always: the child already
    /// has the ones that matter, see [`ChildMask::restore`]).
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
    /// In the forked child, early in pre_exec (before the namespace changes):
    /// open nullroute's /proc status file, to be read by [`ChildMask::restore`].
    /// Raw syscalls only, so it's safe in `pre_exec`.
    pub fn open_parent_status(&self) -> io::Result<libc::c_int> {
        // SAFETY: the path is a valid NUL-terminated string.
        let fd = unsafe {
            libc::open(
                self.parent_status.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// In the forked child, as the last step before exec: hand on the SIGINT /
    /// SIGQUIT that reached nullroute before this child existed, then put back
    /// the mask nullroute had before [`block`], so the command starts with the
    /// mask it always had.
    ///
    /// The signals are re-sent while still blocked and so arrive together with
    /// any the child got directly (one pending signal, delivered once), when the
    /// mask is restored, with the disposition the command inherited. A signal
    /// that reached the child during setup (Ctrl-C to the process group) is
    /// delivered at the same point, so it isn't lost either.
    ///
    /// `parent_status` is the fd from [`ChildMask::open_parent_status`]; it is
    /// closed here. Raw syscalls only, so it's safe in `pre_exec`. Rust's std
    /// leaves the child with the parent's mask, so without the restore the
    /// command would start with these signals blocked.
    pub fn restore(&self, parent_status: libc::c_int) -> io::Result<()> {
        let pending = parent_pending(parent_status);
        // SAFETY: closing an fd we opened.
        unsafe { libc::close(parent_status) };
        let pending = pending?;
        for sig in GROUP_SIGNALS {
            if pending & sig_bit(sig) != 0 {
                // SAFETY: kill and getpid are async-signal-safe.
                unsafe { libc::kill(libc::getpid(), sig) };
            }
        }
        // SAFETY: valid pointer to a sigset_t captured before fork.
        let rc = unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.mask, std::ptr::null_mut()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The bit for `sig` in the hex masks of /proc/PID/status.
fn sig_bit(sig: libc::c_int) -> u64 {
    1u64 << (sig - 1)
}

/// The signals pending on nullroute, thread-directed or process-directed,
/// read from its /proc status file. Raw syscalls and a stack buffer only.
fn parent_pending(fd: libc::c_int) -> io::Result<u64> {
    let mut scan = StatusScan::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: valid buffer and length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }
        scan.feed(&buf[..n as usize]);
    }
    // No allocation: from_raw_os_error doesn't box.
    scan.finish()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))
}

/// A streaming scan of /proc/PID/status for its `SigPnd:` (this thread) and
/// `ShdPnd:` (the whole process) lines, which hold hex signal masks. Streaming
/// because the file's length is not bounded (the `Groups:` line can be long)
/// and the child can't allocate.
struct StatusScan {
    col: usize,
    sig: bool,
    shd: bool,
    acc: u64,
    pending: u64,
    lines: u8,
}

impl StatusScan {
    const SIG: &'static [u8] = b"SigPnd:";
    const SHD: &'static [u8] = b"ShdPnd:";

    fn new() -> StatusScan {
        StatusScan {
            col: 0,
            sig: true,
            shd: true,
            acc: 0,
            pending: 0,
            lines: 0,
        }
    }

    fn end_line(&mut self) {
        if self.col >= Self::SIG.len() && (self.sig || self.shd) {
            self.pending |= self.acc;
            self.lines += 1;
        }
        self.col = 0;
        self.sig = true;
        self.shd = true;
        self.acc = 0;
    }

    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.end_line();
            } else if self.col < Self::SIG.len() {
                self.sig &= b == Self::SIG[self.col];
                self.shd &= b == Self::SHD[self.col];
                self.col += 1;
            } else if (self.sig || self.shd)
                && let Some(d) = (b as char).to_digit(16)
            {
                self.acc = self.acc << 4 | u64::from(d);
            }
        }
    }

    /// The pending mask, if both lines were seen.
    fn finish(mut self) -> Option<u64> {
        self.end_line();
        (self.lines >= 2).then_some(self.pending)
    }
}

impl Drop for Blocked {
    fn drop(&mut self) {
        // SAFETY: valid pointer to the saved mask.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &[u8] = b"Name:\tnullroute\nGroups:\t4 24 27 1000\nVmRSS:\t 2048 kB\nSigQ:\t0/63000\nSigPnd:\t0000000000000002\nShdPnd:\t0000000000000004\nSigBlk:\t0000000000010002\n";

    fn scan(chunks: &[&[u8]]) -> Option<u64> {
        let mut s = StatusScan::new();
        for c in chunks {
            s.feed(c);
        }
        s.finish()
    }

    #[test]
    fn reads_thread_and_process_pending() {
        // SIGINT (2) is bit 1, SIGQUIT (3) bit 2.
        assert_eq!(scan(&[STATUS]), Some(0b110));
        assert_eq!(
            scan(&[STATUS]).map(|p| p & sig_bit(libc::SIGINT) != 0),
            Some(true)
        );
    }

    #[test]
    fn ignores_the_blocked_mask_and_other_lines() {
        let s = b"SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\tffffffffffffffff\nSigIgn:\tffffffffffffffff\n";
        assert_eq!(scan(&[s]), Some(0));
    }

    #[test]
    fn survives_any_chunking() {
        for cut in 1..STATUS.len() {
            let (a, b) = STATUS.split_at(cut);
            assert_eq!(scan(&[a, b]), Some(0b110), "cut at {cut}");
        }
    }

    #[test]
    fn needs_both_lines() {
        assert_eq!(scan(&[b"SigPnd:\t0\n"]), None);
        assert_eq!(scan(&[b"Name:\tx\n"]), None);
    }
}
