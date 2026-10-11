//! Signals while the command runs, so the breach report survives Ctrl-C.
//!
//! - SIGINT / SIGQUIT are dropped by nullroute once the command is running. A
//!   terminal sends them to the whole foreground process group, so the command
//!   still gets them and decides what to do; nullroute just waits, prints its
//!   report and exits with the command's status (130 for an interrupted
//!   command). Shells, `time` and `cargo run` behave the same way.
//! - SIGTERM / SIGHUP sent to nullroute (a CI timeout, a closed terminal) are
//!   forwarded to the command, which otherwise wouldn't see them, exactly once:
//!   not when the command got the signal anyway (see "Group or pid" below).
//!   nullroute never escalates on its own: a command that ignores the signal
//!   keeps it waiting, as long as the command runs. `--kill-after SECS` is the
//!   opt-in escalation: SECS seconds after the first SIGTERM / SIGHUP that
//!   reaches nullroute, a command that is still running gets SIGKILL (once; see
//!   [`Forwarder::arm_escalation`]).
//!
//! # How they are received
//!
//! The four signals are blocked in nullroute's main thread before it spawns
//! the command ([`block`]), so every thread started later inherits the block, and
//! a dedicated thread takes them with `sigwaitinfo` ([`Forwarder::start`]). One
//! that arrives while the child is being set up stays pending instead of
//! killing nullroute with its default action (which used to leave the
//! just-started command running on its own) and is handled as soon as that
//! thread runs. The child gets the original mask back right before exec
//! ([`ChildMask::restore`]). Nothing runs in signal-handler context, so the
//! forwarding path can take a lock and talk to the sentinel (below).
//!
//! # Group or pid
//!
//! `kill -TERM -PGID` (and `timeout`, which signals its whole group) reaches
//! nullroute *and* the command, which is in the same process group: forwarding
//! it as well would deliver it twice, and a command whose first SIGTERM means
//! "shut down gracefully" and whose second means "now" would be cut short.
//! `kill -TERM PID` reaches nullroute only and must be forwarded. The kernel
//! doesn't say which one it was: the siginfo of the two is identical. So
//! nullroute asks a bystander: a *sentinel* process (`Sentinel`), a child that
//! stays in the process group, blocks the four signals and does nothing else.
//! A group-directed signal reaches it too and it reports that it saw it; a
//! pid-directed one doesn't. The group's members are signalled newest first,
//! so the sentinel (forked after nullroute) has the signal before nullroute
//! does, and the check after a short settle time is reliable in practice. If the
//! sentinel can't be started or stops answering, the signal is forwarded
//! (possibly twice) rather than lost. A command that left the group (its own
//! `setsid`, a job-control shell) never got the group's signal, so it always gets
//! the forwarded one.
//!
//! `timeout` signals its child first and then the group, in two system calls:
//! the settle time makes the second one land in time for them to count as one
//! signal in practice (not guaranteed: a sender that is descheduled for longer
//! between the two is sending two signals).
//!
//! # The command's pid
//!
//! The forwarder only signals the command while it is certain the pid is
//! still the command: the main thread waits for the command's exit without
//! reaping it ([`wait_for_exit`], `waitid(WNOWAIT)`), then clears the pid under
//! the lock the forwarder holds while it sends, and only then reaps. A signal
//! that arrives while nullroute kills what the command left behind can no
//! longer reach a recycled pid.
//!
//! # Signals during startup
//!
//! SIGINT / SIGQUIT that arrive in that window need care. Sent to the process
//! group (Ctrl-C, `kill -INT -PGID`), they reach nullroute and, if it already
//! exists, the child, which has them pending until its mask is restored. But
//! one that lands before the fork reaches only nullroute: the child isn't in
//! the group yet and never sees it, and with the "drop" rule above the user's
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
//! background job of a non-interactive shell), as before.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// The signals nullroute handles while the command runs.
const HANDLED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// The ones nullroute drops while the command runs, because the terminal's
/// process-group delivery already reaches it; before it exists they have to be
/// handed on (see the module docs).
const GROUP_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGQUIT];

/// How long to wait after a SIGTERM / SIGHUP before deciding what to do with
/// it, so the rest of a group delivery or a second system call by the same
/// sender (`timeout`) is part of the same decision.
const SETTLE: Duration = Duration::from_millis(5);

/// How long the sentinel may take to answer before it is given up on.
const SENTINEL_TIMEOUT_MS: libc::c_int = 1000;

fn handled_set() -> libc::sigset_t {
    // SAFETY: sigset_t is plain data; sigemptyset/sigaddset get valid pointers.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in HANDLED {
            libc::sigaddset(&mut set, sig);
        }
        set
    }
}

/// Lock, ignoring poisoning: the data is a plain pid, always consistent.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a signal that reaches nullroute is forwarded to: the command, while it
/// is still ours to signal. Shared by the signal thread and the main thread.
pub struct Forwarder {
    /// The command's pid from spawn until it has exited (and not yet been
    /// reaped); None after [`Forwarder::mark_gone`]. Held while sending, so
    /// "clear" can't overtake a send that already decided to go ahead.
    target: Mutex<Option<libc::pid_t>>,
    sentinel: Option<Sentinel>,
    /// `kill(2)`; replaceable so tests can watch what would be sent.
    send: fn(libc::pid_t, libc::c_int) -> libc::c_int,
    /// `--kill-after`: how long after a SIGTERM / SIGHUP the command may keep
    /// running before it is sent SIGKILL. None: never.
    kill_after: Option<Duration>,
    /// The escalation timer has been started (it is started once).
    escalating: AtomicBool,
}

fn real_kill(pid: libc::pid_t, sig: libc::c_int) -> libc::c_int {
    // SAFETY: kill has no memory-safety preconditions; callers only pass the
    // pid of a child that hasn't been reaped yet.
    unsafe { libc::kill(pid, sig) }
}

impl Forwarder {
    fn new(
        pid: libc::pid_t,
        sentinel: Option<Sentinel>,
        send: fn(libc::pid_t, libc::c_int) -> libc::c_int,
        kill_after: Option<Duration>,
    ) -> Arc<Forwarder> {
        Arc::new(Forwarder {
            target: Mutex::new(Some(pid)),
            sentinel,
            send,
            kill_after,
            escalating: AtomicBool::new(false),
        })
    }

    /// The command has exited: from now on nothing is sent to its pid. Waits
    /// for a send in progress. Call before reaping the command.
    pub fn mark_gone(&self) {
        *lock(&self.target) = None;
    }

    /// Forward `sig` (SIGTERM or SIGHUP) to the command unless it has gone, or
    /// `group` says it was sent to the process group and the command, as a
    /// member of that group, has already got it.
    fn deliver(&self, sig: libc::c_int, group: bool) {
        let target = lock(&self.target);
        let Some(pid) = *target else { return };
        if group && in_our_group(pid) {
            return;
        }
        (self.send)(pid, sig);
    }

    /// SIGKILL the command, unless it has gone. Same lock as [`Forwarder::deliver`],
    /// so it can't reach a pid that was already reaped.
    fn kill_now(&self) {
        let target = lock(&self.target);
        if let Some(pid) = *target {
            (self.send)(pid, libc::SIGKILL);
        }
    }

    /// A SIGTERM / SIGHUP has reached nullroute: with `--kill-after`, start
    /// the one timer that SIGKILLs the command if it is still running when it
    /// ends. Later signals don't restart or shorten it. If the timer thread
    /// can't be started the command is killed at once rather than left to
    /// ignore the signal for ever.
    fn arm_escalation(self: &Arc<Self>) {
        let Some(after) = self.kill_after else { return };
        if self.escalating.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        let started = std::thread::Builder::new()
            .name("kill-after".into())
            .spawn(move || {
                std::thread::sleep(after);
                me.kill_now();
            });
        if started.is_err() {
            self.kill_now();
        }
    }

    /// Take the handled signals on a thread of their own, for the life of the
    /// process. The signals must be blocked in the calling thread (`Blocked`).
    fn start(self: &Arc<Self>) -> io::Result<()> {
        let me = self.clone();
        std::thread::Builder::new()
            .name("signals".into())
            .spawn(move || me.run())
            .map(drop)
    }

    fn run(self: &Arc<Self>) {
        let set = handled_set();
        loop {
            // SAFETY: valid set; the siginfo is written by the kernel.
            let sig = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::sigwaitinfo(&set, &mut info)
            };
            if sig < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return; // can't happen with a valid set; don't spin
            }
            if !GROUP_SIGNALS.contains(&sig) {
                self.handle(sig);
            }
        }
    }

    /// A SIGTERM / SIGHUP arrived. Let whatever else belongs to the same send
    /// arrive (the rest of a group delivery, the second system call of
    /// `timeout`), take what is pending as one batch (standard signals
    /// coalesce, so each is forwarded at most once), ask the sentinel which of
    /// them were group-directed, and forward the rest.
    fn handle(self: &Arc<Self>, first: libc::c_int) {
        std::thread::sleep(SETTLE);
        let set = handled_set();
        let none = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut got = sig_bit(first);
        loop {
            // SAFETY: valid set and timeout; the siginfo is written by the kernel.
            let sig = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::sigtimedwait(&set, &mut info, &none)
            };
            if sig > 0 {
                got |= sig_bit(sig);
            } else if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        // The command is being asked to stop (by the forward, or by the group's
        // own copy): from here on it has `--kill-after` to do so.
        self.arm_escalation();
        let group = self
            .sentinel
            .as_ref()
            .and_then(Sentinel::drain)
            .unwrap_or(0);
        for sig in [libc::SIGTERM, libc::SIGHUP] {
            if got & sig_bit(sig) != 0 {
                self.deliver(sig, group & sig_bit(sig) != 0);
            }
        }
    }
}

/// Is the command in the process group nullroute is in, i.e. one that a
/// signal sent to that group reaches?
fn in_our_group(pid: libc::pid_t) -> bool {
    // SAFETY: getpgid/getpgrp have no preconditions.
    unsafe { libc::getpgid(pid) == libc::getpgrp() }
}

/// Wait for the command to exit without reaping it, then tell the forwarder
/// before reaping, so the pid can't be recycled while it might still be
/// signalled. Use instead of `Child::wait`.
pub fn wait_for_exit(child: &mut Child, fwd: &Forwarder) -> io::Result<std::process::ExitStatus> {
    let pid = child.id() as libc::pid_t;
    loop {
        // SAFETY: waitid with WNOWAIT leaves the child waitable; the siginfo is
        // a plain out-parameter.
        let rc = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            // E.g. ECHILD: somebody else reaped it. Nothing left to signal.
            break;
        }
    }
    fwd.mark_gone();
    child.wait()
}

/// A helper process in nullroute's process group that tells whether a signal
/// was sent to the group (see the module docs). It blocks the handled signals
/// and, when asked, reports which of them are pending and discards them.
struct Sentinel {
    pid: libc::pid_t,
    req: OwnedFd,
    resp: OwnedFd,
    /// Set after a timeout: the reply to a late request could be mistaken for
    /// the next one's, so the sentinel is not asked again.
    broken: std::sync::atomic::AtomicBool,
}

impl Sentinel {
    /// Fork the sentinel. Call on the thread that forks the command, while the
    /// handled signals are blocked, before nullroute has any other thread.
    /// None if it can't be started; callers then forward every signal.
    fn spawn(parent: libc::pid_t) -> Option<Sentinel> {
        let (req_r, req_w) = pipe()?;
        let (resp_r, resp_w) = pipe()?;
        let set = handled_set();
        // SAFETY: nullroute is single-threaded here, and the child below only
        // makes raw syscalls on memory prepared before the fork.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return None;
        }
        if pid == 0 {
            // SAFETY: we are the forked child.
            unsafe { sentinel_main(req_r.as_raw_fd(), resp_w.as_raw_fd(), parent, &set) }
        }
        Some(Sentinel {
            pid,
            req: req_w,
            resp: resp_r,
            broken: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Which handled signals the sentinel had pending (and has now discarded),
    /// as a bit mask; None if it didn't answer.
    fn drain(&self) -> Option<u64> {
        use std::sync::atomic::Ordering;
        if self.broken.load(Ordering::Relaxed) {
            return None;
        }
        let answer = (|| {
            write_all(self.req.as_raw_fd(), &[1u8])?;
            let mut pfd = libc::pollfd {
                fd: self.resp.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                // SAFETY: one valid pollfd.
                let n = unsafe { libc::poll(&mut pfd, 1, SENTINEL_TIMEOUT_MS) };
                if n > 0 {
                    break;
                }
                if n == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
            }
            let mut buf = [0u8; 8];
            read_exact(self.resp.as_raw_fd(), &mut buf)?;
            Ok(u64::from_ne_bytes(buf))
        })();
        if answer.is_err() {
            self.broken.store(true, Ordering::Relaxed);
        }
        answer.ok()
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        // SAFETY: our own child; it is killed and reaped here.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

fn pipe() -> Option<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: a valid 2-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    // SAFETY: pipe2 succeeded, so both are open and ours.
    Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn write_all(fd: libc::c_int, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: valid buffer and length.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn read_exact(fd: libc::c_int, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
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
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n as usize..];
    }
    Ok(())
}

/// The sentinel's whole life, in the forked child: raw syscalls and stack
/// memory only. Dies with nullroute (parent-death signal, EOF on `req`).
///
/// # Safety
/// Only call in the child of a fork made while the handled signals were blocked.
unsafe fn sentinel_main(
    req: libc::c_int,
    resp: libc::c_int,
    parent: libc::pid_t,
    set: &libc::sigset_t,
) -> ! {
    // SAFETY: plain syscalls with valid arguments.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
        if libc::getppid() != parent {
            libc::_exit(0);
        }
        libc::sigprocmask(libc::SIG_BLOCK, set, std::ptr::null_mut());
        // Own nothing but the two pipe ends: no stdio (a reader waiting for
        // nullroute's output to end must not wait for this process), and none
        // of nullroute's other descriptors.
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..3 {
                libc::dup2(null, fd);
            }
        }
        let (lo, hi) = (req.min(resp), req.max(resp));
        for (from, to) in [(3, lo - 1), (lo + 1, hi - 1), (hi + 1, libc::c_int::MAX)] {
            if from <= to {
                libc::syscall(
                    libc::SYS_close_range,
                    from as libc::c_uint,
                    to as libc::c_uint,
                    0 as libc::c_uint,
                );
            }
        }
        let none = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut byte = 0u8;
        loop {
            let n = libc::read(req, (&raw mut byte).cast(), 1);
            if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if n <= 0 {
                libc::_exit(0);
            }
            let mut seen = 0u64;
            loop {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                let sig = libc::sigtimedwait(set, &mut info, &none);
                if sig > 0 {
                    seen |= sig_bit(sig);
                } else if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
            let bytes = seen.to_ne_bytes();
            let mut sent = 0;
            while sent < bytes.len() {
                let w = libc::write(resp, bytes.as_ptr().add(sent).cast(), bytes.len() - sent);
                if w < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if w <= 0 {
                    libc::_exit(0);
                }
                sent += w as usize;
            }
        }
    }
}

/// The handled signals, blocked on the spawning thread. They stay blocked for
/// the life of the process once forwarding has started ([`Blocked::start`]);
/// dropping it earlier (an error path) restores the previous mask.
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
    let set = handled_set();
    // SAFETY: sigset_t is plain data; the libc calls get valid pointers.
    unsafe {
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
    pub fn child_mask(&self) -> io::Result<ChildMask> {
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        Ok(ChildMask {
            mask: self.old,
            parent_status: CString::new(format!("/proc/{pid}/status"))
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        })
    }

    /// Fork the sentinel (see the module docs); None if that failed. Call
    /// before spawning the command, with the signals blocked.
    pub fn spawn_sentinel(&self, parent: libc::pid_t) -> Option<SentinelHandle> {
        Sentinel::spawn(parent).map(SentinelHandle)
    }

    /// Call right after the command has been spawned: start the thread that
    /// takes the signals (SIGTERM / SIGHUP forwarded; SIGINT / SIGQUIT
    /// dropped, as always: the child already has the ones that matter, see
    /// [`ChildMask::restore`]), including whatever arrived in between. The
    /// signals stay blocked in this and every later thread.
    pub fn start(
        self,
        child_pid: u32,
        sentinel: Option<SentinelHandle>,
        kill_after: Option<Duration>,
    ) -> io::Result<Arc<Forwarder>> {
        let fwd = Forwarder::new(
            child_pid as libc::pid_t,
            sentinel.map(|s| s.0),
            real_kill,
            kill_after,
        );
        fwd.start()?;
        // The signal thread owns the signals now; don't unblock them.
        std::mem::forget(self);
        Ok(fwd)
    }
}

/// An opaque started sentinel, to be handed to [`Blocked::start`].
pub struct SentinelHandle(Sentinel);

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

    /// How many signals each (fake) pid was sent. A count per pid, not a log:
    /// the stress test below sends as fast as it can.
    static SENT: Mutex<std::collections::BTreeMap<libc::pid_t, usize>> =
        Mutex::new(std::collections::BTreeMap::new());

    fn record(pid: libc::pid_t, _sig: libc::c_int) -> libc::c_int {
        *lock(&SENT).entry(pid).or_default() += 1;
        0
    }

    fn sent_to(pid: libc::pid_t) -> usize {
        lock(&SENT).get(&pid).copied().unwrap_or(0)
    }

    #[test]
    fn forwards_to_the_command_until_it_is_marked_gone() {
        let fwd = Forwarder::new(1_000_001, None, record, None);
        fwd.deliver(libc::SIGTERM, false);
        assert_eq!(sent_to(1_000_001), 1);
        fwd.mark_gone();
        fwd.deliver(libc::SIGTERM, false);
        fwd.deliver(libc::SIGHUP, false);
        assert_eq!(
            sent_to(1_000_001),
            1,
            "a signal went to a pid that was already reaped"
        );
    }

    /// The property that keeps a signal away from a recycled pid: once
    /// mark_gone() has returned, no send is in progress and none starts.
    #[test]
    fn mark_gone_is_a_barrier_for_sends_on_other_threads() {
        use std::sync::atomic::{AtomicBool, Ordering};
        for round in 0..50 {
            let pid = 1_100_000 + round;
            let fwd = Forwarder::new(pid, None, record, None);
            let stop = AtomicBool::new(false);
            std::thread::scope(|s| {
                for _ in 0..4 {
                    s.spawn(|| {
                        while !stop.load(Ordering::Relaxed) {
                            fwd.deliver(libc::SIGTERM, false);
                        }
                    });
                }
                while sent_to(pid) < 20 {
                    std::thread::yield_now();
                }
                fwd.mark_gone();
                let at_return = sent_to(pid);
                std::thread::sleep(Duration::from_millis(2));
                stop.store(true, Ordering::Relaxed);
                assert_eq!(
                    sent_to(pid),
                    at_return,
                    "round {round}: sent after mark_gone returned"
                );
            });
        }
    }

    /// Every (pid, signal) sent through [`record_sig`].
    static SIGS: Mutex<Vec<(libc::pid_t, libc::c_int)>> = Mutex::new(Vec::new());

    fn record_sig(pid: libc::pid_t, sig: libc::c_int) -> libc::c_int {
        lock(&SIGS).push((pid, sig));
        0
    }

    fn sigs_to(pid: libc::pid_t) -> Vec<libc::c_int> {
        lock(&SIGS)
            .iter()
            .filter(|(p, _)| *p == pid)
            .map(|(_, s)| *s)
            .collect()
    }

    #[test]
    fn escalation_kills_a_command_that_is_still_running_after_the_delay() {
        let pid = 1_200_001;
        let fwd = Forwarder::new(pid, None, record_sig, Some(Duration::from_millis(50)));
        fwd.arm_escalation();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while sigs_to(pid).is_empty() {
            assert!(std::time::Instant::now() < deadline, "no SIGKILL");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(sigs_to(pid), [libc::SIGKILL]);
    }

    #[test]
    fn escalation_is_armed_once() {
        let pid = 1_200_002;
        let fwd = Forwarder::new(pid, None, record_sig, Some(Duration::from_millis(30)));
        for _ in 0..5 {
            fwd.arm_escalation();
        }
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(
            sigs_to(pid),
            [libc::SIGKILL],
            "one SIGKILL, not one per signal"
        );
    }

    #[test]
    fn escalation_leaves_a_command_that_has_already_gone_alone() {
        let pid = 1_200_003;
        let fwd = Forwarder::new(pid, None, record_sig, Some(Duration::from_millis(100)));
        fwd.arm_escalation();
        fwd.mark_gone();
        std::thread::sleep(Duration::from_millis(400));
        assert!(
            sigs_to(pid).is_empty(),
            "SIGKILL went to a pid that was already reaped"
        );
    }

    #[test]
    fn without_a_delay_nothing_is_ever_escalated() {
        let pid = 1_200_004;
        let fwd = Forwarder::new(pid, None, record_sig, None);
        fwd.arm_escalation();
        std::thread::sleep(Duration::from_millis(200));
        assert!(sigs_to(pid).is_empty());
    }

    #[test]
    fn wait_for_exit_clears_the_pid_before_reaping() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        let fwd = Forwarder::new(pid, None, record, None);
        let status = wait_for_exit(&mut child, &fwd).unwrap();
        assert!(status.success());
        fwd.deliver(libc::SIGTERM, false);
        assert_eq!(sent_to(pid), 0);
    }
}
