//! Resource caps for the worker threads nullroute starts on behalf of the
//! command: one thread per connection to the --port bridges, the --allow
//! proxy, the DNS sinkhole's TCP side and the socket decoys used to be spawned
//! without limit (300 idle DNS-over-TCP connections meant 310 threads), a
//! thread that couldn't be started panicked the acceptor, and an accept error
//! such as EMFILE made the acceptor spin.
//!
//! - [`Limiter`]: at most N connections being served at once per service;
//!   one more is closed straight away (the client sees a reset or EOF and can
//!   retry), instead of growing without bound.
//! - [`spawn_conn`]: starting a connection thread can fail (EAGAIN); that drops
//!   the connection and is reported once, instead of panicking.
//! - [`accept_loop`]: an accept error backs off briefly instead of spinning,
//!   and a listener that is gone for good ends the loop.
//!
//! Tests lower the numbers with `NULLROUTE_TEST_MAX_CONNECTIONS` (debug builds
//! only, like the other test hooks).

use crate::diag::diagln;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Default number of connections served at once, per service.
pub const MAX_CONNECTIONS: usize = 256;
/// The DNS sinkhole's TCP side: queries are tiny and clients retry over UDP.
pub const MAX_DNS_TCP_CONNECTIONS: usize = 64;
/// The socket decoys: a sandboxed command has no business opening many.
pub const MAX_DECOY_CONNECTIONS: usize = 32;

/// How long an accept loop waits after an error before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(20);

/// `default`, or the debug-build test override.
pub fn max_connections(default: usize) -> usize {
    #[cfg(debug_assertions)]
    if let Some(n) = std::env::var("NULLROUTE_TEST_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return n;
    }
    default
}

/// Counts the connections of one service that are being served right now.
#[derive(Clone)]
pub struct Limiter {
    active: Arc<AtomicUsize>,
    max: usize,
}

/// Held while a connection is served; frees its slot on drop.
pub struct Permit {
    active: Arc<AtomicUsize>,
}

impl Limiter {
    pub fn new(max: usize) -> Limiter {
        Limiter {
            active: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// A slot, or None if `max` connections are being served already.
    pub fn try_acquire(&self) -> Option<Permit> {
        let mut n = self.active.load(Ordering::Relaxed);
        loop {
            if n >= self.max {
                return None;
            }
            match self
                .active
                .compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Some(Permit {
                        active: self.active.clone(),
                    });
                }
                Err(now) => n = now,
            }
        }
    }

    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Run `f` on a new thread holding `permit`. If the thread can't be started
/// (EAGAIN: out of threads or memory) `f` is dropped, which closes whatever
/// connection it owns, and the problem is reported once. Returns whether it
/// started.
pub fn spawn_conn(permit: Permit, f: impl FnOnce() + Send + 'static) -> bool {
    static WARNED: AtomicBool = AtomicBool::new(false);
    match std::thread::Builder::new().spawn(move || {
        let _permit = permit;
        f();
    }) {
        Ok(_) => true,
        Err(e) => {
            if !WARNED.swap(true, Ordering::Relaxed) {
                diagln!(
                    "nullroute: can't start a thread for a connection ({e}); dropping connections until it can"
                );
            }
            false
        }
    }
}

/// Run §f§ on a helper thread and wait at most §timeout§ for it, for calls
/// that can block without a timeout of their own (getaddrinfo). On timeout the
/// helper is left to finish by itself, still counted in §lookups§ so that
/// stuck calls can't pile up without bound: when that many are in flight the
/// next one fails at once.
pub fn run_bounded<T: Send + 'static>(
    lookups: &Limiter,
    timeout: Duration,
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let permit = lookups.try_acquire().ok_or_else(|| {
        io::Error::other("too many name lookups in progress (the resolver isn't answering?)")
    })?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new().spawn(move || {
        let result = f();
        // Release the slot before the result becomes visible: the caller may
        // start the next lookup the moment it has this one's answer.
        drop(permit);
        let _ = tx.send(result);
    })?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "name lookup timed out (is the resolver reachable?)",
        )),
    }
}

/// Start a long-lived service thread (an acceptor, the UDP resolver). If it
/// can't be started the service is simply missing: reported, not a panic.
pub fn spawn_service(f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().spawn(f) {
        diagln!(
            "nullroute: can't start a service thread ({e}); some of the sandbox's relays won't work"
        );
    }
}

/// nullroute holds two descriptors per relayed connection (and more while it
/// sets up a run); the common soft limit of 1024 is reached at a few hundred
/// connections. Raise the soft limit of RLIMIT_NOFILE to the hard limit (at most
/// 1 Mi: some libc functions size tables by it) and return the original soft
/// limit if it was changed, so the command can be given back the limit the
/// user chose: it shouldn't see a bigger limit than it was started with
/// (select() programs, anything that sizes arrays by it, and what "ulimit -n"
/// prints). The hard limit is never touched.
pub fn raise_nofile_limit() -> Option<libc::rlimit> {
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid out-pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur) } != 0 {
        return None;
    }
    let target = cur.rlim_max.min(1 << 20);
    if target <= cur.rlim_cur {
        return None;
    }
    let raised = libc::rlimit {
        rlim_cur: target,
        rlim_max: cur.rlim_max,
    };
    // SAFETY: a valid in-pointer.
    (unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0).then_some(cur)
}

/// The soft descriptor limit nullroute will have once it has raised it
/// ([`raise_nofile_limit`]); what --dry-run checks the listener budget against.
pub fn effective_nofile_limit() -> u64 {
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid out-pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur) } != 0 {
        return 1024;
    }
    cur.rlim_cur.max(cur.rlim_max.min(1 << 20))
}

/// Accept connections until the listener is unusable, handing each to `serve`.
/// `accept` is the listener's accept call. Errors that say "try again later"
/// (out of descriptors, an aborted connection) are retried after a short
/// pause; errors that mean the listener itself is broken end the loop.
pub fn accept_loop<C>(mut accept: impl FnMut() -> io::Result<C>, mut serve: impl FnMut(C)) {
    loop {
        match accept() {
            Ok(c) => serve(c),
            Err(e) => {
                if listener_is_gone(&e) {
                    return;
                }
                if is_out_of_fds(&e) {
                    static WARNED: AtomicBool = AtomicBool::new(false);
                    if !WARNED.swap(true, Ordering::Relaxed) {
                        diagln!(
                            "nullroute: out of file descriptors while accepting connections ({e}); raise the limit (ulimit -n) or open fewer connections"
                        );
                    }
                }
                std::thread::sleep(ACCEPT_BACKOFF);
            }
        }
    }
}

fn listener_is_gone(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK | libc::EFAULT | libc::EOPNOTSUPP)
    )
}

/// Is `e` "out of file descriptors"?
pub fn is_out_of_fds(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_hands_out_max_slots_and_takes_them_back() {
        let l = Limiter::new(3);
        let a = l.try_acquire().unwrap();
        let _b = l.try_acquire().unwrap();
        let _c = l.try_acquire().unwrap();
        assert!(l.try_acquire().is_none());
        assert_eq!(l.active(), 3);
        drop(a);
        assert_eq!(l.active(), 2);
        assert!(l.try_acquire().is_some());
    }

    #[test]
    fn limiter_never_exceeds_max_under_contention() {
        let l = Limiter::new(5);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..2000 {
                        if let Some(p) = l.try_acquire() {
                            peak.fetch_max(l.active(), Ordering::Relaxed);
                            drop(p);
                        }
                    }
                });
            }
        });
        assert!(peak.load(Ordering::Relaxed) <= 5);
        assert_eq!(l.active(), 0);
    }

    #[test]
    fn a_permit_goes_back_when_the_thread_ends() {
        let l = Limiter::new(1);
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(spawn_conn(l.try_acquire().unwrap(), move || {
            let _ = tx.send(());
        }));
        rx.recv().unwrap();
        // The permit is released as the thread winds down.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while l.active() != 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
    }

    #[test]
    fn accept_loop_backs_off_on_errors_and_stops_on_a_dead_listener() {
        let mut calls = 0;
        let mut served = Vec::new();
        let start = std::time::Instant::now();
        accept_loop(
            || {
                calls += 1;
                match calls {
                    1 => Err(io::Error::from_raw_os_error(libc::EMFILE)),
                    2 => Ok(7),
                    3 => Err(io::Error::from_raw_os_error(libc::ECONNABORTED)),
                    _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
                }
            },
            |c| served.push(c),
        );
        assert_eq!(served, vec![7]);
        assert_eq!(calls, 4);
        // Two retried errors paused instead of spinning.
        assert!(start.elapsed() >= ACCEPT_BACKOFF * 2);
    }

    #[test]
    fn a_finished_lookup_has_released_its_slot_when_run_bounded_returns() {
        // One slot: if the helper thread released it only after sending the
        // result, the next call could find it still taken and fail at once with
        // "too many name lookups".
        let l = Limiter::new(1);
        for i in 0..2000u32 {
            let got = run_bounded(&l, Duration::from_secs(5), move || Ok(i));
            assert_eq!(got.unwrap(), i, "call {i}");
            assert_eq!(l.active(), 0, "call {i}");
        }
    }

    #[test]
    fn run_bounded_returns_the_result_or_times_out_without_waiting_for_it() {
        let l = Limiter::new(2);
        assert_eq!(
            run_bounded(&l, Duration::from_secs(5), || Ok(42)).unwrap(),
            42
        );
        let err = run_bounded(&l, Duration::from_secs(5), || -> io::Result<u8> {
            Err(io::Error::from(io::ErrorKind::NotFound))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // A call that blocks for much longer than the timeout.
        let (release, hold) = std::sync::mpsc::channel::<()>();
        let start = std::time::Instant::now();
        let err = run_bounded(&l, Duration::from_millis(100), move || {
            let _ = hold.recv();
            Ok(1)
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        // Still counted while it is stuck, so stuck lookups can't pile up.
        assert_eq!(l.active(), 1);
        let (release2, hold2) = std::sync::mpsc::channel::<()>();
        let _ = run_bounded(&l, Duration::from_millis(50), move || {
            let _ = hold2.recv();
            Ok(1)
        });
        let err = run_bounded(&l, Duration::from_millis(50), || Ok(1)).unwrap_err();
        assert!(err.to_string().contains("too many name lookups"), "{err}");
        drop((release, release2));
    }

    #[test]
    fn raising_the_descriptor_limit_never_touches_the_hard_limit() {
        let get = || {
            let mut r = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: a valid out-pointer.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) }, 0);
            r
        };
        let before = get();
        let original = raise_nofile_limit();
        let after = get();
        assert_eq!(after.rlim_max, before.rlim_max);
        assert!(after.rlim_cur >= before.rlim_cur);
        if let Some(o) = original {
            assert_eq!(o.rlim_cur, before.rlim_cur);
            assert!(after.rlim_cur > before.rlim_cur);
        }
        // Put it back for the other tests in this process.
        // SAFETY: a valid in-pointer.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &before) }, 0);
    }

    #[test]
    fn out_of_fds_is_recognised() {
        assert!(is_out_of_fds(&io::Error::from_raw_os_error(libc::EMFILE)));
        assert!(is_out_of_fds(&io::Error::from_raw_os_error(libc::ENFILE)));
        assert!(!is_out_of_fds(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
    }
}
