//! Private scratch directories that can't be leaked.
//!
//! The decoy sockets (hide.rs) and the generated resolv.conf and mask file
//! (dns.rs) have to exist as files to be bind-mounted into the sandbox, so
//! they need a directory in the temp dir. Three things keep it from piling up
//! there:
//!
//! 1. The directory only lives while the sandbox is being set up: a bind mount
//!    keeps the file it was made from alive, so the directory is removed as
//!    soon as the command has been spawned ([`PrivateDir::remove`]), not when
//!    it exits. A SIGKILL, the OOM killer or a crash while the command runs
//!    therefore leaves nothing behind.
//! 2. Every directory is created holding an exclusive `flock` that the kernel
//!    drops when the process dies, however it dies. The lock is the "in use"
//!    marker: no process-id or start-time guessing, and it works across PID
//!    namespaces.
//! 3. The one window left, a kill between creating the directory and the end
//!    of spawn, is cleaned up by the next run ([`sweep`]): at startup it
//!    removes directories named like ours that belong to the current user, are
//!    over a minute old and that nobody holds the lock of. Directories of
//!    other users, other names, symlinks and anything younger are left alone.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

/// A stale directory must be at least this old to be swept. Only a guard for
/// directories made by a nullroute that predates the lock (the lock tells the
/// rest).
const SWEEP_MIN_AGE: Duration = Duration::from_secs(60);

/// A private (mode 0700) directory in the temp dir, removed on drop.
pub struct PrivateDir {
    path: PathBuf,
    /// The open directory with the exclusive lock; the lock lasts as long as
    /// this file (or the process) does.
    _lock: File,
}

impl PrivateDir {
    /// Create `PREFIX-PID-NONCE` in the temp dir; `prefix` is "nullroute" or
    /// "nullroute-dns". Sweeps stale directories of earlier runs first.
    pub fn create(prefix: &str) -> io::Result<PrivateDir> {
        static SWEPT: Once = Once::new();
        let base = std::env::temp_dir();
        SWEPT.call_once(|| {
            sweep(&base, SWEEP_MIN_AGE);
        });
        for _ in 0..16 {
            let path = base.join(format!("{prefix}-{}-{}", std::process::id(), nonce()));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
            // A concurrent sweep may have removed the (empty, unlocked) new
            // directory before we locked it; then start over with a new name.
            let Ok(dir) = open_dir(&path) else { continue };
            if !try_lock(&dir) || dir.metadata().map(|m| m.nlink()).unwrap_or(0) == 0 {
                continue;
            }
            return Ok(PrivateDir { path, _lock: dir });
        }
        Err(io::Error::other(
            "could not create a private directory in the temp dir",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the directory and everything in it now. Idempotent; things
    /// already bind-mounted from it stay usable.
    pub fn remove(&self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        self.remove();
    }
}

fn nonce() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos}{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Open `path` as a directory, refusing to follow a symlink.
fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn try_lock(f: &File) -> bool {
    // SAFETY: flock on a descriptor we own.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Is `name` one of ours: `nullroute-PID-N` or `nullroute-dns-PID-N`?
fn is_ours(name: &str) -> bool {
    let rest = name.strip_prefix("nullroute-");
    let rest = rest.map(|r| r.strip_prefix("dns-").unwrap_or(r));
    let Some(rest) = rest else { return false };
    let mut parts = rest.split('-');
    let digits =
        |s: Option<&str>| s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    digits(parts.next()) && digits(parts.next()) && parts.next().is_none()
}

/// Remove the stale scratch directories in `base` (see the module docs);
/// returns how many. Never fails: whatever can't be inspected or removed is
/// skipped.
pub fn sweep(base: &Path, min_age: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(base) else {
        return 0;
    };
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().is_some_and(is_ours) {
            continue;
        }
        let path = entry.path();
        // O_NOFOLLOW|O_DIRECTORY: a symlink or a file with this name is not ours.
        let Ok(dir) = open_dir(&path) else { continue };
        let Ok(meta) = dir.metadata() else { continue };
        let old_enough = meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age >= min_age);
        if meta.uid() != me || meta.mode() & 0o077 != 0 || !old_enough {
            continue;
        }
        // Held by a live run (or by one that is creating it right now)?
        if !try_lock(&dir) {
            continue;
        }
        if std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Base(PathBuf);
    impl Base {
        fn new(tag: &str) -> Base {
            let p =
                std::env::temp_dir().join(format!("nr-tmpdir-unit-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Base(p)
        }
    }
    impl Drop for Base {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_old(path: &Path) {
        let t = libc::timespec {
            tv_sec: 1_000_000_000,
            tv_nsec: 0,
        };
        let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()))
            .unwrap();
        // SAFETY: valid path and two timespecs.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [t, t].as_ptr(), 0) };
        assert_eq!(rc, 0);
    }

    fn stale(base: &Base, name: &str) -> PathBuf {
        let p = base.0.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        std::fs::write(p.join("decoy-0.sock"), b"x").unwrap();
        make_old(&p);
        p
    }

    #[test]
    fn names_are_recognised() {
        for ok in ["nullroute-1-2", "nullroute-dns-12345-678901234"] {
            assert!(is_ours(ok), "{ok}");
        }
        for no in [
            "nullroute",
            "nullroute-",
            "nullroute-dns-",
            "nullroute-1",
            "nullroute-a-2",
            "nullroute-1-2-3",
            "nullroute-dns-1",
            "nullroute-x-dns-1-2",
            "nr-lifecycle-1-term",
            "xnullroute-1-2",
        ] {
            assert!(!is_ours(no), "{no}");
        }
    }

    #[test]
    fn sweeps_old_unlocked_directories_and_nothing_else() {
        let b = Base::new("sweep");
        let gone = stale(&b, "nullroute-111-222");
        let gone_dns = stale(&b, "nullroute-dns-111-222");
        // Too young.
        let young = b.0.join("nullroute-333-444");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&young)
            .unwrap();
        // Not ours by name, and a symlink with our name pointing at a victim.
        let other = stale(&b, "someone-elses-dir");
        let victim = stale(&b, "victim");
        let link = b.0.join("nullroute-555-666");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        // Wider than 0700: not made by us.
        let open_mode = stale(&b, "nullroute-777-888");
        std::fs::set_permissions(
            &open_mode,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        make_old(&open_mode);
        // In use: holds the lock.
        let live = stale(&b, "nullroute-999-1000");
        let held = open_dir(&live).unwrap();
        assert!(try_lock(&held));

        assert_eq!(sweep(&b.0, Duration::from_secs(60)), 2);
        assert!(!gone.exists() && !gone_dns.exists());
        for kept in [&young, &other, &victim, &link, &open_mode, &live] {
            assert!(kept.symlink_metadata().is_ok(), "{kept:?} was removed");
        }
        assert!(victim.join("decoy-0.sock").exists());

        // Once the holder is gone (a crashed run) it is swept too.
        drop(held);
        assert_eq!(sweep(&b.0, Duration::from_secs(60)), 1);
        assert!(!live.exists());
    }

    #[test]
    fn a_created_directory_is_locked_private_and_removed_on_drop() {
        let d = PrivateDir::create("nullroute").unwrap();
        let path = d.path().to_path_buf();
        assert!(is_ours(path.file_name().unwrap().to_str().unwrap()));
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        // Locked: a second opener can't take the lock.
        assert!(!try_lock(&open_dir(&path).unwrap()));
        std::fs::write(path.join("f"), b"x").unwrap();
        d.remove();
        d.remove(); // idempotent
        assert!(!path.exists());
        drop(d);
    }
}
