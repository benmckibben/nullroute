// Shared test helpers used by integration tests.

/// Mark every fd above 2 close-on-exec in the child between fork and exec.
///
/// Call from a `pre_exec` closure. When the runner leaks sockets or other
/// fds, they appear as inherited from the caller warnings, and tests that
/// assert empty stderr will break. The descriptors stay open until `exec`,
/// then disappear because of the flag.
///
/// The flag is `CLOSE_RANGE_CLOEXEC`. Rust's standard library keeps a pipe
/// so the child can report `execvp` failures, and that pipe has to stay
/// open until exec. Closing the range here makes the child's error write
/// fail, and the child aborts in `rtassert!`.
///
/// On error (typically `ENOSYS` or `EINVAL`) the closure returns the OS
/// error so the parent `output()` call fails rather than silently keeping
/// the inherited fds.
///
/// # Safety
///
/// `pre_exec` runs in the child between fork and exec. This closure
/// touches only the fd table and does not allocate (no heap allocation
/// or locks), so it is async-signal-safe.
#[allow(dead_code)] // standalone test binary compiles this; used via `mod common`
pub(crate) unsafe fn close_inherited_fds() -> Result<(), std::io::Error> {
    unsafe {
        if libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
