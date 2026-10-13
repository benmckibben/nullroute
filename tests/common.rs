// Shared test helpers used by integration tests.

/// Close every fd above 2 in the child between fork and exec.
///
/// Call from a `pre_exec` closure. When the runner leaks sockets or other
/// fds, they appear as inherited from the caller warnings, and tests that
/// assert empty stderr will break.
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
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
