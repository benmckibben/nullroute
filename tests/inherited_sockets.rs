//! nullroute warns when it starts with sockets the caller left open, because
//! they keep working inside the sandbox. It warns; it doesn't close them.

use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

fn nullroute(prepare: impl FnMut() -> std::io::Result<()> + Send + Sync + 'static) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    // The harness may hold descriptors of its own; start from none above fd 2
    // and let `prepare` add what the test wants.
    let mut prepare = prepare;
    unsafe {
        c.pre_exec(move || {
            libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
            prepare()
        });
    }
    c.args(["run", "--", "sh", "-c", "echo ran"]);
    c.output().unwrap()
}

fn warnings(o: &Output) -> Vec<String> {
    String::from_utf8_lossy(&o.stderr)
        .lines()
        .filter(|l| l.contains("inherited from the caller") || l.contains("more inherited"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn an_inherited_socket_is_reported_and_still_not_closed() {
    // Make fd 9 a connected socket without close-on-exec, in the child only.
    let o = nullroute(|| unsafe {
        let mut fds = [0; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::dup2(fds[0], 9) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    });
    let w = warnings(&o);
    assert!(
        w.iter()
            .any(|l| l.contains("fd 9 is a socket inherited from the caller (unix stream)")),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    // A warning, not a refusal: the command ran and its status is passed on.
    assert!(o.status.success(), "{o:?}");
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "ran");
}

#[test]
fn an_inherited_tcp_socket_is_named_by_family() {
    let o = nullroute(|| unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if s < 0 || libc::dup2(s, 8) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    });
    assert!(
        warnings(&o)
            .iter()
            .any(|l| l.contains("fd 8 is a socket inherited from the caller (IPv4 stream)")),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn a_close_on_exec_socket_is_not_reported() {
    let o = nullroute(|| unsafe {
        let mut fds = [0; 2];
        if libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    });
    assert!(
        warnings(&o).is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success());
}

#[test]
fn no_warning_when_nothing_is_inherited() {
    let o = nullroute(|| Ok(()));
    assert!(
        warnings(&o).is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn dry_run_does_not_warn_because_nothing_is_run() {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    unsafe {
        c.pre_exec(|| {
            libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
            let mut fds = [0; 2];
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr());
            libc::dup2(fds[0], 9);
            Ok(())
        });
    }
    let o = c.args(["run", "--dry-run", "--", "true"]).output().unwrap();
    assert!(
        warnings(&o).is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}
