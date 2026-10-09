//! End-to-end tests: run the real nullroute binary and check what the child can do.

use std::process::{Command, Output};

fn nullroute(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .arg("--")
        .args(args)
        .output()
        .expect("failed to launch nullroute")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn outbound_connection_is_unreachable() {
    // Connect to a public IP. No DNS needed, so this tests routing, not resolution.
    let o = nullroute(&[
        "python3",
        "-c",
        "import socket\n\
         try:\n    socket.create_connection(('1.1.1.1', 80), timeout=5); print('OPEN')\n\
         except OSError as e:\n    print(e.errno)",
    ]);
    assert_eq!(stdout(&o), libc::ENETUNREACH.to_string(), "{o:?}");
}

#[test]
fn only_loopback_interface_exists() {
    let o = nullroute(&["cat", "/proc/net/dev"]);
    let ifaces: Vec<String> = stdout(&o)
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next())
        .map(|s| s.trim().to_string())
        .collect();
    assert_eq!(ifaces, vec!["lo"], "{o:?}");
}

#[test]
fn loopback_works_inside() {
    let o = nullroute(&[
        "python3",
        "-c",
        "import socket, threading\n\
         s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)\n\
         threading.Thread(target=lambda: s.accept()[0].sendall(b'pong'), daemon=True).start()\n\
         c = socket.create_connection(s.getsockname()); print(c.recv(4).decode())",
    ]);
    assert_eq!(stdout(&o), "pong", "{o:?}");
}

#[test]
fn runs_as_the_invoking_user_not_root() {
    let me = unsafe { libc::getuid() };
    let o = nullroute(&["id", "-u"]);
    assert_eq!(stdout(&o), me.to_string(), "{o:?}");
}

#[test]
fn child_cannot_create_a_new_network_namespace() {
    // Without capabilities, the child can't unshare again to escape or reconfigure.
    let o = nullroute(&["unshare", "-n", "true"]);
    assert!(!o.status.success(), "{o:?}");
}

#[test]
fn exit_code_is_propagated() {
    assert_eq!(nullroute(&["sh", "-c", "exit 7"]).status.code(), Some(7));
    assert_eq!(nullroute(&["true"]).status.code(), Some(0));
}

#[test]
fn death_by_signal_maps_to_128_plus_signal() {
    let o = nullroute(&["sh", "-c", "kill -TERM $$"]);
    assert_eq!(o.status.code(), Some(128 + libc::SIGTERM), "{o:?}");
}

#[test]
fn missing_command_exits_127_with_a_message() {
    let o = nullroute(&["/definitely/not/a/command"]);
    assert_eq!(o.status.code(), Some(127), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("nullroute: failed to run"), "{err}");
    assert!(err.contains("No such file"), "{err}");
}

#[test]
fn missing_command_on_path_exits_127() {
    let o = nullroute(&["definitely-not-a-command-xyz"]);
    assert_eq!(o.status.code(), Some(127), "{o:?}");
}

#[test]
fn non_executable_command_exits_126_without_the_namespace_hint() {
    // /etc/passwd exists but has no execute bit.
    let o = nullroute(&["/etc/passwd"]);
    assert_eq!(o.status.code(), Some(126), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("Permission denied"), "{err}");
    assert!(!err.contains("user namespace"), "{err}");
}

#[test]
fn directory_as_command_exits_126() {
    let o = nullroute(&["/tmp"]);
    assert_eq!(o.status.code(), Some(126), "{o:?}");
}

#[test]
fn command_exiting_127_or_126_itself_is_passed_through() {
    assert_eq!(
        nullroute(&["sh", "-c", "exit 127"]).status.code(),
        Some(127)
    );
    assert_eq!(
        nullroute(&["sh", "-c", "exit 126"]).status.code(),
        Some(126)
    );
}

fn run_args(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .output()
        .expect("failed to launch nullroute")
}

#[test]
fn unknown_option_after_run_is_a_usage_error() {
    for bad in ["--bogus", "--strcit", "-x"] {
        let o = run_args(&[bad, "--", "true"]);
        assert_eq!(o.status.code(), Some(2), "{bad}: {o:?}");
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("unexpected argument"),
            "{bad}: {o:?}"
        );
    }
}

#[test]
fn typo_suggests_the_real_option() {
    let o = run_args(&["--strcit", "--", "true"]);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("--strict"),
        "{o:?}"
    );
}

#[test]
fn command_without_double_dash_is_a_usage_error() {
    let o = run_args(&["true"]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
}

#[test]
fn dash_prefixed_command_after_double_dash_is_still_a_command() {
    // Everything after -- belongs to the command, even "--version".
    let o = run_args(&["--", "--version"]);
    assert_eq!(o.status.code(), Some(127), "{o:?}");
}

#[test]
fn command_arguments_that_look_like_options_pass_through() {
    let o = run_args(&["--", "sh", "-c", "exit 3", "--strict"]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
}

#[test]
fn dry_run_into_a_closed_pipe_dies_by_sigpipe_not_a_panic() {
    use std::os::fd::FromRawFd;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    let mut fds = [0i32; 2];
    // SAFETY: pipe fills the two-element array; the fds are owned below.
    unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        libc::close(fds[0]); // no reader: any write gets EPIPE
    }
    // SAFETY: fds[1] is a valid open fd that nothing else owns.
    let w = unsafe { Stdio::from_raw_fd(fds[1]) };
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--dry-run", "--port", "5432,6379", "--", "true"])
        .stdout(w)
        .output()
        .unwrap();
    // Output::stdout is empty because we redirected it; check the exit.
    assert_eq!(o.status.signal(), Some(libc::SIGPIPE), "{o:?}");
    assert!(
        !String::from_utf8_lossy(&o.stderr).contains("panicked"),
        "{o:?}"
    );
}
