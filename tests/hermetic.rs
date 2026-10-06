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
fn missing_command_exits_125_with_a_message() {
    let o = nullroute(&["/definitely/not/a/command"]);
    assert_eq!(o.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&o.stderr).contains("nullroute: failed to run"));
}
