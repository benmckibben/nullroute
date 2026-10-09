//! The seccomp filter and `no_new_privs` (see src/seccomp.rs): socket
//! families that reach outside the network namespace, terminal input
//! injection and io_uring are denied, ordinary programs are unaffected, and
//! `--no-seccomp` turns the filter off, `--allow-new-privs` leaves
//! `no_new_privs` unset.

use std::fs::File;
use std::process::{Command, Output, Stdio};

fn nullroute(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .output()
        .expect("launch nullroute")
}

/// Run a Python snippet outside the sandbox, for comparison.
fn outside(script: &str) -> Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

const VSOCK: &str = "import socket\n\
    try:\n    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); print('created')\n\
    except OSError as e:\n    print('error', e.errno)";

#[test]
fn vsock_sockets_cannot_be_created_inside() {
    // Without the filter a vsock socket can be created inside, which is a
    // side channel to the hypervisor or host. Only meaningful where the
    // kernel has vsock at all.
    if out(&outside(VSOCK)) != "created" {
        return eprintln!("skipping vsock_sockets_cannot_be_created_inside: no AF_VSOCK here");
    }
    let o = nullroute(&["--", "python3", "-c", VSOCK]);
    assert_eq!(out(&o), format!("error {}", libc::EAFNOSUPPORT), "{o:?}");
    // The escape hatch.
    let o = nullroute(&["--no-seccomp", "--", "python3", "-c", VSOCK]);
    assert_eq!(out(&o), "created", "{o:?}");
}

#[test]
fn other_hardware_families_are_denied_too() {
    // Created outside or not, inside they must say "not supported".
    let script = "import socket\n\
        for fam in (socket.AF_BLUETOOTH, 39, 42):\n\
        \x20   try:\n\
        \x20       socket.socket(fam, socket.SOCK_STREAM, 0); print('created')\n\
        \x20   except OSError as e:\n\
        \x20       print(e.errno)";
    let o = nullroute(&["--", "python3", "-c", script]);
    let want = libc::EAFNOSUPPORT.to_string();
    assert_eq!(out(&o), [want.as_str(); 3].join("\n"), "{o:?}");
}

#[test]
fn ordinary_network_code_still_works() {
    // Loopback TCP and UDP, a Unix socketpair, netlink (if_nameindex), IPv6
    // loopback: what tests and tools do inside a sandbox with only lo.
    let script = "import socket, threading\n\
        s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)\n\
        threading.Thread(target=lambda: s.accept()[0].sendall(b'tcp'), daemon=True).start()\n\
        print(socket.create_connection(s.getsockname()).recv(3).decode())\n\
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('127.0.0.1', 0))\n\
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.sendto(b'udp', u.getsockname())\n\
        print(u.recv(3).decode())\n\
        a, b = socket.socketpair(); a.send(b'unix'); print(b.recv(4).decode())\n\
        print([n for _, n in socket.if_nameindex()])\n\
        s6 = socket.socket(socket.AF_INET6); s6.bind(('::1', 0)); print('v6')\n\
        n = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0); print('netlink')";
    let o = nullroute(&["--", "python3", "-c", script]);
    assert_eq!(out(&o), "tcp\nudp\nunix\n['lo']\nv6\nnetlink", "{o:?}");
}

#[test]
fn shells_and_nested_nullroute_still_work() {
    let o = nullroute(&[
        "--",
        "sh",
        "-c",
        "echo $((6*7)); ls / >/dev/null && echo ls-ok",
    ]);
    assert_eq!(out(&o), "42\nls-ok", "{o:?}");
    // The filter is inherited, and a nested nullroute can stack its own.
    let me = env!("CARGO_BIN_EXE_nullroute");
    let o = nullroute(&["--", me, "run", "--", "python3", "-c", VSOCK]);
    assert_eq!(
        out(&o),
        format!("error {}", libc::EAFNOSUPPORT),
        "{o:?} {}",
        err(&o)
    );
}

#[test]
fn filter_and_no_new_privs_are_visible_in_proc() {
    let status = |args: &[&str]| {
        let mut a = args.to_vec();
        a.extend([
            "--",
            "grep",
            "-E",
            "^(NoNewPrivs|Seccomp):",
            "/proc/self/status",
        ]);
        out(&nullroute(&a)).replace('\t', " ")
    };
    assert_eq!(status(&[]), "NoNewPrivs: 1\nSeccomp: 2");
    // no_new_privs is set either way; only the filter is optional.
    assert_eq!(status(&["--no-seccomp"]), "NoNewPrivs: 1\nSeccomp: 0");
    // --allow-new-privs is the other switch: the filter stays, no_new_privs doesn't.
    assert_eq!(status(&["--allow-new-privs"]), "NoNewPrivs: 0\nSeccomp: 2");
    assert_eq!(
        status(&["--no-seccomp", "--allow-new-privs"]),
        "NoNewPrivs: 0\nSeccomp: 0"
    );
}

#[test]
fn allow_new_privs_keeps_the_filter() {
    // io_uring and AF_VSOCK are still refused when only no_new_privs is off.
    let uring = "import ctypes\n\
        libc = ctypes.CDLL(None, use_errno=True)\n\
        fd = libc.syscall(425, 2, ctypes.create_string_buffer(120))\n\
        print('created' if fd >= 0 else 'error %d' % ctypes.get_errno())";
    if out(&outside(uring)) == "created" {
        let o = nullroute(&["--allow-new-privs", "--", "python3", "-c", uring]);
        assert_eq!(out(&o), format!("error {}", libc::EPERM), "{o:?}");
    } else {
        eprintln!(
            "skipping the io_uring half of allow_new_privs_keeps_the_filter: no io_uring here"
        );
    }
    if out(&outside(VSOCK)) == "created" {
        let o = nullroute(&["--allow-new-privs", "--", "python3", "-c", VSOCK]);
        assert_eq!(out(&o), format!("error {}", libc::EAFNOSUPPORT), "{o:?}");
    } else {
        eprintln!("skipping the vsock half of allow_new_privs_keeps_the_filter: no AF_VSOCK here");
    }
}

/// The path of a `ping` that gets `cap_net_raw` from a file capability, if
/// the host has one (on Debian and Ubuntu it does; elsewhere it may be setuid
/// or use unprivileged ICMP sockets instead).
fn ping_with_file_capability() -> Option<String> {
    let path = out(&Command::new("sh")
        .args(["-c", "command -v ping"])
        .output()
        .ok()?);
    let has_cap = out(&outside(&format!(
        "import os\ntry:\n os.getxattr({path:?}, 'security.capability'); print('yes')\nexcept OSError: print('no')"
    ))) == "yes";
    (!path.is_empty() && has_cap).then_some(path)
}

#[test]
fn allow_new_privs_lets_a_file_capability_through() {
    // The motivating case. A file capability (cap_net_raw on ping) is honoured by
    // exec only if no_new_privs is off or the process already holds the capability.
    // The sandbox's child holds its user namespace's capabilities until the
    // first exec, so a ping run directly works either way, but one started by a
    // shell (the second exec) has nothing to keep and fails without the flag.
    let Some(ping) = ping_with_file_capability() else {
        return eprintln!(
            "skipping allow_new_privs_lets_a_file_capability_through: no ping with a file capability"
        );
    };
    let script = format!("{ping} -c1 -W1 127.0.0.1");
    let o = nullroute(&["--allow-new-privs", "--", "sh", "-c", &script]);
    assert!(
        o.status.success(),
        "ping via sh with --allow-new-privs: {o:?}\n{}",
        err(&o)
    );
    let o = nullroute(&["--", "sh", "-c", &script]);
    assert!(
        !o.status.success(),
        "without --allow-new-privs, a file capability must not be granted by a second exec: {o:?}"
    );
}

#[test]
fn io_uring_cannot_be_set_up_inside() {
    let script = "import ctypes\n\
        libc = ctypes.CDLL(None, use_errno=True)\n\
        fd = libc.syscall(425, 2, ctypes.create_string_buffer(120))\n\
        print('created' if fd >= 0 else 'error %d' % ctypes.get_errno())";
    if out(&outside(script)) != "created" {
        return eprintln!(
            "skipping io_uring_cannot_be_set_up_inside: io_uring unavailable here ({})",
            out(&outside(script))
        );
    }
    let o = nullroute(&["--", "python3", "-c", script]);
    assert_eq!(out(&o), format!("error {}", libc::EPERM), "{o:?}");
    let o = nullroute(&["--no-seccomp", "--", "python3", "-c", script]);
    assert_eq!(out(&o), "created", "{o:?}");
}

/// Run `script` (Python) in nullroute with a fresh pseudo-terminal as its
/// stdin; the script makes the pty its controlling terminal first, which is the
/// situation where TIOCSTI would type into the shell that started it.
fn with_controlling_pty(args: &[&str], script: &str) -> Output {
    // SAFETY: plain libc calls on a freshly opened pty master.
    let (master, slave_path) = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt");
        assert_eq!(libc::grantpt(m), 0);
        assert_eq!(libc::unlockpt(m), 0);
        let mut buf = [0 as libc::c_char; 128];
        assert_eq!(libc::ptsname_r(m, buf.as_mut_ptr(), buf.len()), 0);
        (
            m,
            std::ffi::CStr::from_ptr(buf.as_ptr())
                .to_string_lossy()
                .into_owned(),
        )
    };
    let slave = File::options()
        .read(true)
        .write(true)
        .open(&slave_path)
        .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .args(["--", "python3", "-c", script])
        .stdin(Stdio::from(slave))
        .output()
        .unwrap();
    // SAFETY: closing the master we opened above.
    unsafe { libc::close(master) };
    o
}

const TIOC: &str = "import os, fcntl, termios\n\
    os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n\
    def try_(req, arg):\n\
    \x20   try:\n\
    \x20       fcntl.ioctl(0, req, arg); return 0\n\
    \x20   except OSError as e:\n\
    \x20       return e.errno\n\
    print(try_(termios.TIOCSTI, b'x'), try_(0x541C, bytes([11, 0, 0, 0])))";

#[test]
fn terminal_input_injection_is_denied() {
    // With the filter: EPERM for TIOCSTI and TIOCLINUX, whatever the kernel's
    // dev.tty.legacy_tiocsti says.
    let o = with_controlling_pty(&[], TIOC);
    let eperm = libc::EPERM;
    assert_eq!(out(&o), format!("{eperm} {eperm}"), "{o:?}");
    // Without it the call goes to the kernel: it must not say EPERM from our
    // filter. (A kernel with legacy_tiocsti=0 answers EIO; one with 1 accepts
    // the byte.)
    let o = with_controlling_pty(&["--no-seccomp"], TIOC);
    let first = out(&o);
    assert!(
        !first.starts_with(&format!("{eperm} ")),
        "TIOCSTI should reach the kernel with --no-seccomp, got {first:?}"
    );
}

#[test]
fn inspect_and_dry_run_report_the_hardening() {
    let o = nullroute(&["--inspect", "--dry-run", "--", "true"]);
    assert!(
        err(&o).contains("  hardening:       no_new_privs; seccomp denies socket(AF_BLUETOOTH/AF_NFC/AF_VSOCK/AF_QIPCRTR)"),
        "{}",
        err(&o)
    );
    assert!(
        out(&o).contains("seccomp: no_new_privs; seccomp denies"),
        "{o:?}"
    );
    let o = nullroute(&["--inspect", "--dry-run", "--no-seccomp", "--", "true"]);
    assert!(
        err(&o).contains("hardening:       off (--no-seccomp)"),
        "{}",
        err(&o)
    );
    assert!(out(&o).contains("seccomp: off (--no-seccomp)"), "{o:?}");
    let o = nullroute(&["--inspect", "--dry-run", "--allow-new-privs", "--", "true"]);
    assert!(
        err(&o).contains("  hardening:       seccomp denies socket(")
            && err(&o).contains("; no_new_privs is off (--allow-new-privs)\n"),
        "{}",
        err(&o)
    );
    assert!(
        out(&o).contains("seccomp: seccomp denies") && out(&o).contains("no_new_privs is off"),
        "{o:?}"
    );
    let o = nullroute(&[
        "--dry-run",
        "--no-seccomp",
        "--allow-new-privs",
        "--",
        "true",
    ]);
    assert!(
        out(&o).contains("seccomp: off (--no-seccomp, --allow-new-privs)"),
        "{o:?}"
    );
}
