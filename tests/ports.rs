//! --port: host localhost services bridged into the sandbox, and nothing else.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::process::{Command, Output};
use std::thread;

fn nullroute(ports: &[u16], script: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    cmd.arg("run");
    for p in ports {
        cmd.arg("--port").arg(p.to_string());
    }
    cmd.args(["--", "python3", "-c", script])
        .output()
        .expect("failed to launch nullroute")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A host-side service on 127.0.0.1 that echoes everything back until EOF.
fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 65536];
                loop {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if c.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = c.shutdown(Shutdown::Write);
            });
        }
    });
    port
}

/// Python that connects to (host, port), sends "ping", prints the reply or errno.
fn ping(host: &str, port: u16) -> String {
    format!(
        "import socket\n\
         try:\n    c = socket.create_connection(('{host}', {port}), timeout=5); c.sendall(b'ping'); c.shutdown(socket.SHUT_WR); print(c.recv(16).decode())\n\
         except OSError as e:\n    print('ERR', e.errno)"
    )
}

#[test]
fn forwarded_port_reaches_host_service_over_v4_and_v6() {
    let port = echo_server();
    for host in ["127.0.0.1", "localhost", "::1"] {
        let o = nullroute(&[port], &ping(host, port));
        assert_eq!(stdout(&o), "ping", "via {host}: {o:?}");
    }
}

#[test]
fn port_is_unreachable_without_the_flag() {
    let port = echo_server();
    let o = nullroute(&[], &ping("127.0.0.1", port));
    assert_eq!(stdout(&o), format!("ERR {}", libc::ECONNREFUSED), "{o:?}");
}

#[test]
fn only_named_ports_are_bridged() {
    let (a, b) = (echo_server(), echo_server());
    let o = nullroute(&[a], &ping("127.0.0.1", b));
    assert_eq!(stdout(&o), format!("ERR {}", libc::ECONNREFUSED), "{o:?}");
}

#[test]
fn egress_stays_sealed_with_ports_forwarded() {
    let port = echo_server();
    let o = nullroute(&[port], &ping("1.1.1.1", 80));
    assert_eq!(stdout(&o), format!("ERR {}", libc::ENETUNREACH), "{o:?}");
}

#[test]
fn large_transfer_survives_the_bridge() {
    let port = echo_server();
    let script = format!(
        "import socket, os, threading, hashlib\n\
         data = os.urandom(4 << 20)\n\
         c = socket.create_connection(('127.0.0.1', {port}))\n\
         def send():\n    c.sendall(data); c.shutdown(socket.SHUT_WR)\n\
         threading.Thread(target=send).start()\n\
         got = bytearray()\n\
         while (d := c.recv(1 << 16)):\n    got += d\n\
         print(len(got), hashlib.sha256(data).hexdigest() == hashlib.sha256(got).hexdigest())"
    );
    let o = nullroute(&[port], &script);
    assert_eq!(stdout(&o), format!("{} True", 4 << 20), "{o:?}");
}

#[test]
fn dead_host_service_closes_connection_and_warns_once() {
    // Grab a free port, then free it so nothing listens on the host.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let script = format!(
        "import socket\n\
         for _ in range(3):\n    c = socket.create_connection(('127.0.0.1', {port})); print(repr(c.recv(8)))"
    );
    let o = nullroute(&[port], &script);
    assert_eq!(stdout(&o), "b''\nb''\nb''", "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        err.matches("nothing reachable on the host").count(),
        1,
        "{err}"
    );
}

#[test]
fn invalid_ports_are_rejected_before_running() {
    for bad in ["0", "65536", "http"] {
        let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
            .args(["run", "--port", bad, "--", "true"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "--port {bad}: {o:?}");
    }
}

#[test]
fn too_many_ports_is_a_usage_error() {
    let many = (1..=65)
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    for extra in [&[][..], &["--dry-run"][..]] {
        let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
            .args(["run", "--port", &many])
            .args(extra)
            .args(["--", "true"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{extra:?}: {o:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("at most 64 --port values"));
    }
    let ok = (1..=64)
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--dry-run", "--port", &ok, "--", "true"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{o:?}");
}

#[test]
fn comma_separated_and_repeated_ports_both_work() {
    let (a, b) = (echo_server(), echo_server());
    let script = format!("{}\n{}", ping("127.0.0.1", a), ping("127.0.0.1", b));
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args([
            "run",
            "--port",
            &format!("{a},{b}"),
            "--port",
            &a.to_string(),
            "--",
            "python3",
            "-c",
            &script,
        ])
        .output()
        .unwrap();
    assert_eq!(stdout(&o), "ping\nping", "{o:?}");
}
