//! --allow: chosen hosts reachable through nullroute's proxy, nothing else.
//!
//! No internet needed: the "allowed upstream" is a test server bound to this
//! machine's non-loopback address (loopback targets are refused by design).
//! Tests that need it are skipped when the machine has no such address.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::process::{Command, Output};
use std::thread;

/// This machine's outward-facing address, if any. connect() on UDP sends nothing.
fn local_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// HTTP server on ip: replies with the request head it received as the body.
fn reflect_server(ip: IpAddr) -> u16 {
    let l = TcpListener::bind((ip, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let mut c = c;
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{head}",
                    head.len()
                );
            });
        }
    });
    port
}

/// TCP echo server on ip.
fn echo_server(ip: IpAddr) -> u16 {
    let l = TcpListener::bind((ip, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn nullroute(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .output()
        .expect("failed to launch nullroute")
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// Python: raw CONNECT through $HTTPS_PROXY to target, print the status line;
/// if 200, send "ping" through the tunnel and print the echo.
fn connect_script(target: &str) -> String {
    format!(
        "import os, socket, urllib.parse\n\
         u = urllib.parse.urlparse(os.environ['HTTPS_PROXY'])\n\
         s = socket.create_connection((u.hostname, u.port), timeout=10)\n\
         s.sendall(b'CONNECT {target} HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n')\n\
         resp = b''\nwhile b'\\r\\n\\r\\n' not in resp: resp += s.recv(1)\n\
         status = resp.split(b'\\r\\n')[0].decode(); print(status)\n\
         if ' 200 ' in status:\n    s.sendall(b'ping'); print(s.recv(4).decode())"
    )
}

#[test]
fn allowed_plain_http_is_forwarded_in_origin_form() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = reflect_server(ip);
    let script = format!(
        "import urllib.request\nprint(urllib.request.urlopen('http://{ip}:{port}/hello?x=1', timeout=10).read().decode())"
    );
    let o = nullroute(&["--allow", &ip.to_string(), "--", "python3", "-c", &script]);
    let body = out(&o);
    assert!(
        body.starts_with("GET /hello?x=1 HTTP/1.1"),
        "request line not rewritten: {o:?}"
    );
    assert!(body.contains("Connection: close"), "{o:?}");
    assert!(
        !body.to_ascii_lowercase().contains("proxy-"),
        "proxy headers leaked: {o:?}"
    );
}

#[test]
fn allowed_connect_tunnels_bytes() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = echo_server(ip);
    let o = nullroute(&[
        "--allow",
        &ip.to_string(),
        "--",
        "python3",
        "-c",
        &connect_script(&format!("{ip}:{port}")),
    ]);
    assert_eq!(
        out(&o),
        "HTTP/1.1 200 Connection Established\nping",
        "{o:?}"
    );
}

#[test]
fn unlisted_host_gets_403_and_one_warning() {
    let script = format!("{0}\n{0}", connect_script("blocked.example:443"));
    let o = nullroute(&["--allow", "allowed.example", "--", "python3", "-c", &script]);
    assert_eq!(
        out(&o),
        "HTTP/1.1 403 Forbidden\nHTTP/1.1 403 Forbidden",
        "{o:?}"
    );
    assert_eq!(
        err(&o)
            .matches("nullroute: blocked blocked.example (not in --allow)")
            .count(),
        1,
        "{}",
        err(&o)
    );
}

#[test]
fn allowed_loopback_target_is_still_refused() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let o = nullroute(&[
        "--allow",
        "127.0.0.1",
        "--",
        "python3",
        "-c",
        &connect_script(&format!("127.0.0.1:{port}")),
    ]);
    assert_eq!(out(&o), "HTTP/1.1 403 Forbidden", "{o:?}");
    assert!(err(&o).contains("resolves to loopback"), "{}", err(&o));
}

#[test]
fn proxy_env_is_set_and_localhost_bypasses_it() {
    let o = nullroute(&[
        "--allow",
        "example.com",
        "--",
        "sh",
        "-c",
        "echo $HTTP_PROXY $HTTPS_PROXY $https_proxy $ALL_PROXY $NO_PROXY $NODE_USE_ENV_PROXY",
    ]);
    let u = "http://127.0.0.1:3128";
    assert_eq!(
        out(&o),
        format!("{u} {u} {u} {u} localhost,127.0.0.1,::1 1"),
        "{o:?}"
    );
}

#[test]
fn no_proxy_env_without_allow() {
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--", "sh", "-c", "echo \"[$HTTPS_PROXY]\""])
        .env_remove("HTTPS_PROXY")
        .output()
        .unwrap();
    assert_eq!(out(&o), "[]", "{o:?}");
}

#[test]
fn proxy_port_moves_off_a_forwarded_port() {
    let o = nullroute(&[
        "--allow",
        "example.com",
        "--port",
        "3128",
        "--",
        "sh",
        "-c",
        "echo $HTTPS_PROXY",
    ]);
    assert_eq!(out(&o), "http://127.0.0.1:3129", "{o:?}");
}

#[test]
fn raw_sockets_stay_sealed_with_allow() {
    let script = "import socket\ntry:\n    socket.create_connection(('1.1.1.1', 80), timeout=5); print('OPEN')\nexcept OSError as e:\n    print(e.errno)";
    let o = nullroute(&["--allow", "1.1.1.1", "--", "python3", "-c", script]);
    assert_eq!(out(&o), libc::ENETUNREACH.to_string(), "{o:?}");
}

#[test]
fn invalid_allow_values_exit_2() {
    for bad in ["https://x.com", "x.com:0", "*", "a*.b.com", ""] {
        let o = nullroute(&["--allow", bad, "--", "true"]);
        assert_eq!(o.status.code(), Some(2), "--allow {bad:?}: {o:?}");
    }
}

#[test]
fn allow_with_port_restricts_to_that_port() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let (good, other) = (echo_server(ip), echo_server(ip));
    let entry = format!("{ip}:{good}");
    let script = format!(
        "{}\n{}",
        connect_script(&format!("{ip}:{good}")),
        connect_script(&format!("{ip}:{other}"))
    );
    let o = nullroute(&["--allow", &entry, "--", "python3", "-c", &script]);
    assert_eq!(
        out(&o),
        "HTTP/1.1 200 Connection Established\nping\nHTTP/1.1 403 Forbidden",
        "{o:?}"
    );
}
