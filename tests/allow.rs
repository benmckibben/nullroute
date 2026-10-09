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
fn allow_loopback_or_localhost_is_rejected_pointing_at_port() {
    for (bad, hint) in [
        ("127.0.0.1", "--port PORT"),
        ("localhost:5432", "--port 5432"),
        ("[::1]:6379", "--port 6379"),
        ("::ffff:127.0.0.1", "--port PORT"),
        ("db.localhost", "--port PORT"),
    ] {
        let o = nullroute(&["--allow", bad, "--", "true"]);
        assert_eq!(o.status.code(), Some(2), "--allow {bad}: {o:?}");
        assert!(err(&o).contains(hint), "--allow {bad}: {}", err(&o));
    }
}

#[test]
fn allow_loopback_is_rejected_before_anything_runs() {
    // Every common spelling of "this machine", including in a comma list and
    // with --dry-run: refused at parse time (exit 2), nothing runs, and the
    // error says loopback can't work through --allow and points at --port.
    let marker = std::env::temp_dir().join(format!("nr-allow-lo-{}", std::process::id()));
    let touch = format!("touch {}", marker.display());
    for bad in [
        "localhost",
        "LOCALHOST.",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "*.localhost",
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "[::1]",
        "0.0.0.0",
        "::",
        "example.com,localhost",
    ] {
        let o = nullroute(&["--allow", bad, "--", "sh", "-c", &touch]);
        assert_eq!(o.status.code(), Some(2), "--allow {bad}: {o:?}");
        let e = err(&o);
        assert!(
            e.contains("loopback is never reachable through --allow")
                && e.contains("bridge it with --port PORT"),
            "--allow {bad}: {e}"
        );
        assert!(!marker.exists(), "--allow {bad}: the command ran");
        let o = nullroute(&["--allow", bad, "--dry-run", "--", "true"]);
        assert_eq!(o.status.code(), Some(2), "--allow {bad} --dry-run: {o:?}");
    }
}

#[test]
fn allow_link_local_or_metadata_is_rejected() {
    for bad in ["169.254.169.254", "fe80::1", "fd00:ec2::254"] {
        let o = nullroute(&["--allow", bad, "--", "true"]);
        assert_eq!(o.status.code(), Some(2), "--allow {bad}: {o:?}");
        assert!(err(&o).contains("always blocked"), "{}", err(&o));
    }
}

#[test]
fn allowed_name_resolving_to_loopback_is_still_refused() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    for ip in ["127.0.0.1", "::ffff:127.0.0.1"] {
        let o = nullroute(&[
            "--allow",
            "loop.nr.test",
            "--resolve",
            &format!("loop.nr.test:{ip}"),
            "--no-dns",
            "--",
            "python3",
            "-c",
            &connect_script(&format!("loop.nr.test:{port}")),
        ]);
        assert_eq!(out(&o), "HTTP/1.1 403 Forbidden", "{ip}: {o:?}");
        assert!(err(&o).contains("resolves to loopback"), "{}", err(&o));
    }
}

#[test]
fn allowed_name_resolving_to_cloud_metadata_is_refused() {
    // Never dialled: refused before connecting, so no metadata service needed.
    for ip in ["169.254.169.254", "fe80::1", "100.100.100.200"] {
        let o = nullroute(&[
            "--allow",
            "meta.nr.test",
            "--resolve",
            &format!("meta.nr.test:{ip}"),
            "--no-dns",
            "--",
            "python3",
            "-c",
            &connect_script("meta.nr.test:80"),
        ]);
        assert_eq!(out(&o), "HTTP/1.1 403 Forbidden", "{ip}: {o:?}");
        assert!(err(&o).contains("always blocked"), "{ip}: {}", err(&o));
    }
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

// ---- the request must be for the host the allowlist checked -----------------

/// Python: send one plain-HTTP request through $HTTP_PROXY with the given extra
/// header lines, print the status line and the Host headers the server saw.
fn http_script(target: &str, headers: &str) -> String {
    format!(
        "import os, socket, urllib.parse\n\
         u = urllib.parse.urlparse(os.environ['HTTP_PROXY'])\n\
         s = socket.create_connection((u.hostname, u.port), timeout=10)\n\
         s.sendall(('GET http://{target}/x HTTP/1.1\\r\\n{headers}Connection: close\\r\\n\\r\\n').encode())\n\
         data = b''\n\
         while True:\n    c = s.recv(4096)\n    if not c: break\n    data += c\n\
         lines = data.decode().split('\\r\\n')\n\
         print(lines[0])\n\
         for l in lines:\n    if l.lower().startswith('host:'): print(l)"
    )
}

#[test]
fn plain_http_host_header_must_name_the_host_that_was_checked() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = reflect_server(ip);
    let target = format!("{ip}:{port}");
    let run = |headers: &str, extra: &[&str]| {
        let script = http_script(&target, headers);
        let mut args = vec!["--allow", target.as_str()];
        args.extend_from_slice(extra);
        args.extend(["--", "python3", "-c", &script]);
        nullroute(&args)
    };
    // The same name: forwarded (with or without the port, any case).
    for host in [format!("{ip}:{port}"), ip.to_string()] {
        let o = run(&format!("Host: {host}\\r\\n"), &[]);
        assert_eq!(out(&o), format!("HTTP/1.1 200 OK\nHost: {host}"), "{o:?}");
    }
    // No Host header at all: nothing to disagree with.
    let o = run("", &[]);
    assert_eq!(out(&o), "HTTP/1.1 200 OK", "{o:?}");

    // Another name: refused, never reaches the server, and it is reported.
    let o = run("Host: evil.example\\r\\n", &["--strict"]);
    assert_eq!(out(&o), "HTTP/1.1 403 Forbidden", "{o:?}");
    let e = err(&o);
    assert!(
        e.contains("nullroute: blocked Host: evil.example in a request to"),
        "{e}"
    );
    assert!(e.contains("  proxy   evil.example:"), "{e}");
    assert_eq!(o.status.code(), Some(1), "--strict: {o:?}");

    // ...unless that name is allowed too.
    let o = run("Host: evil.example\\r\\n", &["--allow", "evil.example"]);
    assert_eq!(out(&o), "HTTP/1.1 200 OK\nHost: evil.example", "{o:?}");

    // Two Host headers are ambiguous: which one does the server believe?
    let o = run(&format!("Host: {ip}\\r\\nHost: evil.example\\r\\n"), &[]);
    assert_eq!(out(&o), "HTTP/1.1 400 Bad Request", "{o:?}");
}

/// The bytes of a TLS ClientHello with the given server name (None: no SNI).
fn client_hello_py() -> &'static str {
    "import struct\n\
     def hello(name):\n    ext = b''\n    if name:\n        n = name.encode()\n        entry = b'\\x00' + struct.pack('>H', len(n)) + n\n        lst = struct.pack('>H', len(entry)) + entry\n        ext = struct.pack('>HH', 0, len(lst)) + lst\n    body = b'\\x03\\x03' + bytes(32) + b'\\x00' + b'\\x00\\x02\\x13\\x01' + b'\\x01\\x00' + struct.pack('>H', len(ext)) + ext\n    hs = b'\\x01' + struct.pack('>I', len(body))[1:] + body\n    return b'\\x16\\x03\\x01' + struct.pack('>H', len(hs)) + hs\n"
}

/// Python: CONNECT to target through $HTTPS_PROXY, send `payload` (a Python
/// expression) through the tunnel and print ECHO-OK if the echo server sent it
/// back, else CLOSED.
fn tunnel_script(target: &str, payload: &str) -> String {
    format!(
        "{hello}import os, socket, urllib.parse\n\
         u = urllib.parse.urlparse(os.environ['HTTPS_PROXY'])\n\
         s = socket.create_connection((u.hostname, u.port), timeout=10)\n\
         s.sendall(b'CONNECT {target} HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n')\n\
         resp = b''\n\
         while b'\\r\\n\\r\\n' not in resp: resp += s.recv(1)\n\
         assert b' 200 ' in resp.split(b'\\r\\n')[0], resp\n\
         data = {payload}\n\
         try:\n    s.sendall(data)\n    got = b''\n    while len(got) < len(data):\n        c = s.recv(4096)\n        if not c: break\n        got += c\n    print('ECHO-OK' if got == data else 'CLOSED')\n\
         except OSError:\n    print('CLOSED')",
        hello = client_hello_py()
    )
}

#[test]
fn connect_tunnel_sni_must_name_the_host_that_was_checked() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = echo_server(ip);
    let pin = format!("api.nr.test:{ip}");
    let target = format!("api.nr.test:{port}");
    let run = |payload: &str, allow: &str, extra: &[&str]| {
        let script = tunnel_script(&target, payload);
        let mut args = vec!["--allow", allow, "--resolve", pin.as_str()];
        args.extend_from_slice(extra);
        args.extend(["--", "python3", "-c", &script]);
        nullroute(&args)
    };
    // The name asked for: through. No SNI at all: through. Not TLS: through.
    for payload in [
        "hello('api.nr.test')",
        "hello('API.NR.TEST.')",
        "hello(None)",
        "b'ping'",
    ] {
        let o = run(payload, "api.nr.test", &[]);
        assert_eq!(out(&o), "ECHO-OK", "{payload}: {o:?}");
        assert!(!err(&o).contains("blocked"), "{payload}: {}", err(&o));
    }
    // A different name inside TLS: the tunnel is closed and it is reported.
    let o = run("hello('evil.nr.test')", "api.nr.test", &["--strict"]);
    assert_eq!(out(&o), "CLOSED", "{o:?}");
    let e = err(&o);
    assert!(
        e.contains("nullroute: blocked TLS server name evil.nr.test in a tunnel to api.nr.test:"),
        "{e}"
    );
    assert!(e.contains("  proxy   evil.nr.test:"), "{e}");
    assert_eq!(o.status.code(), Some(1), "--strict: {o:?}");
    // ...unless that name is allowed too.
    let o = run("hello('other.nr.test')", "api.nr.test,other.nr.test", &[]);
    assert_eq!(out(&o), "ECHO-OK", "{o:?}");
    // Looks like TLS but can't be read: refused, not guessed at.
    let o = run("b'\\x16\\x03\\x01\\x00\\x05junk!'", "api.nr.test", &[]);
    assert_eq!(out(&o), "CLOSED", "{o:?}");
    assert!(
        err(&o).contains("unreadable TLS ClientHello"),
        "{}",
        err(&o)
    );
}

#[test]
fn connect_tunnel_to_an_ip_literal_refuses_a_foreign_server_name() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = echo_server(ip);
    let target = format!("{ip}:{port}");
    let run = |payload: &str| {
        let script = tunnel_script(&target, payload);
        nullroute(&["--allow", &ip.to_string(), "--", "python3", "-c", &script])
    };
    // A client dialling an IP sends no SNI.
    assert_eq!(out(&run("hello(None)")), "ECHO-OK");
    let o = run("hello('evil.nr.test')");
    assert_eq!(out(&o), "CLOSED", "{o:?}");
    assert!(
        err(&o).contains("blocked TLS server name evil.nr.test"),
        "{}",
        err(&o)
    );
}

#[test]
fn connect_tunnel_sni_split_over_segments_is_still_checked() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = echo_server(ip);
    let pin = format!("api.nr.test:{ip}");
    let target = format!("api.nr.test:{port}");
    // Send the hello a few bytes at a time with a pause in between.
    let slow = |name: &str| format!("(lambda d: d)(hello('{name}'))");
    for (name, want) in [("api.nr.test", "ECHO-OK"), ("evil.nr.test", "CLOSED")] {
        let script = tunnel_script(&target, &slow(name)).replace(
            "s.sendall(data)",
            "import time\n    for i in range(0, len(data), 7):\n        s.sendall(data[i:i+7]); time.sleep(0.01)",
        );
        let o = nullroute(&[
            "--allow",
            "api.nr.test",
            "--resolve",
            &pin,
            "--",
            "python3",
            "-c",
            &script,
        ]);
        assert_eq!(out(&o), want, "{name}: {o:?}");
    }
}

#[test]
fn connect_tunnel_to_a_server_that_speaks_first_is_not_held_up() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    // SMTP/SSH/MySQL style: the server sends a banner and waits.
    let l = TcpListener::bind((ip, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let _ = c.write_all(b"220 hello\r\n");
        }
    });
    let script = format!(
        "import os, socket, urllib.parse\n\
         u = urllib.parse.urlparse(os.environ['HTTPS_PROXY'])\n\
         s = socket.create_connection((u.hostname, u.port), timeout=10)\n\
         s.sendall(b'CONNECT {ip}:{port} HTTP/1.1\\r\\n\\r\\n')\n\
         resp = b''\n\
         while b'\\r\\n\\r\\n' not in resp: resp += s.recv(1)\n\
         s.settimeout(5)\n\
         print(s.recv(64))"
    );
    let o = nullroute(&["--allow", &ip.to_string(), "--", "python3", "-c", &script]);
    assert_eq!(out(&o), "b'220 hello\\r\\n'", "{o:?}");
}

#[test]
fn allowing_private_address_space_prints_a_warning() {
    for (entry, what) in [
        ("10.0.0.5", "is a private (RFC 1918) address"),
        ("192.168.1.10:8080", "is a private (RFC 1918) address"),
        ("100.64.0.1", "is a carrier-grade NAT"),
        ("fd00::1", "is a unique local"),
    ] {
        let o = nullroute(&["--allow", entry, "--dry-run", "--", "true"]);
        assert!(o.status.success(), "{entry}: {o:?}");
        let want = format!(
            "nullroute: warning: --allow {} {what}",
            entry
                .rsplit_once(':')
                .filter(|_| entry.contains('.'))
                .map_or(entry, |(h, _)| h)
        );
        assert!(err(&o).contains(&want), "{entry}: {}", err(&o));
        assert_eq!(err(&o).lines().count(), 1, "one line: {}", err(&o));
        // --quiet keeps it out.
        let o = nullroute(&["-q", "--allow", entry, "--dry-run", "--", "true"]);
        assert_eq!(err(&o), "", "{entry}: {o:?}");
    }
    let o = nullroute(&[
        "--allow",
        "93.184.216.34,example.com",
        "--dry-run",
        "--",
        "true",
    ]);
    assert_eq!(err(&o), "", "{o:?}");
    let o = nullroute(&[
        "--allow",
        "db.nr.test",
        "--resolve",
        "db.nr.test:10.1.2.3",
        "--dry-run",
        "--",
        "true",
    ]);
    assert!(
        err(&o).contains(
            "warning: --resolve db.nr.test:10.1.2.3 points at a private (RFC 1918) address"
        ),
        "{}",
        err(&o)
    );
}

#[test]
fn an_allowed_name_that_resolves_into_private_space_warns_once() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    if !matches!(ip, IpAddr::V4(v4) if v4.is_private() || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
    {
        return eprintln!("skipping: {ip} isn't in private address space");
    }
    let port = echo_server(ip);
    let pin = format!("lan.nr.test:{ip}");
    let script = format!("{0}\n{0}", connect_script(&format!("lan.nr.test:{port}")));
    let o = nullroute(&[
        "--allow",
        "lan.nr.test",
        "--resolve",
        &pin,
        "--",
        "python3",
        "-c",
        &script,
    ]);
    assert_eq!(
        out(&o)
            .matches("HTTP/1.1 200 Connection Established")
            .count(),
        2,
        "it still works: {o:?}"
    );
    assert_eq!(
        err(&o)
            .matches(&format!(
                "nullroute: warning: lan.nr.test resolved to {ip}, a "
            ))
            .count(),
        1,
        "{}",
        err(&o)
    );
}
