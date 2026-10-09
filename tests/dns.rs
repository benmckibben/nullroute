//! DNS sinkhole: non-proxy clients resolve allowed names to synthetic loopback
//! addresses that nullroute relays; everything else gets NXDOMAIN.
//!
//! No internet needed: the "real" upstream is a test server on this machine's
//! non-loopback address, and `--resolve` pins the allowed name to it (loopback
//! upstreams are refused by design). Tests that need it are skipped when the
//! machine has no such address.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::process::{Command, Output};
use std::thread;

fn local_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// TCP server on ip that answers each connection with "echo:" + what it read.
fn echo_server(ip: IpAddr) -> u16 {
    let l = TcpListener::bind((ip, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let mut out = b"echo:".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    if c.write_all(&out).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// A port on ip with nothing listening (bound then released).
fn closed_port(ip: IpAddr) -> u16 {
    TcpListener::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

/// Run a Python script inside the sandbox with the given nullroute flags.
fn py(flags: &[&str], script: &str) -> Output {
    let mut args: Vec<&str> = flags.to_vec();
    args.extend(["--", "python3", "-c", script]);
    nullroute(&args)
}

/// Python: raw TCP (no proxy) to host:port, send "ping", print the reply or
/// the error's class name.
fn dial_script(host: &str, port: u16) -> String {
    format!(
        "import socket\n\
         try:\n    s = socket.create_connection(('{host}', {port}), timeout=10)\n    s.sendall(b'ping'); print(s.recv(64).decode() or 'CLOSED')\n\
         except OSError as e:\n    print(type(e).__name__)"
    )
}

/// Python: getaddrinfo(AF_INET, AI_ADDRCONFIG) like most C clients, print the
/// address or the error.
fn resolve_script(names: &[&str]) -> String {
    let mut s = String::from("import socket\n");
    for n in names {
        s.push_str(&format!(
            "try:\n    print(socket.getaddrinfo('{n}', 80, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)[0][4][0])\n\
             except socket.gaierror as e:\n    print('gaierror', e.errno)\n"
        ));
    }
    s
}

#[test]
fn resolv_conf_points_at_the_sinkhole_without_touching_the_host() {
    let before = std::fs::read_to_string("/etc/resolv.conf").ok();
    let o = nullroute(&["--allow", "api.nr.test", "--", "cat", "/etc/resolv.conf"]);
    assert!(o.status.success(), "{o:?}");
    let stdout = out(&o);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(
        lines,
        ["nameserver 127.0.0.1", "options timeout:2 attempts:2"],
        "{o:?}"
    );
    assert_eq!(std::fs::read_to_string("/etc/resolv.conf").ok(), before);
}

#[test]
fn allowed_names_resolve_to_synthetic_loopback_addresses() {
    let o = py(
        &["--allow", "b.nr.test,a.nr.test:5432"],
        &resolve_script(&["a.nr.test", "B.NR.TEST", "a.nr.test"]),
    );
    // Exact names are numbered in sorted order and stay stable.
    assert_eq!(out(&o), "127.77.0.1\n127.77.0.2\n127.77.0.1", "{o:?}");
    assert!(!err(&o).contains("blocked"), "{}", err(&o));
}

#[test]
fn wildcard_names_get_distinct_pool_addresses() {
    let o = py(
        &["--allow", "*.svc.nr.test"],
        &resolve_script(&["one.svc.nr.test", "two.svc.nr.test", "one.svc.nr.test"]),
    );
    assert_eq!(out(&o), "127.77.0.1\n127.77.0.2\n127.77.0.1", "{o:?}");
}

#[test]
fn blocked_name_is_nxdomain_reported_and_strict_fails() {
    let report = std::env::temp_dir().join(format!("nr-dns-report-{}.json", std::process::id()));
    let o = py(
        &[
            "--allow",
            "api.nr.test",
            "--strict",
            "--report-json",
            report.to_str().unwrap(),
        ],
        &resolve_script(&["evil.nr.test", "evil.nr.test"]),
    );
    let eai_noname = "-2";
    assert_eq!(
        out(&o),
        format!("gaierror {eai_noname}\ngaierror {eai_noname}"),
        "{o:?}"
    );
    assert_eq!(
        err(&o)
            .matches("nullroute: blocked DNS lookup of evil.nr.test (not in --allow)")
            .count(),
        1,
        "{}",
        err(&o)
    );
    assert!(err(&o).contains("  dns     evil.nr.test"), "{}", err(&o));
    assert_eq!(o.status.code(), Some(1), "--strict: {o:?}");
    let json = std::fs::read_to_string(&report).unwrap();
    let _ = std::fs::remove_file(&report);
    assert!(
        json.contains(r#""kind": "dns", "target": "evil.nr.test", "reason": "not in --allow""#),
        "{json}"
    );
}

#[test]
fn non_proxy_client_is_relayed_to_the_real_host() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = echo_server(ip);
    let host = "db.nr.test";
    let o = py(
        &[
            "--allow",
            &format!("{host}:{port}"),
            "--resolve",
            &format!("{host}:{ip}"),
        ],
        &dial_script(host, port),
    );
    assert_eq!(out(&o), "echo:ping", "{o:?}");
}

#[test]
fn wildcard_names_are_relayed_too() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = echo_server(ip);
    let o = py(
        &[
            "--allow",
            &format!("*.nr.test:{port}"),
            "--resolve",
            &format!("x.nr.test:{ip}"),
        ],
        &dial_script("x.nr.test", port),
    );
    assert_eq!(out(&o), "echo:ping", "{o:?}");
}

#[test]
fn default_ports_are_80_and_443_only() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    // The pinned upstream refuses, so accepted connections are just closed.
    let script = format!(
        "{}\n{}\n{}",
        dial_script("web.nr.test", 80),
        dial_script("web.nr.test", 443),
        dial_script("web.nr.test", 8080)
    );
    let o = py(
        &[
            "--allow",
            "web.nr.test",
            "--resolve",
            &format!("web.nr.test:{ip}"),
        ],
        &script,
    );
    let stdout = out(&o);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{o:?}");
    for l in &lines[..2] {
        assert!(
            ["CLOSED", "ConnectionResetError"].contains(l),
            "80/443 are listened on: {o:?}"
        );
    }
    assert_eq!(lines[2], "ConnectionRefusedError", "{o:?}");
}

#[test]
fn pool_port_not_allowed_for_that_name_is_refused_and_reported() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let (a_port, b_port) = (echo_server(ip), echo_server(ip));
    let o = py(
        &[
            "--allow",
            &format!("*.a.nr.test:{a_port},*.b.nr.test:{b_port}"),
            "--resolve",
            &format!("x.a.nr.test:{ip}"),
        ],
        // The pool listens on both ports, but x.a.nr.test is only allowed on a_port.
        &format!(
            "{}\n{}",
            dial_script("x.a.nr.test", a_port),
            dial_script("x.a.nr.test", b_port)
        ),
    );
    let stdout = out(&o);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines[0], "echo:ping", "{o:?}");
    assert!(
        ["CLOSED", "ConnectionResetError"].contains(&lines[1]),
        "{o:?}"
    );
    assert!(
        err(&o).contains(&format!(
            "nullroute: blocked x.a.nr.test:{b_port} (port not in --allow)"
        )),
        "{}",
        err(&o)
    );
}

#[test]
fn allowed_name_pinned_to_loopback_is_refused() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let o = py(
        &[
            "--allow",
            &format!("loop.nr.test:{port}"),
            "--resolve",
            "loop.nr.test:127.0.0.1",
        ],
        &dial_script("loop.nr.test", port),
    );
    assert!(
        ["CLOSED", "ConnectionResetError"].contains(&out(&o).as_str()),
        "{o:?}"
    );
    assert!(err(&o).contains("resolves to loopback"), "{}", err(&o));
}

#[test]
fn upstream_failure_closes_and_warns_once() {
    let Some(ip) = local_ip() else {
        return eprintln!("skipping: no non-loopback address");
    };
    let port = closed_port(ip);
    let script = format!("{0}\n{0}", dial_script("down.nr.test", port));
    let o = py(
        &[
            "--allow",
            &format!("down.nr.test:{port}"),
            "--resolve",
            &format!("down.nr.test:{ip}"),
        ],
        &script,
    );
    assert_eq!(out(&o).lines().count(), 2, "{o:?}");
    assert_eq!(
        err(&o)
            .matches(&format!("nullroute: could not reach down.nr.test:{port}"))
            .count(),
        1,
        "{}",
        err(&o)
    );
}

#[test]
fn dns_over_tcp_is_answered() {
    // Hand-built query for a.nr.test A over TCP to the sinkhole.
    let script = "import socket, struct\n\
        q = struct.pack('>HHHHHH', 0xbeef, 0x0100, 1, 0, 0, 0) + b'\\x01a\\x02nr\\x04test\\x00' + struct.pack('>HH', 1, 1)\n\
        s = socket.create_connection(('127.0.0.1', 53), timeout=5)\n\
        s.sendall(struct.pack('>H', len(q)) + q)\n\
        n = struct.unpack('>H', s.recv(2))[0]; r = b''\n\
        while len(r) < n: r += s.recv(n - len(r))\n\
        print(hex(struct.unpack('>H', r[:2])[0]), r[3] & 0xf, struct.unpack('>H', r[6:8])[0], socket.inet_ntoa(r[-4:]))";
    let o = py(&["--allow", "a.nr.test"], script);
    assert_eq!(out(&o), "0xbeef 0 1 127.77.0.1", "{o:?}");
}

#[test]
fn ip_literals_still_fail_closed() {
    let script = "import socket\ntry:\n    socket.create_connection(('1.1.1.1', 443), timeout=5); print('OPEN')\nexcept OSError as e:\n    print(e.errno)";
    let o = py(&["--allow", "api.nr.test,1.1.1.1"], script);
    assert_eq!(out(&o), libc::ENETUNREACH.to_string(), "{o:?}");
}

#[test]
fn local_resolver_sockets_are_masked() {
    let p = "/run/systemd/resolve/io.systemd.Resolve";
    if std::fs::metadata(p).is_err() {
        return eprintln!("skipping: no systemd-resolved socket");
    }
    let script = format!(
        "import socket\ns = socket.socket(socket.AF_UNIX)\ntry:\n    s.connect('{p}'); print('OPEN')\nexcept OSError:\n    print('masked')"
    );
    let o = py(&["--allow", "api.nr.test"], &script);
    assert_eq!(out(&o), "masked", "{o:?}");
}

#[test]
fn no_dns_leaves_resolution_sealed() {
    let host_conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let o = nullroute(&[
        "--allow",
        "api.nr.test",
        "--no-dns",
        "--",
        "cat",
        "/etc/resolv.conf",
    ]);
    assert_eq!(out(&o), host_conf.trim(), "{o:?}");
    let o = py(
        &["--allow", "api.nr.test", "--no-dns"],
        &resolve_script(&["api.nr.test"]),
    );
    assert!(out(&o).starts_with("gaierror"), "{o:?}");
}

#[test]
fn no_names_to_map_means_a_refuse_everything_resolver() {
    // Bare runs and IP-only allowlists have no names to map: the resolver
    // still runs, but it only refuses and records.
    for flags in [&[][..], &["--allow", "10.0.0.5"][..]] {
        let mut args = flags.to_vec();
        args.extend(["--inspect", "--dry-run", "--", "true"]);
        let o = nullroute(&args);
        assert!(
            err(&o).contains(
                "  dns resolver:    127.0.0.1:53 (udp, tcp; every name gets NXDOMAIN and is recorded)\n"
            ),
            "{o:?}"
        );
        assert!(!err(&o).contains("dns sinkhole"), "{o:?}");
        assert!(
            out(&o)
                .lines()
                .any(|l| l == "dns resolver: 127.0.0.1:53 (every lookup is refused and recorded)"),
            "{o:?}"
        );
        assert!(!out(&o).contains("synthetic address"), "{o:?}");
    }
    // --no-dns switches it off.
    let o = nullroute(&["--no-dns", "--inspect", "--dry-run", "--", "true"]);
    assert!(err(&o).contains("  dns sinkhole:    none\n"), "{o:?}");
    assert!(!out(&o).contains("dns "), "{o:?}");
}

#[test]
fn dry_run_and_inspect_show_the_mapping() {
    let o = nullroute(&[
        "--allow",
        "api.nr.test,db.nr.test:5432,*.svc.nr.test",
        "--inspect",
        "--dry-run",
        "--",
        "true",
    ]);
    let stdout = out(&o);
    assert!(stdout.contains("dns sinkhole: 127.0.0.1:53"), "{o:?}");
    assert!(
        stdout.contains("synthetic address: api.nr.test -> 127.77.0.1 (ports 80, 443)"),
        "{o:?}"
    );
    assert!(
        stdout.contains("synthetic address: db.nr.test -> 127.77.0.2 (ports 5432)"),
        "{o:?}"
    );
    assert!(
        stdout.contains(
            "synthetic address: *.svc.nr.test -> 127.77.0.3-127.77.0.34 (pool, ports 80, 443)"
        ),
        "{o:?}"
    );
    let e = err(&o);
    assert!(
        e.contains("  loopback:        lo: UP (127.0.0.1, ::1, 127.77.0.1/24)\n"),
        "{e}"
    );
    assert!(e.contains("  namespaces:      user, net, mount\n"), "{e}");
    assert!(
        e.contains("  dns sinkhole:    127.0.0.1:53 (udp, tcp; other names get NXDOMAIN)\n    api.nr.test -> 127.77.0.1 (ports 80, 443)\n"),
        "{e}"
    );
}

#[test]
fn bad_flag_combinations_exit_2() {
    for args in [
        &["--allow", "api.nr.test", "--port", "53", "--", "true"][..],
        &[
            "--allow",
            "api.nr.test",
            "--resolve",
            "other.nr.test:10.0.0.1",
            "--",
            "true",
        ][..],
        &[
            "--allow",
            "api.nr.test",
            "--resolve",
            "api.nr.test:nope",
            "--",
            "true",
        ][..],
        &["--resolve", "api.nr.test:10.0.0.1", "--", "true"][..],
    ] {
        let o = nullroute(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {o:?}");
    }
    // --no-dns frees port 53 for --port.
    let o = nullroute(&[
        "--allow",
        "api.nr.test",
        "--no-dns",
        "--port",
        "53",
        "--dry-run",
        "--",
        "true",
    ]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
}

// ---- bare runs: the resolver is always on, so lookups are recorded ----------

/// Python: look a name up (once plainly, once with AI_ADDRCONFIG as most C
/// clients do) and swallow the errors, like a test that logs the failure and
/// carries on.
fn swallow_lookup_script(name: &str) -> String {
    format!(
        "import socket\n\
         for flags in (0, socket.AI_ADDRCONFIG):\n    \
             try:\n        socket.getaddrinfo('{name}', 443, 0, socket.SOCK_STREAM, 0, flags)\n    \
             except OSError:\n        pass"
    )
}

/// Python: plain getaddrinfo (AF_UNSPEC, no flags), print the error number.
fn plain_resolve_script(name: &str) -> String {
    format!(
        "import socket\ntry:\n    socket.getaddrinfo('{name}', 80)\nexcept socket.gaierror as e:\n    print('gaierror', e.errno)"
    )
}

#[test]
fn bare_strict_run_catches_a_swallowed_dns_lookup() {
    let report = std::env::temp_dir().join(format!("nr-bare-dns-{}.json", std::process::id()));
    let o = py(
        &["--strict", "--report-json", report.to_str().unwrap()],
        &swallow_lookup_script("api.nr.test"),
    );
    assert_eq!(o.status.code(), Some(1), "--strict without --allow: {o:?}");
    assert!(
        err(&o).contains("nullroute: blocked DNS lookup of api.nr.test (not in --allow)"),
        "{}",
        err(&o)
    );
    let json = std::fs::read_to_string(&report).unwrap();
    let _ = std::fs::remove_file(&report);
    assert!(json.contains(r#""strict_failed": true"#), "{json}");
    assert!(
        json.contains(r#""kind": "dns", "target": "api.nr.test""#),
        "{json}"
    );
}

#[test]
fn bare_run_without_lookups_is_clean_under_strict() {
    let o = nullroute(&["--strict", "--", "true"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(err(&o), "", "nothing to report: {o:?}");
}

#[test]
fn bare_run_lookup_fails_like_an_allow_run() {
    // NXDOMAIN ("Name or service not known", EAI_NONAME = -2), not the
    // retryable "Temporary failure in name resolution" (EAI_AGAIN = -3) that a
    // resolver with no route used to give.
    let bare = py(&[], &plain_resolve_script("api.nr.test"));
    let with_allow = py(
        &["--allow", "other.nr.test"],
        &plain_resolve_script("api.nr.test"),
    );
    assert_eq!(out(&bare), "gaierror -2", "{bare:?}");
    assert_eq!(out(&bare), out(&with_allow), "{bare:?} vs {with_allow:?}");
}

#[test]
fn bare_run_resolv_conf_points_at_the_resolver_and_the_host_is_untouched() {
    let before = std::fs::read_to_string("/etc/resolv.conf").ok();
    let o = nullroute(&["--", "cat", "/etc/resolv.conf"]);
    let stdout = out(&o);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(
        lines,
        ["nameserver 127.0.0.1", "options timeout:2 attempts:2"],
        "{o:?}"
    );
    assert_eq!(std::fs::read_to_string("/etc/resolv.conf").ok(), before);
}

#[test]
fn port_53_still_bridges_in_a_bare_run() {
    // Without --allow names there is nothing for the sinkhole to say, so
    // bridging port 53 keeps working (the resolver steps aside).
    let o = nullroute(&["--port", "53", "--dry-run", "--", "true"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let o = nullroute(&["--port", "53", "--", "true"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(err(&o), "", "{o:?}");
}

#[test]
fn no_dns_also_turns_off_lookup_recording() {
    let o = py(
        &["--no-dns", "--strict"],
        &swallow_lookup_script("api.nr.test"),
    );
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(!err(&o).contains("blocked DNS lookup"), "{}", err(&o));
}

#[test]
fn bare_run_records_lookups_that_ask_for_ai_addrconfig() {
    // glibc skips the query entirely when the only IPv4 address is 127.0.0.1,
    // which would hide lookups from curl and most C clients.
    let o = py(&["--strict"], &resolve_script(&["api.nr.test"]));
    assert_eq!(out(&o), "gaierror -2", "{o:?}");
    assert!(
        err(&o).contains("nullroute: blocked DNS lookup of api.nr.test"),
        "{}",
        err(&o)
    );
    assert_eq!(o.status.code(), Some(1), "{o:?}");
}

#[test]
fn localhost_is_not_a_lookup_even_when_asked_over_dns() {
    // `getent hosts` asks for ::1 as well; when /etc/hosts doesn't have it
    // the query reaches the resolver, which must answer it, not report it.
    let o = nullroute(&[
        "--strict",
        "--",
        "sh",
        "-c",
        "getent hosts localhost || true",
    ]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(!err(&o).contains("blocked"), "{}", err(&o));
    let script =
        "import socket\nprint(sorted({a[4][0] for a in socket.getaddrinfo('localhost', 80)}))";
    let o = py(&["--strict"], script);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(out(&o).contains("127.0.0.1"), "{o:?}");
}
