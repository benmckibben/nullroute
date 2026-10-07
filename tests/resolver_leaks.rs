//! Out-of-band DNS: local services that would resolve names on the host's
//! network for the sandboxed command, past the network namespace.
//!
//! - the system D-Bus (systemd-resolved's `org.freedesktop.resolve1`) is hidden
//!   by default, and `--allow-socket` opts back in;
//! - systemd-resolved's varlink socket and nscd are masked in every sandbox,
//!   even a bare `nullroute run` with no `--allow`.
//!
//! Each test is skipped when the host lacks the service it probes.

use std::path::Path;
use std::process::{Command, Output};

const DBUS: &str = "/run/dbus/system_bus_socket";
const VARLINK: &str = "/run/systemd/resolve/io.systemd.Resolve";
const NSCD: [&str; 2] = ["/run/nscd/socket", "/var/run/nscd/socket"];

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
fn host_python(script: &str) -> String {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .map(|o| out(&o))
        .unwrap_or_default()
}

/// Python: authenticate to the D-Bus socket at `path` with SASL EXTERNAL and
/// print "AUTH-OK" if the bus accepts, otherwise what went wrong.
fn dbus_auth_script(path: &str) -> String {
    format!(
        "import os, socket\n\
         s = socket.socket(socket.AF_UNIX)\n\
         s.settimeout(5)\n\
         try:\n    \
             s.connect({path:?})\n    \
             s.sendall(b'\\0AUTH EXTERNAL ' + str(os.getuid()).encode().hex().encode() + b'\\r\\n')\n    \
             r = s.recv(256)\n    \
             print('AUTH-OK' if r.startswith(b'OK ') else 'REFUSED ' + repr(r[:40]))\n\
         except OSError as e:\n    \
             print('ERR', e.errno)"
    )
}

/// busctl call into systemd-resolved: resolve "localhost" (answered locally by
/// resolved, so this works on hosts without a network too).
fn busctl_resolve() -> Vec<&'static str> {
    vec![
        "busctl",
        "--system",
        "--timeout=5",
        "call",
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
        "ResolveHostname",
        "isit",
        "0",
        "localhost",
        "0",
        "0",
    ]
}

fn host_can_resolve_over_dbus() -> bool {
    let argv = busctl_resolve();
    Command::new(argv[0])
        .args(&argv[1..])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn systemd_resolved_cannot_be_called_over_dbus() {
    if !Path::new(DBUS).exists() || !host_can_resolve_over_dbus() {
        return eprintln!("skipping: no system D-Bus / systemd-resolved / busctl on the host");
    }
    let mut args = vec!["--"];
    args.extend(busctl_resolve());
    let o = nullroute(&args);
    assert!(
        !o.status.success(),
        "busctl reached org.freedesktop.resolve1 from inside the sandbox: {o:?}"
    );
    assert!(
        err(&o).contains(&format!("blocked a connection to {DBUS}"))
            && err(&o).contains(&format!("--allow-socket {DBUS}")),
        "{}",
        err(&o)
    );
}

#[test]
fn system_bus_rejects_raw_sasl_handshake_inside() {
    if !Path::new(DBUS).exists() || host_python(&dbus_auth_script(DBUS)) != "AUTH-OK" {
        return eprintln!("skipping: no usable system D-Bus on the host");
    }
    let o = nullroute(&["--", "python3", "-c", &dbus_auth_script(DBUS)]);
    assert!(out(&o).starts_with("REFUSED"), "{o:?}");
    // The /var/run alias reaches the same decoy.
    let o = nullroute(&[
        "--",
        "python3",
        "-c",
        &dbus_auth_script("/var/run/dbus/system_bus_socket"),
    ]);
    assert_ne!(out(&o), "AUTH-OK", "{o:?}");
}

#[test]
fn allow_socket_opts_back_into_dbus() {
    if !Path::new(DBUS).exists() || host_python(&dbus_auth_script(DBUS)) != "AUTH-OK" {
        return eprintln!("skipping: no usable system D-Bus on the host");
    }
    let o = nullroute(&[
        "--allow-socket",
        DBUS,
        "--",
        "python3",
        "-c",
        &dbus_auth_script(DBUS),
    ]);
    assert_eq!(out(&o), "AUTH-OK", "{o:?}");
    assert!(!err(&o).contains("blocked a connection"), "{}", err(&o));
}

#[test]
fn dry_run_lists_dbus_as_hidden() {
    if !Path::new(DBUS).exists() {
        return eprintln!("skipping: no system D-Bus socket");
    }
    let o = nullroute(&["--dry-run", "--", "true"]);
    assert!(
        out(&o)
            .lines()
            .any(|l| l == format!("hidden socket: {DBUS}")),
        "{o:?}"
    );
    let o = nullroute(&["--dry-run", "--allow-socket", DBUS, "--", "true"]);
    assert!(!out(&o).contains(DBUS), "{o:?}");
}

/// Python: ask resolved over varlink to resolve "localhost"; print the reply
/// kind, or "masked" if the socket can't be used.
fn varlink_script(path: &str) -> String {
    format!(
        "import json, socket\n\
         s = socket.socket(socket.AF_UNIX)\n\
         s.settimeout(5)\n\
         try:\n    \
             s.connect({path:?})\n    \
             s.sendall(json.dumps({{'method': 'io.systemd.Resolve.ResolveHostname', 'parameters': {{'name': 'localhost'}}}}).encode() + b'\\0')\n    \
             r = b''\n    \
             while not r.endswith(b'\\0'):\n        \
                 c = s.recv(4096)\n        \
                 if not c: break\n        \
                 r += c\n    \
             print('ANSWERED' if b'addresses' in r else 'NOANSWER ' + repr(r[:60]))\n\
         except OSError:\n    \
             print('masked')"
    )
}

#[test]
fn varlink_resolution_fails_closed_in_a_bare_run() {
    if host_python(&varlink_script(VARLINK)) != "ANSWERED" {
        return eprintln!("skipping: systemd-resolved varlink not answering on the host");
    }
    // No --allow, no other flags: the plain sandbox must mask it too.
    let o = nullroute(&["--", "python3", "-c", &varlink_script(VARLINK)]);
    assert_eq!(out(&o), "masked", "{o:?}");
    // Even with every default-hidden socket allowed back in.
    let o = nullroute(&[
        "--allow-socket",
        DBUS,
        "--",
        "python3",
        "-c",
        &varlink_script(VARLINK),
    ]);
    assert_eq!(out(&o), "masked", "{o:?}");
    // And the host's socket is untouched.
    assert_eq!(host_python(&varlink_script(VARLINK)), "ANSWERED");
}

#[test]
fn nscd_is_masked_in_a_bare_run() {
    let Some(sock) = NSCD.iter().find(|p| Path::new(p).exists()) else {
        return eprintln!("skipping: no nscd socket");
    };
    let script = format!(
        "import socket\ns = socket.socket(socket.AF_UNIX)\ntry:\n    s.connect({sock:?}); print('OPEN')\nexcept OSError:\n    print('masked')"
    );
    let o = nullroute(&["--", "python3", "-c", &script]);
    assert_eq!(out(&o), "masked", "{o:?}");
}

#[test]
fn inspect_lists_masked_resolver_sockets() {
    let present: Vec<String> = std::iter::once(VARLINK)
        .chain(NSCD)
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .map(|p| p.display().to_string())
        .collect();
    let o = nullroute(&["--inspect", "--dry-run", "--", "true"]);
    let e = err(&o);
    if present.is_empty() {
        assert!(e.contains("    masked (resolver bypass): none\n"), "{e}");
        return;
    }
    for p in &present {
        assert!(
            e.contains(&format!("\n      {p}\n")),
            "{p} not listed:\n{e}"
        );
    }
    assert!(e.contains("  namespaces:      user, net, mount\n"), "{e}");
}
