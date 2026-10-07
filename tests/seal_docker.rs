//! --seal-docker: the command can use Docker, but containers it starts get no
//! network. Skipped when there's no reachable Docker daemon or no alpine image.

use std::process::{Command, Output};

fn docker_ok() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_alpine() -> bool {
    Command::new("docker")
        .args(["image", "inspect", "alpine"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn nr(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .output()
        .expect("launch nullroute")
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn sealed_container_has_no_network_but_runs() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping: docker/alpine unavailable");
    }
    // NetworkMode none means wget fails but the container still executes.
    let o = nr(&[
        "--seal-docker",
        "--",
        "docker",
        "run",
        "--rm",
        "alpine",
        "sh",
        "-c",
        "wget -q -T5 -O- http://1.1.1.1 >/dev/null 2>&1 && echo HASNET || echo NONET",
    ]);
    assert_eq!(out(&o), "NONET", "{o:?}");
}

#[test]
fn requested_network_is_overridden_to_none() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    let name = format!("nr-seal-{}", std::process::id());
    let script = format!(
        "docker run -d --name {name} --network host alpine sleep 20 >/dev/null; \
         docker inspect -f '{{{{.HostConfig.NetworkMode}}}}' {name}; docker rm -f {name} >/dev/null"
    );
    let o = nr(&["--seal-docker", "--", "sh", "-c", &script]);
    assert_eq!(out(&o), "none", "{o:?}");
}

#[test]
fn network_connect_is_refused() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    let name = format!("nr-conn-{}", std::process::id());
    let script = format!(
        "docker run -d --name {name} alpine sleep 20 >/dev/null; \
         docker network connect bridge {name}; echo rc=$?; docker rm -f {name} >/dev/null"
    );
    let o = nr(&["--seal-docker", "--", "sh", "-c", &script]);
    assert!(
        out(&o).contains("rc=1"),
        "network connect should fail: {o:?}"
    );
}

#[test]
fn sealed_create_is_reported_as_rewritten_and_strict_passes() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    let dir = std::env::temp_dir().join(format!("nr-seal-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let json = dir.join("r.json");
    let o = nr(&[
        "--seal-docker",
        "--strict",
        "--report-json",
        json.to_str().unwrap(),
        "--",
        "docker",
        "run",
        "--rm",
        "alpine",
        "true",
    ]);
    let body = std::fs::read_to_string(&json).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o.status.code(), Some(0), "a rewrite isn't a block: {o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("nullroute: rewrote") && err.contains("rewritten  containers/create"),
        "{err}"
    );
    assert!(!err.contains("nullroute: blocked"), "{err}");
    assert!(!err.contains("--strict: failing"), "{err}");
    assert!(body.contains("\"strict_failed\": false"), "{body}");
    assert!(body.contains("\"blocked\": []"), "{body}");
    let (_, rewritten) = body.split_once("\"rewritten\"").unwrap();
    assert!(
        rewritten.contains("\"kind\": \"rewritten\", \"target\": \"containers/create\""),
        "{body}"
    );
}

#[test]
fn strict_still_fails_on_a_real_docker_block() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    let name = format!("nr-strict-{}", std::process::id());
    // network connect is refused (a block); the script itself still exits 0.
    let script = format!(
        "docker run -d --name {name} alpine sleep 20 >/dev/null; \
         docker network connect bridge {name} 2>/dev/null; docker rm -f {name} >/dev/null; true"
    );
    let o = nr(&["--seal-docker", "--strict", "--", "sh", "-c", &script]);
    assert_eq!(o.status.code(), Some(1), "strict should fail: {o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("--strict: failing") && err.contains("docker  networks/connect"),
        "{err}"
    );
    assert!(err.contains("rewritten  containers/create"), "{err}");
}

/// Python: on ONE connection to docker.sock, send each probe and read its
/// response, then send a create asking for host networking. Prints the
/// create's status line.
fn probe_then_create_script(name: &str, probes: &[(&str, &str)], pipelined: bool) -> String {
    let probes: Vec<String> = probes
        .iter()
        .map(|(m, p)| format!("({m:?}, {p:?})"))
        .collect();
    format!(
        "import json, socket\n\
         s = socket.socket(socket.AF_UNIX); s.settimeout(20)\n\
         s.connect('/var/run/docker.sock')\n\
         buf = b''\n\
         def req(method, path, body):\n    \
             b = json.dumps(body).encode()\n    \
             return (f'{{method}} {{path}} HTTP/1.1\\r\\nHost: docker\\r\\nContent-Type: application/json\\r\\nContent-Length: {{len(b)}}\\r\\n\\r\\n').encode() + b\n\
         def response():\n    \
             global buf\n    \
             while b'\\r\\n\\r\\n' not in buf:\n        \
                 c = s.recv(65536)\n        \
                 if not c: raise SystemExit('closed: ' + repr(buf[:200]))\n        \
                 buf += c\n    \
             head, buf = buf.split(b'\\r\\n\\r\\n', 1)\n    \
             lines = head.decode().split('\\r\\n')\n    \
             n = next((int(l.split(':')[1]) for l in lines if l.lower().startswith('content-length:')), 0)\n    \
             while len(buf) < n:\n        \
                 buf += s.recv(65536)\n    \
             buf = buf[n:]\n    \
             return lines[0]\n\
         probes = [{probes}]\n\
         create = req('POST', '/containers/create?name={name}', {{'Image': 'alpine', 'Cmd': ['true'], 'HostConfig': {{'NetworkMode': 'host'}}}})\n\
         if {pipelined}:\n    \
             s.sendall(b''.join(req(m, p, {{}}) for m, p in probes) + create)\n    \
             for _ in probes: print('probe', response())\n\
         else:\n    \
             for m, p in probes:\n        \
                 s.sendall(req(m, p, {{}})); print('probe', response())\n    \
             s.sendall(create)\n\
         print('create', response())",
        probes = probes.join(", "),
        pipelined = if pipelined { "True" } else { "False" },
    )
}

fn network_mode(name: &str) -> String {
    let o = Command::new("docker")
        .args(["inspect", "-f", "{{.HostConfig.NetworkMode}}", name])
        .output()
        .unwrap();
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
    out(&o)
}

#[test]
fn create_after_probe_on_reused_connection_is_still_forced_to_none() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    // A 404 from an exec/attach-looking path used to switch the proxy to a raw
    // relay, letting the next request on the connection through unrewritten.
    // (Attach to a missing container isn't used: the daemon hijacks before the
    // lookup and closes after its unframed 404, so nothing can follow it.)
    let probes = [
        ("POST", "/exec/nullroute-no-such-exec/start"),
        ("GET", "/v1.43/exec/nullroute-no-such-exec/json"),
        ("GET", "/_ping"),
    ];
    for (i, pipelined) in [false, true].into_iter().enumerate() {
        let name = format!("nr-probe-{}-{i}", std::process::id());
        let o = nr(&[
            "--seal-docker",
            "--",
            "python3",
            "-c",
            &probe_then_create_script(&name, &probes, pipelined),
        ]);
        let text = out(&o);
        assert_eq!(text.matches("probe HTTP/1.1 404").count(), 2, "{o:?}");
        assert_eq!(text.matches("probe HTTP/1.1 200").count(), 1, "{o:?}");
        assert!(text.contains("create HTTP/1.1 201"), "{o:?}");
        assert_eq!(network_mode(&name), "none", "pipelined={pipelined}: {o:?}");
    }
}

#[test]
fn dry_run_distinguishes_sealed_from_hidden() {
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--seal-docker", "--dry-run", "--", "true"])
        .output()
        .unwrap();
    let text = out(&o);
    // On a host with Docker, docker.sock is sealed not hidden.
    if docker_ok() {
        assert!(text.contains("sealed docker socket:"), "{text}");
        assert!(
            !text
                .lines()
                .any(|l| l.starts_with("hidden socket:") && l.contains("docker.sock")),
            "{text}"
        );
    }
}

fn have_buildx() -> bool {
    Command::new("docker")
        .args(["buildx", "version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A build context whose RUN step reports whether it had network.
fn net_probe_context(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nr-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Dockerfile"),
        "FROM alpine\nRUN wget -q -T5 -O- http://1.1.1.1 >/dev/null 2>&1 && echo HASNET || echo NONET\n",
    )
    .unwrap();
    dir
}

#[test]
fn classic_build_with_host_network_is_forced_to_none() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping: docker/alpine unavailable");
    }
    let dir = net_probe_context("build");
    let image = format!("nr-build-{}", std::process::id());
    // --network host arrives as networkmode=host in the /build query string.
    let script = format!(
        "DOCKER_BUILDKIT=0 docker build --network host --no-cache --force-rm -t {image} {}",
        dir.display()
    );
    // --strict: forcing the build onto no network is a rewrite, not a block.
    let o = nr(&["--seal-docker", "--strict", "--", "sh", "-c", &script]);
    let _ = Command::new("docker").args(["rmi", "-f", &image]).output();
    let _ = std::fs::remove_dir_all(&dir);
    let text = out(&o);
    assert!(o.status.success(), "a rewrite isn't a block: {o:?}");
    // (The step's command line is echoed too, so match whole lines.)
    let said = |w: &str| text.lines().any(|l| l.trim() == w);
    assert!(said("NONET") && !said("HASNET"), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("forced networkmode=none"), "{err}");
    assert!(err.contains("rewritten  build"), "{err}");
    assert!(!err.contains("--strict: failing"), "{err}");
}

#[test]
fn buildkit_build_is_refused_without_side_effects() {
    if !docker_ok() || !have_alpine() || !have_buildx() {
        return eprintln!("skipping: docker/alpine/buildx unavailable");
    }
    let dir = net_probe_context("buildx");
    let image = format!("nr-buildx-{}", std::process::id());
    let ctx = dir.display().to_string();
    let o = nr(&[
        "--seal-docker",
        "--",
        "docker",
        "buildx",
        "build",
        "--builder",
        "default",
        "--no-cache",
        "-t",
        &image,
        &ctx,
    ]);
    let _ = Command::new("docker").args(["rmi", "-f", &image]).output();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!o.status.success(), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    // buildx prints the gRPC error nullroute answers with...
    assert!(err.contains("DOCKER_BUILDKIT=0"), "{err}");
    // ...instead of silently falling back to a docker-container builder.
    assert!(!err.contains("booting buildkit"), "{err}");
}

#[test]
fn swarm_service_create_is_blocked() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    let name = format!("nr-svc-{}", std::process::id());
    let o = nr(&[
        "--seal-docker",
        "--",
        "docker",
        "service",
        "create",
        "--no-resolve-image",
        "--name",
        &name,
        "alpine",
        "true",
    ]);
    assert!(!o.status.success(), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("nullroute blocked a Docker Swarm service"),
        "{err}"
    );
    // Recorded in the report, whether or not this daemon is a swarm manager.
    assert!(
        err.contains("services") && err.contains("swarm service tasks get networks"),
        "{err}"
    );
}

#[test]
fn swarm_and_build_paths_are_matched_however_they_are_spelled() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    // Raw requests on one connection: an encoded/dotted services create, a
    // non-canonical classic build with networkmode=host, then a ping.
    let script = r#"
import socket
s = socket.socket(socket.AF_UNIX); s.settimeout(20)
s.connect('/var/run/docker.sock')
def send(method, path, body=b'', extra=''):
    s.sendall(f'{method} {path} HTTP/1.1\r\nHost: docker\r\n{extra}Content-Length: {len(body)}\r\n\r\n'.encode() + body)
    buf = b''
    while b'\r\n\r\n' not in buf:
        c = s.recv(65536)
        if not c: raise SystemExit('closed')
        buf += c
    head, rest = buf.split(b'\r\n\r\n', 1)
    lines = head.decode().split('\r\n')
    n = next((int(l.split(':')[1]) for l in lines if l.lower().startswith('content-length:')), 0)
    while len(rest) < n: rest += s.recv(65536)
    print(method, path, lines[0])
send('POST', '/v1.43//services/%2E/create', b'{}', 'Content-Type: application/json\r\n')
send('POST', '/v1.43/swarm%2Fjoin', b'{}', 'Content-Type: application/json\r\n')
send('POST', '/v1.43/build?version=2', b'', 'Content-Type: application/x-tar\r\n')
"#;
    let o = nr(&["--seal-docker", "--", "python3", "-c", script]);
    let text = out(&o);
    assert_eq!(text.matches("HTTP/1.1 403").count(), 3, "{o:?}");
}

// ---- --seal-docker-pulls ------------------------------------------------------
// None of these need registry access: refused pulls never reach the daemon,
// and the one let through goes to a closed port on this machine.

#[test]
fn seal_docker_pulls_without_seal_docker_is_a_usage_error() {
    for mode in ["any", "allowlisted", "none"] {
        let o = nr(&["--seal-docker-pulls", mode, "--", "true"]);
        assert_eq!(o.status.code(), Some(2), "{mode}: {o:?}");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(
            err.contains("nullroute: --seal-docker-pulls") && err.contains("--seal-docker"),
            "{err}"
        );
    }
    let o = nr(&[
        "--seal-docker",
        "--seal-docker-pulls",
        "sometimes",
        "--",
        "true",
    ]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
}

#[test]
fn allowlisted_refuses_a_pull_from_a_registry_not_in_allow() {
    if !docker_ok() {
        return eprintln!("skipping: docker unavailable");
    }
    let o = nr(&[
        "--seal-docker",
        "--seal-docker-pulls",
        "allowlisted",
        "--",
        "docker",
        "pull",
        "ghcr.io/nonexistent/x",
    ]);
    assert!(!o.status.success(), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    // The Docker CLI prints nullroute's refusal...
    assert!(
        err.contains("Error response from daemon: nullroute blocked pulling ghcr.io/nonexistent/x: --seal-docker-pulls=allowlisted"),
        "{err}"
    );
    assert!(err.contains("Add --allow ghcr.io"), "{err}");
    // ...and it's a docker block in the report.
    assert!(
        err.contains("docker  pull ghcr.io/nonexistent/x")
            && err.contains("ghcr.io not in --allow; --seal-docker-pulls=allowlisted"),
        "{err}"
    );
}

#[test]
fn allowlisted_lets_a_bridged_localhost_registry_through() {
    if !docker_ok() {
        return eprintln!("skipping: docker unavailable");
    }
    // localhost:1 is allowed by --port 1; nothing listens there, so the daemon
    // itself fails the pull (proof it got the request).
    let o = nr(&[
        "--seal-docker",
        "--seal-docker-pulls",
        "allowlisted",
        "--port",
        "1",
        "--",
        "docker",
        "pull",
        "localhost:1/nullroute-no-such-image",
    ]);
    assert!(!o.status.success(), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("nullroute blocked"), "{err}");
    assert!(!err.contains("--seal-docker-pulls"), "{err}");
    assert!(err.contains("Error response from daemon"), "{err}");
}

#[test]
fn none_still_runs_an_image_that_is_already_present() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping: docker/alpine unavailable");
    }
    // docker run only creates the container (no pull request) when the image
    // is there; --strict proves nothing was refused.
    let o = nr(&[
        "--seal-docker",
        "--seal-docker-pulls",
        "none",
        "--strict",
        "--",
        "docker",
        "run",
        "--rm",
        "alpine",
        "echo",
        "ran",
    ]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(out(&o), "ran", "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("nullroute blocked"), "{err}");
}

#[test]
fn strict_fails_on_a_blocked_pull() {
    if !docker_ok() {
        return eprintln!("skipping: docker unavailable");
    }
    // The script swallows the failed pull and exits 0; --strict doesn't.
    let o = nr(&[
        "--seal-docker",
        "--seal-docker-pulls",
        "none",
        "--strict",
        "--",
        "sh",
        "-c",
        "docker pull ghcr.io/nonexistent/x; docker pull alpine; true",
    ]);
    assert_eq!(o.status.code(), Some(1), "strict should fail: {o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("--strict: failing"), "{err}");
    assert!(
        err.contains("--seal-docker-pulls=none doesn't let the Docker daemon"),
        "{err}"
    );
    assert!(err.contains("docker  pull ghcr.io/nonexistent/x"), "{err}");
    // Docker CLIs differ in how they name a Hub image to the daemon: older
    // ones send `alpine` (whatever was typed), newer ones
    // docker.io/library/alpine. Both are Docker Hub to nullroute.
    assert!(
        err.contains("docker  pull alpine")
            || err.contains("docker  pull docker.io/library/alpine"),
        "{err}"
    );
}

#[test]
fn inspect_and_dry_run_show_the_pull_policy_for_sealed_sockets() {
    // A stand-in socket, so this doesn't need Docker.
    let dir = std::env::temp_dir().join(format!("nr-pulls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("docker.sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--inspect", "--dry-run", "--seal-docker-socket"])
        .arg(&sock)
        .args(["--seal-docker-pulls", "allowlisted", "--", "true"])
        .output()
        .unwrap();
    let plain = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--inspect", "--dry-run", "--", "true"])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("\n  docker pulls:    allowlisted (pulls, logins and lookups only from registries in --allow"),
        "{err}"
    );
    assert!(out(&o).contains("docker pulls: allowlisted"), "{o:?}");
    // Nothing sealed, nothing shown (unless this host has a Docker socket,
    // which --seal-docker isn't asking for here either).
    assert!(
        !String::from_utf8_lossy(&plain.stderr).contains("docker pulls"),
        "{plain:?}"
    );
    assert!(!out(&plain).contains("docker pulls"), "{plain:?}");
}
