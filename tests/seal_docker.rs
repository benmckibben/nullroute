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
fn report_and_strict_flag_a_sealed_create() {
    if !docker_ok() || !have_alpine() {
        return eprintln!("skipping");
    }
    let o = nr(&[
        "--seal-docker",
        "--strict",
        "--",
        "docker",
        "run",
        "--rm",
        "alpine",
        "true",
    ]);
    assert_eq!(o.status.code(), Some(1), "strict should fail: {o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("docker") && err.contains("containers/create"),
        "{err}"
    );
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
