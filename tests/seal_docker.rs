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
