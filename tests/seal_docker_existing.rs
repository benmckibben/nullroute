//! --seal-docker and containers that already exist: the command may use the
//! ones it created (they have no network), but not run code in, start, or
//! attach to one that has a network. Skipped loudly when there's no reachable
//! Docker daemon or no alpine image.

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

fn docker(args: &[&str]) -> Output {
    Command::new("docker").args(args).output().expect("docker")
}

fn have_docker() -> bool {
    let ok = |args: &[&str]| docker(args).status.success();
    ok(&["version", "--format", "{{.Server.Version}}"]) && ok(&["image", "inspect", "alpine"])
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
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// A container removed when dropped.
struct Ctr(String);
impl Ctr {
    fn name(tag: &str) -> String {
        format!("nr-existing-{tag}-{}", std::process::id())
    }
    /// A running container on the default bridge network, started outside the
    /// sandbox: what the command must not be able to use.
    fn bridged(tag: &str) -> Ctr {
        let name = Ctr::name(tag);
        let _ = docker(&["rm", "-f", &name]);
        let o = docker(&["run", "-d", "--name", &name, "alpine", "sleep", "120"]);
        assert!(o.status.success(), "{o:?}");
        Ctr(name)
    }
    fn started_at(&self) -> String {
        out(&docker(&["inspect", "-f", "{{.State.StartedAt}}", &self.0]))
    }
}
impl Drop for Ctr {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.0]);
    }
}

/// The host's address as seen from the default bridge network, if there is one.
fn bridge_gateway() -> Option<String> {
    let o = docker(&[
        "network",
        "inspect",
        "bridge",
        "-f",
        "{{(index .IPAM.Config 0).Gateway}}",
    ]);
    let ip = out(&o);
    (o.status.success() && !ip.is_empty()).then_some(ip)
}

/// Did anything connect to `l` and send data within `wait`?
fn received(l: &TcpListener, wait: Duration) -> Option<String> {
    l.set_nonblocking(true).unwrap();
    let end = Instant::now() + wait;
    while Instant::now() < end {
        if let Ok((mut c, _)) = l.accept() {
            c.set_nonblocking(false).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap_or(0);
            return Some(String::from_utf8_lossy(&buf[..n]).trim().to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

macro_rules! need_docker {
    ($name:literal) => {
        if !have_docker() {
            return eprintln!(concat!("skipping ", $name, ": docker/alpine unavailable"));
        }
    };
}

/// The reproduction from the field: `docker exec` into a container on the
/// bridge network ran a command with a network, and its output reached a
/// listener on the host.
#[test]
fn exec_into_a_container_with_a_network_is_refused() {
    need_docker!("exec_into_a_container_with_a_network_is_refused");
    let Some(gateway) = bridge_gateway() else {
        return eprintln!("skipping exec_into_a_container_with_a_network_is_refused: no bridge");
    };
    let victim = Ctr::bridged("exec");
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let send = format!("echo from-container | nc -w3 {gateway} {port}");

    // Control: without nullroute the container can reach the host listener.
    // (If not, a firewall is in the way and the checks below prove less.)
    docker(&["exec", &victim.0, "sh", "-c", &send]);
    let reachable = received(&listener, Duration::from_secs(3)).is_some();
    if !reachable {
        eprintln!(
            "note: this host's containers can't reach {gateway}:{port}; only the refusal is checked"
        );
    }

    let o = nr(&[
        "--seal-docker",
        "--",
        "docker",
        "exec",
        &victim.0,
        "sh",
        "-c",
        &send,
    ]);
    assert!(!o.status.success(), "exec should be refused: {o:?}");
    let e = err(&o);
    assert!(
        e.contains("--seal-docker-allow-existing") && e.contains("NetworkMode=bridge"),
        "the error should name the flag and the reason: {e}"
    );
    assert!(
        e.contains("docker  containers/exec"),
        "reported as a block: {e}"
    );
    assert_eq!(
        received(&listener, Duration::from_secs(2)),
        None,
        "data reached the host"
    );

    // The opt-out is what it says: now the command runs, with the network.
    let o = nr(&[
        "--seal-docker",
        "--seal-docker-allow-existing",
        "--",
        "docker",
        "exec",
        &victim.0,
        "sh",
        "-c",
        &send,
    ]);
    assert!(o.status.success(), "{o:?}");
    if reachable {
        assert_eq!(
            received(&listener, Duration::from_secs(3)).as_deref(),
            Some("from-container"),
            "with the opt-out the command is not sealed"
        );
    }
}

#[test]
fn start_restart_unpause_attach_and_exec_on_a_container_with_a_network_are_refused() {
    need_docker!("start_restart_unpause_attach_and_exec");
    let victim = Ctr::bridged("start");
    let before = victim.started_at();
    let script = format!(
        "n={0}\n\
         for c in 'restart -t 0' start unpause 'attach --no-stdin'; do docker $c $n >/dev/null 2>&1; echo \"$c: $?\"; done\n\
         docker exec $n true >/dev/null 2>&1; echo \"exec: $?\"",
        victim.0
    );
    let o = nr(&["--seal-docker", "--", "sh", "-c", &script]);
    for op in [
        "restart -t 0",
        "start",
        "unpause",
        "attach --no-stdin",
        "exec",
    ] {
        let line = out(&o)
            .lines()
            .find(|l| l.starts_with(&format!("{op}: ")))
            .map(str::to_string)
            .unwrap_or_default();
        assert!(
            !line.is_empty() && !line.ends_with(": 0"),
            "{op} should fail: {line:?}\n{o:?}"
        );
    }
    let e = err(&o);
    for what in ["restart", "start", "unpause", "attach", "exec"] {
        assert!(
            e.contains(&format!(
                "refused containers/{what} (container {}",
                victim.0
            )),
            "{what}: {e}"
        );
    }
    assert_eq!(victim.started_at(), before, "the container was restarted");
}

#[test]
fn reading_about_a_container_with_a_network_still_works() {
    need_docker!("reading_about_a_container_with_a_network_still_works");
    let victim = Ctr::bridged("read");
    let script = format!(
        "docker inspect -f '{{{{.State.Status}}}}' {0}; docker ps -q --filter name={0} | wc -l; \
         docker logs {0} >/dev/null && echo logs-ok; docker top {0} >/dev/null && echo top-ok; \
         docker diff {0} >/dev/null && echo diff-ok; docker stop -t 1 {0} >/dev/null && echo stop-ok; \
         docker rm {0} >/dev/null && echo rm-ok",
        victim.0
    );
    let o = nr(&["--seal-docker", "--", "sh", "-c", &script]);
    assert_eq!(
        out(&o),
        "running\n1\nlogs-ok\ntop-ok\ndiff-ok\nstop-ok\nrm-ok",
        "{o:?}"
    );
}

#[test]
fn containers_made_in_the_sandbox_can_be_started_exec_ed_and_restarted() {
    need_docker!("containers_made_in_the_sandbox");
    let name = Ctr::name("own");
    let _guard = Ctr(name.clone());
    let script = format!(
        "docker create --name {0} --network host alpine sleep 60 >/dev/null && docker start {0} >/dev/null && echo started; \
         docker exec {0} sh -c 'echo exec-ok; wc -l < /proc/net/dev'; \
         docker restart -t 0 {0} >/dev/null && echo restarted; \
         docker exec {0} true && echo exec-again; \
         docker run --rm alpine echo run-ok",
        name
    );
    let o = nr(&["--seal-docker", "--", "sh", "-c", &script]);
    // /proc/net/dev: two header lines and one interface (lo).
    assert_eq!(
        out(&o),
        "started\nexec-ok\n3\nrestarted\nexec-again\nrun-ok",
        "{o:?}"
    );
    // Created in one run, used in the next: it has no network, which is what counts.
    let o = nr(&[
        "--seal-docker",
        "--",
        "docker",
        "exec",
        &name,
        "echo",
        "second-run",
    ]);
    assert_eq!(out(&o), "second-run", "{o:?}");
}

#[test]
fn the_opt_out_flag_needs_a_sealed_socket() {
    let o = nr(&["--seal-docker-allow-existing", "--", "true"]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(
        err(&o).contains("--seal-docker-allow-existing only applies"),
        "{}",
        err(&o)
    );
}

/// Talk HTTP to the sealed socket from inside, with a real daemon behind it.
/// Python, because the point is what the raw bytes do.
fn inside(script: &str) -> Output {
    let socket = ["/var/run/docker.sock", "/run/docker.sock"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or("/var/run/docker.sock");
    nr(&[
        "--seal-docker",
        "--",
        "python3",
        "-c",
        &format!("SOCK = {socket:?}\n{script}"),
    ])
}

#[test]
fn expect_continue_and_the_final_response_both_reach_the_client() {
    need_docker!("expect_continue");
    let name = Ctr::name("expect");
    let _guard = Ctr(name.clone());
    let script = format!(
        r#"
import socket, json
c = socket.socket(socket.AF_UNIX); c.settimeout(10); c.connect(SOCK)
body = json.dumps({{"Image": "alpine", "Cmd": ["true"]}}).encode()
c.sendall(("POST /containers/create?name={name} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\n"
           "Expect: 100-continue\r\nContent-Length: %d\r\n\r\n" % len(body)).encode())
buf = b""
while b"\r\n\r\n" not in buf:
    buf += c.recv(4096)
assert buf.startswith(b"HTTP/1.1 100"), buf
rest = buf.split(b"\r\n\r\n", 1)[1]
c.sendall(body)
while b"\r\n\r\n" not in rest:
    rest += c.recv(4096)
print(rest.split(b"\r\n", 1)[0].decode())
# The same connection answers the next request with its own response.
c.sendall(b"GET /_ping HTTP/1.1\r\nHost: docker\r\n\r\n")
more = rest.split(b"\r\n\r\n", 1)[1]
while b"OK" not in more:
    more += c.recv(4096)
print("next request answered")
"#
    );
    let o = inside(&script);
    assert_eq!(
        out(&o),
        "HTTP/1.1 201 Created\nnext request answered",
        "{o:?}"
    );
}

#[test]
fn oversized_request_heads_get_431() {
    need_docker!("oversized_request_heads");
    let o = inside(
        r#"
import socket
c = socket.socket(socket.AF_UNIX); c.settimeout(10); c.connect(SOCK)
# The daemon may close the connection before sendall finishes sending all
# the oversized headers. Catch the error and read whatever response has
# already arrived.
try:
    c.sendall(b"GET /_ping HTTP/1.1\r\nHost: docker\r\n" + (b"X-Fill: " + b"a" * 1000 + b"\r\n") * 40 + b"\r\n")
except (BrokenPipeError, ConnectionResetError):
    pass
buf = b""
while b"\r\n" not in buf:
    chunk = c.recv(4096)
    if not chunk:
        break
    buf += chunk
print(buf.split(b"\r\n", 1)[0].decode())
"#,
    );
    assert_eq!(
        out(&o),
        "HTTP/1.1 431 Request Header Fields Too Large",
        "{o:?}"
    );
}
