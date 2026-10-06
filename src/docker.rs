//! --seal-docker: let the command use Docker, but force every container it
//! starts onto no network.
//!
//! Without this, Docker is all-or-nothing: hidden by default (the command can't
//! use it), or --allow-socket (it can, and the containers it starts get full
//! host network, straight past the sandbox). --seal-docker is the middle path
//! for test suites that spin up containers: the Docker CLI works, but nullroute
//! rewrites each container-create request to `NetworkMode: "none"` and refuses
//! requests that would attach a network afterwards.
//!
//! It works like socket hiding (see hide.rs): a decoy Unix socket is bind-mounted
//! over docker.sock inside the sandbox's mount namespace. The difference is what
//! the decoy does. Instead of answering 403, it proxies to the real daemon,
//! which nullroute can still reach because the bind-mount only exists in the
//! child's mount namespace. On the way through it parses each HTTP request:
//!
//! - `POST /.../containers/create`: force HostConfig.NetworkMode = "none" and
//!   drop NetworkingConfig, then fix Content-Length.
//! - `POST /.../networks/{id}/connect`: refuse with 403 (it would undo the above).
//! - anything else: forwarded unchanged, then the connection becomes a plain
//!   relay, so attach/exec streaming and keep-alive still work.
//!
//! Scope: this is not a Docker security boundary. It stops the common ways a
//! container gets a network through the CLI; it does not try to cover every
//! Docker API path, and --privileged containers can still escape. It's "CI
//! tests can use throwaway containers without those containers phoning home",
//! not "run hostile images safely".

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use crate::report::{Kind, Report};

const MAX_HEAD: usize = 32 * 1024;
/// Container-create bodies are small; cap to avoid buffering a huge upload.
const MAX_BODY: usize = 4 * 1024 * 1024;

pub const SEAL_REASON: &str = "sealed with --seal-docker: containers forced to no network";

/// Handle one connection to the sealed docker.sock. `upstream` is the real
/// socket path (still reachable from nullroute's mount namespace).
pub fn handle(client: UnixStream, upstream: &Path, report: &Arc<Report>) {
    if let Err(e) = proxy(client, upstream, report) {
        // Best-effort; the client usually just sees a closed connection.
        if e.kind() != io::ErrorKind::BrokenPipe && e.kind() != io::ErrorKind::UnexpectedEof {
            eprintln!("nullroute: --seal-docker: {e}");
        }
    }
}

fn proxy(client: UnixStream, upstream: &Path, report: &Arc<Report>) -> io::Result<()> {
    let mut client_r = BufReader::new(client.try_clone()?);
    let mut client_w = client;
    let up = UnixStream::connect(upstream)?;
    let mut up_r = BufReader::new(up.try_clone()?);
    let mut up_w = up;

    // Docker reuses one connection for many requests (ping, create, start,
    // attach...). Handle each in turn until the connection is hijacked (attach/
    // exec streams) or closed, then fall back to a raw two-way pipe.
    loop {
        let Some(req) = read_request(&mut client_r)? else {
            return Ok(()); // client closed cleanly
        };

        // Refuse attaching a network to an existing container; it would undo sealing.
        if req.is_network_connect() {
            report.record(Kind::Docker, "networks/connect", "would attach a network to a container", || {
                "nullroute: --seal-docker: refused a request to connect a container to a network".into()
            });
            write_403(
                &mut client_w,
                "nullroute blocked docker network connect: it would give a container network access that --seal-docker removed.",
            )?;
            continue;
        }

        let is_create = req.method == "POST" && req.path_no_query().ends_with("/containers/create");
        let body = if is_create {
            rewrite_create(&req.body, report)
        } else {
            req.body.clone()
        };
        up_w.write_all(&req.render_head(body.len()))?;
        up_w.write_all(&body)?;

        // Attach/exec streams and WebSocket upgrades turn the connection into a
        // raw bidirectional pipe; after forwarding the response head we stop parsing.
        let may_hijack = req.path.contains("/attach")
            || req.path.contains("/exec/")
            || req.path.contains("/containers/")
                && req.path.ends_with("/start")
                && req.headers_has_upgrade();

        let resp = read_response_head(&mut up_r)?;
        client_w.write_all(&resp.head)?;
        if resp.is_hijack() || may_hijack {
            // Hand over whatever each side has buffered, then pipe raw until close.
            let c_buf = client_r.buffer().to_vec();
            let u_buf = up_r.buffer().to_vec();
            if !u_buf.is_empty() {
                client_w.write_all(&u_buf)?;
            }
            if !c_buf.is_empty() {
                up_w.write_all(&c_buf)?;
            }
            relay(client_w, up_w);
            return Ok(());
        }
        // Copy the response body by its framing, then loop for the next request.
        copy_body(&mut up_r, &mut client_w, &resp)?;
        if resp.closes || req.wants_close() {
            // No keep-alive: drain nothing more, just pipe anything left and stop.
            relay(client_w, up_w);
            return Ok(());
        }
    }
}

/// A parsed response head plus how its body is framed.
struct Response {
    head: Vec<u8>,
    status: u16,
    content_length: Option<usize>,
    chunked: bool,
    closes: bool,
    upgrade: bool,
}

impl Response {
    fn is_hijack(&self) -> bool {
        self.status == 101 || self.upgrade
    }
}

fn read_response_head(r: &mut BufReader<UnixStream>) -> io::Result<Response> {
    let mut head = Vec::new();
    let mut status = 0u16;
    let mut content_length = None;
    let mut chunked = false;
    let mut closes = false;
    let mut upgrade = false;
    let mut first = true;
    loop {
        let mut line = Vec::new();
        let n = r.read_until(b'\n', &mut line)?;
        if n == 0 {
            if head.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            break;
        }
        head.extend_from_slice(&line);
        let text = String::from_utf8_lossy(&line);
        let trimmed = text.trim_end();
        if first {
            status = trimmed
                .split(' ')
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            first = false;
        } else if trimmed.is_empty() {
            break;
        } else if let Some((name, value)) = trimmed.split_once(':') {
            let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
            match name.as_str() {
                "content-length" => content_length = value.parse().ok(),
                "transfer-encoding" if value.eq_ignore_ascii_case("chunked") => chunked = true,
                "connection" if value.eq_ignore_ascii_case("close") => closes = true,
                "connection" if value.eq_ignore_ascii_case("upgrade") => upgrade = true,
                _ => {}
            }
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::other("response head too large"));
        }
    }
    Ok(Response {
        head,
        status,
        content_length,
        chunked,
        closes,
        upgrade,
    })
}

/// Stream a response body from upstream to the client per its framing.
fn copy_body(r: &mut BufReader<UnixStream>, w: &mut UnixStream, resp: &Response) -> io::Result<()> {
    // No body for 1xx, 204, 304.
    if resp.status / 100 == 1 || resp.status == 204 || resp.status == 304 {
        return Ok(());
    }
    if resp.chunked {
        loop {
            let mut size_line = Vec::new();
            if r.read_until(b'\n', &mut size_line)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            w.write_all(&size_line)?;
            let hex = String::from_utf8_lossy(&size_line);
            let size =
                usize::from_str_radix(hex.trim().split(';').next().unwrap_or("0").trim(), 16)
                    .map_err(|_| io::Error::other("bad chunk size"))?;
            // size bytes + trailing CRLF (or, for the last chunk, trailers + CRLF).
            let mut remaining = size + 2;
            let mut buf = [0u8; 8192];
            while remaining > 0 {
                let want = remaining.min(buf.len());
                let got = r.read(&mut buf[..want])?;
                if got == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                w.write_all(&buf[..got])?;
                remaining -= got;
            }
            if size == 0 {
                return Ok(());
            }
        }
    }
    if let Some(len) = resp.content_length {
        let mut remaining = len;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(buf.len());
            let got = r.read(&mut buf[..want])?;
            if got == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            w.write_all(&buf[..got])?;
            remaining -= got;
        }
        return Ok(());
    }
    // No framing: body runs until the connection closes.
    io::copy(r, w)?;
    Err(io::ErrorKind::UnexpectedEof.into()) // signals "connection ended"
}

struct Request {
    method: String,
    path: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn path_no_query(&self) -> &str {
        self.path.split('?').next().unwrap_or(&self.path)
    }

    /// `POST /networks/{id}/connect`, ignoring any query string.
    fn is_network_connect(&self) -> bool {
        let path = self.path_no_query();
        self.method == "POST" && path.contains("/networks/") && path.ends_with("/connect")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn wants_close(&self) -> bool {
        self.header("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"))
    }

    fn headers_has_upgrade(&self) -> bool {
        self.header("connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"))
    }

    /// Rebuild the request head, replacing Content-Length with `body_len`.
    fn render_head(&self, body_len: usize) -> Vec<u8> {
        let mut s = format!("{} {} {}\r\n", self.method, self.path, self.version);
        let mut wrote_len = false;
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-length") {
                s.push_str(&format!("Content-Length: {body_len}\r\n"));
                wrote_len = true;
            } else {
                s.push_str(&format!("{name}: {value}\r\n"));
            }
        }
        if !wrote_len && body_len > 0 {
            s.push_str(&format!("Content-Length: {body_len}\r\n"));
        }
        s.push_str("\r\n");
        s.into_bytes()
    }
}

fn read_request(reader: &mut BufReader<UnixStream>) -> io::Result<Option<Request>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    if method.is_empty() || path.is_empty() {
        return Err(io::Error::other("malformed request line"));
    }

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    let mut total = line.len();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        total += h.len();
        if total > MAX_HEAD {
            return Err(io::Error::other("request head too large"));
        }
        let trimmed = h.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let (name, value) = (name.trim().to_string(), value.trim().to_string());
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .parse()
                    .map_err(|_| io::Error::other("bad Content-Length"))?;
            }
            headers.push((name, value));
        }
    }
    if content_length > MAX_BODY {
        return Err(io::Error::other("request body too large for --seal-docker"));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some(Request {
        method,
        path,
        version,
        headers,
        body,
    }))
}

/// Force a container-create body onto no network: set HostConfig.NetworkMode to
/// "none" and strip the other networking knobs. A body we can't parse as JSON is
/// passed through unchanged (with a warning) rather than silently mangled.
fn rewrite_create(body: &[u8], report: &Arc<Report>) -> Vec<u8> {
    report.record(
        Kind::Docker,
        "containers/create",
        "forced NetworkMode=none",
        || "nullroute: --seal-docker: forcing the new container onto no network".into(),
    );
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                let host = obj
                    .entry("HostConfig")
                    .or_insert_with(|| serde_json::Value::Object(Default::default()));
                // Docker treats a null HostConfig as "use defaults" (bridge).
                // Replace any non-object so NetworkMode is actually applied.
                if !host.is_object() {
                    *host = serde_json::Value::Object(Default::default());
                }
                if let Some(hc) = host.as_object_mut() {
                    hc.insert(
                        "NetworkMode".into(),
                        serde_json::Value::String("none".into()),
                    );
                    hc.remove("Links");
                    hc.remove("Dns");
                    hc.remove("DnsSearch");
                    hc.remove("ExtraHosts");
                    hc.remove("PublishAllPorts");
                    hc.remove("PortBindings");
                }
                obj.remove("NetworkingConfig");
                // ExposedPorts is harmless without bindings; leave it.
            }
            serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec())
        }
        // If Docker sent something we can't parse, send it on unchanged rather
        // than silently mangling it; NetworkMode none is best-effort here.
        Err(_) => {
            eprintln!(
                "nullroute: --seal-docker: could not parse a container-create body; passing it through unchanged"
            );
            body.to_vec()
        }
    }
}

fn write_403(client: &mut UnixStream, msg: &str) -> io::Result<()> {
    let body = format!("{{\"message\":{}}}", crate::report::json_string(msg));
    // Content-Length framed, no Connection: close, so the CLI can keep using the
    // connection for later requests.
    write!(
        client,
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Two-way copy between the command's connection and the real daemon until both
/// close. Handles the response, attach/exec streams and keep-alive uniformly.
fn relay(client: UnixStream, upstream: UnixStream) {
    let (mut cr, mut uw) = (client.try_clone(), upstream.try_clone());
    let up = thread::spawn(move || {
        if let (Ok(cr), Ok(uw)) = (cr.as_mut(), uw.as_mut()) {
            let _ = io::copy(cr, uw);
            let _ = uw.shutdown(std::net::Shutdown::Write);
        }
    });
    let (mut ur, mut cw) = (upstream, client);
    let _ = io::copy(&mut ur, &mut cw);
    let _ = cw.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

/// Docker sockets that speak the Docker HTTP API (so they can be sealed).
/// containerd/buildkit use a different (gRPC) protocol and are not sealed.
pub fn docker_api_sockets() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/var/run/docker.sock"),
        PathBuf::from("/run/docker.sock"),
    ];
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        v.push(PathBuf::from(xdg).join("docker.sock"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        v.push(PathBuf::from(home).join(".docker/run/docker.sock"));
    }
    if let Ok(h) = std::env::var("DOCKER_HOST")
        && let Some(p) = h.strip_prefix("unix://")
    {
        v.push(PathBuf::from(p));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(json: &str) -> serde_json::Value {
        let r = Report::new(true);
        let out = rewrite_create(json.as_bytes(), &r);
        serde_json::from_slice(&out).unwrap()
    }

    #[test]
    fn create_gets_network_none_added() {
        let v = rewrite(r#"{"Image":"alpine","Cmd":["true"]}"#);
        assert_eq!(v["HostConfig"]["NetworkMode"], "none");
        assert_eq!(v["Image"], "alpine");
    }

    #[test]
    fn create_network_mode_is_overridden() {
        let v = rewrite(r#"{"Image":"x","HostConfig":{"NetworkMode":"host","Memory":1000}}"#);
        assert_eq!(v["HostConfig"]["NetworkMode"], "none");
        assert_eq!(v["HostConfig"]["Memory"], 1000); // other settings kept
    }

    #[test]
    fn networking_config_and_port_bindings_dropped() {
        let v = rewrite(
            r#"{"Image":"x","HostConfig":{"NetworkMode":"bridge","PortBindings":{"80/tcp":[{}]}},"NetworkingConfig":{"EndpointsConfig":{"br":{}}}}"#,
        );
        assert_eq!(v["HostConfig"]["NetworkMode"], "none");
        assert!(v["HostConfig"].get("PortBindings").is_none());
        assert!(v.get("NetworkingConfig").is_none());
    }

    #[test]
    fn unparseable_body_is_passed_through() {
        let r = Report::new(true);
        assert_eq!(rewrite_create(b"not json", &r), b"not json");
    }

    #[test]
    fn render_head_fixes_content_length() {
        let req = Request {
            method: "POST".into(),
            path: "/v1.43/containers/create?name=x".into(),
            version: "HTTP/1.1".into(),
            headers: vec![
                ("Host".into(), "docker".into()),
                ("Content-Length".into(), "999".into()),
            ],
            body: vec![],
        };
        let head = String::from_utf8(req.render_head(7)).unwrap();
        assert!(head.starts_with("POST /v1.43/containers/create?name=x HTTP/1.1\r\n"));
        assert!(head.contains("Content-Length: 7\r\n"));
        assert!(!head.contains("999"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn path_no_query_strips_query() {
        let req = Request {
            method: "POST".into(),
            path: "/v1.43/containers/create?name=x".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(req.path_no_query().ends_with("/containers/create"));
    }

    fn req(method: &str, path: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
        }
    }

    #[test]
    fn network_connect_matches_with_query_string() {
        assert!(req("POST", "/v1.43/networks/abc/connect").is_network_connect());
        assert!(req("POST", "/v1.43/networks/abc/connect?foo=1").is_network_connect());
        assert!(!req("POST", "/v1.43/networks/abc/disconnect?foo=1").is_network_connect());
        assert!(!req("GET", "/v1.43/networks/abc/connect?foo=1").is_network_connect());
        assert!(!req("POST", "/v1.43/containers/create?name=x").is_network_connect());
    }

    #[test]
    fn null_host_config_is_forced_to_network_none() {
        let v = rewrite(
            r#"{"Image":"x","HostConfig":null,"NetworkingConfig":{"EndpointsConfig":{"br":{}}}}"#,
        );
        assert_eq!(v["HostConfig"]["NetworkMode"], "none");
        assert!(v["HostConfig"].is_object());
        assert!(v.get("NetworkingConfig").is_none());
    }

    #[test]
    fn non_object_host_config_is_replaced() {
        let v = rewrite(r#"{"Image":"x","HostConfig":"bridge"}"#);
        assert_eq!(v["HostConfig"]["NetworkMode"], "none");
        assert!(v["HostConfig"].is_object());
    }
}
