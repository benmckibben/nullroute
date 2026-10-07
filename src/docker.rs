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
//!   drop NetworkingConfig, then fix Content-Length. A body that isn't a single
//!   JSON object is refused (400) rather than passed through.
//! - `POST /.../networks/{id}/connect`: refuse with 403 (it would undo the above).
//! - anything else: forwarded unchanged, and its response copied by its
//!   framing; keep-alive connections keep being parsed request by request.
//!
//! The connection only becomes a plain two-way relay on a genuine protocol
//! switch: a `101 Switching Protocols` (attach/exec with Upgrade), or a raw
//! stream answering `POST` attach / exec-start. A 404 or any other ordinary
//! response never ends parsing, so a probe can't be used to slip an unrewritten
//! create through on the same connection. Requests whose bodies can't be framed
//! exactly (Transfer-Encoding, duplicate Content-Length, non-HTTP/1.x) are
//! refused.
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
    // attach...). Every request on it is parsed, so a later container-create
    // is always rewritten. The only way out of parsing is a genuine protocol
    // switch (see Hijack); anything else ends with the connection.
    loop {
        let Some(req) = read_request(&mut client_r)? else {
            return Ok(()); // client closed cleanly
        };

        // Bodies we can't frame exactly could smuggle a second request past
        // the parser (and a chunked create body past the rewrite): refuse.
        if let Some(why) = req.unframeable() {
            report.record(Kind::Docker, "request", why, || {
                format!("nullroute: --seal-docker: refused a request ({why})")
            });
            write_error(
                &mut client_w,
                400,
                &format!("nullroute --seal-docker refused this request: {why}."),
                true,
            )?;
            return Ok(());
        }

        // Refuse attaching a network to an existing container; it would undo sealing.
        if req.is_network_connect() {
            report.record(Kind::Docker, "networks/connect", "would attach a network to a container", || {
                "nullroute: --seal-docker: refused a request to connect a container to a network".into()
            });
            write_error(
                &mut client_w,
                403,
                "nullroute blocked docker network connect: it would give a container network access that --seal-docker removed.",
                false,
            )?;
            continue;
        }

        let body = if req.is_create() {
            match rewrite_create(&req.body, report) {
                Some(b) => b,
                None => {
                    // Docker's JSON decoder is laxer than ours (it ignores
                    // trailing data, for one), so a body we can't parse might
                    // still create a networked container: fail closed.
                    write_error(
                        &mut client_w,
                        400,
                        "nullroute --seal-docker refused a container create whose body is not a single JSON object.",
                        false,
                    )?;
                    continue;
                }
            }
        } else {
            req.body.clone()
        };
        up_w.write_all(&req.render_head(body.len()))?;
        up_w.write_all(&body)?;

        let resp = read_response_head(&mut up_r)?;
        client_w.write_all(&resp.head)?;
        if resp.is_hijack(&req) {
            // Attach/exec stream: hand over whatever each side has buffered,
            // then pipe raw until close. There is no HTTP left to parse.
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
        copy_body(&mut up_r, &mut client_w, &resp, req.is_head())?;
        if resp.closes || req.wants_close() {
            // The exchange is over. Don't relay whatever the client sends
            // next: it would reach the daemon unparsed.
            let _ = client_w.shutdown(std::net::Shutdown::Both);
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
    content_type: String,
}

impl Response {
    /// Does this response turn the connection into a raw stream? Only:
    /// - `101 Switching Protocols`, the daemon's answer to an attach or
    ///   exec-start that asked to upgrade (what every current client does); or
    /// - a `200` raw/multiplexed stream with no body framing, answering a
    ///   `POST` attach or exec-start (how the daemon hijacks for clients
    ///   that don't ask to upgrade).
    ///
    /// Never for any other status (404s included) or path: once relaying
    /// starts nothing is parsed, so a later container-create would go through
    /// unrewritten.
    fn is_hijack(&self, req: &Request) -> bool {
        if self.status == 101 {
            return true;
        }
        let ct = self.content_type.to_ascii_lowercase();
        self.status == 200
            && req.is_stream_endpoint()
            && self.content_length.is_none()
            && !self.chunked
            && (ct.starts_with("application/vnd.docker.raw-stream")
                || ct.starts_with("application/vnd.docker.multiplexed-stream"))
    }
}

fn read_response_head(r: &mut BufReader<UnixStream>) -> io::Result<Response> {
    let mut head = Vec::new();
    let mut status = 0u16;
    let mut content_length = None;
    let mut chunked = false;
    let mut closes = false;
    let mut content_type = String::new();
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
                "content-type" => content_type = value.to_string(),
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
        content_type,
    })
}

/// Stream a response body from upstream to the client per its framing.
fn copy_body(
    r: &mut BufReader<UnixStream>,
    w: &mut UnixStream,
    resp: &Response,
    head_request: bool,
) -> io::Result<()> {
    // No body for HEAD, 1xx, 204, 304.
    if head_request || resp.status / 100 == 1 || resp.status == 204 || resp.status == 304 {
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

    /// The path as the daemon's router sees it: query stripped and
    /// percent-decoded (`/containers/creat%65` is a create too).
    fn route(&self) -> String {
        percent_decode(self.path_no_query())
    }

    fn is_post(&self) -> bool {
        self.method.eq_ignore_ascii_case("POST")
    }

    fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }

    /// `POST /[vX.Y/]containers/create`.
    fn is_create(&self) -> bool {
        self.is_post() && self.route().ends_with("/containers/create")
    }

    /// `POST /networks/{id}/connect`, ignoring any query string.
    fn is_network_connect(&self) -> bool {
        let path = self.route();
        self.is_post() && path.contains("/networks/") && path.ends_with("/connect")
    }

    /// `POST /containers/{id}/attach` or `POST /exec/{id}/start`: the only
    /// endpoints whose response may become a raw stream.
    fn is_stream_endpoint(&self) -> bool {
        if !self.is_post() {
            return false;
        }
        let route = self.route();
        let segs: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
        // Optional leading API version (v1.43).
        let segs = match segs.first() {
            Some(v)
                if v.starts_with('v') && v[1..].chars().all(|c| c.is_ascii_digit() || c == '.') =>
            {
                &segs[1..]
            }
            _ => &segs[..],
        };
        matches!(segs, ["containers", _, "attach"] | ["exec", _, "start"])
    }

    /// Why this request's body can't be framed by Content-Length alone, if so.
    fn unframeable(&self) -> Option<&'static str> {
        if !matches!(self.version.as_str(), "HTTP/1.1" | "HTTP/1.0") {
            return Some("only HTTP/1.x is supported");
        }
        if self.header("transfer-encoding").is_some() {
            return Some("Transfer-Encoding request bodies are not supported");
        }
        let lengths = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .count();
        if lengths > 1 {
            return Some("more than one Content-Length");
        }
        None
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
/// "none" and strip the other networking knobs. Returns None, so the request
/// is refused, for a body that isn't exactly one JSON object.
///
/// Docker decodes with Go's encoding/json, which matches keys
/// case-insensitively (with Unicode folding: `ſ` is `s`, the Kelvin sign is
/// `k`). So `hostconfig`, `HOSTCONFIG` and friends all count as HostConfig
/// and are merged into the one we rewrite, rather than left for Go to apply
/// after it.
fn rewrite_create(body: &[u8], report: &Arc<Report>) -> Option<Vec<u8>> {
    report.record(
        Kind::Rewritten,
        "containers/create",
        "forced NetworkMode=none",
        || "nullroute: --seal-docker: forcing the new container onto no network".into(),
    );
    let mut v = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) if v.is_object() => v,
        _ => {
            report.record(
                Kind::Docker,
                "containers/create (unparseable)",
                "refused: body is not a JSON object",
                || {
                    "nullroute: --seal-docker: refused a container create whose body is not a JSON object".into()
                },
            );
            return None;
        }
    };
    let obj = v.as_object_mut()?;
    // Merge every spelling of HostConfig, in order. Docker treats a null
    // HostConfig as "use defaults" (bridge); non-objects contribute nothing.
    let mut hc = serde_json::Map::new();
    for key in keys_folding_to(obj, "HostConfig") {
        if let Some(serde_json::Value::Object(m)) = obj.remove(&key) {
            hc.extend(m);
        }
    }
    for knob in [
        "NetworkMode",
        "Links",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "ExtraHosts",
        "PublishAllPorts",
        "PortBindings",
    ] {
        for key in keys_folding_to(&hc, knob) {
            hc.remove(&key);
        }
    }
    hc.insert(
        "NetworkMode".into(),
        serde_json::Value::String("none".into()),
    );
    for key in keys_folding_to(obj, "NetworkingConfig") {
        obj.remove(&key);
    }
    obj.insert("HostConfig".into(), serde_json::Value::Object(hc));
    // ExposedPorts is harmless without bindings; leave it.
    serde_json::to_vec(&v).ok()
}

/// Keys of `m` that Go's encoding/json would match to the field `name`.
fn keys_folding_to(m: &serde_json::Map<String, serde_json::Value>, name: &str) -> Vec<String> {
    m.keys().filter(|k| go_fold_eq(k, name)).cloned().collect()
}

/// Case-insensitive comparison the way Go's encoding/json matches a key to an
/// ASCII field name (Unicode simple folding; the only non-ASCII letters that
/// fold onto ASCII ones are U+017F ſ -> s and U+212A Kelvin sign -> k).
fn go_fold_eq(key: &str, ascii_name: &str) -> bool {
    let fold = |c: char| match c {
        '\u{017F}' => 's',
        '\u{212A}' => 'k',
        c => c.to_ascii_lowercase(),
    };
    key.chars()
        .map(fold)
        .eq(ascii_name.chars().map(|c| c.to_ascii_lowercase()))
}

/// Decode %XX escapes (invalid ones are kept as-is), like Go's URL.Path.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// An HTTP error with a JSON `{"message": ...}` the Docker CLI prints.
/// Content-Length framed; `close` adds Connection: close for when the
/// connection can't be used any further.
fn write_error(client: &mut UnixStream, code: u16, msg: &str, close: bool) -> io::Result<()> {
    let body = format!("{{\"message\":{}}}", crate::report::json_string(msg));
    let reason = match code {
        400 => "Bad Request",
        _ => "Forbidden",
    };
    let conn = if close { "Connection: close\r\n" } else { "" };
    write!(
        client,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{conn}\r\n{body}",
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
        let out = rewrite_create(json.as_bytes(), &r).expect("rewritable");
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
    fn unparseable_body_is_refused() {
        let r = Report::new(true);
        for body in [
            &b"not json"[..],
            b"",
            b"[]",
            b"null",
            // Go's decoder stops after the first value; serde doesn't.
            br#"{"Image":"x","HostConfig":{"NetworkMode":"host"}} trailing"#,
            br#"{"Image":"x"}{"HostConfig":{"NetworkMode":"host"}}"#,
        ] {
            assert!(rewrite_create(body, &r).is_none(), "{body:?}");
        }
    }

    #[test]
    fn case_variant_keys_are_folded_like_go() {
        let v = rewrite(
            r#"{"Image":"x","hostconfig":{"networkmode":"host","Memory":5},"HOSTCONFIG":{"NETWORKMODE":"host"},"networkingconfig":{"EndpointsConfig":{"br":{}}}}"#,
        );
        let o = v.as_object().unwrap();
        assert_eq!(
            o.keys().filter(|k| go_fold_eq(k, "HostConfig")).count(),
            1,
            "{v}"
        );
        assert_eq!(v["HostConfig"]["NetworkMode"], "none");
        assert_eq!(v["HostConfig"]["Memory"], 5);
        let hc = v["HostConfig"].as_object().unwrap();
        assert_eq!(
            hc.keys().filter(|k| go_fold_eq(k, "NetworkMode")).count(),
            1,
            "{v}"
        );
        assert!(o.keys().all(|k| !go_fold_eq(k, "NetworkingConfig")), "{v}");
    }

    #[test]
    fn unicode_folding_keys_are_caught() {
        // U+017F (long s) and U+212A (Kelvin sign) fold to s / k in Go.
        let v = rewrite(
            "{\"Image\":\"x\",\"Ho\u{017F}tConfig\":{\"NetworKMode\":\"host\",\"Networ\u{212A}Mode\":\"host\"}}",
        );
        let o = v.as_object().unwrap();
        assert_eq!(o.len(), 2, "{v}");
        assert_eq!(v["HostConfig"]["NetworkMode"], "none");
        assert_eq!(v["HostConfig"].as_object().unwrap().len(), 1, "{v}");
        assert!(go_fold_eq("Ho\u{017F}tConfig", "HostConfig"));
        assert!(go_fold_eq("Networ\u{212A}Mode", "NetworkMode"));
        assert!(!go_fold_eq("HostConfigs", "HostConfig"));
    }

    #[test]
    fn create_route_is_percent_decoded() {
        assert!(req("POST", "/v1.43/containers/creat%65?name=x").is_create());
        assert!(req("POST", "/containers%2Fcreate").is_create());
        assert!(req("post", "/containers/create").is_create());
        assert!(!req("GET", "/containers/create").is_create());
        assert!(req("POST", "/v1.43/networks/abc/conn%65ct").is_network_connect());
        assert_eq!(percent_decode("/a%2"), "/a%2");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
    }

    #[test]
    fn stream_endpoints_are_strictly_scoped() {
        assert!(req("POST", "/v1.43/containers/abc/attach?stream=1").is_stream_endpoint());
        assert!(req("POST", "/containers/abc/attach").is_stream_endpoint());
        assert!(req("POST", "/v1.43/exec/abc/start").is_stream_endpoint());
        assert!(!req("GET", "/v1.43/containers/abc/attach").is_stream_endpoint());
        assert!(!req("POST", "/v1.43/exec/abc/json").is_stream_endpoint());
        assert!(!req("POST", "/v1.43/containers/abc/attach/ws/x").is_stream_endpoint());
        assert!(!req("POST", "/v1.43/containers/create?x=/attach").is_stream_endpoint());
    }

    #[test]
    fn unframeable_requests_are_detected() {
        let mut r = req("POST", "/containers/create");
        assert!(r.unframeable().is_none());
        r.headers
            .push(("Transfer-Encoding".into(), "chunked".into()));
        assert!(r.unframeable().is_some());
        let mut r = req("POST", "/containers/create");
        r.headers.push(("Content-Length".into(), "1".into()));
        r.headers.push(("content-length".into(), "2".into()));
        assert!(r.unframeable().is_some());
        let mut r = req("PRI", "*");
        r.version = "HTTP/2.0".into();
        assert!(r.unframeable().is_some());
    }

    // ---- the proxy loop against a fake daemon -------------------------------

    /// A fake Docker daemon on a Unix socket. It records every request it
    /// parses and answers by path:
    /// - `.../attach-upgrade` (or any attach with Upgrade): `101`, then echoes raw;
    /// - `.../fake-upgrade-header`: `200` with `Connection: Upgrade` (no switch);
    /// - anything else: `404` with a JSON body.
    struct FakeDaemon {
        path: PathBuf,
        seen: std::sync::mpsc::Receiver<(String, String, Vec<u8>)>,
    }

    impl FakeDaemon {
        fn start(tag: &str) -> FakeDaemon {
            static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "nr-docker-unit-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("docker.sock");
            let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            thread::spawn(move || {
                for conn in l.incoming().flatten() {
                    let tx = tx.clone();
                    thread::spawn(move || {
                        let mut w = conn.try_clone().unwrap();
                        let mut r = BufReader::new(conn);
                        while let Ok(Some(req)) = read_request(&mut r) {
                            let _ =
                                tx.send((req.method.clone(), req.path.clone(), req.body.clone()));
                            if req.path.contains("attach") && req.header("upgrade").is_some() {
                                let _ = w.write_all(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n");
                                let buffered = r.buffer().to_vec();
                                let _ = w.write_all(&buffered);
                                let _ = io::copy(r.get_mut(), &mut w);
                                return;
                            }
                            let resp: &[u8] = if req.path.contains("fake-upgrade-header") {
                                b"HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nContent-Length: 2\r\n\r\n{}"
                            } else {
                                b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"message\":\"page not found\"}"
                            };
                            if w.write_all(resp).is_err() {
                                return;
                            }
                        }
                    });
                }
            });
            FakeDaemon { path, seen: rx }
        }

        /// Run the sealing proxy for one client connection; returns our end.
        fn client(&self) -> UnixStream {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let path = self.path.clone();
            thread::spawn(move || {
                let _ = proxy(theirs, &path, &Report::new(true));
            });
            ours.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            ours
        }

        /// Every request the daemon saw (waits briefly for stragglers).
        fn requests(&self) -> Vec<(String, String, Vec<u8>)> {
            let mut v = Vec::new();
            while let Ok(r) = self
                .seen
                .recv_timeout(std::time::Duration::from_millis(300))
            {
                v.push(r);
            }
            v
        }
    }

    impl Drop for FakeDaemon {
        fn drop(&mut self) {
            if let Some(d) = self.path.parent() {
                let _ = std::fs::remove_dir_all(d);
            }
        }
    }

    const HOST_CREATE: &str = r#"{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}"#;

    fn http(method: &str, path: &str, extra: &str, body: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// Read until `n` responses have started (or timeout / close).
    fn read_responses(c: &mut UnixStream, n: usize) -> String {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while String::from_utf8_lossy(&got).matches("HTTP/1.1 ").count() < n {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(k) => got.extend_from_slice(&buf[..k]),
            }
        }
        // Let the last body arrive.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _ = c.set_nonblocking(true);
        while let Ok(k) = c.read(&mut buf) {
            if k == 0 {
                break;
            }
            got.extend_from_slice(&buf[..k]);
        }
        let _ = c.set_nonblocking(false);
        String::from_utf8_lossy(&got).into_owned()
    }

    /// Every create the daemon received must say NetworkMode none.
    fn assert_creates_sealed(reqs: &[(String, String, Vec<u8>)]) {
        let creates: Vec<_> = reqs
            .iter()
            .filter(|(m, p, _)| m == "POST" && percent_decode(p).contains("/containers/create"))
            .collect();
        assert!(
            !creates.is_empty(),
            "create never reached the daemon: {reqs:?}"
        );
        for (_, _, body) in creates {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(v["HostConfig"]["NetworkMode"], "none", "{v}");
        }
    }

    #[test]
    fn create_after_a_404_probe_on_the_same_connection_is_still_sealed() {
        // Paths the old heuristic treated as "may hijack" regardless of the
        // daemon's answer.
        for probe in [
            "/v1.43/exec/nope/start",
            "/v1.43/containers/nope/attach",
            "/v1.43/exec/nope/json",
        ] {
            let d = FakeDaemon::start("probe");
            let mut c = d.client();
            c.write_all(http("POST", probe, "", "{}").as_bytes())
                .unwrap();
            assert!(read_responses(&mut c, 1).starts_with("HTTP/1.1 404"));
            c.write_all(http("POST", "/v1.43/containers/create", "", HOST_CREATE).as_bytes())
                .unwrap();
            read_responses(&mut c, 1);
            drop(c);
            assert_creates_sealed(&d.requests());
        }
    }

    #[test]
    fn pipelined_probe_and_create_are_both_parsed() {
        let d = FakeDaemon::start("pipe");
        let mut c = d.client();
        let both = http("POST", "/exec/nope/start", "", "{}")
            + &http("POST", "/containers/create?name=x", "", HOST_CREATE);
        c.write_all(both.as_bytes()).unwrap();
        let out = read_responses(&mut c, 2);
        assert_eq!(out.matches("HTTP/1.1 404").count(), 2, "{out}");
        drop(c);
        assert_creates_sealed(&d.requests());
    }

    #[test]
    fn connection_upgrade_header_without_101_does_not_switch_to_relay() {
        let d = FakeDaemon::start("hdr");
        let mut c = d.client();
        c.write_all(http("GET", "/fake-upgrade-header", "", "").as_bytes())
            .unwrap();
        assert!(read_responses(&mut c, 1).starts_with("HTTP/1.1 200"));
        c.write_all(http("POST", "/containers/create", "", HOST_CREATE).as_bytes())
            .unwrap();
        read_responses(&mut c, 1);
        drop(c);
        assert_creates_sealed(&d.requests());
    }

    #[test]
    fn upgrade_request_header_alone_does_not_switch_to_relay() {
        // The old heuristic also hijacked on .../start with Connection: Upgrade.
        let d = FakeDaemon::start("start");
        let mut c = d.client();
        let probe = http(
            "POST",
            "/containers/nope/start",
            "Connection: Upgrade\r\nUpgrade: tcp\r\n",
            "",
        );
        c.write_all(probe.as_bytes()).unwrap();
        assert!(read_responses(&mut c, 1).starts_with("HTTP/1.1 404"));
        c.write_all(http("POST", "/containers/create", "", HOST_CREATE).as_bytes())
            .unwrap();
        read_responses(&mut c, 1);
        drop(c);
        assert_creates_sealed(&d.requests());
    }

    #[test]
    fn connection_close_does_not_relay_what_follows() {
        let d = FakeDaemon::start("close");
        let mut c = d.client();
        let both = http("GET", "/_ping", "Connection: close\r\n", "")
            + &http("POST", "/containers/create", "", HOST_CREATE);
        c.write_all(both.as_bytes()).unwrap();
        read_responses(&mut c, 2);
        drop(c);
        let reqs = d.requests();
        // The create is either never forwarded or forwarded sealed; never raw.
        for (m, p, body) in &reqs {
            if m == "POST" && p.contains("/containers/create") {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap();
                assert_eq!(v["HostConfig"]["NetworkMode"], "none", "{v}");
            }
        }
    }

    #[test]
    fn chunked_create_is_refused_not_smuggled() {
        let d = FakeDaemon::start("chunked");
        let mut c = d.client();
        let chunk = format!("{:x}\r\n{HOST_CREATE}\r\n0\r\n\r\n", HOST_CREATE.len());
        let req = format!(
            "POST /containers/create HTTP/1.1\r\nHost: docker\r\nTransfer-Encoding: chunked\r\n\r\n{chunk}"
        );
        c.write_all(req.as_bytes()).unwrap();
        let out = read_responses(&mut c, 1);
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
        drop(c);
        assert!(
            d.requests().iter().all(|(_, p, _)| !p.contains("create")),
            "chunked create must not reach the daemon"
        );
    }

    #[test]
    fn unparseable_create_is_refused_and_connection_stays_usable() {
        let d = FakeDaemon::start("garbage");
        let mut c = d.client();
        let bad = format!("{HOST_CREATE} trailing");
        c.write_all(http("POST", "/containers/create", "", &bad).as_bytes())
            .unwrap();
        assert!(read_responses(&mut c, 1).starts_with("HTTP/1.1 400"));
        c.write_all(http("POST", "/containers/create", "", HOST_CREATE).as_bytes())
            .unwrap();
        read_responses(&mut c, 1);
        drop(c);
        let reqs = d.requests();
        assert_eq!(reqs.len(), 1, "{reqs:?}");
        assert_creates_sealed(&reqs);
    }

    #[test]
    fn genuine_101_upgrade_still_relays_raw() {
        let d = FakeDaemon::start("attach");
        let mut c = d.client();
        let attach = http(
            "POST",
            "/v1.43/containers/abc/attach?stream=1&stdin=1",
            "Connection: Upgrade\r\nUpgrade: tcp\r\n",
            "",
        );
        c.write_all(attach.as_bytes()).unwrap();
        let head = read_responses(&mut c, 1);
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        // Raw bytes now flow both ways, unparsed: the fake daemon echoes them.
        c.write_all(b"raw stdin bytes\n").unwrap();
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"raw stdin bytes\n");
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
