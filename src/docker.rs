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
//! - `POST /.../build` (the classic builder): force the `networkmode` query
//!   parameter to `none`, so every `RUN` step gets no network. BuildKit builds
//!   (`version=2`) and form-encoded parameters are refused. The build context
//!   is streamed through, never buffered.
//! - refused with 403, because they would give something a network that
//!   sealing can't take away:
//!   - `POST /networks/{id}/connect` (it would undo the create rewrite);
//!   - `POST /grpc` and `POST /session`: tunnels to BuildKit, whose builds
//!     choose their own network inside a gRPC stream nullroute can't rewrite
//!     (this is what `docker build` with buildx uses);
//!   - Swarm: `services/create`, `services/{id}/update` (tasks get networks),
//!     `swarm/init`, `swarm/join` (a manager could schedule such tasks here);
//!   - plugins: `plugins/pull`, `plugins/create`, `plugins/{name}/enable` and
//!     `/upgrade` (plugins can run with host networking).
//! - anything else: forwarded unchanged, and its response copied by its
//!   framing; keep-alive connections keep being parsed request by request.
//!
//! Matching is done on the path as the daemon's router sees it: query
//! stripped, percent-decoded, `.`/`..`/empty segments resolved like Go's
//! path.Clean, and an optional `/vX.Y` prefix removed. Sensitive endpoints
//! are matched by suffix, so an extra prefix still counts. Paths that can't
//! be reduced unambiguously (not starting with `/`, invalid or double
//! percent-encoding, control characters, `#`) are refused (400).
//!
//! The connection only becomes a plain two-way relay on a genuine protocol
//! switch: a `101 Switching Protocols` answering attach or exec-start (the
//! only endpoints allowed to upgrade), or a raw stream answering `POST`
//! attach / exec-start. A 404 or any other ordinary response never ends
//! parsing, so a probe can't be used to slip an unrewritten create through on
//! the same connection. Requests whose bodies can't be framed exactly
//! (Transfer-Encoding other than a strictly parsed chunked build upload,
//! duplicate Content-Length, non-HTTP/1.x) are refused.
//!
//! --seal-docker-pulls: the daemon itself still has network, and some requests
//! make it contact a registry (or any URL) the command chose, which can carry
//! data out in the host name or image path. With `any` (the default) they
//! pass. With `allowlisted` or `none` (see PullPolicy) they're classified
//! (Request::registry_reach) and refused (403, a `docker` report entry)
//! unless allowed:
//!
//! - reads from a registry: `POST /images/create?fromImage=` (pull),
//!   `GET /distribution/{name}/json` (manifest lookup), `GET /images/search`,
//!   `POST /auth` (`docker login`; the registry is the body's
//!   serveraddress), `GET /plugins/privileges?remote=`. Under `allowlisted`
//!   these pass when the registry matches --allow (image names are split into
//!   registry and path by Docker's reference rules, see image_registry);
//! - everything else that reaches out: `POST /images/{name}/push`,
//!   `POST /plugins/{name}/push`, `POST /images/create?fromSrc=URL`, and a
//!   classic build with `remote=` (a URL or git context) or `pull=1` (base
//!   images, named inside the uploaded Dockerfile, force-pulled). Refused under
//!   both. A classic build's missing `FROM` image is pulled by the daemon
//!   inside `/build`, with no request of its own: that can't be refused.
//!
//! Scope: this is not a Docker security boundary. It stops the common ways a
//! container gets a network through the API; --privileged containers can still
//! escape, and (unless --seal-docker-pulls says otherwise) the daemon itself
//! still reaches registries when asked to, which a command can use to leak
//! data in a registry host name or image path. It's "CI tests can use
//! throwaway containers without those containers phoning home", not "run
//! hostile images safely".

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use crate::proxy::Allowlist;
use crate::report::{Kind, Report};

const MAX_HEAD: usize = 32 * 1024;
/// Container-create bodies are small; cap to avoid buffering a huge upload.
const MAX_BODY: usize = 4 * 1024 * 1024;
/// Longest chunk-size line accepted in a chunked build upload (Go's limit).
const MAX_CHUNK_LINE: u64 = 4096;

pub const SEAL_REASON: &str = "sealed with --seal-docker: containers forced to no network";

/// Handle one connection to the sealed docker.sock. `upstream` is the real
/// socket path (still reachable from nullroute's mount namespace).
pub fn handle(client: UnixStream, upstream: &Path, report: &Arc<Report>, policy: &Policy) {
    if let Err(e) = proxy(client, upstream, report, policy) {
        // Best-effort; the client usually just sees a closed connection.
        if e.kind() != io::ErrorKind::BrokenPipe && e.kind() != io::ErrorKind::UnexpectedEof {
            eprintln!("nullroute: --seal-docker: {e}");
        }
    }
}

fn proxy(
    client: UnixStream,
    upstream: &Path,
    report: &Arc<Report>,
    policy: &Policy,
) -> io::Result<()> {
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
        let Some(mut req) = read_request(&mut client_r)? else {
            return Ok(()); // client closed cleanly
        };
        // A streamed (build) body is still in client_r: refusing such a
        // request must close the connection, or its body would be parsed as
        // the next request.
        let body_unread = req.stream.is_some();

        // Bodies we can't frame exactly could smuggle a second request past
        // the parser (and a chunked create body past the rewrite): refuse.
        if let Some(why) = req.unframeable() {
            refuse(&mut client_w, report, 400, "request", why, true)?;
            return Ok(());
        }

        // Match on the path the daemon will route; if that's ambiguous, refuse.
        if let Err(why) = req.route {
            refuse(&mut client_w, report, 400, "request", why, body_unread)?;
            if body_unread {
                return Ok(());
            }
            continue;
        }

        if let Some(b) = req.blocked() {
            report.record(Kind::Docker, b.target, b.why, || {
                format!("nullroute: --seal-docker: refused {} ({})", b.target, b.why)
            });
            if b.target == "buildkit"
                && ends_with(req.segs(), &["grpc"])
                && req.header("upgrade").is_some()
            {
                client_w.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
                refuse_grpc(&mut client_r, &mut client_w, b.message)?;
                return Ok(());
            }
            write_error(&mut client_w, 403, b.message, body_unread)?;
            if body_unread {
                return Ok(());
            }
            continue;
        }

        if let Some(b) = policy.check(&req) {
            report.record(Kind::Docker, &b.target, &b.why, || {
                format!(
                    "nullroute: --seal-docker-pulls: refused {} ({})",
                    b.target, b.why
                )
            });
            write_error(&mut client_w, 403, &b.message, body_unread)?;
            if body_unread {
                return Ok(());
            }
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
        } else if req.is_build() {
            match rewrite_build(&req) {
                Ok(target) => {
                    report.record(Kind::Rewritten, "build", "forced networkmode=none", || {
                        "nullroute: --seal-docker: forcing the build's RUN steps onto no network"
                            .into()
                    });
                    req.forward_target = Some(target);
                    Vec::new()
                }
                Err(why) => {
                    refuse(&mut client_w, report, 403, "build", why, body_unread)?;
                    if body_unread {
                        return Ok(());
                    }
                    continue;
                }
            }
        } else {
            req.body.clone()
        };
        if let Some(framing) = req.stream {
            up_w.write_all(&req.render_head(None))?;
            forward_body(&mut client_r, &mut up_w, framing)?;
        } else {
            up_w.write_all(&req.render_head(Some(body.len())))?;
            up_w.write_all(&body)?;
        }

        let resp = read_response_head(&mut up_r)?;
        if resp.status == 101 && !req.may_upgrade() {
            // Only attach and exec-start may become raw streams. Anything
            // else that switches protocols is a tunnel we can't parse
            // (BuildKit's /grpc and /session are refused above; this catches
            // the rest).
            refuse(
                &mut client_w,
                report,
                502,
                "upgrade",
                "protocol switch on an endpoint other than attach or exec",
                true,
            )?;
            return Ok(());
        }
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

/// Refuse a BuildKit gRPC tunnel in a way buildx reports.
///
/// buildx probes `/grpc` to pick its driver: if the upgrade fails it quietly
/// falls back to a "docker-container" builder, pulling moby/buildkit and
/// leaving a privileged container behind (which then fails anyway), and a
/// closed connection just makes gRPC reconnect in a loop. So nullroute (not
/// the daemon) accepts the upgrade and speaks just enough HTTP/2 to answer
/// every gRPC call with PERMISSION_DENIED and `message`, which buildx prints.
/// Nothing on this connection reaches the daemon.
fn refuse_grpc<R: Read, W: Write>(r: &mut R, w: &mut W, message: &str) -> io::Result<()> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const MAX_FRAMES: usize = 256;
    const MAX_PAYLOAD: usize = 1 << 20;
    let frame = |kind: u8, flags: u8, stream: u32, payload: &[u8]| {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend_from_slice(&[kind, flags]);
        f.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
        f.extend_from_slice(payload);
        f
    };
    // Trailers-only gRPC response, HPACK-encoded without indexing or Huffman.
    let mut trailers = vec![0x88]; // :status 200 (static table)
    for (name, value) in [
        ("content-type", "application/grpc"),
        ("grpc-status", "7"), // PERMISSION_DENIED
        ("grpc-message", message),
    ] {
        trailers.push(0x00);
        hpack_string(&mut trailers, name.as_bytes());
        hpack_string(&mut trailers, value.as_bytes());
    }

    w.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
    )?;
    w.write_all(&frame(0x4, 0, 0, &[]))?; // our SETTINGS
    let mut preface = [0u8; PREFACE.len()];
    if r.read_exact(&mut preface).is_err() || preface != PREFACE {
        return Ok(()); // a probe that hung up, or not HTTP/2: nothing to answer
    }
    for _ in 0..MAX_FRAMES {
        let mut head = [0u8; 9];
        if r.read_exact(&mut head).is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let (kind, flags) = (head[3], head[4]);
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        if len > MAX_PAYLOAD {
            return Ok(());
        }
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload)?;
        match kind {
            // SETTINGS (not an ACK): acknowledge.
            0x4 if flags & 0x1 == 0 => w.write_all(&frame(0x4, 0x1, 0, &[]))?,
            // HEADERS opening a call: answer it, ending the stream.
            0x1 if stream % 2 == 1 => w.write_all(&frame(0x1, 0x4 | 0x1, stream, &trailers))?,
            // PING: echo back with ACK.
            0x6 if flags & 0x1 == 0 => w.write_all(&frame(0x6, 0x1, 0, &payload))?,
            // GOAWAY: the client is done.
            0x7 => return Ok(()),
            _ => {} // DATA, WINDOW_UPDATE, RST_STREAM, CONTINUATION...
        }
    }
    Ok(())
}

/// Append an HPACK string literal (no Huffman): 7-bit-prefix length, bytes.
fn hpack_string(out: &mut Vec<u8>, s: &[u8]) {
    let mut n = s.len();
    if n < 127 {
        out.push(n as u8);
    } else {
        out.push(127);
        n -= 127;
        while n >= 128 {
            out.push((n % 128) as u8 | 0x80);
            n /= 128;
        }
        out.push(n as u8);
    }
    out.extend_from_slice(s);
}

/// Record a refused request and answer it with a Docker-style error.
fn refuse(
    client: &mut UnixStream,
    report: &Arc<Report>,
    code: u16,
    target: &str,
    why: &str,
    close: bool,
) -> io::Result<()> {
    report.record(Kind::Docker, target, why, || {
        format!("nullroute: --seal-docker: refused a request ({why})")
    });
    write_error(
        client,
        code,
        &format!("nullroute --seal-docker refused this request: {why}."),
        close,
    )
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

/// How a streamed (not buffered) request body is framed on the wire.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Framing {
    Length(u64),
    Chunked,
}

/// A request --seal-docker refuses outright: report target, reason, and the
/// message the Docker CLI prints.
struct Block {
    target: &'static str,
    why: &'static str,
    message: &'static str,
}

const BUILDKIT_MSG: &str = "nullroute blocked a BuildKit build: --seal-docker can't take network away from BuildKit (buildx) builds. Use the classic builder instead (DOCKER_BUILDKIT=0 docker build ...); nullroute runs its RUN steps with no network.";

struct Request {
    method: String,
    /// The request target exactly as received (path and query).
    path: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Set for docker build uploads, which are streamed rather than
    /// buffered: `body` is empty and the caller forwards the body.
    stream: Option<Framing>,
    /// The path segments the daemon routes on (see canonical_route), or why
    /// they can't be determined.
    route: Result<Vec<String>, &'static str>,
    /// A rewritten request target to forward instead of `path`.
    forward_target: Option<String>,
}

impl Request {
    fn new(method: &str, path: &str, version: &str, headers: Vec<(String, String)>) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            version: version.into(),
            headers,
            body: Vec::new(),
            stream: None,
            route: canonical_route(path),
            forward_target: None,
        }
    }

    /// Canonical path segments, empty if the path couldn't be normalised
    /// (such requests are refused before anything else looks at them).
    fn segs(&self) -> &[String] {
        self.route.as_deref().unwrap_or(&[])
    }

    fn is_post(&self) -> bool {
        self.method.eq_ignore_ascii_case("POST")
    }

    fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }

    /// `POST /[vX.Y/]containers/create` (or anything ending in it).
    fn is_create(&self) -> bool {
        self.is_post() && ends_with(self.segs(), &["containers", "create"])
    }

    /// `POST /[vX.Y/]build` (or anything ending in it).
    fn is_build(&self) -> bool {
        self.is_post() && ends_with(self.segs(), &["build"])
    }

    /// `POST /networks/{id}/connect`, ignoring any query string.
    #[cfg(test)]
    fn is_network_connect(&self) -> bool {
        self.blocked()
            .is_some_and(|b| b.target == "networks/connect")
    }

    /// Requests refused outright, because what they set up would have a
    /// network that sealing can't remove. Matched by suffix on the canonical
    /// path: refusing a path the daemon would 404 anyway costs nothing.
    fn blocked(&self) -> Option<Block> {
        if !self.is_post() {
            return None;
        }
        let s = self.segs();
        if ends_with(s, &["networks", "*", "connect"]) {
            return Some(Block {
                target: "networks/connect",
                why: "would attach a network to a container",
                message: "nullroute blocked docker network connect: it would give a container network access that --seal-docker removed.",
            });
        }
        if ends_with(s, &["grpc"]) || ends_with(s, &["session"]) {
            return Some(Block {
                target: "buildkit",
                why: "BuildKit builds choose their own network",
                message: BUILDKIT_MSG,
            });
        }
        if ends_with(s, &["services", "create"]) || ends_with(s, &["services", "*", "update"]) {
            return Some(Block {
                target: "services",
                why: "swarm service tasks get networks",
                message: "nullroute blocked a Docker Swarm service create/update: service tasks get networks that --seal-docker can't remove.",
            });
        }
        if ends_with(s, &["swarm", "init"]) || ends_with(s, &["swarm", "join"]) {
            return Some(Block {
                target: "swarm",
                why: "a swarm can run tasks with networks",
                message: "nullroute blocked docker swarm init/join: a swarm can schedule tasks with networks that --seal-docker can't remove.",
            });
        }
        let plugin_action = s.len() >= 3
            && matches!(s[s.len() - 1].as_str(), "enable" | "upgrade")
            && s[..s.len() - 2].iter().any(|x| x == "plugins");
        if plugin_action
            || ends_with(s, &["plugins", "pull"])
            || ends_with(s, &["plugins", "create"])
        {
            return Some(Block {
                target: "plugins",
                why: "plugins can run with host networking",
                message: "nullroute blocked installing or enabling a Docker plugin: plugins can run with host networking that --seal-docker can't remove.",
            });
        }
        None
    }

    /// `POST /containers/{id}/attach` or `POST /exec/{id}/start`: the only
    /// endpoints whose response may become a raw stream without a 101.
    fn is_stream_endpoint(&self) -> bool {
        self.is_post()
            && (matches_exactly(self.segs(), &["containers", "*", "attach"])
                || matches_exactly(self.segs(), &["exec", "*", "start"]))
    }

    /// May the daemon answer this with `101 Switching Protocols`? Attach,
    /// exec start, and the attach websocket; never a tunnel to another API.
    fn may_upgrade(&self) -> bool {
        self.is_stream_endpoint()
            || (self.method.eq_ignore_ascii_case("GET")
                && matches_exactly(self.segs(), &["containers", "*", "attach", "ws"]))
    }

    /// Why this request's body can't be framed exactly, if so.
    fn unframeable(&self) -> Option<&'static str> {
        if !matches!(self.version.as_str(), "HTTP/1.1" | "HTTP/1.0") {
            return Some("only HTTP/1.x is supported");
        }
        let count = |name: &str| {
            self.headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .count()
        };
        let (lengths, encodings) = (count("content-length"), count("transfer-encoding"));
        if lengths > 1 {
            return Some("more than one Content-Length");
        }
        if encodings > 0 {
            // Only a build upload may be chunked (the classic builder streams
            // its context that way), and only in the one form Go's server
            // reads exactly as we do. Go ignores Transfer-Encoding on
            // HTTP/1.0, so a chunked 1.0 body would be read as requests.
            let chunked_build = self.stream == Some(Framing::Chunked)
                && self.version == "HTTP/1.1"
                && encodings == 1
                && lengths == 0
                && self
                    .header("transfer-encoding")
                    .is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
            if !chunked_build {
                return Some("Transfer-Encoding request bodies are not supported");
            }
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

    /// Does the body carry form parameters? Go's FormValue lets those
    /// override the query string, so the query alone can't be trusted.
    fn has_form_body(&self) -> bool {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.trim().to_ascii_lowercase())
            .any(|v| {
                v.starts_with("application/x-www-form-urlencoded") || v.starts_with("multipart/")
            })
    }

    /// What this request would make the daemon contact, for
    /// --seal-docker-pulls: empty for requests that don't reach out, Err if
    /// it does but we can't tell where (refused unless the policy is `any`).
    ///
    /// Fixed paths are matched by suffix, like blocked(); pushes by a final
    /// `push` after an `images` or `plugins` segment. Manifest lookups are
    /// matched from the first segment, since the daemon's router is anchored
    /// there and an image name may contain anything (`docker inspect
    /// x/distribution/y` is not a manifest lookup).
    fn registry_reach(&self) -> Result<Vec<Reach>, &'static str> {
        let s = self.segs();
        let n = s.len();
        let read = |verb, name: &str, search| Reach::Read {
            verb,
            name: name.to_string(),
            registry: image_registry(name, search),
        };
        let other = |verb, name: &str| Reach::Other {
            verb,
            name: name.to_string(),
        };
        let is_get = self.method.eq_ignore_ascii_case("GET") || self.is_head();
        let mut out = Vec::new();
        if self.is_post() && ends_with(s, &["images", "create"]) {
            if self.has_form_body() {
                return Err("form-encoded image create parameters");
            }
            let q = query_params(&self.path)?;
            // The daemon pulls if fromImage is set, else imports fromSrc:
            // "-" is the request body, anything else a URL it downloads.
            let images: Vec<&str> = values(&q, "fromImage").filter(|v| !v.is_empty()).collect();
            if images.is_empty() {
                for src in values(&q, "fromSrc").filter(|v| !v.is_empty() && *v != "-") {
                    out.push(other(Verb::Import, src));
                }
            }
            for image in images {
                out.push(read(Verb::Pull, image, false));
            }
        } else if self.is_post() && ends_with(s, &["auth"]) {
            for addr in auth_addresses(&self.body)? {
                out.push(Reach::Read {
                    verb: Verb::Login,
                    registry: auth_registry(&addr),
                    name: if addr.is_empty() {
                        "docker.io".into()
                    } else {
                        addr
                    },
                });
            }
        } else if self.is_post()
            && n >= 3
            && s[n - 1] == "push"
            && let Some(i) = s[..n - 2]
                .iter()
                .position(|x| x == "images" || x == "plugins")
        {
            let verb = if s[i] == "images" {
                Verb::Push
            } else {
                Verb::PluginPush
            };
            out.push(other(verb, &s[i + 1..n - 1].join("/")));
        } else if is_get && n >= 3 && s[0] == "distribution" && s[n - 1] == "json" {
            out.push(read(Verb::Manifest, &s[1..n - 1].join("/"), false));
        } else if is_get && ends_with(s, &["images", "search"]) {
            for term in values(&query_params(&self.path)?, "term") {
                out.push(read(Verb::Search, term, true));
            }
        } else if is_get && ends_with(s, &["plugins", "privileges"]) {
            for remote in values(&query_params(&self.path)?, "remote").filter(|v| !v.is_empty()) {
                out.push(read(Verb::PluginLookup, remote, false));
            }
        } else if self.is_build() {
            // A query or body rewrite_build can't read is refused there.
            let Ok(q) = query_params(&self.path) else {
                return Ok(out);
            };
            for remote in values(&q, "remote").filter(|v| !v.is_empty()) {
                out.push(other(Verb::RemoteBuild, remote));
            }
            if values(&q, "pull").any(go_bool) {
                out.push(other(Verb::BuildPull, "base images"));
            }
        }
        Ok(out)
    }

    /// Rebuild the request head with the (possibly rewritten) target. With
    /// `Some(len)` Content-Length is replaced by `len`; with `None` (a streamed
    /// body) the framing headers are kept as they are.
    fn render_head(&self, body_len: Option<usize>) -> Vec<u8> {
        let target = self.forward_target.as_deref().unwrap_or(&self.path);
        let mut s = format!("{} {} {}\r\n", self.method, target, self.version);
        let mut wrote_len = false;
        for (name, value) in &self.headers {
            match body_len {
                Some(len) if name.eq_ignore_ascii_case("content-length") => {
                    s.push_str(&format!("Content-Length: {len}\r\n"));
                    wrote_len = true;
                }
                _ => s.push_str(&format!("{name}: {value}\r\n")),
            }
        }
        if let Some(len) = body_len
            && !wrote_len
            && len > 0
        {
            s.push_str(&format!("Content-Length: {len}\r\n"));
        }
        s.push_str("\r\n");
        s.into_bytes()
    }
}

/// Does `segs` end with `pat`? `"*"` in the pattern matches any one segment.
fn ends_with(segs: &[String], pat: &[&str]) -> bool {
    segs.len() >= pat.len()
        && segs[segs.len() - pat.len()..]
            .iter()
            .zip(pat)
            .all(|(s, p)| *p == "*" || s == p)
}

fn matches_exactly(segs: &[String], pat: &[&str]) -> bool {
    segs.len() == pat.len() && ends_with(segs, pat)
}

fn read_request<R: BufRead>(reader: &mut R) -> io::Result<Option<Request>> {
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
    let mut content_length = 0u64;
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
                // Digits only, like Go (Rust's parser would also take "+5").
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(io::Error::other("bad Content-Length"));
                }
                content_length = value
                    .parse()
                    .map_err(|_| io::Error::other("bad Content-Length"))?;
            }
            headers.push((name, value));
        }
    }
    let mut req = Request::new(&method, &path, &version, headers);
    if req.is_build() {
        // The build context can be large and the classic builder sends it
        // chunked: stream it instead of buffering. (Whether a chunked body is
        // acceptable is decided by unframeable().)
        req.stream = Some(if req.header("transfer-encoding").is_some() {
            Framing::Chunked
        } else {
            Framing::Length(content_length)
        });
        return Ok(Some(req));
    }
    if content_length > MAX_BODY as u64 {
        return Err(io::Error::other("request body too large for --seal-docker"));
    }
    let mut body = vec![0u8; content_length as usize];
    reader.read_exact(&mut body)?;
    req.body = body;
    Ok(Some(req))
}

/// Copy a streamed request body from the client to the daemon, exactly as
/// framed. Chunked bodies are parsed strictly (hex size, CRLF everywhere, no
/// trailers) so that where we think the body ends is where Go's server
/// thinks it ends; anything else is an error, and the connection is dropped
/// mid-body rather than resynchronised.
fn forward_body<R: BufRead, W: Write>(r: &mut R, w: &mut W, framing: Framing) -> io::Result<()> {
    let copy_exact = |r: &mut R, w: &mut W, n: u64| -> io::Result<()> {
        if io::copy(&mut r.take(n), w)? == n {
            Ok(())
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    };
    let bad = |why: &str| io::Error::other(format!("malformed chunked body: {why}"));
    match framing {
        Framing::Length(n) => copy_exact(r, w, n),
        Framing::Chunked => loop {
            let mut line = Vec::new();
            r.take(MAX_CHUNK_LINE).read_until(b'\n', &mut line)?;
            let Some(l) = line.strip_suffix(b"\r\n") else {
                return Err(bad("size line not ended by CRLF"));
            };
            let (size_hex, ext) = match l.iter().position(|&b| b == b';') {
                Some(i) => (&l[..i], &l[i..]),
                None => (l, &[][..]),
            };
            if size_hex.is_empty()
                || size_hex.len() > 15
                || !size_hex.iter().all(u8::is_ascii_hexdigit)
                || ext.iter().any(|&b| b.is_ascii_control() && b != b'\t')
            {
                return Err(bad("bad chunk size"));
            }
            let size = u64::from_str_radix(std::str::from_utf8(size_hex).unwrap_or("x"), 16)
                .map_err(|_| bad("bad chunk size"))?;
            w.write_all(&line)?;
            copy_exact(r, w, size)?;
            let mut crlf = [0u8; 2];
            r.read_exact(&mut crlf)?;
            if &crlf != b"\r\n" {
                // After the last chunk this is where trailers would start.
                return Err(bad(
                    "chunk not followed by CRLF (trailers are not supported)",
                ));
            }
            w.write_all(&crlf)?;
            if size == 0 {
                return Ok(());
            }
        },
    }
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
    let out = serde_json::to_vec(&v).ok()?;
    report.record(
        Kind::Rewritten,
        "containers/create",
        "forced NetworkMode=none",
        || "nullroute: --seal-docker: forcing the new container onto no network".into(),
    );
    Some(out)
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

/// Reduce a request target to the path segments the daemon's router matches
/// on, or say why that can't be done unambiguously.
///
/// Go's server percent-decodes the path (`%2F` included) and gorilla/mux
/// cleans it (`//`, `.`, `..`; a non-clean path is redirected to the clean
/// one), then routes with an optional `/v{version}` prefix. We do the same and
/// drop that prefix. A trailing slash is dropped too: the daemon 404s such a
/// path, so treating it like the slash-less one only errs on the safe side.
fn canonical_route(target: &str) -> Result<Vec<String>, &'static str> {
    if !target.starts_with('/') {
        return Err("request target is not an absolute path");
    }
    if target.contains('#') {
        return Err("request target contains '#'");
    }
    let raw = target.split('?').next().unwrap_or(target);
    let decoded = percent_decode_strict(raw, false).ok_or("invalid percent-encoding in path")?;
    let decoded = String::from_utf8(decoded).map_err(|_| "path is not UTF-8")?;
    if decoded.chars().any(char::is_control) {
        return Err("control character in path");
    }
    // Docker decodes once; a path that is still encoded after that is
    // ambiguous (and nothing the Docker CLI sends looks like it).
    if percent_decode_strict(&decoded, false).is_some_and(|d| d != decoded.as_bytes()) {
        return Err("path is percent-encoded more than once");
    }
    let mut segs: Vec<String> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s.to_string()),
        }
    }
    if segs.first().is_some_and(|v| is_api_version(v)) {
        segs.remove(0);
    }
    Ok(segs)
}

/// `v1.43` and friends: Docker's `/v{version:[0-9.]+}` route prefix.
fn is_api_version(seg: &str) -> bool {
    seg.strip_prefix('v')
        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// Decode %XX escapes like Go's url package: None for an invalid escape
/// (Go refuses those with 400). `plus_is_space` for query components.
fn percent_decode_strict(s: &str, plus_is_space: bool) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = hex(*b.get(i + 1)?)?;
                let l = hex(*b.get(i + 2)?)?;
                out.push(h << 4 | l);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// The request target to forward for a classic-builder `POST /build`: every
/// `networkmode` parameter dropped and `networkmode=none` appended, so it's the
/// only value the daemon sees. Refuses what can't be rewritten safely:
/// - `version` other than 1: a BuildKit build, whose Dockerfile frontend
///   (or a custom `# syntax=` one) decides each step's network itself;
/// - form-encoded bodies: Go's FormValue lets body parameters override the
///   query, so a `networkmode=host` there would win;
/// - query strings Go would parse differently from us (`;`, bad escapes).
fn rewrite_build(req: &Request) -> Result<String, &'static str> {
    if req.has_form_body() {
        return Err("form-encoded build parameters can't be sealed");
    }
    let (path, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
    let mut kept = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if pair.contains(';') {
            return Err("';' in the build query string");
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let bad = "invalid percent-encoding in the build query string";
        let key = percent_decode_strict(k, true).ok_or(bad)?;
        let value = percent_decode_strict(v, true).ok_or(bad)?;
        if key.eq_ignore_ascii_case(b"networkmode") {
            continue;
        }
        if key == b"version" && !(value.is_empty() || value == b"1") {
            return Err(
                "BuildKit builds can't be sealed; use the classic builder (DOCKER_BUILDKIT=0)",
            );
        }
        kept.push(pair);
    }
    kept.push("networkmode=none");
    Ok(format!("{path}?{}", kept.join("&")))
}

// ---- --seal-docker-pulls --------------------------------------------------------

/// `--seal-docker-pulls`: what the Docker daemon may contact on the
/// command's behalf (see the module docs for which requests that covers).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum PullPolicy {
    /// Any registry or URL, as without the flag.
    #[default]
    Any,
    /// Only pulls, logins and lookups from registries matched by --allow (or
    /// a localhost registry bridged with --port); no pushes, URL imports or
    /// remote build contexts.
    Allowlisted,
    /// Nothing: every request that would make the daemon contact a registry
    /// or URL is refused.
    #[value(name = "none")]
    Never,
}

impl PullPolicy {
    /// The flag value and what it means, for --inspect and --dry-run.
    pub fn describe(self) -> &'static str {
        match self {
            PullPolicy::Any => "any (the daemon may contact any registry or URL)",
            PullPolicy::Allowlisted => {
                "allowlisted (pulls, logins and lookups only from registries in --allow; no push, URL import or remote build)"
            }
            PullPolicy::Never => {
                "none (no registry or URL access: pulls, pushes, logins and lookups refused)"
            }
        }
    }

    fn flag(self) -> &'static str {
        match self {
            PullPolicy::Any => "--seal-docker-pulls=any",
            PullPolicy::Allowlisted => "--seal-docker-pulls=allowlisted",
            PullPolicy::Never => "--seal-docker-pulls=none",
        }
    }
}

/// What the sealing proxy needs to apply --seal-docker-pulls.
#[derive(Debug, Default)]
pub struct Policy {
    pub pulls: PullPolicy,
    /// --allow: the registries `allowlisted` lets the daemon read from.
    pub allow: Allowlist,
    /// --port: localhost registries `allowlisted` lets the daemon read from.
    pub ports: Vec<u16>,
}

/// A request --seal-docker-pulls refuses: report target and reason, and the
/// message the Docker CLI prints.
struct PullBlock {
    target: String,
    why: String,
    message: String,
}

impl Policy {
    /// Should this request be refused, and how?
    fn check(&self, req: &Request) -> Option<PullBlock> {
        if self.pulls == PullPolicy::Any {
            return None;
        }
        let flag = self.pulls.flag();
        match req.registry_reach() {
            Ok(reach) => reach.iter().find_map(|r| self.refusal(r)),
            Err(why) => Some(PullBlock {
                target: "registry request".into(),
                why: format!("{why}; {flag}"),
                message: format!(
                    "nullroute blocked a request that makes the Docker daemon contact a registry: {flag} couldn't tell which one ({why})."
                ),
            }),
        }
    }

    fn refusal(&self, reach: &Reach) -> Option<PullBlock> {
        let flag = self.pulls.flag();
        let (verb, name) = match reach {
            Reach::Read { verb, name, .. } | Reach::Other { verb, name } => (*verb, shown(name)),
        };
        let target = format!("{} {name}", verb.noun());
        let doing = format!("nullroute blocked {} {name}", verb.doing());
        if self.pulls == PullPolicy::Never {
            return Some(PullBlock {
                target,
                why: flag.into(),
                message: format!(
                    "{doing}: {flag} doesn't let the Docker daemon contact registries or URLs for the command. Pull the images you need before running nullroute, or use --seal-docker-pulls=allowlisted with --allow REGISTRY."
                ),
            });
        }
        let registry = match reach {
            Reach::Other { .. } => {
                return Some(PullBlock {
                    target,
                    why: flag.into(),
                    message: format!(
                        "{doing}: {flag} only lets the Docker daemon read from registries in --allow; it never pushes, imports from a URL, builds from a remote context or force-pulls build base images (--pull). Use --seal-docker-pulls=any to allow that."
                    ),
                });
            }
            Reach::Read { registry, .. } => registry,
        };
        let Some(r) = registry else {
            return Some(PullBlock {
                target,
                why: format!("unrecognised registry; {flag}"),
                message: format!(
                    "{doing}: {flag} couldn't tell which registry that names, so it can't check it against --allow."
                ),
            });
        };
        if self.allows(r) {
            return None;
        }
        let shown = r.display();
        let (why, reason, fix) = if r.is_local() {
            (
                format!("{shown} not bridged with --port"),
                format!("{shown} is on this machine and its port isn't bridged with --port"),
                format!("Add --port {}", r.port()),
            )
        } else if r.is_hub() {
            (
                "docker.io not in --allow".to_string(),
                "Docker Hub isn't one".to_string(),
                "Add --allow docker.io".to_string(),
            )
        } else {
            (
                format!("{shown} not in --allow"),
                format!("{shown} isn't one"),
                format!("Add --allow {shown}"),
            )
        };
        let or_prepull = if verb == Verb::Pull {
            ", or pull the image before running nullroute"
        } else {
            ""
        };
        Some(PullBlock {
            target,
            why: format!("{why}; {flag}"),
            message: format!(
                "{doing}: {flag} only lets the Docker daemon contact registries in --allow, and {reason}. {fix}{or_prepull}."
            ),
        })
    }

    /// May `allowlisted` contact this registry? By the --allow rules (port
    /// 443 unless the reference names one); Docker Hub if --allow matches any
    /// of its names; a localhost registry if its port is bridged with --port
    /// (--allow never matches loopback).
    fn allows(&self, r: &Registry) -> bool {
        let port = r.port();
        if r.is_local() {
            self.ports.contains(&port)
        } else if r.is_hub() {
            HUB.iter().any(|h| self.allow.allows(h, port))
        } else {
            self.allow.allows(&r.host, port)
        }
    }
}

/// A request that makes the daemon reach out.
#[derive(Debug)]
enum Reach {
    /// A read from a registry: `allowlisted` permits it if the registry is
    /// allowed. `registry` is None if it can't be determined.
    Read {
        verb: Verb,
        name: String,
        registry: Option<Registry>,
    },
    /// A push, a download from an arbitrary URL, or a pull from registries we
    /// can't see: `allowlisted` never permits it.
    Other { verb: Verb, name: String },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Verb {
    Pull,
    Login,
    Manifest,
    Search,
    PluginLookup,
    Push,
    PluginPush,
    Import,
    RemoteBuild,
    BuildPull,
}

impl Verb {
    /// Report target prefix.
    fn noun(self) -> &'static str {
        match self {
            Verb::Pull => "pull",
            Verb::Login => "login",
            Verb::Manifest => "manifest",
            Verb::Search => "search",
            Verb::PluginLookup => "plugin privileges",
            Verb::Push => "push",
            Verb::PluginPush => "plugin push",
            Verb::Import => "import",
            Verb::RemoteBuild => "build remote",
            Verb::BuildPull => "build --pull",
        }
    }

    /// For "nullroute blocked <doing> <name>".
    fn doing(self) -> &'static str {
        match self {
            Verb::Pull => "pulling",
            Verb::Login => "logging in to",
            Verb::Manifest => "looking up",
            Verb::Search => "searching for",
            Verb::PluginLookup => "looking up plugin",
            Verb::Push => "pushing",
            Verb::PluginPush => "pushing plugin",
            Verb::Import => "importing from",
            Verb::RemoteBuild => "building from",
            Verb::BuildPull => "force-pulling (docker build --pull) the",
        }
    }
}

/// Docker Hub's names. Docker's reference parser maps "no host" and
/// `index.docker.io` to `docker.io`, and the daemon pulls from
/// `registry-1.docker.io`; all three are one registry here.
const HUB: [&str; 3] = ["docker.io", "index.docker.io", "registry-1.docker.io"];

/// A registry host as the daemon would dial it.
#[derive(Debug, Clone, PartialEq)]
struct Registry {
    /// Lowercase host name, or an IP in canonical form (no brackets).
    host: String,
    port: Option<u16>,
}

impl Registry {
    fn hub() -> Registry {
        Registry {
            host: "docker.io".into(),
            port: None,
        }
    }

    fn is_hub(&self) -> bool {
        HUB.contains(&self.host.as_str())
    }

    /// Port the daemon dials (registries are HTTPS unless they say otherwise).
    fn port(&self) -> u16 {
        self.port.unwrap_or(443)
    }

    /// On this machine: localhost names and loopback addresses, which
    /// --allow refuses (see proxy::Forbidden::Loopback).
    fn is_local(&self) -> bool {
        let h = self.host.as_str();
        match h.parse::<IpAddr>() {
            Ok(ip) => crate::proxy::forbidden(ip) == Some(crate::proxy::Forbidden::Loopback),
            Err(_) => {
                h == "localhost"
                    || h.ends_with(".localhost")
                    || h == "localhost.localdomain"
                    || h == "ip6-localhost"
                    || h == "ip6-loopback"
            }
        }
    }

    fn display(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(p) => format!("{h}:{p}"),
            None => h,
        }
    }
}

/// The registry an image name refers to, by Docker's reference rules
/// (distribution/reference splitDockerDomain): the part before the first `/`
/// is a registry host only if it contains `.` or `:`, is `localhost`, or
/// (except in a search term, see the daemon's splitReposSearchTerm) has an
/// uppercase letter. Otherwise the image is on Docker Hub. None if the host
/// part isn't a host name, IP or `[IPv6]` with an optional port.
fn image_registry(name: &str, search_term: bool) -> Option<Registry> {
    let Some((first, _)) = name.split_once('/') else {
        return Some(Registry::hub());
    };
    let is_host = first.contains(['.', ':'])
        || first == "localhost"
        || (!search_term && first.to_lowercase() != first);
    if is_host {
        registry_host(first)
    } else {
        Some(Registry::hub())
    }
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn registry_host(s: &str) -> Option<Registry> {
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (h, after) = rest.split_once(']')?;
            h.parse::<std::net::Ipv6Addr>().ok()?;
            let port = match after {
                "" => None,
                a => Some(a.strip_prefix(':')?),
            };
            (h, port)
        }
        None => match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        },
    };
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            Some(p.parse::<u16>().ok().filter(|&p| p != 0)?)
        }
        Some(_) => return None,
    };
    let host = host.to_ascii_lowercase();
    if host.parse::<IpAddr>().is_err() && !crate::proxy::valid_hostname(&host) {
        return None;
    }
    Some(Registry {
        host: Allowlist::norm(&host),
        port,
    })
}

/// The registry a `docker login` server address names, read the way the
/// daemon does (registry.Service.Auth): `https://` is assumed without an
/// `http(s)://` prefix, and the host is what comes before the next `/`,
/// `?` or `#`. Empty means Docker Hub. User info (`a@b`) and escapes are
/// refused rather than interpreted.
fn auth_registry(addr: &str) -> Option<Registry> {
    if addr.is_empty() {
        return Some(Registry::hub());
    }
    let rest = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))
        .unwrap_or(addr);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains(['@', '%']) {
        return None;
    }
    registry_host(authority)
}

/// Every `serveraddress` in a `POST /auth` body. Go matches the key
/// case-insensitively, so all spellings are returned; none (or an empty body)
/// means Docker Hub, returned as "".
fn auth_addresses(body: &[u8]) -> Result<Vec<String>, &'static str> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(vec![String::new()]);
    }
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "login request body is not one JSON object")?;
    let obj = v
        .as_object()
        .ok_or("login request body is not a JSON object")?;
    let keys = keys_folding_to(obj, "serveraddress");
    if keys.is_empty() {
        return Ok(vec![String::new()]);
    }
    keys.iter()
        .map(|k| match &obj[k] {
            serde_json::Value::String(s) => Ok(s.clone()),
            serde_json::Value::Null => Ok(String::new()),
            _ => Err("login server address is not a string"),
        })
        .collect()
}

/// A request target's query parameters, decoded like Go's url.ParseQuery
/// (`+` is a space). Err where Go would parse it differently or not at all.
fn query_params(target: &str) -> Result<Vec<(String, String)>, &'static str> {
    let query = target.split_once('?').map_or("", |(_, q)| q);
    let mut out = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if pair.contains(';') {
            return Err("';' in the query string");
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |s: &str| {
            percent_decode_strict(s, true)
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or("invalid percent-encoding in the query string")
        };
        out.push((decode(k)?, decode(v)?));
    }
    Ok(out)
}

/// Every value of `key` (Go's keys are case-sensitive). The daemon reads
/// only the first; checking all of them errs on the safe side.
fn values<'a>(q: &'a [(String, String)], key: &'a str) -> impl Iterator<Item = &'a str> {
    q.iter()
        .filter(move |(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The daemon's httputils.BoolValue: true unless empty, 0, no, false or none.
fn go_bool(v: &str) -> bool {
    !matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "no" | "false" | "none"
    )
}

/// A user-chosen name, fit for one line of stderr: control characters
/// escaped, at most 200 characters.
fn shown(s: &str) -> String {
    let mut out: String = s
        .chars()
        .take(200)
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect();
    if s.chars().count() > 200 {
        out.push_str("...");
    }
    out
}

/// An HTTP error with a JSON `{"message": ...}` the Docker CLI prints.
/// Content-Length framed; `close` adds Connection: close for when the
/// connection can't be used any further.
fn write_error(client: &mut UnixStream, code: u16, msg: &str, close: bool) -> io::Result<()> {
    let body = format!("{{\"message\":{}}}", crate::report::json_string(msg));
    let reason = match code {
        400 => "Bad Request",
        502 => "Bad Gateway",
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
    crate::hide::SocketEnv::from_env().docker_api_sockets()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(json: &str) -> serde_json::Value {
        let r = Report::new(true);
        let out = rewrite_create(json.as_bytes(), &r).expect("rewritable");
        let entries = r.entries();
        assert!(
            entries.iter().all(|e| e.kind == Kind::Rewritten) && entries.len() == 1,
            "a successful create rewrite is a rewrite, not a block: {entries:?}"
        );
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
        let entries = r.entries();
        assert!(
            entries.iter().all(|e| e.kind == Kind::Docker) && entries.len() == 1,
            "a refused create must not also be listed as rewritten: {entries:?}"
        );
        assert_eq!(entries[0].count, 6, "{entries:?}");
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
        assert_eq!(percent_decode_strict("/a%2", false), None);
        assert_eq!(percent_decode_strict("%zz%41", false), None);
        assert_eq!(percent_decode_strict("a+b%41", false).unwrap(), b"a+bA");
        assert_eq!(percent_decode_strict("a+b%41", true).unwrap(), b"a bA");
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
                        while let Ok(Some(mut req)) = read_request(&mut r) {
                            if let Some(f) = req.stream {
                                let mut body = Vec::new();
                                if forward_body(&mut r, &mut body, f).is_err() {
                                    return;
                                }
                                req.body = body;
                            }
                            let _ =
                                tx.send((req.method.clone(), req.path.clone(), req.body.clone()));
                            if req.path.contains("fake-101") {
                                let _ = w.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");
                                let _ = io::copy(r.get_mut(), &mut w);
                                return;
                            }
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
            self.client_with(Policy::default())
        }

        /// Like client(), with a --seal-docker-pulls policy.
        fn client_with(&self, policy: Policy) -> UnixStream {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let path = self.path.clone();
            thread::spawn(move || {
                let _ = proxy(theirs, &path, &Report::new(true), &policy);
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
            .filter(|(m, p, _)| {
                m == "POST"
                    && canonical_route(p).is_ok_and(|s| ends_with(&s, &["containers", "create"]))
            })
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
        let req = Request::new(
            "POST",
            "/v1.43/containers/create?name=x",
            "HTTP/1.1",
            vec![
                ("Host".into(), "docker".into()),
                ("Content-Length".into(), "999".into()),
            ],
        );
        let head = String::from_utf8(req.render_head(Some(7))).unwrap();
        assert!(head.starts_with("POST /v1.43/containers/create?name=x HTTP/1.1\r\n"));
        assert!(head.contains("Content-Length: 7\r\n"));
        assert!(!head.contains("999"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn render_head_keeps_framing_of_streamed_body_and_uses_rewritten_target() {
        let mut req = Request::new(
            "POST",
            "/build?networkmode=host",
            "HTTP/1.1",
            vec![("Transfer-Encoding".into(), "chunked".into())],
        );
        req.forward_target = Some("/build?networkmode=none".into());
        let head = String::from_utf8(req.render_head(None)).unwrap();
        assert!(
            head.starts_with("POST /build?networkmode=none HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
        assert!(!head.contains("Content-Length"), "{head}");
    }

    fn req(method: &str, path: &str) -> Request {
        Request::new(method, path, "HTTP/1.1", vec![])
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

    // ---- path normalisation and endpoint matching ----------------------------

    fn route(p: &str) -> Vec<String> {
        canonical_route(p).unwrap_or_else(|e| panic!("{p}: {e}"))
    }

    #[test]
    fn canonical_route_normalises_like_the_daemon_router() {
        let want = ["containers", "create"];
        for p in [
            "/containers/create",
            "/v1.43/containers/create",
            "/v1.43/containers/create?name=x&y=/../build",
            "//containers//create",
            "/v1.43//containers/./create/",
            "/v1.43/../containers/create",
            "/images/../containers/x/../create",
            "/v1.43/containers%2Fcreate",
            "/v1.43/%63ontainers/%2e%2e/containers/cre%61te",
            "/../../containers/create",
        ] {
            assert_eq!(route(p), want, "{p}");
        }
        // Only one leading version prefix, and only a real one, is dropped.
        assert_eq!(route("/v1.43/v1.43/build"), ["v1.43", "build"]);
        assert_eq!(route("/v/build"), ["v", "build"]);
        assert_eq!(route("/vx1/build"), ["vx1", "build"]);
        assert_eq!(route("/"), Vec::<String>::new());
        // '+' is not a space in a path; ';' is not a separator.
        assert_eq!(route("/a+b;c"), ["a+b;c"]);
    }

    #[test]
    fn ambiguous_paths_are_rejected() {
        for p in [
            "containers/create",
            "http://docker/containers/create",
            "*",
            "/containers/create%",
            "/containers/creat%6",
            "/containers/%zzcreate",
            "/containers/create#frag",
            "/containers/%00create",
            "/containers/create%0a",
            "/containers/%ff",
            "/containers%252Fcreate",
            "/v1.43/services%252Fcreate",
        ] {
            assert!(canonical_route(p).is_err(), "{p} should be rejected");
        }
        // A literal % that doesn't form an escape after decoding is fine.
        assert!(canonical_route("/images/50%25off/json").is_ok());
    }

    fn blocked_target(method: &str, p: &str) -> Option<&'static str> {
        req(method, p).blocked().map(|b| b.target)
    }

    #[test]
    fn network_granting_endpoints_are_blocked() {
        for (p, target) in [
            ("/v1.43/networks/abc/connect", "networks/connect"),
            ("/networks//abc/./connect?x=1", "networks/connect"),
            ("/grpc", "buildkit"),
            ("/v1.43/session", "buildkit"),
            ("/services/create", "services"),
            ("/v1.43/services/create?x", "services"),
            ("/v1.43/services%2Fcreate", "services"),
            ("/v1.43//services/abc/update?version=3", "services"),
            ("/v1.43/services/abc/../create", "services"),
            ("/swarm/init", "swarm"),
            ("/v1.43/swarm/join", "swarm"),
            ("/plugins/pull?remote=x", "plugins"),
            ("/v1.43/plugins/create?name=x", "plugins"),
            ("/v1.43/plugins/vieux/sshfs:latest/enable", "plugins"),
            ("/plugins/foo/upgrade?remote=x", "plugins"),
        ] {
            assert_eq!(blocked_target("POST", p), Some(target), "{p}");
            assert_eq!(blocked_target("post", p), Some(target), "{p}");
        }
        for (m, p) in [
            ("GET", "/services/create"),
            ("GET", "/v1.43/services"),
            ("GET", "/v1.43/swarm"),
            ("POST", "/v1.43/swarm/update"),
            ("POST", "/v1.43/swarm/leave"),
            ("POST", "/v1.43/networks/create"),
            ("POST", "/v1.43/networks/abc/disconnect"),
            ("POST", "/v1.43/plugins/foo/disable"),
            ("POST", "/v1.43/plugins/enable"),
            ("POST", "/v1.43/containers/abc/update"),
            ("POST", "/v1.43/containers/create"),
            ("POST", "/v1.43/build"),
            ("POST", "/v1.43/images/create?fromImage=alpine"),
            ("GET", "/grpc"),
        ] {
            assert_eq!(blocked_target(m, p), None, "{m} {p}");
        }
    }

    #[test]
    fn build_route_matching() {
        assert!(req("POST", "/v1.56/build?t=x").is_build());
        assert!(req("POST", "//build/").is_build());
        assert!(req("POST", "/v1.56/bu%69ld").is_build());
        assert!(!req("GET", "/build").is_build());
        assert!(!req("POST", "/build/prune").is_build());
        assert!(!req("POST", "/images/build/json").is_build());
    }

    #[test]
    fn upgrades_only_allowed_on_attach_and_exec() {
        assert!(req("POST", "/v1.43/containers/abc/attach?stream=1").may_upgrade());
        assert!(req("POST", "/v1.43/exec/abc/start").may_upgrade());
        assert!(req("GET", "/v1.43/containers/abc/attach/ws").may_upgrade());
        assert!(!req("POST", "/grpc").may_upgrade());
        assert!(!req("POST", "/session").may_upgrade());
        assert!(!req("POST", "/v1.43/containers/abc/start").may_upgrade());
        assert!(!req("GET", "/v1.43/containers/abc/attach").may_upgrade());
    }

    fn build_with(path: &str, headers: &[(&str, &str)]) -> Result<String, &'static str> {
        let h = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        rewrite_build(&Request::new("POST", path, "HTTP/1.1", h))
    }

    #[test]
    fn build_network_mode_is_forced_to_none() {
        let tar = [("Content-Type", "application/x-tar")];
        for (path, want) in [
            (
                "/v1.56/build?t=x&networkmode=host",
                "/v1.56/build?t=x&networkmode=none",
            ),
            ("/build", "/build?networkmode=none"),
            ("/build?", "/build?networkmode=none"),
            (
                "/build?networkmode=host&networkmode=bridge&NetworkMode=host&network%6dode=host&version=1",
                "/build?version=1&networkmode=none",
            ),
            ("/build?networkmode", "/build?networkmode=none"),
            (
                "/build?t=a%2Bb&&q=x+y",
                "/build?t=a%2Bb&q=x+y&networkmode=none",
            ),
        ] {
            assert_eq!(build_with(path, &tar).unwrap(), want, "{path}");
        }
    }

    #[test]
    fn unsealable_builds_are_refused() {
        for path in [
            "/build?version=2",
            "/build?version=2&networkmode=none",
            "/build?vers%69on=2",
            "/build?version=1&version=2",
            "/build?networkmode=host;x=1",
            "/build?networkmode=ho%zzst",
            "/build?n%etworkmode=host",
        ] {
            assert!(build_with(path, &[]).is_err(), "{path}");
        }
        for ct in [
            "application/x-www-form-urlencoded",
            " Application/X-WWW-Form-Urlencoded; charset=utf-8",
            "multipart/form-data; boundary=x",
        ] {
            assert!(
                build_with("/build", &[("Content-Type", ct)]).is_err(),
                "{ct}"
            );
        }
    }

    // ---- chunked build uploads ---------------------------------------------------

    fn forward(body: &[u8], framing: Framing) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut r = BufReader::new(body);
        let mut out = Vec::new();
        forward_body(&mut r, &mut out, framing)?;
        let mut rest = Vec::new();
        r.read_to_end(&mut rest)?;
        Ok((out, rest))
    }

    #[test]
    fn chunked_body_is_forwarded_exactly_and_stops_at_its_end() {
        let body =
            b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\nPOST /containers/create HTTP/1.1\r\n";
        let (out, rest) = forward(body, Framing::Chunked).unwrap();
        assert_eq!(out, b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n");
        assert_eq!(rest, b"POST /containers/create HTTP/1.1\r\n");
        let (out, rest) = forward(b"abcdeXYZ", Framing::Length(5)).unwrap();
        assert_eq!((&out[..], &rest[..]), (&b"abcde"[..], &b"XYZ"[..]));
        assert!(forward(b"abc", Framing::Length(5)).is_err());
    }

    #[test]
    fn malformed_chunked_bodies_are_errors() {
        for body in [
            &b"5\nhello\r\n0\r\n\r\n"[..],   // bare LF
            b"5 \r\nhello\r\n0\r\n\r\n",     // whitespace in size
            b"+5\r\nhello\r\n0\r\n\r\n",     // sign
            b"0x5\r\nhello\r\n0\r\n\r\n",    // 0x prefix
            b"\r\nhello\r\n0\r\n\r\n",       // empty size
            b"5\r\nhelloXX0\r\n\r\n",        // missing CRLF after data
            b"0\r\nTrailer: x\r\n\r\n",      // trailers
            b"5\r\nhel",                     // truncated
            b"1000000000000000\r\n",         // too large
            b"5;\x00\r\nhello\r\n0\r\n\r\n", // control char in extension
        ] {
            assert!(
                forward(body, Framing::Chunked).is_err(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn chunked_transfer_encoding_is_only_accepted_for_builds_over_http_1_1() {
        let te = |path: &str, version: &str, extra: &[(&str, &str)]| {
            let mut h = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
            h.extend(extra.iter().map(|(n, v)| (n.to_string(), v.to_string())));
            let mut r = Request::new("POST", path, version, h);
            if r.is_build() {
                r.stream = Some(Framing::Chunked);
            }
            r.unframeable()
        };
        assert_eq!(te("/v1.56/build", "HTTP/1.1", &[]), None);
        assert!(te("/v1.56/build", "HTTP/1.0", &[]).is_some());
        assert!(te("/v1.56/build", "HTTP/1.1", &[("Content-Length", "5")]).is_some());
        assert!(
            te(
                "/v1.56/build",
                "HTTP/1.1",
                &[("Transfer-Encoding", "chunked")]
            )
            .is_some()
        );
        assert!(te("/v1.56/containers/create", "HTTP/1.1", &[]).is_some());
        assert!(te("/v1.56/containers/x/archive", "HTTP/1.1", &[]).is_some());
    }

    // ---- the refusals end-to-end through the proxy ---------------------------

    #[test]
    fn build_with_host_network_is_rewritten_and_framing_kept() {
        for chunked in [false, true] {
            let d = FakeDaemon::start("build");
            let mut c = d.client();
            let build = if chunked {
                "POST /v1.56/build?t=x&networkmode=host HTTP/1.1\r\nHost: docker\r\nContent-Type: application/x-tar\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nTARS\r\n0\r\n\r\n".to_string()
            } else {
                http(
                    "POST",
                    "/v1.56/build?t=x&networkmode=host",
                    "Content-Type: application/x-tar\r\n",
                    "TARS",
                )
            };
            // A create right behind it on the same connection must still be
            // parsed (and sealed): the body ended where we said it did.
            let both = build + &http("POST", "/containers/create", "", HOST_CREATE);
            c.write_all(both.as_bytes()).unwrap();
            let out = read_responses(&mut c, 2);
            assert_eq!(out.matches("HTTP/1.1 404").count(), 2, "{out}");
            drop(c);
            let reqs = d.requests();
            let builds: Vec<_> = reqs
                .iter()
                .filter(|(_, p, _)| p.contains("build"))
                .collect();
            assert_eq!(builds.len(), 1, "{reqs:?}");
            assert_eq!(builds[0].1, "/v1.56/build?t=x&networkmode=none");
            // Forwarded exactly as framed (the fake daemon keeps the raw chunks).
            let want: &[u8] = if chunked {
                b"4\r\nTARS\r\n0\r\n\r\n"
            } else {
                b"TARS"
            };
            assert_eq!(builds[0].2, want);
            assert_creates_sealed(&reqs);
        }
    }

    #[test]
    fn buildkit_build_is_refused_and_connection_closed() {
        let d = FakeDaemon::start("bk");
        let mut c = d.client();
        let both = http(
            "POST",
            "/v1.56/build?version=2&networkmode=none",
            "",
            "TARS",
        ) + &http("POST", "/containers/create", "", HOST_CREATE);
        c.write_all(both.as_bytes()).unwrap();
        let out = read_responses(&mut c, 2);
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
        assert!(out.contains("DOCKER_BUILDKIT=0"), "{out}");
        assert!(out.contains("Connection: close"), "{out}");
        drop(c);
        assert!(d.requests().is_empty());
    }

    #[test]
    fn swarm_and_plugin_requests_never_reach_the_daemon() {
        let d = FakeDaemon::start("swarm");
        let mut c = d.client();
        let all = http("POST", "/v1.43/services/create", "", r#"{"Name":"x"}"#)
            + &http("POST", "/v1.43/services//abc/update?version=1", "", "{}")
            + &http("POST", "/v1.43/swarm/join", "", "{}")
            + &http("POST", "/v1.43/plugins/pull?remote=x", "", "[]")
            + &http("POST", "/v1.43/../grpc", "", "")
            + &http("GET", "/_ping", "", "");
        c.write_all(all.as_bytes()).unwrap();
        let out = read_responses(&mut c, 6);
        assert_eq!(out.matches("HTTP/1.1 403").count(), 5, "{out}");
        assert_eq!(out.matches("HTTP/1.1 404").count(), 1, "{out}");
        drop(c);
        let reqs = d.requests();
        assert_eq!(reqs.len(), 1, "{reqs:?}");
        assert_eq!(reqs[0].1, "/_ping");
    }

    #[test]
    fn unnormalisable_path_is_refused_and_connection_stays_usable() {
        let d = FakeDaemon::start("badpath");
        let mut c = d.client();
        let both = http("POST", "/containers%252Fcreate", "", HOST_CREATE)
            + &http("POST", "/containers/create", "", HOST_CREATE);
        c.write_all(both.as_bytes()).unwrap();
        let out = read_responses(&mut c, 2);
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
        drop(c);
        let reqs = d.requests();
        assert_eq!(reqs.len(), 1, "{reqs:?}");
        assert_creates_sealed(&reqs);
    }

    #[test]
    fn unexpected_101_is_not_relayed() {
        let d = FakeDaemon::start("up");
        let mut c = d.client();
        let both = http(
            "POST",
            "/v1.43/fake-101",
            "Connection: Upgrade\r\nUpgrade: h2c\r\n",
            "",
        ) + &http("POST", "/containers/create", "", HOST_CREATE);
        c.write_all(both.as_bytes()).unwrap();
        let out = read_responses(&mut c, 2);
        assert!(out.starts_with("HTTP/1.1 502"), "{out}");
        assert!(!out.contains("101"), "{out}");
        drop(c);
        // The create was never relayed raw (the daemon would see it as part
        // of the tunnel, or not at all).
        let reqs = d.requests();
        assert_eq!(reqs.len(), 1, "{reqs:?}");
    }

    #[test]
    fn grpc_tunnel_gets_a_grpc_permission_denied() {
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        ours.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let t = thread::spawn(move || {
            let mut tr = theirs.try_clone().unwrap();
            refuse_grpc(&mut tr, &mut theirs, BUILDKIT_MSG)
        });
        let mut client = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        client.extend_from_slice(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0]); // SETTINGS
        client.extend_from_slice(&[0, 0, 1, 0x1, 0x4, 0, 0, 0, 1, 0x83]); // HEADERS s1
        client.extend_from_slice(&[0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // GOAWAY
        ours.write_all(&client).unwrap();
        let mut got = Vec::new();
        let _ = ours.read_to_end(&mut got);
        t.join().unwrap().unwrap();
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.1 101 "), "{text}");
        assert!(text.contains("grpc-status"), "{text}");
        assert!(text.contains(BUILDKIT_MSG), "{text}");
        // The answer is a HEADERS frame on stream 1 with END_STREAM|END_HEADERS.
        let i = got
            .windows(5)
            .position(|w| w == [0x1, 0x5, 0, 0, 0])
            .unwrap();
        assert_eq!(got[i + 5], 1);
    }

    #[test]
    fn hpack_lengths_use_the_7_bit_prefix_encoding() {
        let mut out = Vec::new();
        hpack_string(&mut out, &[b'a'; 126]);
        assert_eq!(out[0], 126);
        let mut out = Vec::new();
        hpack_string(&mut out, &[b'a'; 127]);
        assert_eq!(&out[..2], &[127, 0]);
        let mut out = Vec::new();
        hpack_string(&mut out, &[b'a'; 1337]);
        // RFC 7541 C.1.2: 1337 with a 5-bit prefix; here 7-bit: 1337-127 = 1210.
        assert_eq!(&out[..3], &[127, 0xba, 0x09]);
        assert_eq!(out.len(), 3 + 1337);
    }
    // ---- --seal-docker-pulls ---------------------------------------------------

    fn reg(host: &str, port: Option<u16>) -> Option<Registry> {
        Some(Registry {
            host: host.into(),
            port,
        })
    }

    #[test]
    fn image_names_are_split_by_dockers_reference_rules() {
        let hub = Some(Registry::hub());
        for (name, want) in [
            ("alpine", hub.clone()),
            ("alpine:3.20", hub.clone()),
            ("library/alpine", hub.clone()),
            ("user/repo:tag", hub.clone()),
            ("user/repo@sha256:0123", hub.clone()),
            ("docker.io/library/alpine", reg("docker.io", None)),
            (
                "index.docker.io/library/alpine",
                reg("index.docker.io", None),
            ),
            (
                "registry-1.docker.io/x/y",
                reg("registry-1.docker.io", None),
            ),
            ("localhost/x", reg("localhost", None)),
            ("localhost:5000/x", reg("localhost", Some(5000))),
            ("127.0.0.1:5000/x", reg("127.0.0.1", Some(5000))),
            ("[::1]:5000/x", reg("::1", Some(5000))),
            ("[2001:DB8::1]/x", reg("2001:db8::1", None)),
            ("ghcr.io/a/b:tag@sha256:0123abcd", reg("ghcr.io", None)),
            ("GHCR.IO/a/b", reg("ghcr.io", None)),
            ("myreg:5000/a/b", reg("myreg", Some(5000))),
            // An uppercase first component is a host (it can't be a Hub
            // namespace, those are lowercase).
            ("Foo/bar", reg("foo", None)),
            // Not hosts: invalid ports, junk, a trailing dot. Refused, not guessed.
            ("reg:abc/x", None),
            ("reg:0/x", None),
            ("reg:99999/x", None),
            ("reg:/x", None),
            ("re g.io/x", None),
            ("reg.io./x", None),
            ("[zz]:1/x", None),
            ("[::1]x/y", None),
            (".io/x", None),
        ] {
            assert_eq!(image_registry(name, false), want, "{name}");
        }
        // Search terms don't have the uppercase rule.
        assert_eq!(image_registry("Foo/bar", true), hub);
        assert_eq!(image_registry("ghcr.io/x", true), reg("ghcr.io", None));
        assert!(reg("docker.io", None).unwrap().is_hub());
        assert!(reg("registry-1.docker.io", Some(443)).unwrap().is_hub());
        assert!(!reg("hub.docker.com", None).unwrap().is_hub());
        for local in [
            "localhost",
            "a.localhost",
            "127.0.0.2",
            "::1",
            "0.0.0.0",
            "::ffff:127.0.0.1",
        ] {
            assert!(reg(local, None).unwrap().is_local(), "{local}");
        }
        assert!(!reg("10.0.0.1", None).unwrap().is_local());
    }

    #[test]
    fn login_server_addresses_are_read_like_the_daemon() {
        for (addr, want) in [
            ("", Some(Registry::hub())),
            ("https://index.docker.io/v1/", reg("index.docker.io", None)),
            ("ghcr.io", reg("ghcr.io", None)),
            ("http://myreg:5000/v2/x?y#z", reg("myreg", Some(5000))),
            ("https://GHCR.io", reg("ghcr.io", None)),
            ("localhost:5000", reg("localhost", Some(5000))),
            // Ambiguous ones are refused.
            ("https://ghcr.io@evil.example", None),
            ("evil.example%2fghcr.io", None),
            ("HTTPS://ghcr.io", None),
            ("https://", None),
        ] {
            assert_eq!(auth_registry(addr), want, "{addr}");
        }
        let addrs = |b: &str| auth_addresses(b.as_bytes());
        assert_eq!(addrs("").unwrap(), [""]);
        assert_eq!(addrs(r#"{"username":"u"}"#).unwrap(), [""]);
        assert_eq!(
            addrs(r#"{"serveraddress":"ghcr.io"}"#).unwrap(),
            ["ghcr.io"]
        );
        let mut both =
            addrs(r#"{"ServerAddress":"ghcr.io","SERVERADDRESS":"evil.example"}"#).unwrap();
        both.sort();
        assert_eq!(both, ["evil.example", "ghcr.io"]);
        assert!(addrs(r#"{"serveraddress":1}"#).is_err());
        assert!(addrs(r#"{"serveraddress":"a"} trailing"#).is_err());
        assert!(addrs("[]").is_err());
    }

    #[test]
    fn query_params_decode_like_go() {
        let q = query_params("/images/create?fromImage=ghcr%2Eio%2Fa+b&tag=1&&x").unwrap();
        assert_eq!(
            q,
            [
                ("fromImage".to_string(), "ghcr.io/a b".to_string()),
                ("tag".to_string(), "1".to_string()),
                ("x".to_string(), String::new()),
            ]
        );
        assert!(query_params("/x?a=%zz").is_err());
        assert!(query_params("/x?a=1;b=2").is_err());
        assert!(query_params("/x?a=%ff").is_err());
        assert!(go_bool("1") && go_bool("True") && go_bool("yes"));
        assert!(!go_bool("") && !go_bool("0") && !go_bool("FALSE") && !go_bool("none"));
    }

    fn policy(pulls: PullPolicy, allow: &[&str], ports: &[u16]) -> Policy {
        let allow: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
        Policy {
            pulls,
            allow: Allowlist::parse(&allow).unwrap(),
            ports: ports.to_vec(),
        }
    }

    /// The report target of the refusal, or None if the request passes.
    fn decide(
        p: &Policy,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Option<String> {
        let h = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        let mut r = Request::new(method, path, "HTTP/1.1", h);
        r.body = body.as_bytes().to_vec();
        p.check(&r).map(|b| {
            assert!(b.message.contains("--seal-docker-pulls"), "{}", b.message);
            assert!(b.why.contains("--seal-docker-pulls"), "{}", b.why);
            b.target
        })
    }

    #[test]
    fn pull_policy_decision_table() {
        use PullPolicy::*;
        // (method, path, body, any, allowlisted with --allow ghcr.io + --port 5000, none)
        // true = allowed.
        let rows: &[(&str, &str, &str, bool, bool, bool)] = &[
            // pulls
            (
                "POST",
                "/v1.56/images/create?fromImage=ghcr.io%2Fa%2Fb&tag=1",
                "",
                true,
                true,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=ghcr.io/a/b:t@sha256:00",
                "",
                true,
                true,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=GHCR.IO/a",
                "",
                true,
                true,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=quay.io/a/b",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=alpine&tag=latest",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=docker.io/library/alpine",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=localhost:5000/x",
                "",
                true,
                true,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=localhost:5001/x",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=ghcr.io/a&fromImage=quay.io/b",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=reg:bad/x",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/images/create?fromImage=ghcr.io%2",
                "",
                true,
                false,
                false,
            ),
            // imports
            (
                "POST",
                "/images/create?fromSrc=-&repo=x",
                "",
                true,
                true,
                true,
            ),
            ("POST", "/images/create?repo=x", "", true, true, true),
            (
                "POST",
                "/images/create?fromSrc=https://ghcr.io/x.tar",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/images/create?fromSrc=evil.example",
                "",
                true,
                false,
                false,
            ),
            // push
            (
                "POST",
                "/v1.56/images/ghcr.io/a/b/push?tag=1",
                "",
                true,
                false,
                false,
            ),
            ("POST", "/plugins/ghcr.io/p/push", "", true, false, false),
            // login
            (
                "POST",
                "/v1.56/auth",
                r#"{"username":"u","serveraddress":"ghcr.io"}"#,
                true,
                true,
                false,
            ),
            (
                "POST",
                "/auth",
                r#"{"username":"u","serveraddress":"https://quay.io/v2/"}"#,
                true,
                false,
                false,
            ),
            ("POST", "/auth", r#"{"username":"u"}"#, true, false, false),
            ("POST", "/auth", "not json", true, false, false),
            // manifest lookup, search, plugin privileges
            (
                "GET",
                "/v1.56/distribution/ghcr.io/a/b:1/json",
                "",
                true,
                true,
                false,
            ),
            (
                "GET",
                "/distribution/ghcr.io%2Fa/json",
                "",
                true,
                true,
                false,
            ),
            (
                "GET",
                "/distribution/quay.io/a/json",
                "",
                true,
                false,
                false,
            ),
            ("GET", "/distribution/alpine/json", "", true, false, false),
            (
                "GET",
                "/images/search?term=ghcr.io/x",
                "",
                true,
                true,
                false,
            ),
            ("GET", "/images/search?term=alpine", "", true, false, false),
            (
                "GET",
                "/plugins/privileges?remote=ghcr.io/p",
                "",
                true,
                true,
                false,
            ),
            (
                "GET",
                "/plugins/privileges?remote=vieux/sshfs",
                "",
                true,
                false,
                false,
            ),
            // builds
            ("POST", "/build?t=x", "", true, true, true),
            (
                "POST",
                "/build?remote=https://ghcr.io/ctx.tar",
                "",
                true,
                false,
                false,
            ),
            (
                "POST",
                "/build?remote=git%40github.com%3Ax%2Fy.git",
                "",
                true,
                false,
                false,
            ),
            ("POST", "/build?pull=1", "", true, false, false),
            ("POST", "/build?pull=0", "", true, true, true),
            // unrelated requests never reach out
            ("GET", "/images/ghcr.io/a/json", "", true, true, true),
            ("GET", "/images/x/distribution/y/json", "", true, true, true),
            (
                "POST",
                "/images/ghcr.io/a/tag?repo=quay.io/b",
                "",
                true,
                true,
                true,
            ),
            ("POST", "/containers/create", "{}", true, true, true),
            (
                "GET",
                "/images/create?fromImage=quay.io/a",
                "",
                true,
                true,
                true,
            ),
        ];
        let any = policy(Any, &[], &[]);
        let allowlisted = policy(Allowlisted, &["ghcr.io"], &[5000]);
        let none = policy(Never, &["ghcr.io"], &[5000]);
        for &(m, path, body, a, al, n) in rows {
            for (p, want) in [(&any, a), (&allowlisted, al), (&none, n)] {
                assert_eq!(
                    decide(p, m, path, &[], body).is_none(),
                    want,
                    "{:?} {m} {path} {body}",
                    p.pulls
                );
            }
        }
        // A form body could override the query string: refused.
        let form = [("Content-Type", "application/x-www-form-urlencoded")];
        assert!(
            decide(
                &allowlisted,
                "POST",
                "/images/create?fromImage=ghcr.io/a",
                &form,
                "fromImage=quay.io/b"
            )
            .is_some()
        );
        assert!(
            decide(
                &any,
                "POST",
                "/images/create?fromImage=ghcr.io/a",
                &form,
                ""
            )
            .is_none()
        );
    }

    #[test]
    fn docker_hub_is_one_registry_under_any_of_its_names() {
        let hub_refs = [
            "/images/create?fromImage=alpine",
            "/images/create?fromImage=library/alpine",
            "/images/create?fromImage=docker.io/library/alpine",
            "/images/create?fromImage=index.docker.io/library/alpine",
            "/images/create?fromImage=registry-1.docker.io/library/alpine",
        ];
        for allow in [
            "docker.io",
            "index.docker.io",
            "registry-1.docker.io",
            "*.docker.io",
            "docker.io:443",
        ] {
            let p = policy(PullPolicy::Allowlisted, &[allow], &[]);
            for path in hub_refs {
                assert_eq!(
                    decide(&p, "POST", path, &[], ""),
                    None,
                    "--allow {allow}: {path}"
                );
            }
            assert_eq!(decide(&p, "POST", "/auth", &[], "{}"), None);
            let body = r#"{"serveraddress":"https://index.docker.io/v1/"}"#;
            assert_eq!(decide(&p, "POST", "/auth", &[], body), None);
        }
        let p = policy(
            PullPolicy::Allowlisted,
            &["docker.io:5000", "hub.docker.com"],
            &[],
        );
        for path in hub_refs {
            assert_eq!(
                decide(&p, "POST", path, &[], "").as_deref(),
                Some(&*format!("pull {}", path.split('=').nth(1).unwrap()))
            );
        }
    }

    #[test]
    fn refusals_name_the_registry_and_how_to_allow_it() {
        let msg = |p: &Policy, path: &str| {
            p.check(&req("POST", path))
                .map(|b| (b.target, b.why, b.message))
                .unwrap()
        };
        let p = policy(PullPolicy::Allowlisted, &[], &[]);
        let (t, why, m) = msg(&p, "/images/create?fromImage=ghcr.io/nonexistent/x");
        assert_eq!(t, "pull ghcr.io/nonexistent/x");
        assert_eq!(
            why,
            "ghcr.io not in --allow; --seal-docker-pulls=allowlisted"
        );
        assert!(
            m.contains("nullroute blocked pulling ghcr.io/nonexistent/x")
                && m.contains("Add --allow ghcr.io, or pull the image"),
            "{m}"
        );
        let (_, _, m) = msg(&p, "/images/create?fromImage=alpine");
        assert!(m.contains("--allow docker.io"), "{m}");
        let (_, why, m) = msg(&p, "/images/create?fromImage=localhost:5000/x");
        assert!(
            why.contains("not bridged with --port") && m.contains("--port 5000"),
            "{m}"
        );
        let (t, _, m) = msg(&p, "/images/x/push");
        assert_eq!(t, "push x");
        assert!(m.contains("never pushes"), "{m}");
        let p = policy(PullPolicy::Never, &["ghcr.io"], &[]);
        let (_, why, m) = msg(&p, "/images/create?fromImage=ghcr.io/a");
        assert_eq!(why, "--seal-docker-pulls=none");
        assert!(m.contains("--seal-docker-pulls=none"), "{m}");
        // Names are user-chosen: control characters are escaped, length capped.
        let long = "a".repeat(500);
        let (t, _, _) = msg(&p, &format!("/images/create?fromImage=x%0a{long}"));
        assert!(
            !t.contains('\n') && t.contains("x\\n") && t.len() < 230,
            "{t}"
        );
    }

    #[test]
    fn refused_pull_never_reaches_the_daemon_and_connection_stays_usable() {
        let d = FakeDaemon::start("pull");
        let mut c = d.client_with(policy(PullPolicy::Allowlisted, &["ghcr.io"], &[]));
        let all = http(
            "POST",
            "/v1.56/images/create?fromImage=quay.io%2Fx&tag=1",
            "",
            "",
        ) + &http(
            "POST",
            "/v1.56/images/create?fromImage=ghcr.io%2Fx&tag=1",
            "",
            "",
        ) + &http("POST", "/v1.56/containers/create", "", HOST_CREATE);
        c.write_all(all.as_bytes()).unwrap();
        let out = read_responses(&mut c, 3);
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
        assert!(out.contains("--seal-docker-pulls=allowlisted"), "{out}");
        assert_eq!(out.matches("HTTP/1.1 404").count(), 2, "{out}");
        drop(c);
        let reqs = d.requests();
        assert_eq!(reqs.len(), 2, "{reqs:?}");
        assert!(reqs[0].1.contains("ghcr.io"), "{reqs:?}");
        assert_creates_sealed(&reqs);
    }

    #[test]
    fn refused_remote_build_closes_the_connection_without_reading_the_body() {
        let d = FakeDaemon::start("remote");
        let mut c = d.client_with(policy(PullPolicy::Never, &[], &[]));
        let both = http(
            "POST",
            "/v1.56/build?remote=https%3A%2F%2Fevil.example%2Fx",
            "Content-Type: application/x-tar\r\n",
            "TARS",
        ) + &http("POST", "/containers/create", "", HOST_CREATE);
        c.write_all(both.as_bytes()).unwrap();
        let out = read_responses(&mut c, 2);
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
        assert!(out.contains("Connection: close"), "{out}");
        assert_eq!(out.matches("HTTP/1.1 ").count(), 1, "{out}");
        drop(c);
        assert!(d.requests().is_empty());
    }

    #[test]
    fn default_policy_changes_nothing() {
        let d = FakeDaemon::start("any");
        let mut c = d.client();
        let all = http("POST", "/images/create?fromImage=quay.io%2Fx", "", "")
            + &http("POST", "/images/x/push", "", "")
            + &http("POST", "/auth", "", r#"{"serveraddress":"evil.example"}"#)
            + &http(
                "POST",
                "/build?remote=x&pull=1",
                "Content-Type: application/x-tar\r\n",
                "",
            );
        c.write_all(all.as_bytes()).unwrap();
        let out = read_responses(&mut c, 4);
        assert_eq!(out.matches("HTTP/1.1 404").count(), 4, "{out}");
        drop(c);
        assert_eq!(d.requests().len(), 4);
    }
}
