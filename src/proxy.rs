//! `--allow`: let chosen hosts through, via an HTTP proxy only nullroute can dial out of.
//!
//! The sandbox still has no route out. nullroute listens on a port inside the
//! sandbox's loopback (passed to the parent like a `--port` listener, see
//! forward.rs) and points the standard proxy variables at it (HTTP_PROXY,
//! HTTPS_PROXY, ALL_PROXY and lowercase forms). The parent, on the host's
//! network, handles each request:
//!
//! - `CONNECT host:port` (HTTPS and anything tunnelled): checked against the
//!   allowlist, then tunnelled. TLS stays end-to-end; nullroute never sees
//!   plaintext and needs no certificates.
//! - `GET http://host/...` (plain HTTP): checked, then forwarded with the
//!   request line rewritten to origin form and `Connection: close`.
//!
//! Blocked hosts get `403` with an explanation, and one warning per host on stderr.
//!
//! This only covers clients that honour proxy variables (curl, wget, pip,
//! Python requests/urllib/httpx, Go net/http, Node's fetch with
//! NODE_USE_ENV_PROXY, Java with flags...). Other clients can reach allowed
//! host names through the DNS sinkhole (dns.rs); anything else still hits the
//! sealed network and fails with "network unreachable", so the failure mode is
//! closed, never open.
//!
//! Resolution happens on the host. Addresses that resolve to loopback or
//! "unspecified" are refused even for allowed names, so an allowed name can't be
//! used to reach the host's localhost services behind `--port`'s back.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;

use crate::report::{Kind, Report};
use std::thread;
use std::time::Duration;

/// Default port for the proxy inside the sandbox (the conventional proxy port).
/// The sandbox's loopback is private, so this only clashes with the command's
/// own listeners or with a `--port`; see pick_port.
pub const DEFAULT_PORT: u16 = 3128;

const MAX_HEAD: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// Exact host name or IP literal, lowercase, no trailing dot.
    Exact(String),
    /// `*.example.com`: any subdomain of example.com (not example.com itself).
    Suffix(String),
}

impl Pattern {
    pub(crate) fn matches(&self, h: &str) -> bool {
        match self {
            Pattern::Exact(e) => e == h,
            Pattern::Suffix(s) => {
                h.len() > s.len()
                    && h.ends_with(s.as_str())
                    && h.as_bytes()[h.len() - s.len() - 1] == b'.'
            }
        }
    }
}

/// One `--allow` entry: a pattern and, optionally, the only port it allows.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub pattern: Pattern,
    /// None: every port.
    pub port: Option<u16>,
}

#[derive(Debug, Default, Clone)]
pub struct Allowlist {
    entries: Vec<Entry>,
}

impl Allowlist {
    /// Parse `--allow` values: a host, an IP literal or `*.domain`, each
    /// optionally with `:port` (`[v6]:port` for IPv6 literals).
    pub fn parse(values: &[String]) -> Result<Self, String> {
        let mut entries = Vec::new();
        for raw in values {
            let v = raw.trim().to_ascii_lowercase();
            let bad = |why: &str| Err(format!("--allow {raw:?}: {why}"));
            if v.is_empty() {
                return bad("empty");
            }
            if v.contains("://") || v.contains('/') {
                return bad("give a host name, not a URL (e.g. api.github.com)");
            }
            // Bare IPv6 literal (has colons, no brackets): no port possible.
            if let Ok(ip) = v.parse::<IpAddr>() {
                entries.push(Entry {
                    pattern: Pattern::Exact(ip.to_string()),
                    port: None,
                });
                continue;
            }
            let (host, port) = if let Some(rest) = v.strip_prefix('[') {
                let Some((h, after)) = rest.split_once(']') else {
                    return bad("unclosed [");
                };
                if h.parse::<std::net::Ipv6Addr>().is_err() {
                    return bad("brackets are only for IPv6 literals");
                }
                match after {
                    "" => (h.to_string(), None),
                    a => match a
                        .strip_prefix(':')
                        .and_then(|p| p.parse::<u16>().ok())
                        .filter(|&p| p != 0)
                    {
                        Some(p) => (h.to_string(), Some(p)),
                        None => return bad("port must be 1-65535"),
                    },
                }
            } else {
                match v.rsplit_once(':') {
                    Some((h, p)) => match p.parse::<u16>().ok().filter(|&p| p != 0) {
                        Some(p) => (h.to_string(), Some(p)),
                        None => return bad("port must be 1-65535"),
                    },
                    None => (v.clone(), None),
                }
            };
            let host = host.trim_end_matches('.').to_string();
            // Store IpAddr's canonical form so `2001:0db8::1` matches `2001:db8::1`.
            let pattern = if let Ok(ip) = host.parse::<IpAddr>() {
                Pattern::Exact(ip.to_string())
            } else if let Some(rest) = host.strip_prefix("*.") {
                if !valid_hostname(rest) || !rest.contains('.') {
                    return bad("wildcards must look like *.example.com");
                }
                Pattern::Suffix(rest.to_string())
            } else if host.contains('*') {
                return bad("only a leading *. wildcard is supported (e.g. *.example.com)");
            } else if valid_hostname(&host) {
                Pattern::Exact(host)
            } else {
                return bad("not a valid host name");
            };
            entries.push(Entry { pattern, port });
        }
        Ok(Allowlist { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Is host allowed on at least one port?
    pub fn allows_host(&self, host: &str) -> bool {
        let h = Self::norm(host);
        self.entries.iter().any(|e| e.pattern.matches(&h))
    }

    pub(crate) fn norm(host: &str) -> String {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let h = h.trim_start_matches('[').trim_end_matches(']');
        // Same canonical IP form stored by parse, so either spelling matches.
        match h.parse::<IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => h.to_string(),
        }
    }

    /// Is host:port allowed?
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let h = Self::norm(host);
        self.entries
            .iter()
            .any(|e| e.pattern.matches(&h) && e.port.is_none_or(|p| p == port))
    }
}

pub(crate) fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// `--resolve HOST:IP` pins: host name (normalized) to the address nullroute
/// dials instead of resolving the name on the host.
pub type Overrides = std::collections::BTreeMap<String, IpAddr>;

/// Parse `--resolve` values (`host:ip`, `host:[v6]` or `host:v6`). Every
/// pinned host must be allowed by `allow`, so a pin can't widen the allowlist.
pub fn parse_overrides(values: &[String], allow: &Allowlist) -> Result<Overrides, String> {
    let mut out = Overrides::new();
    for raw in values {
        let v = raw.trim().to_ascii_lowercase();
        let bad = |why: &str| Err(format!("--resolve {raw:?}: {why}"));
        let Some((host, ip)) = v.split_once(':') else {
            return bad("expected HOST:IP, e.g. api.example.com:10.0.0.5");
        };
        let host = host.trim_end_matches('.');
        if !valid_hostname(host) || host.parse::<IpAddr>().is_ok() {
            return bad("not a valid host name");
        }
        let ip = ip.trim_start_matches('[').trim_end_matches(']');
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return bad("not a valid IP address");
        };
        if !allow.allows_host(host) {
            return bad("host is not in --allow");
        }
        out.insert(host.to_string(), ip);
    }
    Ok(out)
}

/// First port from DEFAULT_PORT up that isn't a `--port`.
pub fn pick_port(forwarded: &[u16]) -> u16 {
    (DEFAULT_PORT..=u16::MAX)
        .find(|p| !forwarded.contains(p))
        .unwrap_or(DEFAULT_PORT)
}

/// Environment to give the command so proxy-aware clients use us.
pub fn env_vars(port: u16) -> Vec<(&'static str, String)> {
    let url = format!("http://127.0.0.1:{port}");
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    vec![
        ("HTTP_PROXY", url.clone()),
        ("http_proxy", url.clone()),
        ("HTTPS_PROXY", url.clone()),
        ("https_proxy", url.clone()),
        ("ALL_PROXY", url.clone()),
        ("all_proxy", url),
        ("NO_PROXY", no_proxy.clone()),
        ("no_proxy", no_proxy),
        // Node 24+ only honours the variables above when this is set.
        ("NODE_USE_ENV_PROXY", "1".to_string()),
    ]
}

/// Shared state for one run: the allowlist and where blocks are recorded.
pub struct Proxy {
    allow: Allowlist,
    overrides: Overrides,
    report: Arc<Report>,
}

impl Proxy {
    pub fn new(allow: Allowlist, overrides: Overrides, report: Arc<Report>) -> Arc<Self> {
        Arc::new(Proxy {
            allow,
            overrides,
            report,
        })
    }

    /// Serve proxy connections on a listener fd received from the sandbox.
    pub fn spawn_acceptor(self: &Arc<Self>, fd: RawFd) {
        // SAFETY: fd is a listening TCP socket received from the child; we own it.
        let listener = unsafe { TcpListener::from_raw_fd(fd) };
        let me = self.clone();
        thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let me = me.clone();
                thread::spawn(move || me.handle(conn));
            }
        });
    }

    fn block(&self, host: &str, port: u16, why: &str) {
        self.report
            .record(Kind::Proxy, &format!("{host}:{port}"), why, || {
                format!("nullroute: blocked {host} ({why})")
            });
    }

    fn handle(&self, mut client: TcpStream) {
        let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
        let Ok((head, rest)) = read_head(&mut client) else {
            return;
        };
        let _ = client.set_read_timeout(None);
        let Some(req) = parse_request(&head) else {
            respond(&mut client, 400, "nullroute proxy: malformed request");
            return;
        };

        if !self.allow.allows(&req.host, req.port) {
            self.block(&req.host, req.port, "not in --allow");
            respond(
                &mut client,
                403,
                &format!(
                    "nullroute blocked {}: it is not in --allow. Rerun with --allow {} to permit it.",
                    req.host, req.host
                ),
            );
            return;
        }
        let upstream = match dial(&req.host, req.port, &self.overrides) {
            Ok(s) => s,
            Err(DialError::Loopback) => {
                self.block(
                    &req.host,
                    req.port,
                    "resolves to loopback; use --port for local services",
                );
                respond(
                    &mut client,
                    403,
                    &format!(
                        "nullroute blocked {}: it resolves to a loopback address. Use --port for services on this machine.",
                        req.host
                    ),
                );
                return;
            }
            Err(DialError::Io(e)) => {
                respond(
                    &mut client,
                    502,
                    &format!("nullroute could not reach {}:{}: {e}", req.host, req.port),
                );
                return;
            }
        };

        let mut upstream = upstream;
        if req.connect {
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
        } else {
            let head = rewrite_for_origin(&head, &req);
            if upstream.write_all(&head).is_err() {
                return;
            }
        }
        if !rest.is_empty() && upstream.write_all(&rest).is_err() {
            return;
        }
        crate::forward::relay(client, upstream);
    }
}

struct Request {
    connect: bool,
    host: String,
    port: u16,
    /// For absolute-form requests: the request line with an origin-form target.
    origin_line: String,
}

/// Read until the end of the request head. Returns (head, bytes after it).
fn read_head(s: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("request head too large"));
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, None)?;
        return Some(Request {
            connect: true,
            host,
            port,
            origin_line: String::new(),
        });
    }
    // Absolute form: scheme://authority/path
    let (scheme, after) = target.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        // https:// in absolute form would mean we originate TLS; clients use CONNECT for that.
        _ => return None,
    };
    let (authority, path) = match after.find('/') {
        Some(i) => (&after[..i], &after[i..]),
        None => (after, "/"),
    };
    let authority = authority.rsplit('@').next()?; // drop userinfo
    let (host, port) = split_host_port(authority, Some(default_port))?;
    Some(Request {
        connect: false,
        host,
        port,
        origin_line: format!("{method} {path} {version}"),
    })
}

/// "host:port", "[v6]:port", or "host" when a default port is given.
fn split_host_port(s: &str, default: Option<u16>) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default?,
            None => return None,
        };
        return Some((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        Some(_) => None,
        None => Some((s.to_string(), default?)),
    }
    .filter(|(h, p)| !h.is_empty() && *p != 0)
}

/// Origin-form request line, Proxy-* headers dropped, and Connection: close so
/// each proxied connection carries one request to one host.
fn rewrite_for_origin(head: &[u8], req: &Request) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out = String::with_capacity(head.len());
    out.push_str(&req.origin_line);
    out.push_str("\r\n");
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if name.starts_with("proxy-") || name == "connection" || name == "keep-alive" {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

pub(crate) enum DialError {
    Loopback,
    Io(io::Error),
}

/// Resolve (or look up in `overrides`) and connect, refusing loopback targets.
pub(crate) fn dial(host: &str, port: u16, overrides: &Overrides) -> Result<TcpStream, DialError> {
    let addrs: Vec<SocketAddr> = match overrides.get(&Allowlist::norm(host)) {
        Some(&ip) => vec![SocketAddr::new(ip, port)],
        None => (host, port)
            .to_socket_addrs()
            .map_err(DialError::Io)?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(DialError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses",
        )));
    }
    if addrs.iter().any(|a| forbidden(a.ip())) {
        return Err(DialError::Loopback);
    }
    let mut last = None;
    for a in &addrs {
        match TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(DialError::Io(last.unwrap()))
}

fn forbidden(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    ip.is_loopback() || ip.is_unspecified()
}

fn respond(s: &mut TcpStream, code: u16, msg: &str) {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Bad Gateway",
    };
    let body = format!("{msg}\n");
    let _ = write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn al(v: &[&str]) -> Allowlist {
        Allowlist::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn exact_and_case_and_trailing_dot() {
        let a = al(&["API.GitHub.com."]);
        assert!(a.allows("api.github.com", 443));
        assert!(a.allows("api.github.com.", 443));
        assert!(a.allows("Api.GitHub.Com", 443));
        assert!(!a.allows("github.com", 443));
        assert!(!a.allows("evilapi.github.com", 443));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let a = al(&["*.stripe.dev"]);
        assert!(a.allows("api.stripe.dev", 443));
        assert!(a.allows("a.b.stripe.dev", 443));
        assert!(!a.allows("stripe.dev", 443));
        assert!(!a.allows("notstripe.dev", 443));
        assert!(!a.allows("stripe.dev.evil.com", 443));
    }

    #[test]
    fn ip_literals() {
        let a = al(&["10.0.0.5", "2001:db8::1"]);
        assert!(a.allows("10.0.0.5", 443));
        assert!(a.allows("[2001:db8::1]", 443));
        assert!(!a.allows("10.0.0.6", 443));
    }

    #[test]
    fn ipv6_allow_entries_match_canonical_form() {
        // Bare literals already go through IpAddr::to_string.
        let bare = al(&["2001:0db8:0000::0001"]);
        assert!(bare.allows("2001:db8::1", 443));
        assert!(bare.allows("[2001:0db8::1]", 443));

        let bracketed = al(&["[2001:0db8::1]"]);
        assert!(bracketed.allows("2001:db8::1", 443));
        assert!(bracketed.allows("[2001:db8::1]", 80));

        // Port-qualified bracketed form must store the canonical address too.
        let ported = al(&["[2001:0DB8:0:0:0:0:0:1]:8443"]);
        assert!(ported.allows("2001:db8::1", 8443));
        assert!(ported.allows("[2001:db8::1]", 8443));
        assert!(ported.allows("2001:0db8::1", 8443));
        assert!(!ported.allows("2001:db8::1", 443));
        assert!(!ported.allows("2001:db8::2", 8443));
    }

    #[test]
    fn ports_restrict_entries() {
        let a = al(&[
            "db.example.com:5432",
            "api.example.com",
            "[2001:db8::1]:8443",
            "*.svc.test:9000",
        ]);
        assert!(a.allows("db.example.com", 5432));
        assert!(!a.allows("db.example.com", 443));
        assert!(a.allows("api.example.com", 1234));
        assert!(a.allows("2001:db8::1", 8443) && !a.allows("2001:db8::1", 443));
        assert!(a.allows("x.svc.test", 9000) && !a.allows("x.svc.test", 80));
    }

    #[test]
    fn rejects_bad_patterns() {
        for bad in [
            "",
            "*",
            "*.com",
            "https://x.com",
            "x.com/path",
            "x.com:0",
            "x.com:99999",
            "x.com:http",
            "[x.com]:443",
            "[::1",
            "a*.b.com",
            "-x.com",
            "x..com",
        ] {
            assert!(
                Allowlist::parse(&[bad.to_string()]).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn parses_connect_and_absolute_form() {
        let r = parse_request(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(r.connect && r.host == "api.github.com" && r.port == 443);
        let r = parse_request(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("2001:db8::1", 8443));
        let r = parse_request(b"GET http://user:pw@example.com/a?b=1 HTTP/1.1\r\n\r\n").unwrap();
        assert!(!r.connect && r.host == "example.com" && r.port == 80);
        assert_eq!(r.origin_line, "GET /a?b=1 HTTP/1.1");
        let r = parse_request(b"POST http://example.com:8080 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((r.port, r.origin_line.as_str()), (8080, "POST / HTTP/1.1"));
        assert!(parse_request(b"GET /relative HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"GET https://x.com/ HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"CONNECT nohost HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn rewrite_drops_proxy_headers_and_forces_close() {
        let head = b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic abc\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n";
        let req = parse_request(head).unwrap();
        let out = String::from_utf8(rewrite_for_origin(head, &req)).unwrap();
        assert_eq!(
            out,
            "GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn loopback_targets_are_forbidden() {
        for ip in [
            "127.0.0.1",
            "127.8.9.10",
            "::1",
            "0.0.0.0",
            "::",
            "::ffff:127.0.0.1",
        ] {
            assert!(forbidden(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["10.0.0.1", "93.184.216.34", "2001:db8::1"] {
            assert!(!forbidden(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn resolve_overrides_must_be_allowed_and_valid() {
        let a = al(&["api.example.com", "*.svc.test:9000"]);
        let o = parse_overrides(
            &[
                "API.example.com.:10.0.0.5".to_string(),
                "x.svc.test:[2001:db8::1]".to_string(),
                "y.svc.test:2001:db8::2".to_string(),
            ],
            &a,
        )
        .unwrap();
        assert_eq!(o["api.example.com"], "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(o["x.svc.test"], "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(o["y.svc.test"], "2001:db8::2".parse::<IpAddr>().unwrap());
        for bad in [
            "other.com:10.0.0.5",
            "api.example.com",
            "api.example.com:nope",
            "10.0.0.1:10.0.0.5",
            "svc.test:10.0.0.5",
        ] {
            assert!(parse_overrides(&[bad.to_string()], &a).is_err(), "{bad}");
        }
    }

    #[test]
    fn dial_uses_override_and_still_refuses_loopback() {
        let mut o = Overrides::new();
        o.insert("pinned.test".into(), "127.0.0.1".parse().unwrap());
        assert!(matches!(
            dial("Pinned.Test", 1, &o),
            Err(DialError::Loopback)
        ));
    }

    #[test]
    fn proxy_port_avoids_forwarded_ports() {
        assert_eq!(pick_port(&[]), 3128);
        assert_eq!(pick_port(&[3128, 3129, 5432]), 3130);
    }
}
