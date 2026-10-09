//! Peeking at a TLS ClientHello to read the server name (SNI) before a tunnel
//! is let through.
//!
//! The `--allow` proxy and the DNS sinkhole decide by the name a client asks to
//! be connected to. A client can ask for an allowed host and then name a
//! different one inside TLS (domain fronting). Reading the SNI of the first
//! TLS record catches that, with no decryption and no certificates: the bytes
//! are forwarded untouched once they pass.
//!
//! What it does and doesn't do:
//!
//! - The first bytes of the tunnel are looked at. If they aren't a TLS
//!   handshake record (SSH, a database protocol, plain HTTP), they are
//!   forwarded as they are. If the *server* speaks first (SMTP, MySQL, SSH),
//!   nothing is held back either.
//! - A ClientHello with a server name that isn't the host the tunnel was
//!   opened for (and isn't itself allowed) is refused.
//! - No server name (a client dialling an IP address, or an old client) is let
//!   through: the server then picks its default site, and there is nothing to
//!   compare.
//! - A first record that starts like TLS but can't be read (malformed, or
//!   split over too many bytes) is refused rather than guessed at.
//!
//! What it can't do: the HTTP `Host` header inside TLS is invisible here, so a
//! client that names the allowed host in the SNI and a different one inside the
//! encrypted request still gets through, on a server that serves both (a shared
//! CDN address). Encrypted Client Hello hides the real name in the same way;
//! the outer name is what is checked.

use std::io::{self, Read};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// How long a client that has started a TLS record may take to finish its
/// ClientHello before the tunnel is closed.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// Most bytes read while looking for the ClientHello (it is a few hundred
/// bytes, a couple of KB with post-quantum key shares).
const MAX_PEEK: usize = 64 * 1024;

/// What the bytes read so far say.
#[derive(Debug, PartialEq, Eq)]
pub enum Peek {
    /// Not a TLS handshake: forward as is.
    NotTls,
    /// A ClientHello, with its server name if it has one.
    Hello(Option<String>),
    /// Starts like TLS but isn't a readable ClientHello.
    Unreadable,
    /// A readable ClientHello needs more bytes.
    Incomplete,
}

/// Parse the start of a client-to-server stream.
pub fn peek_client_hello(buf: &[u8]) -> Peek {
    if buf.is_empty() {
        return Peek::Incomplete;
    }
    // 0x16 = handshake record. Anything else isn't a TLS (1.0-1.3) hello.
    if buf[0] != 0x16 {
        return Peek::NotTls;
    }
    if buf.len() >= 2 && buf[1] != 3 {
        return Peek::NotTls;
    }
    let mut handshake: Vec<u8> = Vec::new();
    let mut pos = 0;
    loop {
        let Some(header) = buf.get(pos..pos + 5) else {
            return Peek::Incomplete;
        };
        if header[0] != 0x16 || header[1] != 3 {
            return Peek::Unreadable;
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        // A record carries at most 2^14 bytes of plaintext (+ expansion).
        if len == 0 || len > 16384 + 2048 {
            return Peek::Unreadable;
        }
        let Some(payload) = buf.get(pos + 5..pos + 5 + len) else {
            return Peek::Incomplete;
        };
        handshake.extend_from_slice(payload);
        pos += 5 + len;
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Peek::Unreadable; // not a ClientHello
            }
            let want = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            if want > MAX_PEEK {
                return Peek::Unreadable;
            }
            if handshake.len() >= 4 + want {
                return match server_name(&handshake[4..4 + want]) {
                    Some(name) => Peek::Hello(name),
                    None => Peek::Unreadable,
                };
            }
        }
    }
}

/// A bounds-checked reader over a byte slice.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    /// A block with a 1-byte length prefix.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    /// A block with a 2-byte length prefix.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// The server name in a ClientHello body (after the 4-byte handshake header).
/// Outer None: malformed. Inner None: well-formed, no server name. A name that
/// isn't printable ASCII comes back as an empty string, which matches nothing.
fn server_name(body: &[u8]) -> Option<Option<String>> {
    let mut c = Cursor(body);
    c.take(2 + 32)?; // legacy_version, random
    c.vec8()?; // session id
    c.vec16()?; // cipher suites
    c.vec8()?; // compression methods
    if c.0.is_empty() {
        return Some(None); // no extensions at all (TLS 1.0 style)
    }
    let mut exts = Cursor(c.vec16()?);
    let mut found: Option<Option<String>> = None;
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        if ty != 0 {
            continue;
        }
        if found.is_some() {
            return None; // two server_name extensions
        }
        let mut list = Cursor(Cursor(data).vec16()?);
        let mut name = None;
        while !list.0.is_empty() {
            let kind = list.u8()?;
            let value = list.vec16()?;
            if kind == 0 {
                if name.is_some() {
                    return None;
                }
                name = Some(normalize(value));
            }
        }
        found = Some(name);
    }
    Some(found.flatten())
}

/// Lowercase, no trailing dot; "" if it isn't printable ASCII.
fn normalize(raw: &[u8]) -> String {
    if raw.is_empty() || !raw.iter().all(|b| b.is_ascii_graphic()) {
        return String::new();
    }
    String::from_utf8_lossy(raw)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Why a tunnel was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The ClientHello names a server that isn't acceptable.
    Name(String),
    /// Looked like TLS but couldn't be read, or never finished.
    Unreadable,
}

/// The verdict on the start of a tunnel.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward these bytes (already read from the client) and carry on.
    Pass(Vec<u8>),
    Refuse(Refusal),
}

/// Decide whether a tunnel may carry on, reading just enough from `client`.
///
/// `initial` is what the caller already has from the client (bytes that came
/// in right behind a CONNECT head). `ok(name)` says whether a server name is
/// acceptable. `upstream` is only watched: if the server speaks first, the
/// protocol isn't TLS and the tunnel is let through at once.
pub fn gate(
    client: &TcpStream,
    upstream: &TcpStream,
    initial: Vec<u8>,
    ok: impl Fn(&str) -> bool,
) -> Verdict {
    let mut buf = initial;
    let mut started: Option<Instant> = None;
    let mut chunk = [0u8; 4096];
    loop {
        match peek_client_hello(&buf) {
            Peek::NotTls | Peek::Hello(None) => return Verdict::Pass(buf),
            Peek::Hello(Some(name)) => {
                return if ok(&name) {
                    Verdict::Pass(buf)
                } else {
                    Verdict::Refuse(Refusal::Name(name))
                };
            }
            Peek::Unreadable => return Verdict::Refuse(Refusal::Unreadable),
            Peek::Incomplete => {}
        }
        if buf.len() >= MAX_PEEK {
            return Verdict::Refuse(Refusal::Unreadable);
        }
        // Nothing yet: wait for either side (a server that speaks first isn't
        // TLS). Part of a record: only the client can finish it, and not forever.
        let wait = started.map(|t| HANDSHAKE_WAIT.saturating_sub(t.elapsed()));
        let watch_upstream = buf.is_empty();
        match poll(client, watch_upstream.then_some(upstream), wait) {
            Ready::Client => {}
            Ready::Upstream => return Verdict::Pass(buf),
            Ready::Timeout => return Verdict::Refuse(Refusal::Unreadable),
        }
        match (&*client).read(&mut chunk) {
            Ok(0) | Err(_) => {
                // The client went away: nothing to forward, and nothing to
                // refuse; let the relay see the close.
                return if buf.is_empty() {
                    Verdict::Pass(buf)
                } else {
                    Verdict::Refuse(Refusal::Unreadable)
                };
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        started.get_or_insert_with(Instant::now);
    }
}

enum Ready {
    Client,
    Upstream,
    Timeout,
}

/// Wait until `client` (or `upstream`, if given) is readable. A client that is
/// readable wins a tie.
fn poll(client: &TcpStream, upstream: Option<&TcpStream>, wait: Option<Duration>) -> Ready {
    let deadline = wait.map(|w| Instant::now() + w);
    loop {
        let mut fds = [
            libc::pollfd {
                fd: client.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: upstream.map_or(-1, |u| u.as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout_ms: libc::c_int = match deadline {
            None => -1,
            Some(d) => d
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as libc::c_int,
        };
        // SAFETY: fds is a valid array of two pollfds; a negative fd is ignored.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // Can't wait: don't hold the tunnel hostage; the read decides.
            return Ready::Client;
        }
        if fds[0].revents != 0 {
            return Ready::Client;
        }
        if fds[1].revents != 0 {
            return Ready::Upstream;
        }
        if n == 0 {
            return Ready::Timeout;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello record carrying the given extensions.
    pub fn hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0u8; 32]); // random
        body.push(0); // session id
        body.extend([0, 2, 0x13, 0x01]); // one cipher suite
        body.extend([1, 0]); // null compression
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut hs = vec![1];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        record(&hs)
    }

    pub fn record(payload: &[u8]) -> Vec<u8> {
        let mut r = vec![0x16, 3, 1];
        r.extend((payload.len() as u16).to_be_bytes());
        r.extend(payload);
        r
    }

    pub fn sni_ext(name: &str) -> Vec<u8> {
        let mut entry = vec![0];
        entry.extend((name.len() as u16).to_be_bytes());
        entry.extend(name.as_bytes());
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend(entry);
        let mut ext = vec![0, 0];
        ext.extend((list.len() as u16).to_be_bytes());
        ext.extend(list);
        ext
    }

    fn other_ext(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut e = ty.to_be_bytes().to_vec();
        e.extend((data.len() as u16).to_be_bytes());
        e.extend(data);
        e
    }

    #[test]
    fn reads_the_server_name() {
        let h = hello(&sni_ext("API.Example.com"));
        assert_eq!(
            peek_client_hello(&h),
            Peek::Hello(Some("api.example.com".into()))
        );
        // After other extensions, and with bytes following the record.
        let mut exts = other_ext(10, &[0, 2, 0, 29]);
        exts.extend(sni_ext("a.test."));
        exts.extend(other_ext(0xfe0d, &[1, 2, 3]));
        let mut h = hello(&exts);
        h.extend([0x17, 3, 3, 0, 1, 0]);
        assert_eq!(peek_client_hello(&h), Peek::Hello(Some("a.test".into())));
    }

    #[test]
    fn no_server_name_is_not_an_error() {
        assert_eq!(peek_client_hello(&hello(&[])), Peek::Hello(None));
        assert_eq!(
            peek_client_hello(&hello(&other_ext(10, &[0, 2, 0, 29]))),
            Peek::Hello(None)
        );
        // A server_name extension with an empty list.
        assert_eq!(
            peek_client_hello(&hello(&other_ext(0, &[0, 0]))),
            Peek::Hello(None)
        );
    }

    #[test]
    fn other_protocols_are_not_tls() {
        for first in [
            &b"SSH-2.0-OpenSSH_9.6\r\n"[..],
            b"GET / HTTP/1.1\r\n\r\n",
            b"\x00\x00\x00\x08\x04\xd2\x16\x2f", // Postgres SSLRequest
            b"\x80\x2e\x01\x03\x01",             // SSLv2-style hello
            b"\x16\x02\x00",                     // a 0x16 byte, but not TLS 3.x
        ] {
            assert_eq!(peek_client_hello(first), Peek::NotTls, "{first:?}");
        }
    }

    #[test]
    fn short_reads_wait_for_more() {
        let h = hello(&sni_ext("a.test"));
        assert_eq!(peek_client_hello(&[]), Peek::Incomplete);
        for n in 1..h.len() {
            assert_eq!(peek_client_hello(&h[..n]), Peek::Incomplete, "{n} bytes");
        }
        assert!(matches!(peek_client_hello(&h), Peek::Hello(Some(_))));
    }

    #[test]
    fn a_hello_split_over_records_is_reassembled() {
        let h = hello(&sni_ext("split.test"));
        let payload = &h[5..];
        let (a, b) = payload.split_at(20);
        let mut two = record(a);
        two.extend(record(b));
        assert_eq!(
            peek_client_hello(&two),
            Peek::Hello(Some("split.test".into()))
        );
        assert_eq!(peek_client_hello(&two[..two.len() - 1]), Peek::Incomplete);
        // Records so small that not even the handshake header fits in the
        // first one still work.
        let mut many = Vec::new();
        for piece in payload.chunks(3) {
            many.extend(record(piece));
        }
        assert_eq!(
            peek_client_hello(&many),
            Peek::Hello(Some("split.test".into()))
        );
    }

    #[test]
    fn malformed_hellos_are_unreadable() {
        let good = hello(&sni_ext("a.test"));
        // Wrong handshake type.
        let mut bad = good.clone();
        bad[5] = 2;
        assert_eq!(peek_client_hello(&bad), Peek::Unreadable);
        // A zero-length record.
        assert_eq!(peek_client_hello(&[0x16, 3, 1, 0, 0]), Peek::Unreadable);
        // Extensions length overruns the hello.
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 12] = 0xff;
        assert_eq!(peek_client_hello(&bad), Peek::Unreadable);
        // Two server_name extensions are ambiguous.
        let mut exts = sni_ext("a.test");
        exts.extend(sni_ext("b.test"));
        assert_eq!(peek_client_hello(&hello(&exts)), Peek::Unreadable);
        // An absurd handshake length.
        let mut huge = record(&[1, 0xff, 0xff, 0xff, 0, 0]);
        huge.extend(record(&[0; 10]));
        assert_eq!(peek_client_hello(&huge), Peek::Unreadable);
        // A different record type after a partial handshake record.
        let mut cut = record(&good[5..10]);
        cut.extend([0x17, 3, 3, 0, 1, 0]);
        assert_eq!(peek_client_hello(&cut), Peek::Unreadable);
    }

    #[test]
    fn odd_names_match_nothing() {
        let h = hello(&sni_ext("evil\u{e9}.test"));
        assert_eq!(peek_client_hello(&h), Peek::Hello(Some(String::new())));
        let h = hello(&sni_ext("bad name.test"));
        assert_eq!(peek_client_hello(&h), Peek::Hello(Some(String::new())));
    }

    #[test]
    fn garbage_never_panics() {
        // Single-byte corruptions and every prefix of a real hello.
        let good = hello(&sni_ext("a.test"));
        for i in 0..good.len() {
            for v in [0u8, 0xff, 0x16, 3] {
                let mut m = good.clone();
                m[i] = v;
                let _ = peek_client_hello(&m);
                let _ = peek_client_hello(&m[..i]);
            }
        }
    }
}
