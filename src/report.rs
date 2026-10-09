//! Breach report: everything nullroute blocked during a run.
//!
//! Each blocking site (the --allow proxy, the DNS sinkhole and socket decoys) records what it blocked here.
//! Requests --seal-docker changed and let through are recorded too, as
//! `Kind::Rewritten`: listed separately, and not blocks as far as --strict goes. The first attempt at each target is
//! printed immediately (unless --quiet), so a hung or failing command shows why
//! right away; a summary of all of them is printed when the command exits, and
//! can also be written as JSON for CI (--report-json).
//!
//! What can't be listed: a connection straight to an IP address that isn't
//! allowed fails inside the kernel ("network unreachable") without reaching
//! nullroute, so it doesn't appear here. Proxy requests, DNS lookups and hidden
//! sockets do.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Version of the --report-json layout. Bumped only for a change that can break
/// a consumer (a field removed or renamed, a meaning changed); new fields and
/// new entry kinds don't. See docs/report-json.md.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A Unix socket hidden by default or with --hide-socket.
    Socket,
    /// A request through the --allow proxy to a host that isn't allowed.
    Proxy,
    /// A Docker API request changed or refused by --seal-docker.
    Docker,
    /// A DNS lookup of a name that isn't allowed (answered NXDOMAIN), or a
    /// connection to a synthetic address the sinkhole refused to relay.
    Dns,
    /// Not a block: a request that was let through after being changed, e.g.
    /// a container create forced onto NetworkMode=none by --seal-docker.
    /// Listed separately and ignored by --strict.
    Rewritten,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Socket => "socket",
            Kind::Proxy => "proxy",
            Kind::Docker => "docker",
            Kind::Dns => "dns",
            Kind::Rewritten => "rewritten",
        }
    }

    /// Was something actually blocked (as opposed to rewritten and let through)?
    pub fn is_block(self) -> bool {
        self != Kind::Rewritten
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub kind: Kind,
    pub target: String,
    pub reason: String,
    pub count: u64,
}

#[derive(Default)]
pub struct Report {
    quiet: bool,
    entries: Mutex<BTreeMap<(Kind, String), Entry>>,
}

impl Report {
    pub fn new(quiet: bool) -> Arc<Self> {
        Arc::new(Report {
            quiet,
            entries: Mutex::new(BTreeMap::new()),
        })
    }

    /// Record a blocked (or, for `Kind::Rewritten`, rewritten) attempt. On the first attempt at `target`, print
    /// `first_line()` to stderr (unless quiet). Returns true if it was the first.
    pub fn record(
        &self,
        kind: Kind,
        target: &str,
        reason: &str,
        first_line: impl FnOnce() -> String,
    ) -> bool {
        let first = {
            let Ok(mut m) = self.entries.lock() else {
                return false;
            };
            let e = m
                .entry((kind, target.to_string()))
                .or_insert_with(|| Entry {
                    kind,
                    target: target.to_string(),
                    reason: reason.to_string(),
                    count: 0,
                });
            e.count += 1;
            e.count == 1
        };
        if first && !self.quiet {
            eprintln!("{}", first_line());
        }
        first
    }

    /// Was --quiet given (no live lines)?
    pub fn quiet(&self) -> bool {
        self.quiet
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.entries
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().map(|m| m.is_empty()).unwrap_or(true)
    }

    /// Was anything blocked? Rewrites don't count (this is what --strict checks).
    pub fn has_blocks(&self) -> bool {
        self.entries
            .lock()
            .map(|m| m.keys().any(|(k, _)| k.is_block()))
            .unwrap_or(false)
    }

    /// (blocked, rewritten) entries.
    fn split(&self) -> (Vec<Entry>, Vec<Entry>) {
        self.entries().into_iter().partition(|e| e.kind.is_block())
    }

    /// Human summary, or None if nothing was blocked or rewritten.
    pub fn summary(&self) -> Option<String> {
        let (blocked, rewritten) = self.split();
        if blocked.is_empty() && rewritten.is_empty() {
            return None;
        }
        let width = blocked
            .iter()
            .chain(&rewritten)
            .map(|e| e.target.len())
            .max()
            .unwrap_or(0)
            .min(60);
        let line = |e: &Entry| {
            format!(
                "  {:<6}  {:<width$}  {:>4}x  ({})\n",
                e.kind.label(),
                e.target,
                e.count,
                e.reason
            )
        };
        let mut s = String::new();
        if !blocked.is_empty() {
            let attempts: u64 = blocked.iter().map(|e| e.count).sum();
            s.push_str(&format!(
                "nullroute: blocked {attempts} attempt{} to reach {} target{}:\n",
                plural(attempts),
                blocked.len(),
                plural(blocked.len() as u64)
            ));
            blocked.iter().for_each(|e| s.push_str(&line(e)));
        }
        if !rewritten.is_empty() {
            let n: u64 = rewritten.iter().map(|e| e.count).sum();
            s.push_str(&format!(
                "nullroute: rewrote {n} request{} and let {} through (not blocks; --strict ignores these):\n",
                plural(n),
                if n == 1 { "it" } else { "them" }
            ));
            rewritten.iter().for_each(|e| s.push_str(&line(e)));
        }
        Some(s)
    }

    /// Machine-readable report for CI.
    pub fn write_json(
        &self,
        path: &Path,
        argv: &[String],
        exit_code: i32,
        strict_failed: bool,
    ) -> io::Result<()> {
        let (blocked, rewritten) = self.split();
        let mut s = format!("{{\n  \"schema_version\": {SCHEMA_VERSION},\n  \"command\": [");
        s.push_str(
            &argv
                .iter()
                .map(|a| json_string(a))
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push_str(&format!(
            "],\n  \"exit_code\": {exit_code},\n  \"strict_failed\": {strict_failed},\n"
        ));
        s.push_str(&json_list("blocked", &blocked));
        s.push_str(",\n");
        s.push_str(&json_list("rewritten", &rewritten));
        s.push_str("\n}\n");
        let mut f = std::fs::File::create(path)?;
        f.write_all(s.as_bytes())
    }
}

/// `  "name": [...]`, one entry per line.
fn json_list(name: &str, entries: &[Entry]) -> String {
    let mut s = format!("  {}: [", json_string(name));
    for (i, e) in entries.iter().enumerate() {
        s.push_str(if i == 0 { "\n" } else { ",\n" });
        s.push_str(&format!(
            "    {{\"kind\": {}, \"target\": {}, \"reason\": {}, \"count\": {}}}",
            json_string(e.kind.label()),
            json_string(&e.target),
            json_string(&e.reason),
            e.count
        ));
    }
    s.push_str(if entries.is_empty() { "]" } else { "\n  ]" });
    s
}

/// Check up front that the --report-json file can be written, so a bad path
/// fails before the command runs instead of after. Opens it for writing
/// without truncating; a file that wasn't there is created only for the test
/// and removed again.
pub fn check_writable(path: &Path) -> io::Result<()> {
    let existed = path.symlink_metadata().is_ok();
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if !existed {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

fn plural(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_prints_once() {
        let r = Report::new(true);
        assert!(r.record(Kind::Proxy, "a.com:443", "not in --allow", || "x".into()));
        assert!(!r.record(Kind::Proxy, "a.com:443", "not in --allow", || "x".into()));
        assert!(r.record(Kind::Socket, "/a.sock", "hidden", || "x".into()));
        let e = r.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e.iter().find(|e| e.kind == Kind::Proxy).unwrap().count, 2);
    }

    #[test]
    fn summary_none_when_empty() {
        assert!(Report::new(true).summary().is_none());
    }

    #[test]
    fn summary_lists_targets() {
        let r = Report::new(true);
        r.record(
            Kind::Socket,
            "/run/docker.sock",
            "container runtime",
            String::new,
        );
        r.record(
            Kind::Proxy,
            "api.github.com:443",
            "not in --allow",
            String::new,
        );
        r.record(
            Kind::Proxy,
            "api.github.com:443",
            "not in --allow",
            String::new,
        );
        let s = r.summary().unwrap();
        assert!(
            s.starts_with("nullroute: blocked 3 attempts to reach 2 targets:"),
            "{s}"
        );
        assert!(s.contains("socket  /run/docker.sock"), "{s}");
        assert!(s.contains("2x  (not in --allow)"), "{s}");
    }

    #[test]
    fn rewrites_are_listed_but_are_not_blocks() {
        let r = Report::new(true);
        r.record(
            Kind::Rewritten,
            "containers/create",
            "forced NetworkMode=none",
            String::new,
        );
        r.record(
            Kind::Rewritten,
            "containers/create",
            "forced NetworkMode=none",
            String::new,
        );
        assert!(!r.has_blocks());
        let s = r.summary().unwrap();
        assert!(!s.contains("nullroute: blocked"), "{s}");
        assert!(
            s.starts_with("nullroute: rewrote 2 requests and let them through"),
            "{s}"
        );
        assert!(s.contains("rewritten  containers/create"), "{s}");

        r.record(Kind::Docker, "networks/connect", "refused", String::new);
        assert!(r.has_blocks());
        let s = r.summary().unwrap();
        assert!(
            s.starts_with("nullroute: blocked 1 attempt to reach 1 target:\n  docker"),
            "{s}"
        );
        assert!(s.contains("nullroute: rewrote 2 requests"), "{s}");
    }

    #[test]
    fn json_separates_blocked_and_rewritten() {
        let dir = std::env::temp_dir().join(format!("nr-report-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.json");
        let r = Report::new(true);
        let argv = ["true".to_string()];
        r.write_json(&path, &argv, 0, false).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("\"blocked\": [],\n  \"rewritten\": []\n}"),
            "{body}"
        );
        r.record(Kind::Rewritten, "containers/create", "forced", String::new);
        r.record(Kind::Socket, "/a.sock", "hidden", String::new);
        r.write_json(&path, &argv, 0, false).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let (b, w) = body.split_once("\"rewritten\"").unwrap();
        assert!(
            b.contains("\"kind\": \"socket\"") && !b.contains("containers/create"),
            "{body}"
        );
        assert!(
            w.contains("\"kind\": \"rewritten\", \"target\": \"containers/create\""),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_matches_the_golden_file() {
        // The layout is a contract for CI consumers (docs/report-json.md): any
        // change to this file is a schema change and needs a version decision.
        let dir = std::env::temp_dir().join(format!("nr-report-golden-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.json");
        let r = Report::new(true);
        // Recorded out of order and more than once: the file is sorted by kind
        // then target and carries counts.
        r.record(
            Kind::Rewritten,
            "containers/create",
            "forced NetworkMode=none",
            String::new,
        );
        r.record(Kind::Dns, "evil.example", "not in --allow", String::new);
        r.record(Kind::Dns, "evil.example", "not in --allow", String::new);
        r.record(
            Kind::Proxy,
            "api.github.com:443",
            "not in --allow",
            String::new,
        );
        r.record(
            Kind::Socket,
            "/run/docker.sock",
            "container runtimes can start containers with full network access",
            String::new,
        );
        r.record(Kind::Docker, "networks/connect", "refused", String::new);
        let argv = [
            "sh".to_string(),
            "-c".to_string(),
            "echo \"hi\"\tthere \\ \u{e9}".to_string(),
        ];
        r.write_json(&path, &argv, 1, true).unwrap();
        let got = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, include_str!("../tests/golden/report-all-kinds.json"));
        // And it is valid JSON that says which schema it is.
        let v: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
    }

    #[test]
    fn check_writable_leaves_no_trace() {
        let dir = std::env::temp_dir().join(format!("nr-report-chk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let new = dir.join("new.json");
        check_writable(&new).unwrap();
        assert!(!new.exists());
        let old = dir.join("old.json");
        std::fs::write(&old, "keep").unwrap();
        check_writable(&old).unwrap();
        assert_eq!(std::fs::read_to_string(&old).unwrap(), "keep");
        assert!(
            check_writable(&dir).is_err(),
            "a directory isn't writable as a file"
        );
        assert!(check_writable(&dir.join("missing/r.json")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_escapes() {
        assert_eq!(json_string("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }
}
