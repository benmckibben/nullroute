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

use crate::diag::diagln;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Distinct (kind, target) entries kept. A command that looks up thousands of
/// generated names would otherwise grow the report, the live output and the
/// summary without bound. Attempts at targets beyond this are still counted
/// (and still count as blocks for --strict), just not listed.
pub const MAX_ENTRIES: usize = 1000;
/// Live "blocked ..." lines printed per second; the rest wait for the summary.
pub const MAX_LIVE_LINES_PER_SECOND: u32 = 20;

/// (max entries, max live lines per second), or the debug-build test override
/// NULLROUTE_TEST_REPORT_LIMITS=ENTRIES,LINES.
fn limits() -> (usize, u32) {
    #[cfg(debug_assertions)]
    if let Some((e, l)) = std::env::var("NULLROUTE_TEST_REPORT_LIMITS")
        .ok()
        .as_deref()
        .and_then(|v| v.split_once(','))
        && let (Ok(e), Ok(l)) = (e.parse(), l.parse())
    {
        return (e, l);
    }
    (MAX_ENTRIES, MAX_LIVE_LINES_PER_SECOND)
}

/// Decides which live lines get printed: at most per_second in each second.
struct LiveLimiter {
    per_second: u32,
    window_start: Option<Instant>,
    printed: u32,
    skipped: u64,
    /// Skipped in total, for the summary.
    skipped_total: u64,
}

enum Live {
    Print,
    /// Print it, after saying that this many were skipped in the second before.
    PrintAfterSkipped(u64),
    Skip,
}

impl LiveLimiter {
    fn new(per_second: u32) -> Self {
        LiveLimiter {
            per_second,
            window_start: None,
            printed: 0,
            skipped: 0,
            skipped_total: 0,
        }
    }

    fn allow(&mut self, now: Instant) -> Live {
        let mut note = 0;
        match self.window_start {
            Some(t) if now.duration_since(t) < Duration::from_secs(1) => {}
            _ => {
                self.window_start = Some(now);
                self.printed = 0;
                note = std::mem::take(&mut self.skipped);
            }
        }
        if self.printed < self.per_second {
            self.printed += 1;
            if note > 0 {
                Live::PrintAfterSkipped(note)
            } else {
                Live::Print
            }
        } else {
            self.skipped += 1;
            self.skipped_total += 1;
            Live::Skip
        }
    }
}

/// What the caps held back.
#[derive(Default)]
struct Overflow {
    /// Attempts at targets that didn't fit in the entry table, by kind class.
    blocked_attempts: u64,
    rewritten_attempts: u64,
}

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

pub struct Report {
    quiet: bool,
    max_entries: usize,
    entries: Mutex<BTreeMap<(Kind, String), Entry>>,
    overflow: Mutex<Overflow>,
    live: Mutex<LiveLimiter>,
}

impl Report {
    pub fn new(quiet: bool) -> Arc<Self> {
        let (max_entries, lines) = limits();
        Self::with_limits(quiet, max_entries, lines)
    }

    fn with_limits(quiet: bool, max_entries: usize, live_per_second: u32) -> Arc<Self> {
        Arc::new(Report {
            quiet,
            max_entries,
            entries: Mutex::new(BTreeMap::new()),
            overflow: Mutex::new(Overflow::default()),
            live: Mutex::new(LiveLimiter::new(live_per_second)),
        })
    }

    /// Count an attempt at a target that doesn't fit in the table.
    fn note_overflow(&self, kind: Kind) {
        if let Ok(mut o) = self.overflow.lock() {
            if kind.is_block() {
                o.blocked_attempts += 1;
            } else {
                o.rewritten_attempts += 1;
            }
        }
    }

    /// (blocked, rewritten) attempts that didn't fit in the table.
    fn overflow(&self) -> (u64, u64) {
        self.overflow
            .lock()
            .map(|o| (o.blocked_attempts, o.rewritten_attempts))
            .unwrap_or((0, 0))
    }

    /// Print a live line unless more than the allowed number have gone out in
    /// the last second.
    fn print_live(&self, line: impl FnOnce() -> String) {
        let verdict = match self.live.lock() {
            Ok(mut l) => l.allow(Instant::now()),
            Err(_) => Live::Print,
        };
        match verdict {
            Live::Skip => {}
            Live::Print => diagln!("{}", line()),
            Live::PrintAfterSkipped(n) => {
                diagln!(
                    "nullroute: ... {n} more message{} suppressed (all of them are in the summary)",
                    plural(n)
                );
                diagln!("{}", line());
            }
        }
    }

    fn live_per_second(&self) -> u32 {
        self.live.lock().map(|l| l.per_second).unwrap_or(0)
    }

    /// How many live lines were held back, in total.
    fn live_skipped(&self) -> u64 {
        self.live.lock().map(|l| l.skipped_total).unwrap_or(0)
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
            let key = (kind, target.to_string());
            if !m.contains_key(&key) && m.len() >= self.max_entries {
                drop(m);
                self.note_overflow(kind);
                return false;
            }
            let e = m.entry(key).or_insert_with(|| Entry {
                kind,
                target: target.to_string(),
                reason: reason.to_string(),
                count: 0,
            });
            e.count += 1;
            e.count == 1
        };
        if first && !self.quiet {
            self.print_live(first_line);
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
        self.overflow().0 > 0
            || self
                .entries
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
        let (over_blocked, over_rewritten) = self.overflow();
        if blocked.is_empty() && rewritten.is_empty() && over_blocked + over_rewritten == 0 {
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
        let more = |n: u64| {
            format!(
                "  ... and {n} more attempt{} at other targets (only the first {} targets are listed)\n",
                plural(n),
                self.max_entries
            )
        };
        let mut s = String::new();
        if !blocked.is_empty() || over_blocked > 0 {
            let attempts: u64 = blocked.iter().map(|e| e.count).sum::<u64>() + over_blocked;
            s.push_str(&format!(
                "nullroute: blocked {attempts} attempt{} to reach {}{} target{}:\n",
                plural(attempts),
                if over_blocked > 0 { "at least " } else { "" },
                blocked.len(),
                plural(blocked.len() as u64)
            ));
            blocked.iter().for_each(|e| s.push_str(&line(e)));
            if over_blocked > 0 {
                s.push_str(&more(over_blocked));
            }
        }
        if !rewritten.is_empty() || over_rewritten > 0 {
            let n: u64 = rewritten.iter().map(|e| e.count).sum::<u64>() + over_rewritten;
            s.push_str(&format!(
                "nullroute: rewrote {n} request{} and let {} through (not blocks; --strict ignores these):\n",
                plural(n),
                if n == 1 { "it" } else { "them" }
            ));
            rewritten.iter().for_each(|e| s.push_str(&line(e)));
            if over_rewritten > 0 {
                s.push_str(&more(over_rewritten));
            }
        }
        let held_back = self.live_skipped();
        if held_back > 0 {
            s.push_str(&format!(
                "nullroute: {held_back} live message{} were held back while the command ran (at most {} per second are printed); the lines above are complete.\n",
                plural(held_back),
                self.live_per_second()
            ));
        }
        Some(s)
    }

    /// Machine-readable report for CI.
    pub fn write_json(
        &self,
        path: &Path,
        argv: &[std::ffi::OsString],
        exit_code: i32,
        strict_failed: bool,
    ) -> io::Result<()> {
        let (blocked, rewritten) = self.split();
        let mut s = format!("{{\n  \"schema_version\": {SCHEMA_VERSION},\n  \"command\": [");
        s.push_str(
            &argv
                .iter()
                // JSON text is Unicode: bytes that aren't UTF-8 become U+FFFD here.
                .map(|a| json_string(&a.to_string_lossy()))
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push_str(&format!(
            "],\n  \"exit_code\": {exit_code},\n  \"strict_failed\": {strict_failed},\n"
        ));
        s.push_str(&json_list("blocked", &blocked));
        s.push_str(",\n");
        s.push_str(&json_list("rewritten", &rewritten));
        let (over_blocked, over_rewritten) = self.overflow();
        if over_blocked + over_rewritten > 0 {
            // Only present when the cap was hit, so the usual shape is unchanged.
            s.push_str(&format!(
                ",\n  \"not_listed\": {{\"blocked_attempts\": {over_blocked}, \"rewritten_attempts\": {over_rewritten}}}"
            ));
        }
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
    fn entries_beyond_the_cap_are_counted_but_not_listed_and_still_block() {
        let r = Report::with_limits(true, 3, 100);
        for i in 0..10 {
            r.record(
                Kind::Dns,
                &format!("name{i}.example"),
                "not allowed",
                String::new,
            );
        }
        // A second attempt at a listed target still counts on its entry.
        r.record(Kind::Dns, "name0.example", "not allowed", String::new);
        assert_eq!(r.entries().len(), 3);
        assert!(r.has_blocks());
        let s = r.summary().unwrap();
        assert!(
            s.contains("blocked 11 attempts to reach at least 3 targets"),
            "{s}"
        );
        assert!(
            s.contains(
                "... and 7 more attempts at other targets (only the first 3 targets are listed)"
            ),
            "{s}"
        );
        let path = std::env::temp_dir().join(format!("nr-report-cap-{}.json", std::process::id()));
        r.write_json(&path, &["x".into()], 0, true).unwrap();
        let json = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            json.contains("\"not_listed\": {\"blocked_attempts\": 7, \"rewritten_attempts\": 0}"),
            "{json}"
        );
    }

    #[test]
    fn suppressed_attempts_alone_make_strict_fail_but_rewrites_do_not() {
        // A full table: everything new is suppressed, yet it is a block.
        let r = Report::with_limits(true, 0, 100);
        assert!(!r.has_blocks());
        r.record(Kind::Rewritten, "create", "forced offline", String::new);
        assert!(!r.has_blocks(), "a suppressed rewrite is not a block");
        r.record(Kind::Socket, "/var/run/docker.sock", "hidden", String::new);
        assert!(
            r.has_blocks(),
            "a suppressed block must still fail --strict"
        );
        assert!(r.summary().is_some());
    }

    #[test]
    fn live_lines_are_limited_per_second_and_the_skipped_ones_are_announced() {
        let mut l = LiveLimiter::new(2);
        let t0 = Instant::now();
        assert!(matches!(l.allow(t0), Live::Print));
        assert!(matches!(l.allow(t0), Live::Print));
        assert!(matches!(l.allow(t0), Live::Skip));
        assert!(matches!(
            l.allow(t0 + Duration::from_millis(900)),
            Live::Skip
        ));
        // The next second: the first line says how many were held back.
        assert!(matches!(
            l.allow(t0 + Duration::from_millis(1100)),
            Live::PrintAfterSkipped(2)
        ));
        assert!(matches!(
            l.allow(t0 + Duration::from_millis(1200)),
            Live::Print
        ));
        assert!(matches!(
            l.allow(t0 + Duration::from_millis(1300)),
            Live::Skip
        ));
        assert_eq!(l.skipped_total, 3);
    }

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
        let argv: [std::ffi::OsString; 1] = ["true".into()];
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
        let argv: [std::ffi::OsString; 3] = [
            "sh".into(),
            "-c".into(),
            "echo \"hi\"\tthere \\ \u{e9}".into(),
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
