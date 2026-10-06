//! Breach report: everything nullroute blocked during a run.
//!
//! Each blocking site (the --allow proxy and socket decoys) records what it blocked here. The first attempt at each target is
//! printed immediately (unless --quiet), so a hung or failing command shows why
//! right away; a summary of all of them is printed when the command exits, and
//! can also be written as JSON for CI (--report-json).
//!
//! What can't be listed: a connection straight to an IP address that isn't
//! allowed fails inside the kernel ("network unreachable") without reaching
//! nullroute, so it doesn't appear here. Proxy requests and hidden sockets do.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A Unix socket hidden by default or with --hide-socket.
    Socket,
    /// A request through the --allow proxy to a host that isn't allowed.
    Proxy,
    /// A Docker API request changed or refused by --seal-docker.
    Docker,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Socket => "socket",
            Kind::Proxy => "proxy",
            Kind::Docker => "docker",
        }
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

    /// Record a blocked attempt. On the first attempt at `target`, print
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

    pub fn entries(&self) -> Vec<Entry> {
        self.entries
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().map(|m| m.is_empty()).unwrap_or(true)
    }

    /// Human summary, or None if nothing was blocked.
    pub fn summary(&self) -> Option<String> {
        let entries = self.entries();
        if entries.is_empty() {
            return None;
        }
        let attempts: u64 = entries.iter().map(|e| e.count).sum();
        let width = entries
            .iter()
            .map(|e| e.target.len())
            .max()
            .unwrap_or(0)
            .min(60);
        let mut s = format!(
            "nullroute: blocked {attempts} attempt{} to reach {} target{}:\n",
            plural(attempts),
            entries.len(),
            plural(entries.len() as u64)
        );
        for e in &entries {
            s.push_str(&format!(
                "  {:<6}  {:<width$}  {:>4}x  ({})\n",
                e.kind.label(),
                e.target,
                e.count,
                e.reason
            ));
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
        let entries = self.entries();
        let mut s = String::from("{\n  \"command\": [");
        s.push_str(
            &argv
                .iter()
                .map(|a| json_string(a))
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push_str(&format!("],\n  \"exit_code\": {exit_code},\n  \"strict_failed\": {strict_failed},\n  \"blocked\": ["));
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
        s.push_str(if entries.is_empty() {
            "]\n}\n"
        } else {
            "\n  ]\n}\n"
        });
        let mut f = std::fs::File::create(path)?;
        f.write_all(s.as_bytes())
    }
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
    fn json_escapes() {
        assert_eq!(json_string("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }
}
