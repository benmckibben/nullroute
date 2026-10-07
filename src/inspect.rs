//! `--inspect`: print the sandbox topology to stderr before running.
//!
//! The summary is built from the same inputs the sandbox is built from (the
//! namespace flags from `sandbox::namespace_flags`, the socket plan, the
//! deduplicated port list and the proxy port), so it can't drift from what is
//! actually set up. It goes to stderr so the command's stdout stays clean.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::{hide, sandbox};

/// Everything `--inspect` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    /// The `CLONE_NEW*` flags the child will unshare.
    pub ns_flags: libc::c_int,
    /// Bridged `--port`s (sorted, deduplicated).
    pub ports: Vec<u16>,
    /// Sockets replaced by a 403 decoy.
    pub blocked: Vec<PathBuf>,
    /// Docker sockets replaced by a sealing proxy (`--seal-docker`).
    pub sealed: Vec<PathBuf>,
    /// Port of the `--allow` proxy inside the sandbox, and the allowed hosts.
    pub proxy: Option<(u16, Vec<String>)>,
}

impl Topology {
    pub fn new(
        ports: &[u16],
        plan: Option<&hide::Plan>,
        proxy: Option<(u16, Vec<String>)>,
    ) -> Self {
        let (blocked, sealed) = match plan {
            None => (Vec::new(), Vec::new()),
            Some(p) => (
                p.blocked_targets().map(PathBuf::from).collect(),
                p.sealed_targets().map(PathBuf::from).collect(),
            ),
        };
        Topology {
            ns_flags: sandbox::namespace_flags(plan.is_some()),
            ports: ports.to_vec(),
            blocked,
            sealed,
            proxy,
        }
    }

    /// Names of the namespaces in `ns_flags`, in a fixed order.
    pub fn namespaces(&self) -> Vec<&'static str> {
        [
            (libc::CLONE_NEWUSER, "user"),
            (libc::CLONE_NEWNET, "net"),
            (libc::CLONE_NEWNS, "mount"),
        ]
        .into_iter()
        .filter(|(f, _)| self.ns_flags & f != 0)
        .map(|(_, n)| n)
        .collect()
    }

    /// The human-readable summary.
    pub fn render(&self) -> String {
        let mut s = String::from("nullroute: inspect: sandbox topology\n");
        let _ = writeln!(s, "  namespaces:      {}", self.namespaces().join(", "));
        let _ = writeln!(s, "  loopback:        lo: UP (127.0.0.1, ::1)");
        let ports = if self.ports.is_empty() {
            "none".to_string()
        } else {
            self.ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(s, "  bridged ports:   {ports}");
        let _ = writeln!(s, "  unix sockets:");
        list(&mut s, "blocked (403 decoy)", &self.blocked);
        list(&mut s, "sealed (--seal-docker proxy)", &self.sealed);
        match &self.proxy {
            None => {
                let _ = writeln!(s, "  upstream proxy:  none");
            }
            Some((port, hosts)) => {
                let _ = writeln!(
                    s,
                    "  upstream proxy:  http://127.0.0.1:{port} (allow: {})",
                    hosts.join(", ")
                );
            }
        }
        s
    }
}

fn list(s: &mut String, label: &str, paths: &[PathBuf]) {
    if paths.is_empty() {
        let _ = writeln!(s, "    {label}: none");
        return;
    }
    let _ = writeln!(s, "    {label}:");
    for p in paths {
        let _ = writeln!(s, "      {}", p.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare() -> Topology {
        Topology {
            ns_flags: sandbox::namespace_flags(false),
            ports: vec![],
            blocked: vec![],
            sealed: vec![],
            proxy: None,
        }
    }

    #[test]
    fn minimal_topology_reports_none_everywhere() {
        let expected = [
            "nullroute: inspect: sandbox topology",
            "  namespaces:      user, net",
            "  loopback:        lo: UP (127.0.0.1, ::1)",
            "  bridged ports:   none",
            "  unix sockets:",
            "    blocked (403 decoy): none",
            "    sealed (--seal-docker proxy): none",
            "  upstream proxy:  none",
            "",
        ]
        .join("\n");
        assert_eq!(bare().render(), expected);
    }

    #[test]
    fn mount_namespace_only_when_sockets_are_hidden() {
        assert_eq!(bare().namespaces(), vec!["user", "net"]);
        let t = Topology {
            ns_flags: sandbox::namespace_flags(true),
            ..bare()
        };
        assert_eq!(t.namespaces(), vec!["user", "net", "mount"]);
    }

    #[test]
    fn new_without_plan_has_no_mount_namespace_or_sockets() {
        let t = Topology::new(&[80, 443], None, None);
        assert_eq!(t.namespaces(), vec!["user", "net"]);
        assert!(t.blocked.is_empty() && t.sealed.is_empty());
        assert_eq!(t.ports, vec![80, 443]);
        assert!(t.render().contains("  bridged ports:   80, 443\n"));
    }

    #[test]
    fn full_topology_lists_ports_sockets_and_proxy() {
        let t = Topology {
            ns_flags: sandbox::namespace_flags(true),
            ports: vec![5432, 6379],
            blocked: vec!["/run/podman/podman.sock".into(), "/tmp/a.sock".into()],
            sealed: vec!["/run/docker.sock".into()],
            proxy: Some((3128, vec!["api.github.com".into(), "*.stripe.dev".into()])),
        };
        let out = t.render();
        assert!(
            out.contains("  namespaces:      user, net, mount\n"),
            "{out}"
        );
        assert!(out.contains("  bridged ports:   5432, 6379\n"), "{out}");
        assert!(
            out.contains(
                "    blocked (403 decoy):\n      /run/podman/podman.sock\n      /tmp/a.sock\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("    sealed (--seal-docker proxy):\n      /run/docker.sock\n"),
            "{out}"
        );
        assert!(
            out.contains(
                "  upstream proxy:  http://127.0.0.1:3128 (allow: api.github.com, *.stripe.dev)\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn render_is_deterministic() {
        let t = Topology {
            ports: vec![1, 2, 3],
            ..bare()
        };
        assert_eq!(t.render(), t.clone().render());
    }
}
