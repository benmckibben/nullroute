//! `--inspect`: print the sandbox topology to stderr before running.
//!
//! The summary is built from the same inputs the sandbox is built from (the
//! namespace flags from `sandbox::namespace_flags`, the socket plan, the
//! deduplicated port list, the proxy port and the DNS sinkhole plan), so it can't drift from what is
//! actually set up. It goes to stderr so the command's stdout stays clean.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::{dns, docker, hide, sandbox};

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
    /// Resolver bypass sockets (resolved varlink, nscd) masked with an
    /// unconnectable file, in every sandbox.
    pub masked: Vec<PathBuf>,
    /// Port of the `--allow` proxy inside the sandbox, and the allowed hosts.
    pub proxy: Option<(u16, Vec<String>)>,
    /// DNS sinkhole mapping lines (host -> synthetic address, ports), if on.
    pub dns: Option<Vec<String>>,
    /// `--seal-docker-pulls`, when a Docker socket is sealed.
    pub docker_pulls: Option<docker::PullPolicy>,
    /// Which of the seccomp filter and `no_new_privs` are on.
    pub hardening: crate::seccomp::Hardening,
}

/// What `--inspect` and `--dry-run` say about the seccomp filter and `no_new_privs`.
pub fn hardening(h: crate::seccomp::Hardening) -> String {
    match (h.seccomp, h.no_new_privs) {
        (true, nnp) => crate::seccomp::describe(nnp),
        (false, true) => "off (--no-seccomp); no_new_privs is still set".to_string(),
        (false, false) => "off (--no-seccomp, --allow-new-privs)".to_string(),
    }
}

impl Topology {
    pub fn new(
        ports: &[u16],
        plan: Option<&hide::Plan>,
        proxy: Option<(u16, Vec<String>)>,
        dns: Option<&dns::Plan>,
        masked: &[PathBuf],
    ) -> Self {
        let (blocked, sealed) = match plan {
            None => (Vec::new(), Vec::new()),
            Some(p) => (
                p.blocked_targets().map(PathBuf::from).collect(),
                p.sealed_targets().map(PathBuf::from).collect(),
            ),
        };
        Topology {
            // The resolver needs the mount namespace only to put its
            // resolv.conf in place (nothing to mount over if the host has none).
            ns_flags: sandbox::namespace_flags(
                plan.is_some()
                    || (dns.is_some() && dns::resolv_conf_target().is_some())
                    || !masked.is_empty(),
            ),
            ports: ports.to_vec(),
            blocked,
            sealed,
            masked: masked.to_vec(),
            proxy,
            dns: dns.map(dns::Plan::describe),
            docker_pulls: None,
            hardening: crate::seccomp::Hardening::default(),
        }
    }

    /// Show which of the seccomp filter and `no_new_privs` are on
    /// (`--no-seccomp`, `--allow-new-privs`).
    pub fn with_hardening(mut self, h: crate::seccomp::Hardening) -> Self {
        self.hardening = h;
        self
    }

    /// Show the --seal-docker-pulls policy (only if a socket is sealed).
    pub fn with_docker_pulls(mut self, pulls: docker::PullPolicy) -> Self {
        self.docker_pulls = (!self.sealed.is_empty()).then_some(pulls);
        self
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
        let _ = writeln!(s, "  hardening:       {}", hardening(self.hardening));
        let pool = if self.dns.is_some() {
            format!(", {}", dns::POOL_CIDR)
        } else {
            String::new()
        };
        let _ = writeln!(s, "  loopback:        lo: UP (127.0.0.1, ::1{pool})");
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
        list(&mut s, "masked (resolver bypass)", &self.masked);
        if let Some(p) = self.docker_pulls {
            let _ = writeln!(s, "  docker pulls:    {}", p.describe());
        }
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
        match &self.dns {
            None => {
                let _ = writeln!(s, "  dns sinkhole:    none");
            }
            Some(lines) if lines.is_empty() => {
                let _ = writeln!(
                    s,
                    "  dns resolver:    127.0.0.1:{} (udp, tcp; every name gets NXDOMAIN and is recorded)",
                    dns::PORT
                );
            }
            Some(lines) => {
                let _ = writeln!(
                    s,
                    "  dns sinkhole:    127.0.0.1:{} (udp, tcp; other names get NXDOMAIN)",
                    dns::PORT
                );
                for l in lines {
                    let _ = writeln!(s, "    {l}");
                }
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
            masked: vec![],
            proxy: None,
            dns: None,
            docker_pulls: None,
            hardening: crate::seccomp::Hardening::default(),
        }
    }

    #[test]
    fn minimal_topology_reports_none_everywhere() {
        let hardening = format!(
            "  hardening:       {}",
            hardening(crate::seccomp::Hardening::default())
        );
        let expected = [
            "nullroute: inspect: sandbox topology",
            "  namespaces:      user, net",
            hardening.as_str(),
            "  loopback:        lo: UP (127.0.0.1, ::1)",
            "  bridged ports:   none",
            "  unix sockets:",
            "    blocked (403 decoy): none",
            "    sealed (--seal-docker proxy): none",
            "    masked (resolver bypass): none",
            "  upstream proxy:  none",
            "  dns sinkhole:    none",
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
        let t = Topology::new(&[80, 443], None, None, None, &[]);
        assert_eq!(t.namespaces(), vec!["user", "net"]);
        assert!(t.blocked.is_empty() && t.sealed.is_empty() && t.masked.is_empty());
        assert_eq!(t.ports, vec![80, 443]);
        assert!(t.render().contains("  bridged ports:   80, 443\n"));
    }

    #[test]
    fn masked_resolver_sockets_are_listed_and_add_mount_namespace() {
        let sock = PathBuf::from("/run/systemd/resolve/io.systemd.Resolve");
        let t = Topology::new(&[], None, None, None, std::slice::from_ref(&sock));
        assert_eq!(t.namespaces(), vec!["user", "net", "mount"]);
        assert!(
            t.render().contains(
                "    masked (resolver bypass):\n      /run/systemd/resolve/io.systemd.Resolve\n"
            ),
            "{}",
            t.render()
        );
    }

    #[test]
    fn full_topology_lists_ports_sockets_and_proxy() {
        let t = Topology {
            ns_flags: sandbox::namespace_flags(true),
            ports: vec![5432, 6379],
            blocked: vec!["/run/podman/podman.sock".into(), "/tmp/a.sock".into()],
            sealed: vec!["/run/docker.sock".into()],
            masked: vec![],
            proxy: Some((3128, vec!["api.github.com".into(), "*.stripe.dev".into()])),
            dns: Some(vec!["api.github.com -> 127.77.0.1 (ports 80, 443)".into()]),
            docker_pulls: Some(docker::PullPolicy::Allowlisted),
            hardening: crate::seccomp::Hardening::default(),
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
        assert!(
            out.contains("\n  docker pulls:    allowlisted (pulls, logins and lookups only from registries in --allow;"),
            "{out}"
        );
    }

    #[test]
    fn docker_pulls_only_shown_when_a_socket_is_sealed() {
        let t = bare().with_docker_pulls(docker::PullPolicy::Never);
        assert!(!t.render().contains("docker pulls"), "{}", t.render());
        let t = Topology {
            sealed: vec!["/run/docker.sock".into()],
            ..bare()
        }
        .with_docker_pulls(docker::PullPolicy::Never);
        assert!(
            t.render().contains("  docker pulls:    none (no registry"),
            "{}",
            t.render()
        );
    }

    #[test]
    fn dns_sinkhole_lists_mapping_and_adds_mount_namespace() {
        let allow = crate::proxy::Allowlist::parse(&["db.example.com:5432".to_string()]).unwrap();
        let plan = dns::Plan::new(&allow).unwrap().unwrap();
        let t = Topology::new(&[], None, None, Some(&plan), &[]);
        assert_eq!(t.namespaces(), vec!["user", "net", "mount"]);
        let out = t.render();
        assert!(
            out.ends_with(
                "  dns sinkhole:    127.0.0.1:53 (udp, tcp; other names get NXDOMAIN)
    db.example.com -> 127.77.0.1 (ports 5432)
"
            ),
            "{out}"
        );
    }

    #[test]
    fn hardening_line_says_when_seccomp_is_off() {
        let on = bare().render();
        assert!(
            on.contains("  hardening:       no_new_privs; seccomp denies socket("),
            "{on}"
        );
        let h = |seccomp, no_new_privs| crate::seccomp::Hardening {
            seccomp,
            no_new_privs,
        };
        let off = bare().with_hardening(h(false, true)).render();
        assert!(
            off.contains("  hardening:       off (--no-seccomp); no_new_privs is still set\n"),
            "{off}"
        );
        let nnp_off = bare().with_hardening(h(true, false)).render();
        assert!(
            nnp_off.contains("  hardening:       seccomp denies socket(")
                && nnp_off.contains("; no_new_privs is off (--allow-new-privs)\n"),
            "{nnp_off}"
        );
        let both = bare().with_hardening(h(false, false)).render();
        assert!(
            both.contains("  hardening:       off (--no-seccomp, --allow-new-privs)\n"),
            "{both}"
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
