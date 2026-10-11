//! nullroute: run a command with no network access except its own loopback.

// nullroute is Linux-only. On other targets the modules and the real main()
// are cfg'd out, so the build stops with this one error instead of dozens of
// missing-libc-symbol errors; allow(unused) keeps the leftovers quiet.
#![cfg_attr(not(target_os = "linux"), allow(unused))]
// Diagnostics go through diag!/diagln! (src/diag.rs), which can't panic.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#[cfg(not(target_os = "linux"))]
compile_error!(
    "nullroute only supports Linux (it relies on Linux network namespaces); build it for a Linux target"
);
#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
mod diag;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod docker;
#[cfg(target_os = "linux")]
mod forward;
#[cfg(target_os = "linux")]
mod hide;
#[cfg(target_os = "linux")]
mod inspect;
#[cfg(target_os = "linux")]
mod lifecycle;
#[cfg(target_os = "linux")]
mod limits;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(target_os = "linux")]
mod report;
#[cfg(target_os = "linux")]
mod sandbox;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod signals;
#[cfg(target_os = "linux")]
mod sni;
mod tmpdir;

use crate::diag::{diag, diagln};
use clap::{Parser, Subcommand};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Run commands with outbound network access sealed off"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command in a fresh network namespace with only loopback.
    ///
    /// Example: nullroute run -- pytest -x
    #[command(
        override_usage = "nullroute run [OPTIONS] -- <COMMAND>...",
        after_help = "Note: Place the command and any of its arguments after '--' so flags are not parsed by nullroute.\nExample: nullroute run --port 5432 -- pytest -x"
    )]
    Run {
        /// Make the host's localhost:PORT reachable as localhost:PORT inside.
        /// Repeat or comma-separate: --port 5432 --port 6379, or --port 5432,6379.
        #[arg(short, long = "port", value_name = "PORT", value_delimiter = ',', value_parser = clap::value_parser!(u16).range(1..))]
        ports: Vec<u16>,

        /// Also hide this Unix socket (repeatable), e.g. an X11 or Wayland
        /// display socket or a local proxy. Container-runtime sockets, the
        /// system and session D-Bus, the systemd user manager, snapd, SSH and
        /// keyring agents ($SSH_AUTH_SOCK) and gpg-agent/dirmngr are hidden by
        /// default (see --dry-run for the list on this machine).
        #[arg(long = "hide-socket", value_name = "PATH")]
        hide_sockets: Vec<std::path::PathBuf>,

        /// Keep this socket reachable even though it's hidden by default
        /// (repeatable).
        ///
        /// For example --allow-socket /var/run/docker.sock for tests that start
        /// containers (those containers will have network access), or
        /// --allow-socket /run/dbus/system_bus_socket for the system D-Bus (which
        /// can resolve names through systemd-resolved), or --allow-socket
        /// "$SSH_AUTH_SOCK" to let the command use your SSH agent.
        #[arg(long = "allow-socket", value_name = "PATH")]
        allow_sockets: Vec<std::path::PathBuf>,

        /// Let the command use Docker, but put every container it starts on no
        /// network (NetworkMode=none), instead of hiding the socket.
        ///
        /// Seals the standard docker.sock paths. Not a security boundary for
        /// hostile images (see the README).
        #[arg(long = "seal-docker")]
        seal_docker: bool,

        /// Seal this specific Docker API socket (repeatable). Like --seal-docker
        /// but for a non-standard path.
        #[arg(long = "seal-docker-socket", value_name = "PATH")]
        seal_docker_sockets: Vec<std::path::PathBuf>,

        /// With --seal-docker: what the Docker daemon may contact for the command
        /// (image pulls, pushes, logins, manifest lookups, URL imports, remote
        /// build contexts).
        ///
        /// The default is any: no restriction, as without this flag. A classic
        /// build's missing FROM image is still pulled (see the README). Docker
        /// Hub is --allow docker.io; a registry on localhost is --port.
        #[arg(long = "seal-docker-pulls", value_name = "MODE", value_enum)]
        seal_docker_pulls: Option<docker::PullPolicy>,

        /// With --seal-docker: also let the command run code in, start, restart,
        /// attach to or copy files into containers that have a network (ones it
        /// didn't create here: docker exec, docker start...). By default those
        /// are refused, because the code would run with that network. This
        /// unseals them.
        #[arg(long = "seal-docker-allow-existing")]
        seal_docker_allow_existing: bool,

        /// Let this host through (repeatable or comma-separated): api.github.com,
        /// *.stripe.dev (subdomains only), or an IP, each optionally :PORT.
        ///
        /// Proxy-aware clients go through an HTTP(S) proxy; other clients resolve
        /// allowed names via nullroute's DNS sinkhole and are relayed on the
        /// allowed ports (80 and 443 without :PORT). The Host header of a proxied
        /// HTTP request and the TLS server name (SNI) of a tunnel must name the
        /// allowed host too.
        ///
        /// localhost and loopback, link-local and cloud-metadata IPs are refused
        /// (use --port for local services). Private/LAN addresses (RFC 1918,
        /// 100.64.0.0/10, fc00::/7) work, with a warning.
        #[arg(short, long = "allow", value_name = "HOST", value_delimiter = ',')]
        allow: Vec<String>,

        /// Dial this allowed host at IP instead of resolving it on the host, like
        /// curl's --resolve (repeatable): --resolve db.internal:10.0.0.5.
        ///
        /// Loopback, link-local and cloud-metadata addresses are still refused.
        #[arg(long = "resolve", value_name = "HOST:IP")]
        resolve: Vec<String>,

        /// Don't run the DNS resolver or sinkhole.
        ///
        /// Names then don't resolve inside, only proxy-aware clients can reach
        /// allowed hosts, and DNS lookups are not recorded (so --strict can't see
        /// them). Also frees port 53 for --port.
        #[arg(long = "no-dns")]
        no_dns: bool,

        /// Fail (exit 1) if anything was blocked, even if the command succeeded.
        ///
        /// A command that already failed keeps its own exit code. Requests
        /// --seal-docker rewrote and let through don't count. With --report-json,
        /// "strict_failed" tells this exit 1 from the command's own.
        ///
        /// Sees DNS lookups (with or without --allow), proxy requests and hidden
        /// sockets. It can't see a connection straight to an IP address: that
        /// fails inside the kernel (ENETUNREACH) without reaching nullroute.
        #[arg(long)]
        strict: bool,

        /// Don't print each blocked target as it happens; only the summary.
        #[arg(short, long)]
        quiet: bool,

        /// Also write the breach report as JSON to this file.
        ///
        /// Written on every run, with an empty "blocked" list when nothing was
        /// blocked; the layout is in docs/report-json.md. The file is checked
        /// before the command runs (exit 2 if it can't be written); if writing
        /// still fails afterwards, a run that would have exited 0 exits 74.
        #[arg(long, value_name = "FILE")]
        report_json: Option<std::path::PathBuf>,

        /// Don't install the seccomp filter (no_new_privs is still set; see
        /// --allow-new-privs). By default the command can't open AF_VSOCK,
        /// Bluetooth, NFC or QIPCRTR sockets, can't use io_uring or the
        /// TIOCSTI/TIOCLINUX terminal ioctls (all fail with an error). Use this
        /// for a tool that needs one.
        #[arg(long = "no-seccomp")]
        no_seccomp: bool,

        /// Don't set no_new_privs, so a setuid, setgid or file-capability
        /// program can still raise its privileges when it runs (a ping binary
        /// that carries cap_net_raw as a file capability, say).
        ///
        /// Only your own id is mapped inside the sandbox, so a root-owned setuid
        /// file (sudo, su) has no effect either way. The seccomp filter stays on
        /// unless --no-seccomp is also given. A nested nullroute or any other
        /// child inherits the setting.
        #[arg(long = "allow-new-privs")]
        allow_new_privs: bool,

        /// Seconds to wait, after SIGTERM or SIGHUP reaches nullroute, for the
        /// command to exit before it is sent SIGKILL.
        ///
        /// Without this nullroute forwards the signal once and then waits for as
        /// long as the command runs, so a command that ignores SIGTERM keeps
        /// nullroute (and a CI job) waiting. The timer starts at the first
        /// SIGTERM or SIGHUP and is not restarted by later ones. Like
        /// `timeout --kill-after`. Ctrl-C (SIGINT, SIGQUIT) is not escalated.
        #[arg(long = "kill-after", value_name = "SECS", value_parser = clap::value_parser!(u64).range(1..=86_400))]
        kill_after: Option<u64>,

        /// Print what would be hidden, masked, forwarded and allowed, then exit.
        ///
        /// Lists the hidden and sealed sockets, the masked resolver sockets,
        /// forwarded ports, allowed hosts, the DNS resolver and the namespaces.
        /// Add --inspect for the full sandbox topology.
        #[arg(long)]
        dry_run: bool,

        /// With --dry-run, also check that this machine lets nullroute create
        /// the namespaces a run needs (a throw-away process does the real
        /// setup and exits; nothing is left behind). Without it --dry-run only
        /// checks the options and the listener/descriptor budget.
        #[arg(long, requires = "dry_run")]
        check_sandbox: bool,

        /// Print the sandbox topology (namespaces, loopback, bridged ports,
        /// blocked/sealed sockets, proxy) to stderr before running the command.
        ///
        /// With --dry-run, print it and exit without running anything.
        #[arg(long)]
        inspect: bool,

        /// The command to run, followed by its arguments (put them after --).
        #[arg(required = true, last = true, value_name = "COMMAND")]
        argv: Vec<std::ffi::OsString>,
    },
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Run {
            mut ports,
            hide_sockets,
            allow_sockets,
            seal_docker,
            seal_docker_sockets,
            seal_docker_pulls,
            seal_docker_allow_existing,
            allow,
            resolve,
            no_dns,
            strict,
            quiet,
            report_json,
            no_seccomp,
            allow_new_privs,
            kill_after,
            dry_run,
            check_sandbox,
            inspect,
            argv,
        } => {
            if seal_docker_pulls.is_some() && !seal_docker && seal_docker_sockets.is_empty() {
                diagln!(
                    "nullroute: --seal-docker-pulls only applies to sealed Docker sockets; add --seal-docker (or --seal-docker-socket PATH)"
                );
                return ExitCode::from(2);
            }
            if seal_docker_allow_existing && !seal_docker && seal_docker_sockets.is_empty() {
                diagln!(
                    "nullroute: --seal-docker-allow-existing only applies to sealed Docker sockets; add --seal-docker (or --seal-docker-socket PATH)"
                );
                return ExitCode::from(2);
            }
            let pulls = seal_docker_pulls.unwrap_or_default();
            let allowlist = match proxy::Allowlist::parse(&allow) {
                Ok(a) => a,
                Err(e) => {
                    diagln!("nullroute: {e}");
                    return ExitCode::from(2);
                }
            };
            let overrides = match proxy::parse_overrides(&resolve, &allowlist) {
                Ok(o) => o,
                Err(e) => {
                    diagln!("nullroute: {e}");
                    return ExitCode::from(2);
                }
            };
            if !quiet {
                for w in proxy::private_address_warnings(&allowlist, &overrides) {
                    diagln!("{w}");
                }
            }
            // The resolver is always on (it records lookups for --strict and
            // makes them fail for good); only --no-dns, or --port 53 without
            // allowed names to map, leaves port 53 alone.
            let dns_plan = if no_dns {
                None
            } else {
                match dns::Plan::new(&allowlist) {
                    Ok(Some(p)) => Some(p),
                    Ok(None) if ports.contains(&dns::PORT) => None,
                    Ok(None) => Some(dns::Plan::resolver_only()),
                    Err(e) => {
                        diagln!("nullroute: {e}");
                        return ExitCode::from(2);
                    }
                }
            };
            if let Some(path) = &report_json
                && let Err(e) = report::check_writable(path)
            {
                diagln!(
                    "nullroute: --report-json {}: can't write the report there: {e}; not running the command",
                    path.display()
                );
                return ExitCode::from(2);
            }
            ports.sort_unstable();
            ports.dedup();
            if dns_plan.is_some() && ports.contains(&dns::PORT) {
                diagln!(
                    "nullroute: --port {} clashes with the DNS sinkhole for --allow; add --no-dns to bridge it",
                    dns::PORT
                );
                return ExitCode::from(2);
            }
            if ports.len() > forward::MAX_PORTS {
                diagln!(
                    "nullroute: at most {} --port values (got {})",
                    forward::MAX_PORTS,
                    ports.len()
                );
                return ExitCode::from(2);
            }
            let seal_defaults = if seal_docker {
                docker::docker_api_sockets()
            } else {
                Vec::new()
            };
            let mut plan = match hide::plan(
                &hide_sockets,
                &allow_sockets,
                &seal_docker_sockets,
                &seal_defaults,
            ) {
                Ok(p) => p,
                Err(e) => {
                    diagln!("nullroute: preparing socket hiding: {e}");
                    return ExitCode::from(125);
                }
            };
            if let Some(p) = plan.as_mut() {
                p.set_docker_policy(docker::Policy {
                    pulls,
                    allow: allowlist.clone(),
                    ports: ports.clone(),
                    allow_existing: seal_docker_allow_existing,
                });
            }
            let hardening = seccomp::Hardening {
                seccomp: !no_seccomp,
                no_new_privs: !allow_new_privs,
            };
            let allowed_hosts: Vec<String> = allow.iter().map(|h| normalize_host(h)).collect();
            let proxy_info =
                (!allowlist.is_empty()).then(|| (proxy::pick_port(&ports), allowed_hosts.clone()));
            let topology = inspect::Topology::new(
                &ports,
                plan.as_ref(),
                proxy_info,
                dns_plan.as_ref(),
                &dns::bypass_targets(),
            )
            .with_docker_pulls(pulls)
            .with_hardening(hardening);
            if inspect {
                diag!("{}", topology.render());
            }
            if dry_run {
                // What the real run would refuse, say so now: the listener
                // and descriptor budget, and (opt-in) whether namespaces can
                // be created at all.
                let listeners =
                    sandbox::planned_listeners(&ports, !allowlist.is_empty(), dns_plan.as_ref());
                if let Err(e) = forward::check_budget(listeners, limits::effective_nofile_limit()) {
                    diagln!("nullroute: could not set up the sandbox: {e}");
                    return ExitCode::from(125);
                }
                if check_sandbox && let Err(e) = sandbox::probe_namespaces() {
                    diagln!("nullroute: could not set up the sandbox: {e}");
                    return ExitCode::from(125);
                }
                // Rust ignores SIGPIPE, so a reader that exits early (| head)
                // would turn a write error into a panic (101). The listing is
                // the result of the command, not a diagnostic: die by the
                // signal instead, like ls does.
                // SAFETY: restoring the default disposition has no preconditions.
                unsafe {
                    libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                }
                let mut out = std::io::stdout().lock();
                let listing = DryRunListing {
                    plan: plan.as_ref(),
                    pulls,
                    masked: &topology.masked,
                    namespaces: topology.namespaces(),
                    ports: &ports,
                    allowed_hosts: &allowed_hosts,
                    proxy: !allowlist.is_empty(),
                    dns_plan: dns_plan.as_ref(),
                    hardening,
                };
                return match write_dry_run(&mut out, &listing) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        // Anything but a closed pipe (which killed us above),
                        // e.g. a full disk: say so, don't panic.
                        diagln!("nullroute: writing the --dry-run listing: {e}");
                        ExitCode::from(EXIT_OUTPUT_FAILED as u8)
                    }
                };
            }
            let report = report::Report::new(quiet);
            let proxy = (!allowlist.is_empty()).then(|| {
                (
                    proxy::pick_port(&ports),
                    proxy::Proxy::new(allowlist.clone(), overrides.clone(), report.clone()),
                )
            });
            let dns = dns_plan.map(|p| dns::Sinkhole::new(p, allowlist, overrides, report.clone()));
            let opts = RunOpts {
                strict,
                report_json,
                hardening,
                kill_after: kill_after.map(std::time::Duration::from_secs),
            };
            run(
                &argv,
                &ports,
                plan.as_mut(),
                proxy,
                dns.as_ref(),
                &report,
                &opts,
            )
        }
    }
}

/// The --dry-run listing: what would be hidden, forwarded and allowed.
struct DryRunListing<'a> {
    plan: Option<&'a hide::Plan>,
    pulls: docker::PullPolicy,
    masked: &'a [std::path::PathBuf],
    namespaces: Vec<&'static str>,
    ports: &'a [u16],
    allowed_hosts: &'a [String],
    proxy: bool,
    dns_plan: Option<&'a dns::Plan>,
    hardening: seccomp::Hardening,
}

fn write_dry_run(out: &mut impl std::io::Write, l: &DryRunListing<'_>) -> std::io::Result<()> {
    let DryRunListing {
        plan,
        pulls,
        masked,
        namespaces,
        ports,
        allowed_hosts,
        proxy,
        dns_plan,
        hardening,
    } = l;
    let (pulls, proxy, hardening) = (*pulls, *proxy, *hardening);
    let (plan, dns_plan) = (*plan, *dns_plan);
    let (ports, allowed_hosts) = (*ports, *allowed_hosts);
    match plan {
        None => writeln!(out, "hidden sockets: none")?,
        Some(p) => {
            for t in p.blocked_targets() {
                writeln!(out, "hidden socket: {}", t.display())?;
            }
            for t in p.sealed_targets() {
                writeln!(out, "sealed docker socket: {}", t.display())?;
            }
            if p.sealed_targets().next().is_some() {
                writeln!(out, "docker pulls: {}", pulls.describe())?;
            }
        }
    }
    for m in masked.iter() {
        writeln!(out, "masked resolver socket: {}", m.display())?;
    }
    writeln!(out, "seccomp: {}", inspect::hardening(hardening))?;
    for p in ports {
        writeln!(out, "forwarded port: {p}")?;
    }
    for h in allowed_hosts {
        writeln!(out, "allowed host: {h}")?;
    }
    if proxy {
        writeln!(out, "proxy: http://127.0.0.1:{}", proxy::pick_port(ports))?;
    }
    match dns_plan {
        Some(d) if d.has_names() => {
            writeln!(out, "dns sinkhole: 127.0.0.1:{}", dns::PORT)?;
            for l in d.describe() {
                writeln!(out, "synthetic address: {l}")?;
            }
        }
        Some(_) => writeln!(
            out,
            "dns resolver: 127.0.0.1:{} (every lookup is refused and recorded)",
            dns::PORT
        )?,
        None => {}
    }
    writeln!(out, "namespaces: {}", namespaces.join(", "))?;
    out.flush()
}

/// How an --allow value is displayed: trimmed, no trailing dot, lowercase.
fn normalize_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Exit code when the command (and --strict) would have exited 0 but the
/// --report-json file couldn't be written at the end (EX_IOERR, sysexits.h).
const EXIT_REPORT_WRITE_FAILED: i32 = 74;

/// Exit code when the --dry-run listing itself can't be written to stdout
/// (a full disk, say); same sysexits.h code.
const EXIT_OUTPUT_FAILED: i32 = 74;

struct RunOpts {
    strict: bool,
    report_json: Option<std::path::PathBuf>,
    /// Which of the seccomp filter and no_new_privs to apply (--no-seccomp,
    /// --allow-new-privs).
    hardening: seccomp::Hardening,
    /// --kill-after.
    kill_after: Option<std::time::Duration>,
}

#[cfg(target_os = "linux")]
fn run(
    argv: &[std::ffi::OsString],
    ports: &[u16],
    hide: Option<&mut hide::Plan>,
    proxy: Option<(u16, std::sync::Arc<proxy::Proxy>)>,
    dns: Option<&std::sync::Arc<dns::Sinkhole>>,
    report: &std::sync::Arc<report::Report>,
    opts: &RunOpts,
) -> ExitCode {
    let options = sandbox::RunOptions {
        hardening: opts.hardening,
        kill_after: opts.kill_after,
    };
    let status = match sandbox::run_hermetic(argv, ports, hide, proxy, dns, report, options) {
        Ok(s) => s,
        Err(e) => {
            if sandbox::command_exit_code(&e).is_some() {
                diagln!("nullroute: failed to run {:?}: {e}", argv[0]);
            } else {
                // Not the command's fault: nothing was started, or the
                // sandbox around it couldn't be built.
                diagln!("nullroute: could not set up the sandbox: {e}");
            }
            // Like docker run and shells: 127 = command not found, 126 = found
            // but not executable. Otherwise 125, "the runner failed", as opposed
            // to the command; keeps the two distinguishable.
            return ExitCode::from(sandbox::command_exit_code(&e).unwrap_or(125));
        }
    };
    // Mirror the child's exit status so nullroute is transparent in CI.
    let mut code = match (status.code(), status.signal()) {
        (Some(c), _) => c,
        (None, Some(sig)) => 128 + sig,
        _ => 1,
    };
    if let Some(s) = report.summary() {
        diag!("{s}");
    }
    let strict_failed = opts.strict && code == 0 && report.has_blocks();
    if strict_failed {
        diagln!("nullroute: --strict: failing because the command tried to reach blocked targets");
        code = 1;
    }
    if let Some(path) = &opts.report_json
        && let Err(e) = report.write_json(path, argv, code, strict_failed)
    {
        diagln!(
            "nullroute: --report-json {}: writing the report failed: {e}",
            path.display()
        );
        // Don't mask a failure that's already there; just don't report success.
        if code == 0 {
            code = EXIT_REPORT_WRITE_FAILED;
        }
    }
    ExitCode::from(code as u8)
}
