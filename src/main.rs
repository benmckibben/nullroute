//! nullroute: run a command with no network access except its own loopback.

#[cfg(not(target_os = "linux"))]
compile_error!("nullroute currently supports Linux only (it uses network namespaces)");

mod dns;
mod docker;
mod forward;
mod hide;
mod inspect;
mod proxy;
mod report;
mod sandbox;
mod signals;

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
    Run {
        /// Make the host's localhost:PORT reachable as localhost:PORT inside.
        /// Repeat or comma-separate: --port 5432 --port 6379, or --port 5432,6379.
        #[arg(short, long = "port", value_name = "PORT", value_delimiter = ',', value_parser = clap::value_parser!(u16).range(1..))]
        ports: Vec<u16>,

        /// Also hide this Unix socket (repeatable). Container-runtime sockets
        /// (docker.sock, podman.sock, containerd, buildkit) and the system D-Bus
        /// are hidden by default.
        #[arg(long = "hide-socket", value_name = "PATH")]
        hide_sockets: Vec<std::path::PathBuf>,

        /// Keep this socket reachable even though it's hidden by default
        /// (repeatable). E.g. --allow-socket /var/run/docker.sock for tests that
        /// start containers; those containers will have network access. Or
        /// --allow-socket /run/dbus/system_bus_socket for the system D-Bus (which
        /// can resolve names through systemd-resolved).
        #[arg(long = "allow-socket", value_name = "PATH")]
        allow_sockets: Vec<std::path::PathBuf>,

        /// Let the command use Docker, but force every container it starts onto
        /// no network (NetworkMode=none), instead of hiding the socket. Seals the
        /// standard docker.sock paths. Not a security boundary for hostile images
        /// (see the README).
        #[arg(long = "seal-docker")]
        seal_docker: bool,

        /// Seal this specific Docker API socket (repeatable). Like --seal-docker
        /// but for a non-standard path.
        #[arg(long = "seal-docker-socket", value_name = "PATH")]
        seal_docker_sockets: Vec<std::path::PathBuf>,

        /// With --seal-docker: what the Docker daemon may contact for the
        /// command (image pulls, pushes, logins, manifest lookups, URL imports,
        /// remote build contexts). any (default): anything, as without this
        /// flag; allowlisted: only pulls, logins and lookups from registries in
        /// --allow (Docker Hub: --allow docker.io; a localhost registry: --port);
        /// none: nothing. A classic build's missing FROM image is still pulled
        /// (see the README).
        #[arg(long = "seal-docker-pulls", value_name = "MODE", value_enum)]
        seal_docker_pulls: Option<docker::PullPolicy>,

        /// Let this host through (repeatable or comma-separated):
        /// api.github.com, *.stripe.dev (subdomains only), or an IP, each
        /// optionally :PORT. Proxy-aware clients go through an HTTP(S) proxy;
        /// other clients resolve allowed names via nullroute's DNS sinkhole and
        /// are relayed on the allowed ports (80/443 without :PORT). localhost and
        /// loopback, link-local and cloud-metadata IPs are refused (use --port
        /// for local services).
        #[arg(short, long = "allow", value_name = "HOST", value_delimiter = ',')]
        allow: Vec<String>,

        /// Dial this allowed host at IP instead of resolving it on the host,
        /// like curl's --resolve (repeatable): --resolve db.internal:10.0.0.5.
        /// Loopback, link-local and cloud-metadata addresses are still refused.
        #[arg(long = "resolve", value_name = "HOST:IP")]
        resolve: Vec<String>,

        /// Don't run the DNS sinkhole for --allow: names don't resolve inside
        /// and only proxy-aware clients can reach allowed hosts.
        #[arg(long = "no-dns")]
        no_dns: bool,

        /// Fail (exit 1) if anything was blocked, even if the command succeeded.
        /// A command that already failed keeps its own exit code. Requests
        /// --seal-docker rewrote and let through don't count.
        #[arg(long)]
        strict: bool,

        /// Don't print each blocked target as it happens; only the summary.
        #[arg(short, long)]
        quiet: bool,

        /// Also write the breach report as JSON to this file (written on every
        /// run, with an empty "blocked" list when nothing was blocked). Checked
        /// before the command runs (exit 2 if it can't be written); if writing
        /// still fails afterwards, a run that would have exited 0 exits 74.
        #[arg(long, value_name = "FILE")]
        report_json: Option<std::path::PathBuf>,

        /// Print what would be hidden, forwarded and allowed, then exit.
        #[arg(long)]
        dry_run: bool,

        /// Print the sandbox topology (namespaces, loopback, bridged ports,
        /// blocked/sealed sockets, proxy) to stderr before running the command.
        /// With --dry-run, print it and exit without running anything.
        #[arg(long)]
        inspect: bool,

        /// The command and its arguments (put them after --).
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
}

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
            allow,
            resolve,
            no_dns,
            strict,
            quiet,
            report_json,
            dry_run,
            inspect,
            argv,
        } => {
            if seal_docker_pulls.is_some() && !seal_docker && seal_docker_sockets.is_empty() {
                eprintln!(
                    "nullroute: --seal-docker-pulls only applies to sealed Docker sockets; add --seal-docker (or --seal-docker-socket PATH)"
                );
                return ExitCode::from(2);
            }
            let pulls = seal_docker_pulls.unwrap_or_default();
            let allowlist = match proxy::Allowlist::parse(&allow) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("nullroute: {e}");
                    return ExitCode::from(2);
                }
            };
            let overrides = match proxy::parse_overrides(&resolve, &allowlist) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("nullroute: {e}");
                    return ExitCode::from(2);
                }
            };
            let dns_plan = if no_dns {
                None
            } else {
                match dns::Plan::new(&allowlist) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("nullroute: {e}");
                        return ExitCode::from(2);
                    }
                }
            };
            if let Some(path) = &report_json
                && let Err(e) = report::check_writable(path)
            {
                eprintln!(
                    "nullroute: --report-json {}: can't write the report there: {e}; not running the command",
                    path.display()
                );
                return ExitCode::from(2);
            }
            ports.sort_unstable();
            ports.dedup();
            if dns_plan.is_some() && ports.contains(&dns::PORT) {
                eprintln!(
                    "nullroute: --port {} clashes with the DNS sinkhole for --allow; add --no-dns to bridge it",
                    dns::PORT
                );
                return ExitCode::from(2);
            }
            if ports.len() > forward::MAX_PORTS {
                eprintln!("nullroute: at most {} --port values", forward::MAX_PORTS);
                return ExitCode::from(125);
            }
            let mut seal = seal_docker_sockets;
            if seal_docker {
                seal.extend(docker::docker_api_sockets());
            }
            let mut plan = match hide::plan(&hide_sockets, &allow_sockets, &seal) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("nullroute: preparing socket hiding: {e}");
                    return ExitCode::from(125);
                }
            };
            if let Some(p) = plan.as_mut() {
                p.set_docker_policy(docker::Policy {
                    pulls,
                    allow: allowlist.clone(),
                    ports: ports.clone(),
                });
            }
            let allowed_hosts: Vec<String> = allow.iter().map(|h| normalize_host(h)).collect();
            if inspect {
                let proxy = (!allowlist.is_empty())
                    .then(|| (proxy::pick_port(&ports), allowed_hosts.clone()));
                eprint!(
                    "{}",
                    inspect::Topology::new(
                        &ports,
                        plan.as_ref(),
                        proxy,
                        dns_plan.as_ref(),
                        &dns::bypass_targets(),
                    )
                    .with_docker_pulls(pulls)
                    .render()
                );
            }
            if dry_run {
                match &plan {
                    None => println!("hidden sockets: none"),
                    Some(p) => {
                        p.blocked_targets()
                            .for_each(|t| println!("hidden socket: {}", t.display()));
                        p.sealed_targets()
                            .for_each(|t| println!("sealed docker socket: {}", t.display()));
                        if p.sealed_targets().next().is_some() {
                            println!("docker pulls: {}", pulls.describe());
                        }
                    }
                }
                for p in &ports {
                    println!("forwarded port: {p}");
                }
                for h in &allowed_hosts {
                    println!("allowed host: {h}");
                }
                if !allowlist.is_empty() {
                    println!("proxy: http://127.0.0.1:{}", proxy::pick_port(&ports));
                }
                if let Some(d) = &dns_plan {
                    println!("dns sinkhole: 127.0.0.1:{}", dns::PORT);
                    for l in d.describe() {
                        println!("synthetic address: {l}");
                    }
                }
                return ExitCode::SUCCESS;
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
            };
            run(
                &argv,
                &ports,
                plan.as_ref(),
                proxy,
                dns.as_ref(),
                &report,
                &opts,
            )
        }
    }
}

/// How an --allow value is displayed: trimmed, no trailing dot, lowercase.
fn normalize_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Exit code when the command (and --strict) would have exited 0 but the
/// --report-json file couldn't be written at the end (EX_IOERR, sysexits.h).
const EXIT_REPORT_WRITE_FAILED: i32 = 74;

struct RunOpts {
    strict: bool,
    report_json: Option<std::path::PathBuf>,
}

fn run(
    argv: &[String],
    ports: &[u16],
    hide: Option<&hide::Plan>,
    proxy: Option<(u16, std::sync::Arc<proxy::Proxy>)>,
    dns: Option<&std::sync::Arc<dns::Sinkhole>>,
    report: &std::sync::Arc<report::Report>,
    opts: &RunOpts,
) -> ExitCode {
    let status = match sandbox::run_hermetic(argv, ports, hide, proxy, dns, report) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nullroute: failed to run {:?}: {e}", argv[0]);
            // 125 is what docker/podman use for "the runner failed", as
            // opposed to the command; keeps the two distinguishable.
            return ExitCode::from(125);
        }
    };
    // Mirror the child's exit status so nullroute is transparent in CI.
    let mut code = match (status.code(), status.signal()) {
        (Some(c), _) => c,
        (None, Some(sig)) => 128 + sig,
        _ => 1,
    };
    if let Some(s) = report.summary() {
        eprint!("{s}");
    }
    let strict_failed = opts.strict && code == 0 && report.has_blocks();
    if strict_failed {
        eprintln!(
            "nullroute: --strict: failing because the command tried to reach blocked targets"
        );
        code = 1;
    }
    if let Some(path) = &opts.report_json
        && let Err(e) = report.write_json(path, argv, code, strict_failed)
    {
        eprintln!(
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
