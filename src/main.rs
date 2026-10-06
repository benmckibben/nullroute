//! nullroute: run a command with no network access except its own loopback.

#[cfg(not(target_os = "linux"))]
compile_error!("nullroute currently supports Linux only (it uses network namespaces)");

mod docker;
mod forward;
mod hide;
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
        /// (docker.sock, podman.sock, containerd, buildkit) are hidden by default.
        #[arg(long = "hide-socket", value_name = "PATH")]
        hide_sockets: Vec<std::path::PathBuf>,

        /// Keep this socket reachable even though it's hidden by default
        /// (repeatable). E.g. --allow-socket /var/run/docker.sock for tests that
        /// start containers; those containers will have network access.
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

        /// Let HTTP(S) to this host through (repeatable or comma-separated):
        /// api.github.com, *.stripe.dev (subdomains only), or an IP. Works for
        /// clients that honour HTTP(S)_PROXY; everything else stays sealed.
        #[arg(short, long = "allow", value_name = "HOST", value_delimiter = ',')]
        allow: Vec<String>,

        /// Fail (exit 1) if anything was blocked, even if the command succeeded.
        /// A command that already failed keeps its own exit code.
        #[arg(long)]
        strict: bool,

        /// Don't print each blocked target as it happens; only the summary.
        #[arg(short, long)]
        quiet: bool,

        /// Also write the breach report as JSON to this file (written on every
        /// run, with an empty "blocked" list when nothing was blocked).
        #[arg(long, value_name = "FILE")]
        report_json: Option<std::path::PathBuf>,

        /// Print what would be hidden, forwarded and allowed, then exit.
        #[arg(long)]
        dry_run: bool,

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
            allow,
            strict,
            quiet,
            report_json,
            dry_run,
            argv,
        } => {
            let allowlist = match proxy::Allowlist::parse(&allow) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("nullroute: {e}");
                    return ExitCode::from(2);
                }
            };
            ports.sort_unstable();
            ports.dedup();
            if ports.len() > forward::MAX_PORTS {
                eprintln!("nullroute: at most {} --port values", forward::MAX_PORTS);
                return ExitCode::from(125);
            }
            let mut seal = seal_docker_sockets;
            if seal_docker {
                seal.extend(docker::docker_api_sockets());
            }
            let plan = match hide::plan(&hide_sockets, &allow_sockets, &seal) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("nullroute: preparing socket hiding: {e}");
                    return ExitCode::from(125);
                }
            };
            if dry_run {
                match &plan {
                    None => println!("hidden sockets: none"),
                    Some(p) => {
                        p.blocked_targets()
                            .for_each(|t| println!("hidden socket: {}", t.display()));
                        p.sealed_targets()
                            .for_each(|t| println!("sealed docker socket: {}", t.display()));
                    }
                }
                for p in &ports {
                    println!("forwarded port: {p}");
                }
                for h in &allow {
                    println!(
                        "allowed host: {}",
                        h.trim().trim_end_matches('.').to_ascii_lowercase()
                    );
                }
                if !allowlist.is_empty() {
                    println!("proxy: http://127.0.0.1:{}", proxy::pick_port(&ports));
                }
                return ExitCode::SUCCESS;
            }
            let report = report::Report::new(quiet);
            let proxy = (!allowlist.is_empty()).then(|| {
                (
                    proxy::pick_port(&ports),
                    proxy::Proxy::new(allowlist, report.clone()),
                )
            });
            let opts = RunOpts {
                strict,
                report_json,
            };
            run(&argv, &ports, plan.as_ref(), proxy, &report, &opts)
        }
    }
}

struct RunOpts {
    strict: bool,
    report_json: Option<std::path::PathBuf>,
}

fn run(
    argv: &[String],
    ports: &[u16],
    hide: Option<&hide::Plan>,
    proxy: Option<(u16, std::sync::Arc<proxy::Proxy>)>,
    report: &std::sync::Arc<report::Report>,
    opts: &RunOpts,
) -> ExitCode {
    let status = match sandbox::run_hermetic(argv, ports, hide, proxy, report) {
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
    let strict_failed = opts.strict && code == 0 && !report.is_empty();
    if strict_failed {
        eprintln!(
            "nullroute: --strict: failing because the command tried to reach blocked targets"
        );
        code = 1;
    }
    if let Some(path) = &opts.report_json
        && let Err(e) = report.write_json(path, argv, code, strict_failed)
    {
        eprintln!("nullroute: writing --report-json {}: {e}", path.display());
    }
    ExitCode::from(code as u8)
}
