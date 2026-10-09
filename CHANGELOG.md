# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No release has been made yet. The first release will be 0.1.0 and will contain
everything listed here. (The name `nullroute` on crates.io currently holds only
an empty 0.0.0 placeholder, which is not this program.)

### Added

- `nullroute run [OPTIONS] -- COMMAND`: run a command in a new user and network
  namespace that has only its own loopback. No root needed; the command's exit
  code is passed through (`128+N` for signals, `125` if nullroute itself fails,
  `127` if the command isn't found, `126` if it can't be executed). The command
  must follow `--`; an unknown option before it is a usage error (exit 2).
  `--dry-run | head` ends quietly by SIGPIPE instead of panicking.
- The command doesn't outlive nullroute: it gets SIGKILL when nullroute dies
  (`PR_SET_PDEATHSIG`), and whatever it leaves running when it exits (background
  jobs, daemons, even `setsid` ones) is killed before nullroute exits.
  SIGTERM, SIGHUP, SIGINT and SIGQUIT sent to nullroute are passed on to the
  command, including ones that arrive while the command is starting (it starts
  with the signal mask it would normally have).
- `--port`: bridge chosen ports of the host's localhost into the sandbox
  (TCP, IPv4 and IPv6). At most 64; more is a usage error (exit 2).
- `--allow`: let chosen hosts through (`host`, `*.domain`, IP literals, optional
  `:port`) via an HTTP(S) proxy (`HTTP_PROXY` and friends) and, for clients that
  ignore proxy variables, a DNS sinkhole with a transparent TCP relay on
  synthetic loopback addresses. `--resolve HOST:IP` pins an allowed host;
  `--no-dns` turns the sinkhole off. A proxied plain-HTTP request's `Host`
  header and the TLS server name (SNI) of a tunnel, read from the first record
  without decrypting, must name the allowed host (or another allowed host), so a
  client can't ask for an allowed host and be served another (domain fronting
  through a shared CDN address still gets through). `--allow` of, or a name
  resolving to, private/LAN space (RFC 1918, 100.64.0.0/10, fc00::/7) works and
  prints a warning.
- Container-runtime sockets (Docker, Podman, containerd, BuildKit) are hidden
  by default behind a decoy that answers `403`; `--hide-socket` and
  `--allow-socket` adjust the list.
- `--seal-docker` and `--seal-docker-socket`: let the command use Docker, with
  every container it creates forced onto `NetworkMode=none` and classic-builder
  builds forced onto `networkmode=none`.
- `--seal-docker-pulls any|allowlisted|none`: limit what the Docker daemon
  contacts on the command's behalf (pulls, logins, lookups, pushes, URL imports,
  remote build contexts).
- Report of everything that was blocked, printed live and as a summary;
  `--strict` (fail if anything was blocked), `--quiet`, and `--report-json FILE`
  (including a separate `rewritten` list for requests `--seal-docker` changed
  and let through; those don't count as blocks, so `--strict --seal-docker`
  passes when the command only starts sealed containers). The report file is
  checked before the command runs (exit `2` if it can't be written); a write
  failure at the end of an otherwise successful run exits `74`. The file starts with `"schema_version": 1` and its layout
  is documented in `docs/report-json.md` and pinned by golden-file tests.
- DNS lookups are recorded in every run, with or without `--allow`: the
  sandbox's resolver answers `NXDOMAIN` for any name that isn't allowed, so
  `--strict` catches a command that looks a name up and swallows the error. A
  lookup fails with "Name or service not known" (final) instead of "Temporary
  failure in name resolution" (retryable; musl's resolver sat out 5 s per
  lookup). `localhost` still resolves. `--no-dns` turns the resolver off, and
  `--port 53` without allowed names still bridges port 53. `--strict` and the
  report can't see a connection straight to an IP address (it fails in the
  kernel with `ENETUNREACH`); the README says so.
- `--dry-run` and `--inspect`: show what would be hidden, masked, bridged,
  allowed and sealed (`--dry-run` includes the masked resolver sockets and the
  namespaces), and the sandbox topology.
- Linux builds for x86_64 and aarch64, glibc and musl (static) targets. Other
  targets fail to build with a single clear error.
- CI: rustfmt, clippy, tests on stable and the MSRV (Rust 1.88) and on musl,
  cross-target checks, and a `cargo-deny` audit (also run weekly); Dependabot for
  Actions and Cargo.
- A build-only release workflow that produces release archives and
  `SHA256SUMS` as workflow-run artifacts, after checking the tag against the
  crate version and running the CI checks.
- `SECURITY.md`, `CONTRIBUTING.md` and this changelog.
- Developer examples under `examples/` (Python test leak, npm postinstall,
  local service `--port`, surgical `--allow`) and a terminal demo under
  `demo/` (`run-demo.sh` and a VHS tape). Not part of the published crate.
  `NULLROUTE_EXAMPLES_OFFLINE=1` skips the steps that need the public internet,
  and each example prints an `examples: <name>: N assertions run, M skipped`
  summary; CI runs examples 01 and 03 this way, plus `shellcheck`.

### Security

Hardening that the first release ships with:

- The system D-Bus socket is hidden by default (it would let a sandboxed command
  resolve names on the host through systemd-resolved).
  `--allow-socket /run/dbus/system_bus_socket` opts back in.
- systemd-resolved's varlink socket and nscd are masked in every sandbox, not
  only with `--allow`, so name resolution can't bypass the sandbox.
- `--seal-docker` only switches a connection to a raw relay on a genuine
  `101 Switching Protocols` (or the daemon's raw stream for attach/exec start),
  never because a request path looks like attach/exec, so a probe followed by a
  `NetworkMode=host` container create on the same connection can't get a
  host-networked container. Container-create bodies that aren't a single JSON
  object, chunked bodies and duplicate `Content-Length` headers are refused, and
  JSON keys are matched the way Docker's decoder matches them.
- `--seal-docker` also seals classic `docker build` (`networkmode=none`) and
  refuses what can't be sealed: BuildKit/buildx builds (`/build?version=2`,
  `/grpc`, `/session`; the "BuildKit gap"), `/networks/{id}/connect`, Swarm
  services and `swarm init/join`, and plugin install/enable/upgrade. Request
  paths are matched after percent-decoding and dot/slash cleaning, and ambiguous
  ones are refused.
- The `--allow` proxy and the DNS sinkhole refuse link-local addresses
  (including the `169.254.169.254` cloud metadata service), other known metadata
  endpoints, `0.0.0.0/8` and IPv6 forms that wrap a forbidden IPv4 address.
  `--allow` entries that can never work (`localhost`, loopback and link-local
  IPs) are rejected at startup.

[Unreleased]: https://github.com/benmckibben/nullroute/commits/master