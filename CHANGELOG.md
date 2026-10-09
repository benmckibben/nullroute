# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing has been released yet. This section lists everything the first release
will contain.

### Added

- `nullroute run [OPTIONS] -- COMMAND`: run a command in a new user and network
  namespace that has only its own loopback. No root needed; the command's exit
  code is passed through (`128+N` for signals, `125` if nullroute itself fails,
  `127` if the command isn't found, `126` if it can't be executed). The command
  must follow `--`; an unknown option before it is a usage error (exit 2).
  `--dry-run | head` ends quietly by SIGPIPE instead of panicking.
- `--port`: bridge chosen ports of the host's localhost into the sandbox
  (TCP, IPv4 and IPv6). At most 64; more is a usage error (exit 2).
- `--allow`: let chosen hosts through (`host`, `*.domain`, IP literals, optional
  `:port`) via an HTTP(S) proxy (`HTTP_PROXY` and friends) and, for clients that
  ignore proxy variables, a DNS sinkhole with a transparent TCP relay on
  synthetic loopback addresses. `--resolve HOST:IP` pins an allowed host;
  `--no-dns` turns the sinkhole off.
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
  and let through).
- `--dry-run` and `--inspect`: show what would be hidden, bridged, allowed and
  sealed, and the sandbox topology.
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

Findings from a security review of the first version, all fixed before release:

- S1: the system D-Bus socket is hidden by default (it let a sandboxed command
  resolve names on the host through systemd-resolved).
  `--allow-socket /run/dbus/system_bus_socket` opts back in.
- S2: systemd-resolved's varlink socket and nscd are masked in every sandbox,
  not only with `--allow`, so name resolution can't bypass the sandbox.
- `--seal-docker`: the connection is no longer switched to an unparsed raw relay
  just because a request path looked like attach/exec; a probe followed by a
  `NetworkMode=host` container create on the same connection used to get a
  host-networked container. Only a genuine `101 Switching Protocols` (or the
  daemon's raw stream for attach/exec start) starts a relay. Container-create
  bodies that aren't a single JSON object, chunked bodies and duplicate
  `Content-Length` headers are refused, and JSON keys are matched the way
  Docker's decoder matches them.
- S4: `--seal-docker` now also seals classic `docker build` (`networkmode=none`)
  and refuses what can't be sealed: BuildKit/buildx builds (`/build?version=2`,
  `/grpc`, `/session`; the "BuildKit gap"), `/networks/{id}/connect`, Swarm
  services and `swarm init/join`, and plugin install/enable/upgrade. Request paths
  are matched after percent-decoding and dot/slash cleaning, and ambiguous ones
  are refused.
- S5: the `--allow` proxy and the DNS sinkhole refuse link-local addresses
  (including the `169.254.169.254` cloud metadata service), other known metadata
  endpoints, `0.0.0.0/8` and IPv6 forms that wrap a forbidden IPv4 address.
  `--allow` entries that can never work (`localhost`, loopback and link-local
  IPs) are rejected at startup.

### Fixed

- The command no longer outlives nullroute: it gets SIGKILL when nullroute dies
  (`PR_SET_PDEATHSIG`), and whatever it leaves running when it exits (background
  jobs, daemons, even `setsid` ones) is killed before nullroute exits.
- SIGTERM, SIGHUP, SIGINT and SIGQUIT that arrive while the command is starting
  are no longer lost or fatal to nullroute; the command starts with the signal
  mask it would normally have. A SIGINT/SIGQUIT that reaches nullroute before
  the command exists (Ctrl-C right after launch, sent to the process group) is
  passed on to it instead of being dropped, so it stops the command before it
  runs; it used to be swallowed, and the command then ran with nullroute
  waiting for it.
- A closed or full stderr (a CI log pipe whose reader went away, `/dev/full`) no
  longer changes the result of a run: nullroute's warnings, live "blocked" lines
  and summary ignore write errors instead of panicking, so a command that exited
  7 still exits 7 (it used to become 101, and a panic in a worker thread could
  silently stop the DNS sinkhole or the proxy). `--dry-run` to a stdout that
  can't be written (a full disk) fails with exit `74` and a message, not a panic.
- SIGTERM and SIGHUP sent to a process group (`kill -TERM -PGID`, `timeout`) no
  longer reach the command twice: the command is in the group and got the
  signal itself, and nullroute used to forward a second copy as well. A signal
  sent to nullroute's pid alone is still forwarded, exactly once. Signals are
  now taken by a dedicated thread, and a helper process in nullroute's process
  group tells group-directed signals from pid-directed ones. nullroute also no
  longer signals the command's pid after the command has been reaped (a signal
  arriving while it cleans up leftovers could have hit an unrelated process
  that reused the pid).
- nullroute's scratch directories (`nullroute-*` and `nullroute-dns-*` in the temp
  dir, holding the decoy sockets and generated resolv.conf) are no longer left
  behind when nullroute is killed (SIGKILL, the OOM killer) or crashes: they
  are removed as soon as the command has started, and what a kill during the
  few milliseconds of setup leaves is swept by the next run (only directories of
  the current user, over a minute old, that no running nullroute holds a lock
  on). `--dry-run` and `--inspect` no longer create them at all.
- `--report-json` is checked before the command runs (exit `2` if it can't be
  written); a write failure at the end of an otherwise successful run now exits
  `74` instead of `0`.
- `--seal-docker` rewrites (forced `NetworkMode=none`, sealed classic builds)
  no longer count as blocks, so `--strict --seal-docker` passes when the command
  only starts sealed containers.
- musl targets build (the `ioctl` request type differs from glibc).

[Unreleased]: https://github.com/benmckibben/nullroute/commits/master
