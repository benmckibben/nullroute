# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--kill-after SECS`: SIGKILL the command SECS seconds after the first SIGTERM
  or SIGHUP that reaches nullroute, if it is still running. Without the flag
  nothing changes: nullroute forwards the signal once and waits for as long as
  the command runs, so a command that ignores SIGTERM keeps it (and a CI job)
  waiting; this is now said in the README. SIGINT and SIGQUIT are not
  escalated. Checked with a command that traps TERM and has a background child:
  killed after the delay, the child cleaned up, exit status 137; a command that
  exits within the delay is left alone.

## [0.1.0] - 2026-10-09

The first release.

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
- The user's session services are hidden by default too, because their
  sockets reach processes outside the network namespace: the session D-Bus
  (`$DBUS_SESSION_BUS_ADDRESS`, `$XDG_RUNTIME_DIR/bus`; `busctl --user list`
  worked from inside and `systemd-run --user` ran a command in the host's
  network namespace), the systemd user manager, snapd, SSH and keyring agents
  (`$SSH_AUTH_SOCK`), gpg-agent and dirmngr (a `gpg --recv-keys` inside reached
  the network through the host's dirmngr), and more container runtimes
  (rootless containerd and BuildKit, Docker Desktop, Colima, Rancher Desktop,
  Lima, OrbStack, k3s, CRI-O, LXD, libvirt). Only sockets that exist are hidden,
  without a message for the rest. `--allow-socket PATH` brings one back, and
  `--dry-run`/`--inspect` list them. Display servers (X11, Wayland) and abstract
  sockets are not hidden; see the README for why.

- The command runs with `no_new_privs` and a small seccomp filter (x86-64 and
  AArch64): `socket()` with `AF_VSOCK` (a side channel to the hypervisor or host
  on microVMs, WSL2, Hyper-V, Firecracker and Docker Desktop), `AF_BLUETOOTH`,
  `AF_NFC` or `AF_QIPCRTR` fails with `EAFNOSUPPORT`; `ioctl(TIOCSTI)` and
  `ioctl(TIOCLINUX)`, which inject input into the terminal the command was
  started from, fail with `EPERM` (on kernels with `dev.tty.legacy_tiocsti=1`
  that was typing into the parent shell); `io_uring_setup()` fails with `EPERM`,
  because io_uring can create sockets without `socket()`. Nothing else is
  filtered. `--no-seccomp` turns the filter off; `no_new_privs` stays. See the
  README for the effect on setuid and file-capability binaries.
- `--allow-new-privs` leaves `no_new_privs` unset (the seccomp filter stays,
  unless `--no-seccomp` is given too). Needed when a file capability or setuid
  helper has to work: `ping` carries `cap_net_raw` as a file capability on Debian
  and Ubuntu, so `nullroute run -- ping` worked (the command's first exec still
  holds the sandbox's capabilities) while `nullroute run -- sh -c 'ping ...'`
  failed with `Operation not permitted`. `--dry-run` and `--inspect` show which
  of the two are on.

- `--seal-docker` only rewrote container creation, so containers that already
  existed were unsealed: `docker exec db sh -c 'echo x | nc 172.17.0.1 9999'`
  from inside the sandbox delivered data to a listener on the host, and
  `start`, `restart`, `unpause`, `attach`, `update` and copying files in were the
  same. Under `--seal-docker` those operations (and starting an exec instance)
  are now refused with a `403` that names the flag unless the container has no
  network (`NetworkMode: none`): the ones created through the sandbox, in this
  or an earlier run, still work. Reads (`inspect`, `logs`, `ps`, `cp` out) are
  unaffected. `--seal-docker-allow-existing` opts out and unseals them.

### Fixed

- The README no longer says the command has "a loopback interface and nothing
  else": it now says what is isolated (the network namespace plus the hardening
  listed) and what is not (the filesystem, `/proc` and signalling of your other
  processes, IPC and `/dev/shm`, inherited credentials, display servers and other
  unlisted Unix sockets), and SECURITY.md lists the default-hidden sockets and
  the seccomp filter as in scope.
- The `--seal-docker` proxy now handles `Expect: 100-continue` (it used to
  forward only the interim `100 Continue` and hold the real response until the
  next request, so a client such as `curl` hung), answers an oversized request
  head with `431` (and an oversized body with `413`, a malformed request line
  or an unsupported `Expect` with `400`/`417`) instead of silently closing the
  connection, and no longer buffers a header line without bound.
- `--seal-docker` no longer prints a "not found, ignoring" warning for each
  standard Docker socket that doesn't exist on the machine (it warned twice on
  an ordinary host). Only a `--seal-docker-socket` path that can't be used is
  reported, plus one line if no Docker socket was found at all.
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
  dir, holding the decoy sockets and generated resolv.conf) used to pile up
  when nullroute was killed (SIGKILL, the OOM killer) or crashed. Each one is
  now locked while its nullroute runs, and the next run sweeps the ones that
  are left (only directories of the current user, over a minute old, that no
  running nullroute holds a lock on). `--dry-run` no longer creates them at
  all.
- nullroute no longer lets a command make it grow without bound: at most 256
  connections are relayed at once per `--port` / proxy / DNS-bridge listener (64
  for DNS over TCP, which also gets a 30 s lifetime and 64 queries per
  connection, and 32 for socket decoys); one more is closed immediately instead
  of getting a new thread (300 idle DNS-over-TCP connections used to mean 310
  threads), a thread that can't be started drops the connection instead of
  panicking the acceptor, and an accept error (e.g. out of descriptors)
  backs off instead of spinning. Name lookups for the proxy and the DNS bridge
  give up after 10 s instead of waiting for a dead resolver.
- The breach report is bounded: at most 1000 distinct targets are listed, at
  most 20 live "blocked ..." lines are printed per second, and the summary says
  how many more attempts were counted but not listed ("... and N more
  attempts at other targets"); `--report-json` gets a `not_listed` object with
  the counts when that happens. Suppressed attempts still count as blocks, so
  `--strict` still fails (a flood of 20000 generated names used to print 40000
  lines, 2.5 MB).
- nullroute raises its own soft file-descriptor limit to the hard limit while
  it runs (the command still gets the soft limit it was started with), and
  running out of descriptors is reported as that instead of "nothing
  reachable on the host" for a `--port`.
- `--dry-run` no longer says everything is fine for a configuration the real run
  rejects: it applies the same listener and file-descriptor budget (32 pool
  addresses x 40 ports used to pass a dry run and then fail with "too many
  listeners", exit 125). New `--dry-run --check-sandbox` also checks that
  namespaces can be created on this machine. A failure while setting up the
  sandbox is now reported as "could not set up the sandbox: ..."; "failed to
  run" is kept for the command itself not being found or executable.
- Command arguments that aren't valid UTF-8 (file names are bytes on Linux) are
  passed to the command intact instead of being rejected with exit 2 ("invalid
  UTF-8 was detected in one or more arguments"). In the `--report-json` command
  list such bytes appear as U+FFFD.
- `--report-json` is checked before the command runs (exit `2` if it can't be
  written); a write failure at the end of an otherwise successful run now exits
  `74` instead of `0`.
- `--seal-docker` rewrites (forced `NetworkMode=none`, sealed classic builds)
  no longer count as blocks, so `--strict --seal-docker` passes when the command
  only starts sealed containers.
- musl targets build (the `ioctl` request type differs from glibc).

### Known limitations

What 0.1.0 does not do, and what nobody has checked. The README's `What
nullroute is not` section has the detail; this is the short version.

- **It stops accidental network access; it is not a boundary for hostile code.**
  The command sees your filesystem and credentials and runs as you. Run as root
  it keeps its capabilities and can unmount the socket decoys. A socket the
  parent opened before starting it keeps working inside. Anything you open with
  `--port`, `--allow`, `--allow-socket` or a Docker socket is open to the
  command.
- **`no_new_privs` is on by default.** A program that needs a file capability
  through a second exec (`ping` started by `sh -c`, on Debian and Ubuntu) fails;
  `--allow-new-privs` turns that off, and `--no-seccomp` does not.
- **Tested on x86_64 only.** CI runs the test suite on Ubuntu 24.04 (x86_64,
  glibc and musl). The aarch64 targets are compiled and linted, not run. The
  development host was a WSL2 kernel. Other distributions and kernels are
  untested.
- **Never exercised:**
  - `AF_VSOCK` on a host that really has vsock: the tests check that creating
    the socket is refused, not what could have been sent over it;
  - a kernel where `TIOCSTI` is still enabled (`dev.tty.legacy_tiocsti=1`),
    where the denial matters most;
  - rootless Docker, Docker Desktop, Podman and the other runtimes whose socket
    paths are hidden or sealed: `--seal-docker` was run against a classic
    local Docker daemon only;
  - a real failure to start a connection thread (`EAGAIN`): the code drops that
    connection instead of crashing, but nothing has provoked it;
  - Go programs under the sandbox (the README example uses `go test`; Go's
    resolver retry behaviour has not been run here).
- **Linux only.** No macOS support; it needs unprivileged user namespaces
  (Ubuntu 23.10+ restricts them through AppArmor by default).
- **No external security review.** The code had an internal review and fixes
  before this release, which is not the same thing.

[Unreleased]: https://github.com/benmckibben/nullroute/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/benmckibben/nullroute/releases/tag/v0.1.0
