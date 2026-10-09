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

[Unreleased]: https://github.com/benmckibben/nullroute/commits/master
