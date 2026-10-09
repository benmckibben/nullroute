# nullroute

[![CI](https://github.com/benmckibben/nullroute/actions/workflows/ci.yml/badge.svg)](https://github.com/benmckibben/nullroute/actions/workflows/ci.yml)

Run a command with outbound network access sealed off. Language-agnostic: it
works the same for `pytest`, `go test`, `cargo test`, `npm test` or any binary,
with no code changes, fixtures or monkeypatching.

```bash
nullroute run -- pytest -x
nullroute run -- go test ./...
nullroute run --port 5432,6379 -- pytest   # local Postgres + Redis still reachable
```

<p align="center">
  <img src="demo/demo.gif" alt="nullroute terminal demo (about 20 seconds)" width="760" />
</p>

Inside, the command runs in its own network namespace: a loopback interface and
no other network device. Connecting to any other host fails immediately with
"network unreachable", and DNS lookups fail (with `--allow`, only allowed names
resolve; see below). Because a network namespace doesn't cover everything that
can reach a network, nullroute also hides the Unix sockets of services that act
outside it (container runtimes, D-Bus, systemd, snapd, SSH and GPG agents),
sets `no_new_privs` and denies a few kernel interfaces that lead out of the
namespace (AF_VSOCK sockets, io_uring, terminal input injection). That is the
whole of it: nullroute isolates the **network**, not the filesystem, the
processes or the credentials of the command (see [What nullroute is
not](#what-nullroute-is-not)).
The exit code is passed through, so it drops into CI unchanged.

## Installing

There are no release binaries and no published crate yet, so today you build it
from source (Rust 1.88 or newer, Linux only; see [Requirements](#requirements)):

```bash
git clone https://github.com/benmckibben/nullroute
cd nullroute
cargo install --locked --path .   # installs nullroute into ~/.cargo/bin
```

Don't run `cargo install nullroute`: the name on crates.io currently holds only
an empty 0.0.0 placeholder, which is not this program. This section will change
when a release exists.

## Reaching local services: `--port`

The sandbox has its own loopback, so a database on your machine's
`127.0.0.1:5432` is invisible inside by default. `--port 5432` bridges exactly
that port: inside, `localhost:5432` (IPv4 or IPv6) reaches the host's
`localhost:5432`. Repeat the flag or comma-separate: `--port 5432 --port 6379`,
`--port 5432,6379`. This covers Docker containers published on the host
(`-p 127.0.0.1:5432:5432`).

If nothing is listening on the host, the connection is closed and nullroute warns
once per port. At most 64 ports can be bridged.

## Letting chosen hosts through: `--allow`

```bash
nullroute run --allow api.github.com,*.stripe.dev -- pytest
```

Allowed hosts are reachable two ways, and both apply the same allowlist:

- **Proxy-aware clients** use an HTTP(S) proxy (below).
- **Everything else** (database drivers, gRPC, custom binaries, `curl --noproxy '*'`)
  resolves names through nullroute's DNS sinkhole and has its TCP connections
  relayed. See [Clients that ignore proxy variables](#clients-that-ignore-proxy-variables-the-dns-sinkhole).

nullroute runs an HTTP proxy that is the only thing able to reach the network,
and points `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (plus lowercase forms) at it.
HTTPS goes through `CONNECT`, so TLS stays end-to-end: nullroute sees the host
name, never the traffic, and needs no certificates.

| Pattern | Matches |
|---|---|
| `api.github.com` | exactly that host (case-insensitive) |
| `*.stripe.dev` | any subdomain, e.g. `api.stripe.dev`, but **not** `stripe.dev` itself |
| `10.0.0.5`, `2001:db8::1` | that IP literal |
| `db.example.com:5432`, `[2001:db8::1]:8443` | only that port (any pattern above can take `:port`) |

Without `:port`, allowing a host allows all its ports. A blocked request gets `403` and nullroute
warns once per host:

```text
$ nullroute run --allow example.com -- curl https://api.github.com
nullroute: blocked api.github.com (not in --allow)
curl: (56) CONNECT tunnel failed, response 403
```

curl, wget, git, pip, Python `urllib`/`requests`/`httpx`, Go's `net/http` and
Node 24's `fetch` (nullroute sets `NODE_USE_ENV_PROXY=1`) all honour the proxy
variables; curl, Python `urllib`, git and Node `fetch` are tested. Clients that
ignore them are covered by the DNS sinkhole for allowed *host names*; anything
else still hits the sealed network. The failure mode is closed, never open.

Other details:

- `NO_PROXY=localhost,127.0.0.1,::1`, so `--port` services are reached directly.
- Host names are resolved on the host. A name that resolves to a loopback
  address (`127.0.0.0/8`, `::1`, `0.0.0.0/8`, `::`, or an IPv6 form wrapping
  one, like `::ffff:127.0.0.1`) is refused even if allowed (use `--port` for
  local services). So is a link-local address (`169.254.0.0/16`, `fe80::/10`),
  which covers the `169.254.169.254` cloud metadata service, and the other
  known metadata endpoints (`fd00:ec2::254`, `100.100.100.200`).
- `--allow` entries that can never be reached this way are rejected up front
  (exit 2): `localhost`, `*.localhost`, loopback IPs (with a pointer to
  `--port`), and link-local/metadata IPs.
- Plain-HTTP requests are sent with `Connection: close`: one request per
  proxied connection.
- **The name has to be the same all the way down.** The allowlist is checked
  against the host in the request (the proxy's `CONNECT` target or request URL,
  or the name the client resolved through the sinkhole). A client could ask for
  an allowed host and then name another one for the server to serve (domain
  fronting), so nullroute also checks what it can see without decrypting
  anything:
  - a plain-HTTP request through the proxy must have a `Host` header that names
    the host it is sent to (or another allowed host), exactly one `Host` header,
    or none; anything else gets `403` (or `400` for several) and is reported as
    a `proxy` block;
  - the first TLS record of a tunnel (the proxy's `CONNECT` and the sinkhole's
    relayed connections) is read before anything reaches the host: a ClientHello
    whose server name (SNI) isn't the tunnel's host or another allowed host is
    cut off and reported. No SNI (a client dialling an IP address) is let
    through; a first record that looks like TLS but can't be parsed is refused.
    Other protocols, and servers that speak first (SSH, SMTP, MySQL), are
    forwarded untouched. To use a different SNI deliberately (for example a
    client-facing name for Encrypted Client Hello), allow that name too.
- **What that doesn't stop.** The server name and the `Host` header inside TLS
  are the same name for any honest client, but a program that wants to front
  can send the allowed name in the SNI and a different `Host` in the encrypted
  request, to a server that serves both (typically several sites behind one CDN
  address). Plain HTTP through the sinkhole's relay isn't `Host`-checked either:
  one connection carries many requests. Allowlisting by name can't close this;
  nullroute stops accidental access, not a client that is trying to get around it
  (see [What nullroute is not](#what-nullroute-is-not)).
- **Private and LAN addresses work, on purpose.** `--allow 10.0.0.5`, or a name
  that resolves into RFC 1918, carrier-grade NAT (100.64.0.0/10) or unique-local
  (fc00::/7) space, reaches that machine on your network (only loopback,
  link-local and cloud-metadata addresses are always refused). nullroute prints
  a warning for an `--allow` or `--resolve` IP in that space, and once per host
  when an allowed name resolves into it, because that is usually a corporate or
  split-horizon name you didn't mean to open up. `-q` silences the warnings.
  An allowed IP allows everything that answers there, but a `Host` header or
  SNI naming another host is still refused unless that host is allowed too.
- The proxy listens on `127.0.0.1:3128` inside the sandbox (or the next port
  that isn't a `--port`). An existing `HTTP(S)_PROXY` is overridden; chaining to
  a corporate upstream proxy isn't supported yet.

### Clients that ignore proxy variables: the DNS sinkhole

```bash
nullroute run --allow db.staging.example.com:5432 -- psql -h db.staging.example.com
nullroute run --allow api.github.com -- ./my-static-binary   # ports 80 and 443
```

Every sandbox gets its own resolver, and with `--allow` host names it becomes a
sinkhole that maps those names:

1. **Resolver.** nullroute answers DNS on `127.0.0.1:53` (UDP and TCP) inside the
   sandbox, and bind-mounts a generated `/etc/resolv.conf` (`nameserver 127.0.0.1`)
   over the real one in the sandbox's private mount namespace. Local resolver
   sockets that would bypass `resolv.conf` (systemd-resolved's
   `/run/systemd/resolve/io.systemd.Resolve`, used by `nss-resolve`, and nscd's
   socket) are masked, so glibc falls back to plain DNS. (They are masked in
   every sandbox, with or without `--allow`; see
   [Unix sockets](#unix-sockets-the-side-door-closed-by-default).) Nothing
   changes on the host.
2. **Synthetic addresses.** An allowed name resolves to a loopback address from
   `127.77.0.0/24`: each exact host gets its own (`127.77.0.1`, `.2`, ... in
   sorted order); names matching a `*.domain` wildcard share a pool of 32,
   assigned on first lookup and recycled least-recently-resolved first (TTL 30s).
   **Any other name gets `NXDOMAIN`** and is recorded in the report as `dns`.
   `AAAA` queries for allowed names get an empty answer, so clients use IPv4.
   (`localhost` and `*.localhost` resolve to loopback and aren't reported.)
3. **Transparent relay.** nullroute listens on each synthetic address on the
   ports that name is allowed on: the `:port` from `--allow`, or **80 and 443**
   when none is given. A connection to `127.77.0.x:PORT` is mapped back to its
   name and dialled from the host's network, with the same rules as the proxy:
   resolved on the host, loopback results refused. TLS stays end-to-end, and the
   client sends the right SNI/`Host` because it dialled by name.

**Without `--allow` host names** the resolver still runs: it answers every name
with `NXDOMAIN` ("Name or service not known") and records the lookup as a `dns`
block (see [the report](#what-got-blocked-the-report-and---strict)), so a plain
`nullroute run --strict` catches a test that looks a name up and swallows the
error. A lookup fails the same way with and without `--allow`: with an answer
that is final, not the retryable "Temporary failure in name resolution" that a
resolver with no route gives, which clients such as musl's sit out for seconds.

| Flag | Effect |
|---|---|
| `--resolve HOST:IP` | Dial an allowed host at `IP` instead of resolving it on the host, like curl's `--resolve` (repeatable; applies to the proxy too). The host must be allowed; loopback IPs are still refused. |
| `--no-dns` | Don't run the resolver or the sinkhole: names don't resolve inside (the host's `resolv.conf` has no route out, so lookups typically fail with "Temporary failure in name resolution"), only proxy-aware clients reach allowed hosts, and DNS lookups are not recorded, so `--strict` can't see them. |

```text
$ nullroute run --allow api.github.com -- python3 -c "import socket; socket.create_connection(('example.com', 443))"
nullroute: blocked DNS lookup of example.com (not in --allow)
socket.gaierror: [Errno -2] Name or service not known
```

Limits (all fail closed):

- **IP literals never ask DNS**, so dialling one directly still fails with
  `ENETUNREACH` ("network unreachable"), even if the IP is in `--allow`. IP
  entries only work through the proxy.
- Only the listed ports are relayed. A port the name isn't allowed on gets
  "connection refused" (or, in a wildcard pool that listens on another
  wildcard's port, is closed and reported as `dns  host:port (port not in --allow)`).
- Only TCP is relayed; UDP to a synthetic address (e.g. QUIC/HTTP3) gets
  nothing back, and clients fall back to TCP.
- An allowed name that has no port and isn't HTTP(S) needs `--allow host:port`.
- A client with a hard-coded resolver (`dig @8.8.8.8`, DNS-over-HTTPS) bypasses
  `resolv.conf`; it gets "network unreachable" instead of an answer.
- With `--allow` host names, `--port 53` clashes with the resolver; add
  `--no-dns` to bridge it. Without them, `--port 53` bridges as asked and the
  resolver steps aside (lookups are then not recorded).
- nullroute adds `127.77.0.1/24` to the sandbox's `lo` (in every sandbox that
  has the resolver): routing doesn't need it, but glibc's `AI_ADDRCONFIG`
  ignores lookups for IPv4 when the only IPv4 address is `127.0.0.1`, which
  would hide those lookups from the report.

## What got blocked: the report and `--strict`

Every blocked attempt is recorded. The first attempt at each target is printed
as it happens (so a hanging test shows why), and a summary is printed when the
command exits:

```text
$ nullroute run --allow example.com -- ./run-tests.sh
nullroute: blocked api.github.com (not in --allow)
nullroute: blocked a connection to /run/docker.sock (...). Rerun with --allow-socket /run/docker.sock to permit it.
...test output...
nullroute: blocked 7 attempts to reach 2 targets:
  socket  /run/docker.sock       5x  (container runtimes can start containers with full network access)
  proxy   api.github.com:443     2x  (not in --allow)
```

| Kind | What | Counts as blocked (`--strict`) |
|---|---|---|
| `socket` | a connection to a hidden socket | yes |
| `proxy` | a proxy request to a host that isn't allowed, or one whose `Host` header or TLS server name names a host that isn't | yes |
| `dns` | a lookup of a name that isn't allowed, or a relay the sinkhole refused | yes |
| `docker` | a Docker API request `--seal-docker` (or `--seal-docker-pulls`) refused | yes |
| `rewritten` | a request `--seal-docker` changed and let through (a container create forced onto `NetworkMode=none`, or a classic `docker build` forced onto `networkmode=none`) | no |

`rewritten` entries are listed after the blocks, under their own heading
(`nullroute: rewrote N requests and let them through (not blocks; --strict
ignores these):`), and in their own `"rewritten"` list in the JSON report.

DNS counts are queries, so one lookup can count twice (`A` and `AAAA`).

Counts are connections, so one `docker ps` can count several times (the Docker
CLI reconnects).

| Flag | Effect |
|---|---|
| `--strict` | Exit 1 if anything was blocked, even if the command succeeded. Catches tests that swallow network errors, as long as the attempt reaches nullroute: DNS lookups (with or without `--allow`), proxy requests and hidden sockets do; a connection straight to an IP address does not (see below). A command that already failed keeps its own exit code. `rewritten` entries don't count, so `--strict --seal-docker` passes when the command only starts (sealed) containers or runs (sealed) classic builds. |
| `-q`, `--quiet` | Skip the live lines; keep the summary. |
| `--report-json FILE` | Write the report as JSON for CI artifacts (always written, `"blocked": []` and `"rewritten": []` when clean; layout and compatibility rules in [docs/report-json.md](docs/report-json.md)). The file is checked before the command runs: if it can't be written (missing directory, a directory, no permission) nullroute exits 2 without running anything. If writing still fails at the end, a run that would have exited 0 exits 74 instead; a non-zero exit is kept. |

```json
{
  "schema_version": 1,
  "command": ["docker", "run", "--rm", "alpine", "true"],
  "exit_code": 0,
  "strict_failed": false,
  "blocked": [],
  "rewritten": [
    {"kind": "rewritten", "target": "containers/create", "reason": "forced NetworkMode=none", "count": 1}
  ]
}
```

**Exit codes.** The command's own exit code is passed through (`128+N` if signal
`N` killed it). nullroute adds these:

| Code | When |
|---|---|
| `1` | `--strict` and something was blocked, though the command succeeded |
| `2` | bad arguments, and nothing is run: unknown or invalid options (before or after `run`; the command must follow `--`), an `--allow`, `--resolve` or `--port` value that can't work (or more than 64 of them), `--seal-docker-pulls` without a sealed socket, an unwritable `--report-json` |
| `74` | the `--report-json` file couldn't be written after a run that would have exited 0 (a non-zero exit is kept) |
| `125` | nullroute itself failed: the sandbox couldn't be set up (e.g. namespaces refused) or socket hiding couldn't be prepared |
| `126` | the command was found but couldn't be executed (not executable, a directory, ...) |
| `127` | the command was not found |

The command can exit with any of these itself, so they only mean something when
the command isn't known to use them. In particular a `1` is either the command's
own or `--strict`'s: with `--report-json`, `"strict_failed": true` says that
nullroute turned a success into `1` (see [docs/report-json.md](docs/report-json.md)).
(Like Docker: `125` for "the runner failed", `126` and `127` for the contained
command that couldn't be invoked or found. Usage errors are `2`, as for most
CLIs.)

**What `--strict` can't see.** A direct connection to an IP address (`connect()` to
`93.184.216.34:443`, no name lookup) fails inside the kernel with "network
unreachable" (`ENETUNREACH`), because the sandbox has only a loopback. Nothing
reaches nullroute, so there is nothing to record: `--strict` can't tell that
such a command tried, and it passes if the command swallows the error. Proxy
requests, DNS lookups and hidden sockets are listed. A program that talks to
hard-coded IP addresses is only caught by its own failure.

**Signals and process lifetime.** Ctrl-C reaches the command as usual; nullroute
itself ignores SIGINT/SIGQUIT so it can still print the report, then exits with
the command's status (130). SIGTERM and SIGHUP sent to nullroute are forwarded
to the command, also when they arrive while the command is still starting, and
the command gets each exactly once: a signal sent to nullroute's pid
(`kill -TERM PID`) is forwarded, while one sent to the whole process group
(`kill -TERM -PGID`, `timeout`), which already reaches the command because it
is in the group, is not forwarded again. (nullroute tells the two apart with a
small helper process of its own in the group; if that can't be started, signals
are forwarded unconditionally. A command that moved to another group always gets
the forwarded copy.) The signal is also never sent to the command's pid once it
has exited and been reaped. A
SIGINT/SIGQUIT that reaches nullroute before the command exists (Ctrl-C right
after you hit enter) is passed on to it as well: it stops the command before it
runs, instead of vanishing while the command runs on. The command never outlives
nullroute: if nullroute is killed outright (SIGKILL, the OOM killer, a crash),
the kernel SIGKILLs the command too. When the command exits, anything it left
running in the sandbox (background jobs, daemons, even ones that called
`setsid`) is killed before nullroute exits, since nothing outside can reach it
once nullroute's relays are gone. One gap: if nullroute itself is SIGKILLed, the
command's own child processes are orphaned rather than killed (a parent-death
signal only covers direct children), and a command that is itself a set-user-ID
or file-capability binary (`ping` on many distros) survives too, because exec
clears the setting. Send nullroute SIGTERM first (as `timeout` and CI runners
do) so it can clean up.

**Scratch files.** The decoy sockets and the generated resolver files are
bind-mounted into the sandbox from a private directory in the temp dir
(`nullroute-*`, `nullroute-dns-*`). It is removed when nullroute exits. If
nullroute is killed (SIGKILL, the OOM killer) or crashes it can't clean up, and
the directory is swept by the next run (only directories of the current user,
over a minute old, that no running nullroute has locked). The files have to stay
while the command runs: a nullroute started inside the sandbox mounts its own
decoys over them. `--dry-run` (with or without `--inspect`) creates nothing.

**Limits.** nullroute relays at most 256 connections at a time per
`--port` / proxy / DNS-bridge listener (64 for DNS over TCP, 32 for socket
decoys); one more is closed immediately. DNS-over-TCP connections last at most
30 s, and name lookups for the proxy give up after 10 s. The report lists at
most 1000 distinct targets and the terminal gets at most 20 live lines per
second; the summary says how many more attempts were counted ("... and N more
attempts at other targets"), they still make `--strict` fail, and
`--report-json` gets a `not_listed` object with the counts. nullroute raises its
own soft file-descriptor limit to the hard limit while it runs; the command
gets the soft limit it was started with.

## Seeing the sandbox: `--inspect`

`--inspect` prints the sandbox topology to stderr before the command starts,
then runs the command as usual (stdout and the exit code are untouched):

```text
$ nullroute run --inspect --seal-docker --port 5432 --allow api.github.com -- pytest
nullroute: inspect: sandbox topology
  namespaces:      user, net, mount
  loopback:        lo: UP (127.0.0.1, ::1, 127.77.0.1/24)
  bridged ports:   5432
  unix sockets:
    blocked (403 decoy):
      /run/containerd/containerd.sock
      /run/dbus/system_bus_socket
    sealed (--seal-docker proxy):
      /run/docker.sock
    masked (resolver bypass):
      /run/systemd/resolve/io.systemd.Resolve
  docker pulls:    any (the daemon may contact any registry or URL)
  upstream proxy:  http://127.0.0.1:3128 (allow: api.github.com)
  dns sinkhole:    127.0.0.1:53 (udp, tcp; other names get NXDOMAIN)
    api.github.com -> 127.77.0.1 (ports 80, 443)
...test output...
```

| Line | Meaning |
|---|---|
| `namespaces` | Linux namespaces the command gets: always `user` and `net`; `mount` when a socket is hidden, sealed or masked, or the resolver has a `resolv.conf` to put in place (almost always). |
| `loopback` | The sandbox's own `lo`, brought up before the command runs (plus the resolver's synthetic pool address, `127.77.0.1/24`, unless `--no-dns`). |
| `bridged ports` | `--port` values (sorted, deduplicated), or `none`. |
| `blocked (403 decoy)` | Sockets replaced by a decoy that answers `403` (defaults + `--hide-socket`, minus `--allow-socket`). |
| `sealed (--seal-docker proxy)` | Docker sockets proxied with containers forced to `NetworkMode=none`. |
| `docker pulls` | The `--seal-docker-pulls` mode (only shown when a socket is sealed). `--dry-run` prints it too. |
| `masked (resolver bypass)` | Local resolver sockets (systemd-resolved varlink, nscd) replaced by an unconnectable file, always. |
| `upstream proxy` | Where the `--allow` proxy listens inside the sandbox, and the allowed hosts, or `none`. |
| `dns sinkhole` / `dns resolver` | The resolver address and each allowed name's synthetic address and relayed ports (`dns sinkhole`); `dns resolver` when there are no allowed names and it only refuses and records every lookup; `none` with `--no-dns` (or `--port 53` and no allowed names). |

The summary is built from the same plan the sandbox is built from, so it shows
exactly what will be set up. Combine with `--dry-run` to print it and exit
without running anything: `nullroute run --inspect --dry-run -- true`.
(`--dry-run`'s own stdout listing is unchanged by `--inspect`.)

## Unix sockets: the side door, closed by default

A network namespace only covers network sockets. Unix socket *files* are reached
through the filesystem, so without extra care `docker run` inside the sandbox
would ask the Docker daemon (outside, with full network) to start a container
for you, and that container could reach the internet.

So nullroute hides container-runtime sockets by default: Docker
(`/var/run/docker.sock`, rootless, Docker Desktop, or wherever `DOCKER_HOST=unix://`
points), Podman, containerd and BuildKit. Inside, the command connects to a decoy
instead, and Docker shows a clear error:

```text
$ nullroute run -- docker ps
nullroute: blocked a connection to /run/docker.sock (container runtimes can start containers with full network access). Rerun with --allow-socket /run/docker.sock to permit it.
Error response from daemon: nullroute blocked access to /run/docker.sock (...). Rerun with --allow-socket /run/docker.sock to permit it.
```

Local resolvers are a side door too: they resolve names on the host's network
for whoever asks, which leaks DNS queries (and their answers) out of the
sandbox. So, also by default:

- The **system D-Bus** (`/run/dbus/system_bus_socket`, or wherever
  `DBUS_SYSTEM_BUS_ADDRESS=unix:path=` points) is hidden, because
  systemd-resolved answers `org.freedesktop.resolve1` calls on it. If the
  command genuinely needs the system bus, `--allow-socket /run/dbus/system_bus_socket`
  brings it back (and with it resolved's D-Bus API).
- **systemd-resolved's varlink socket** (`/run/systemd/resolve/io.systemd.Resolve`)
  and **nscd** are masked in every sandbox, even a bare `nullroute run`, and
  can't be opted back in: connecting fails with `EACCES`. glibc then falls back
  to plain DNS, which has no route out (or reaches the `--allow` sinkhole).

| Flag | Effect |
|---|---|
| `--allow-socket PATH` | Keep a default-hidden socket reachable (repeatable). Any path to the socket works (symlinks are followed); `--dry-run` shows what is hidden. |
| `--hide-socket PATH` | Hide another socket too, e.g. an X11 or Wayland display socket or a local proxy (repeatable). |
| `--dry-run` | Print what would be hidden, masked, forwarded and allowed (hidden and sealed sockets, masked resolver sockets, the seccomp filter, forwarded ports, allowed hosts, the DNS resolver or sinkhole mapping, the namespaces), then exit. It validates the options and the listener / file-descriptor budget exactly as a real run does (a configuration that would fail with "too many listeners" fails here too, exit 125), but it does **not** start anything: it can't tell you that user namespaces are disabled, that a port is free, or that the command exists. |
| `--check-sandbox` | With `--dry-run`: also check that this machine lets nullroute create the user, network and mount namespaces (a throw-away process does the real setup and exits; nothing is left behind). Exit 125 with the same message a real run would give if it can't. |
| `--inspect` | Print the full sandbox topology to stderr before running (see above). |

### The user's session: D-Bus, systemd, snapd, agents

The same goes for the services of your login session. Their sockets are plain
files, so a command in the sandbox could ask them to do things *outside* the
sandbox, with the host's network. For example, `systemd-run --user` over the
session bus starts a process in the host's network namespace
(`busctl --user list` works from inside a bare sandbox unless these are
hidden). So, also by default, nullroute hides the ones that exist on your
machine:

| Hidden | Where | Why |
|---|---|---|
| session D-Bus | `$DBUS_SESSION_BUS_ADDRESS` (`unix:path=`), `$XDG_RUNTIME_DIR/bus`, `/run/user/UID/bus` | starts processes on the host (`systemd-run --user`, D-Bus activation) |
| systemd user manager | `…/systemd/private` in the same directories | starts processes on the host |
| snapd | `/run/snapd.socket`, `/run/snapd-snap.socket`, `…/snapd-session-agent.socket` | installs and runs snaps, with network |
| SSH and keyring agents | `$SSH_AUTH_SOCK`, `…/ssh-agent.socket`, `…/openssh_agent`, `…/gcr/ssh`, `…/keyring/*` | sign with your keys for anything the command can reach |
| gpg-agent and dirmngr | `…/gnupg/S.*`, `~/.gnupg/S.*`, `$GNUPGHOME/S.*` | dirmngr fetches keys over the host's network (a `gpg --recv-keys` inside would go out) |
| more container runtimes | rootless Docker/Podman/containerd/BuildKit, Docker Desktop, Colima, Rancher Desktop, Lima, OrbStack, k3s, CRI-O, LXD, libvirt | start containers and VMs with a network |

Nothing is printed for the ones you don't have. A connection to a hidden
socket gets the same decoy as above, is reported, and counts as a block for
`--strict`; `--allow-socket PATH` brings one back (for instance
`--allow-socket "$SSH_AUTH_SOCK"` if the command has to use your SSH agent, which
it can only do over a route you've opened with `--allow` or `--port`).
`nullroute run --dry-run -- true` lists what is hidden on this machine.

Not hidden, on purpose:

- **Abstract sockets** (a D-Bus address like `unix:abstract=/tmp/dbus-…`, X11's
  `@/tmp/.X11-unix/X0`): they belong to a network namespace, so the sandbox's own
  empty one already keeps the host's out. (Checked: connecting to a host's
  abstract socket from inside fails with `ECONNREFUSED`.)
- **Display servers** (`/tmp/.X11-unix/X0`, `$XDG_RUNTIME_DIR/wayland-0`) and the
  accessibility bus (`$XDG_RUNTIME_DIR/at-spi/bus_*`). They can read the screen
  and inject keystrokes into other windows, which could be turned into running
  something on the host, but that is not a path to the network, and hiding them
  would break GUI test runs. If that matters to you, `--hide-socket` them, or
  don't run untrusted code on a desktop session.
- `$XDG_RUNTIME_DIR/systemd/notify` (readiness notifications only), PulseAudio
  and PipeWire, dconf.

### Other ways out: seccomp and `no_new_privs`

A few kernel interfaces reach outside the network namespace (or into the
terminal you started the command from), and a command that is meant to have no
network has no use for them. nullroute sets `no_new_privs` and installs a small
seccomp filter before running the command. It denies, with an error and
without killing the command:

| Call | Result | Why |
|---|---|---|
| `socket(AF_VSOCK)` | `EAFNOSUPPORT` | a channel to the host or hypervisor on microVMs, WSL2, Hyper-V, Firecracker and Docker Desktop (it isn't scoped to the network namespace) |
| `socket(AF_BLUETOOTH)`, `AF_NFC`, `AF_QIPCRTR` | `EAFNOSUPPORT` | hardware, also outside the namespace |
| `ioctl(TIOCSTI)`, `ioctl(TIOCLINUX)` | `EPERM` | push input into the terminal the command was started from: on kernels with `dev.tty.legacy_tiocsti=1` that is typing into your shell |
| `io_uring_setup()` | `EPERM` | io_uring can create sockets without `socket()`, so it would walk around the list above; programs already handle this error where `kernel.io_uring_disabled` is set |

Everything else is allowed, including `AF_UNIX`, `AF_INET`, `AF_INET6`,
`AF_NETLINK` and `AF_PACKET`. It is tested with bash, Python, Node, curl, git, the
Docker CLI (`--seal-docker`), cargo and a nested nullroute; `ptrace` isn't filtered
(strace and gdb should work, but weren't tried). It is not a syscall sandbox. On x86-64 the x32
ABI fails with `ENOSYS` and 32-bit x86 programs can't use `socketcall()` (their
direct `socket` calls are filtered like native ones); on AArch64 the 32-bit ARM
mode is filtered the same way as the native one.

`no_new_privs` means a setuid, setgid or file-capability binary can't raise
privileges after exec. `sudo` and `su` never worked in the sandbox anyway (only
your own id is mapped in the user namespace, so a root-owned setuid file has no
effect); what changes is that a file capability (`cap_net_raw` on `ping` on some
distributions) is no longer granted. A nested sandbox or helper inherits both
settings. `nullroute run --dry-run -- true` and `--inspect` show them.

`--no-seccomp` leaves the filter out, for the odd tool that needs one of these
calls (`no_new_privs` stays set).

### Letting Docker tests run, with sealed containers

`--seal-docker` is the middle ground between hiding docker.sock (the command
can't use Docker) and `--allow-socket` (it can, and its containers get full
network). The command uses Docker normally, but nullroute rewrites each
container-create request to `NetworkMode: none`, forces classic-builder builds
onto `--network none`, refuses the API calls that would hand out a network
it can't take back, and refuses to run code in, start or attach to a container
that already has one:

```bash
nullroute run --seal-docker -- pytest        # tests may start containers; none get network
nullroute run --seal-docker-socket /custom/docker.sock -- ...   # non-standard path
nullroute run --seal-docker --seal-docker-pulls none -- pytest  # and the daemon pulls nothing either
```

| Flag | Effect |
|---|---|
| `--seal-docker` | Seal the standard Docker socket paths (`/var/run/docker.sock`, rootless, Docker Desktop, `DOCKER_HOST=unix://`). |
| `--seal-docker-socket PATH` | Seal this Docker API socket (repeatable). |
| `--seal-docker-allow-existing` | Also let the command run code in, start, restart, attach to or copy files into containers that have a network (see [Containers that already exist](#containers-that-already-exist)). This unseals them. Needs `--seal-docker` or `--seal-docker-socket` (exit 2 otherwise). |
| `--seal-docker-pulls MODE` | What the Docker daemon may contact for the command: `any` (default), `allowlisted` or `none`. See [Registry access](#registry-access---seal-docker-pulls). Needs `--seal-docker` or `--seal-docker-socket` (exit 2 otherwise). |

The sealed container still runs and can mount volumes, but it has no network at
all: not the internet, not other containers, and not the host's `--port`
services. A requested `--network` (including `host`) is overridden to `none`.

| Docker API request | Under `--seal-docker` |
|---|---|
| `POST /containers/create` | rewritten: `NetworkMode: none`, networking settings dropped |
| `POST /build` (classic builder) | rewritten: `networkmode=none`, so `RUN` steps have no network; the context is streamed through |
| `POST /build?version=2`, `/grpc`, `/session` (BuildKit / buildx) | refused: a BuildKit build picks each step's network inside a gRPC stream nullroute can't rewrite |
| `POST /containers/{id}/exec`, `/start`, `/restart`, `/unpause`, `/update`, `/attach`, `GET .../attach/ws`, `PUT .../archive`, `POST /exec/{id}/start` | refused unless the container has no network (see below) |
| `POST /networks/{id}/connect` | refused |
| `POST /services/create`, `/services/{id}/update` | refused: Swarm tasks get networks |
| `POST /swarm/init`, `/swarm/join` | refused: a swarm manager could schedule such tasks here |
| `POST /plugins/pull`, `/plugins/create`, `/plugins/{name}/enable`, `/upgrade` | refused: plugins can run with host networking |
| everything else | forwarded unchanged |

Refusals are Docker-style errors (`Error response from daemon: nullroute
blocked ...`) and show up in the report as `docker` entries.

#### Containers that already exist

Rewriting what the command *creates* isn't enough: a container that already
exists, say a database on the default bridge network that you started
earlier, has a network, and `docker exec` into it would run the command's code
with that network (a `docker exec db sh -c 'echo x | nc 172.17.0.1 9999'` from
inside the sandbox reached a listener on the host). So under `--seal-docker`
the Docker API operations that run code in, start, resume, attach to or write
into a container (`exec`, `start`, `restart`, `unpause`, `update`, `attach`
and its WebSocket form, `PUT archive`, and starting an exec instance) are only
forwarded for a container that has **no network**: `NetworkMode: none` and
attached to no other network. That includes everything the command created
(also in an earlier run); the daemon is asked, so names, id prefixes and link
names can't be used to slip past, and the request is sent to the container's
full id. Any other container gets a `403` that names the flag:

```
Error response from daemon: nullroute blocked trying to run a command in container db: it has a network (NetworkMode=bridge), and --seal-docker only lets the command run code in, start or attach to containers that have none (the ones it creates here). Create the container through the sandbox, or pass --seal-docker-allow-existing to allow this; that unseals the container's network.
```

Reads are unaffected (`inspect`, `logs`, `ps`, `top`, `diff`, `export`, `stats`,
`cp` out of a container), and so are stop, kill, pause, rename and remove.
The list of operations that are *not* guarded is explicit, and an endpoint a
later Docker version adds under `/containers/{id}/` is guarded until someone
looks at it. `--seal-docker-allow-existing` turns the check off for people who
really want the command to drive existing containers; it unseals them. (`docker
cp` *into* a container isn't supported under `--seal-docker` at all: the CLI
uploads the archive chunked, which the proxy doesn't accept.)

Malformed or oversized requests get an answer rather than a silent close:
`431` for a request head over 64 KiB, `413` for a body over 4 MiB, `417` for an
`Expect` other than `100-continue`. `Expect: 100-continue` is answered by
nullroute (the client gets its `100 Continue` before it sends the body) and not
forwarded to the daemon.

**Building images.** `docker build` uses BuildKit (buildx) by default, and
BuildKit builds can't be sealed, so under `--seal-docker` they fail with a
message saying so. Use the classic builder, whose `RUN` steps nullroute runs
with no network:

```bash
DOCKER_BUILDKIT=0 nullroute run --seal-docker -- docker build -t myimage .
```

The classic builder doesn't support BuildKit-only Dockerfile syntax (`RUN
--mount`, heredocs, ...). Its `FROM` images must already be present or
pullable (see below; `--seal-docker-pulls` can't stop that pull).

Requests are matched on the path the daemon routes: percent-decoded, with
`//`, `.` and `..` resolved, any `/vX.Y` prefix and query string ignored. A
path that can't be reduced unambiguously (invalid or double percent-encoding,
control characters, not starting with `/`) is refused (`400`).

Every request on a connection is parsed, including keep-alive and pipelined
ones. The connection only becomes a raw stream after a genuine protocol switch
(`101 Switching Protocols` from attach/exec, or the daemon's raw stream for a
`POST` attach / exec start), never after a `404` or any other ordinary
response. Container-create bodies that aren't a single JSON object are refused
(`400`), `HostConfig`/`NetworkMode` keys are matched case-insensitively the
way Docker's JSON decoder does, and request bodies that can't be framed by one
`Content-Length` (e.g. `Transfer-Encoding: chunked`) are refused.

**This is not a Docker security boundary.** It stops the ways a container
gets a network through the Docker API that are listed above; a `--privileged`
container can still escape, and a container can still reach the host through
bind mounts (for example of another daemon's socket). It's "CI containers
shouldn't phone home", not "run hostile images safely". containerd and BuildKit
sockets speak a different protocol and are still hidden (not sealed) by default.

The Docker daemon itself still has network, and some requests make it reach out
on the command's behalf. Each one sends a host name (and a path) the command
chose to the network, so it can carry data out even though no container has a
network. By default (`--seal-docker-pulls=any`) `--seal-docker` lets them
through unchanged; `--seal-docker-pulls` can refuse them (next section).

Still open in every mode:

- a classic `docker build` whose `FROM` image isn't present: the daemon pulls
  it inside the `/build` request (no request of its own to refuse, and the
  image is named in the uploaded Dockerfile). Pre-pull base images;
- registry mirrors configured on the daemon (`registry-mirrors`): a Docker Hub
  pull goes to the mirror, and the registry's own redirects (token service,
  blob CDN) are followed as the daemon sees fit;
- the daemon resolves allowed registry names itself, on the host's DNS;
- logging drivers that ship container logs over the network (`--log-driver
  syslog|gelf|fluentd|splunk|...` with a remote address) and `local` volumes
  backed by NFS/CIFS (`--opt type=nfs,o=addr=HOST`): the daemon or kernel
  connects to a host the command chose. Not covered by `--seal-docker` at all.

#### Registry access: `--seal-docker-pulls`

```bash
nullroute run --seal-docker --seal-docker-pulls none -- pytest
nullroute run --seal-docker --seal-docker-pulls allowlisted --allow ghcr.io,docker.io -- pytest
```

| Request | `any` (default) | `allowlisted` | `none` |
|---|---|---|---|
| image pull (`POST /images/create?fromImage=`: `docker pull`, `docker run`/`create` of a missing image, compose) | allowed | if the registry is allowed | refused |
| `docker login` (`POST /auth`, the body's `serveraddress`) | allowed | if the registry is allowed | refused |
| manifest lookup (`GET /distribution/{name}/json`) | allowed | if the registry is allowed | refused |
| `docker search` (`GET /images/search`) | allowed | if the registry is allowed | refused |
| plugin privileges (`GET /plugins/privileges`; installing a plugin is refused anyway) | allowed | if the registry is allowed | refused |
| `docker push`, `docker plugin push` | allowed | refused | refused |
| import from a URL (`POST /images/create?fromSrc=URL`); `fromSrc=-` (stdin) is local and always allowed | allowed | refused | refused |
| classic build from a remote context (`POST /build?remote=`) | allowed (sealed) | refused | refused |
| classic `docker build --pull` (`pull=1`: force-pull base images nullroute can't see) | allowed (sealed) | refused | refused |
| classic build `FROM` an image that isn't present | pulled | **pulled** (can't be refused) | **pulled** (can't be refused) |
| `docker run` / classic build of images already present | allowed | allowed | allowed |

Refusals are `403`s the Docker CLI prints, naming the flag, and `docker`
entries in the report (so `--strict` fails):

```text
$ nullroute run --seal-docker --seal-docker-pulls allowlisted -- docker pull ghcr.io/acme/tool
nullroute: --seal-docker-pulls: refused pull ghcr.io/acme/tool (ghcr.io not in --allow; --seal-docker-pulls=allowlisted)
Error response from daemon: nullroute blocked pulling ghcr.io/acme/tool: --seal-docker-pulls=allowlisted only lets the Docker daemon contact registries in --allow, and ghcr.io isn't one. Add --allow ghcr.io, or pull the image before running nullroute.
```

Allowed requests aren't listed in the report. How `allowlisted` decides:

- **Which registry.** Image names follow Docker's reference rules: the part
  before the first `/` is a registry only if it contains `.` or `:`, is
  `localhost`, or has an uppercase letter; otherwise the image is on Docker
  Hub (`alpine`, `library/alpine`, `user/repo`). `ghcr.io/a/b:tag@sha256:...`
  is `ghcr.io`; `localhost:5000/x` is `localhost` port 5000. A name whose
  registry part isn't a valid host (bad port, stray characters) is refused.
- **Matching.** The registry host is checked against `--allow` with the usual
  rules (case-insensitive, `*.example.com` for subdomains, `:port`). Without
  a port in the image name the port is 443, so `--allow ghcr.io` and
  `--allow ghcr.io:443` both allow `ghcr.io/...`, and `myreg:5000/x` needs
  `--allow myreg` or `--allow myreg:5000`.
- **Docker Hub** is one registry under any of its names: images without a
  registry, `docker.io/...`, `index.docker.io/...` and
  `registry-1.docker.io/...` (and `docker login` with no server or
  `https://index.docker.io/v1/`) are allowed if `--allow` matches any of
  `docker.io`, `index.docker.io` or `registry-1.docker.io` (so
  `--allow docker.io` or `--allow '*.docker.io'` both work).
  Other hosts such as `hub.docker.com` only match themselves.
- **Local registries** (`localhost`, `*.localhost`, loopback IPs) can't be in
  `--allow`; a local registry is allowed when its port is bridged with
  `--port` (`--port 5000` for `localhost:5000/x`), since the command can
  reach it then anyway.
- `allowlisted` only lets the daemon *read* from allowed registries: pushes,
  URL imports, remote build contexts and `build --pull` are refused whatever
  `--allow` says. Use `any` for those.
- Query strings are decoded like the daemon does; one it would read differently
  (`;`, bad escapes) or form-encoded parameters in the body are refused.

Recent Docker CLIs fetch `docker build https://...` and git contexts
themselves (inside the sandbox, under its network rules) and send the daemon a
plain build, so `remote=` only comes from other API clients.

## Status: pre-1.0, Linux only

nullroute hasn't had a 1.0 release; options and output formats may still change
(see the [changelog](CHANGELOG.md)).

| | |
|---|---|
| Network namespace isolation (no network but the sandbox's own loopback) | ✅ |
| No root needed | ✅ (unprivileged user namespaces) |
| Runs as you, not as root inside | ✅ |
| Exit code / signal passthrough | ✅ (`128+N` for signals, `125` if nullroute itself fails, `127`/`126` if the command isn't found/executable) |
| Reach chosen services on the host's localhost (`--port`) | ✅ TCP, IPv4 + IPv6 |
| Reach a Docker container by its container IP | ❌ (publish it on localhost and use `--port`) |
| Hide Unix-socket escapes (`docker.sock` etc.) | ✅ on by default for container runtimes, the system and session D-Bus, the systemd user manager, snapd, SSH/GPG agents |
| Block out-of-band DNS via local resolvers | ✅ resolved varlink + nscd always masked; D-Bus hidden by default |
| Sandbox containers the command starts (`--seal-docker`) | ✅ forced to `NetworkMode=none` (classic builds too; BuildKit, Swarm services and plugins refused); running code in, starting or attaching to existing containers that have a network is refused; not a boundary for hostile images |
| Limit what the Docker daemon pulls for the command (`--seal-docker-pulls`) | ✅ `allowlisted` (registries in `--allow`) or `none`; except a classic build's missing `FROM` image |
| Allowlist (`--allow api.github.com,*.stripe.dev`) | ✅ HTTP(S) via proxy; any TCP client by host name via the DNS sinkhole (80/443 or `:port`) |
| Allowlist for direct IP-literal connections | ❌ proxy only; raw connects to an IP fail with `ENETUNREACH` |
| Deny AF_VSOCK/Bluetooth/NFC sockets, TIOCSTI and io_uring (seccomp, `no_new_privs`) | ✅ on by default; `--no-seccomp` turns the filter off |
| Report what was blocked (+ `--strict`, `--report-json`) | ✅ proxy, DNS and socket blocks; not direct IP connects |
| Show the sandbox topology (`--inspect`) | ✅ namespaces, loopback, ports, sockets, proxy, DNS sinkhole |
| macOS | ❌ no network namespaces; needs a different mechanism |

### What nullroute is not

nullroute stops **accidental** network access. It is not a security boundary
for hostile code. For untrusted code use a real sandbox such as a VM, gVisor
or bubblewrap with a locked-down filesystem. Specifically, these are **not**
protected:

- **The filesystem and everything else that isn't the network.** The command
  sees your whole filesystem (the mount namespace is a private copy, created only
  to hide sockets, not a different view) and runs as you. There is no PID
  namespace: your other processes are visible in `/proc` (their command lines
  are readable) and can be signalled (`kill -0` on a host process works). The
  kernel does refuse the command `/proc/PID/environ`, `cwd` and `exe` of those
  processes, and, with Yama's default `ptrace_scope=1`, `ptrace` attach (both
  checked on one host; don't rely on them: Yama can be set to 0). The IPC,
  UTS, cgroup and time namespaces are the host's: System V IPC and POSIX shared
  memory (`/dev/shm`) are shared with the host, and the hostname is the host's.
  There are no resource limits, and the seccomp filter is only the short list
  above, not a syscall sandbox.
- **Credentials, by design.** The command inherits your environment variables
  and can read the files you can: tokens, `~/.ssh` keys, cloud credentials. With
  no route out they can't be sent anywhere, but anything you open (`--port`,
  `--allow`, `--allow-socket`) is open to all of it. The SSH agent and gpg-agent
  sockets are hidden, not the key files.
- **Unix sockets that aren't on the default list.** Display servers (X11,
  Wayland), the accessibility bus, PulseAudio/PipeWire, a local proxy, and any
  other daemon reachable through a socket file stay reachable unless you
  `--hide-socket` them, and anything they can do for the command goes
  unchecked. (The reasoning for X11 and Wayland is in [the session
  section](#the-users-session-d-bus-systemd-snapd-agents).) Sockets that appear
  after the command starts aren't hidden either.
- **File descriptors the command inherits.** A socket that nullroute's parent
  opened before starting it (and left inheritable) belongs to the host's
  network namespace and keeps working inside the sandbox. Start nullroute from a
  shell or CI step that hasn't opened network connections for it.
- **Running nullroute as root.** The sandbox assumes an unprivileged user. As
  uid 0 the command is root inside its own namespaces, keeps its capabilities,
  and can unmount the socket decoys and masks (it still can't reach the host's
  network namespace). Don't run it as root (CI jobs normally don't need to).
- **What you let through.** Anything reachable through `--port`, `--allow`,
  `--allow-socket` and a Docker socket given to `--seal-docker` is reachable.
  Data can leave through those channels, including as host names in DNS
  lookups and registry requests (see [the Docker caveats](#letting-docker-tests-run-with-sealed-containers)).
- **The kernel.** User and network namespaces enlarge the kernel's attack
  surface, and a kernel bug can defeat them.

See [SECURITY.md](SECURITY.md) for how to report a way around the isolation.

## How it works

`nullroute` forks, and in the child, before running your command:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`: a new user namespace (so no root is
   needed) plus a new network namespace, which starts with only a loopback device.
2. Maps your real uid/gid into the user namespace, so tools don't think they're root.
3. Brings `lo` up (it starts down).
4. Sets `no_new_privs` and installs the seccomp filter (see above), after the
   last socket and ioctl that setup itself needs.
5. `exec`s your command. Run as an ordinary user (not root), it holds no
   capabilities after exec, so it can't add interfaces, change routes, or create
   another namespace to get out.

This is enforced by the kernel, not by environment variables or library hooks, so
it also covers raw sockets, UDP, subprocesses and statically linked binaries.

Socket hiding adds a mount namespace (`CLONE_NEWNS`): nullroute binds a Unix
listener in a private temp dir for each hidden socket, and the child, after
entering the new namespaces, makes all mounts private and bind-mounts each decoy
over its target path. Nothing changes on the host. The command can't undo it
(when nullroute isn't run as root): after exec it holds no capabilities, and
unmounting needs `CAP_SYS_ADMIN`.

`--port` works by having the child, once inside the new namespace, open a
listening socket on `127.0.0.1:PORT` (and `[::1]:PORT`) and hand it to the parent
over a Unix socketpair (`SCM_RIGHTS`) before running your command. A socket
stays in the namespace it was created in, so the parent, still on the host's
network, accepts connections on it and relays each one to the host's
`localhost:PORT`. Only the named ports are bridged, and only TCP.

The `--allow` proxy and the DNS sinkhole use the same handover. For the
sinkhole the child also binds `127.0.0.1:53` (UDP and TCP) and one listener per
synthetic address and allowed port (binding ports below 1024 works because the
child still holds its namespace capabilities at that point; the command doesn't
after exec), adds `127.77.0.1/24` to `lo` over rtnetlink, and bind-mounts the
generated `resolv.conf`. The resolver-socket masks (an empty mode-000 file
bind-mounted over each one) are applied in every sandbox, which is why even a
bare run usually gets a mount namespace. The parent answers the queries and
relays the connections on the host's network.

## Requirements

- **Linux only**, x86_64 and aarch64 (CI tests x86_64 and builds both; glibc or musl,
  so static musl builds work). On macOS, FreeBSD and other targets the
  build stops with a single "nullroute only supports Linux" error.
- **Unprivileged user namespaces must be enabled**, and mount namespaces are used
  for socket hiding and the DNS sinkhole. On Ubuntu 23.10+ AppArmor restricts
  user namespaces by default (`kernel.apparmor_restrict_unprivileged_userns=1`);
  nullroute prints a hint if namespace creation is refused. Containers and some
  hardened hosts (`user.max_user_namespaces=0`, a seccomp profile that blocks
  `unshare`) refuse them too; run nullroute as an ordinary user, not root.
- A kernel with `/proc/<pid>/task/<tid>/children` (`CONFIG_PROC_CHILDREN`,
  enabled on mainstream distributions) lets nullroute find and kill what the
  command leaves running; without it, leftovers aren't cleaned up.
- **Docker** (only for `--seal-docker`): a daemon reachable on a Unix socket.
- **Rust 1.88 or newer** to build from source.

## Troubleshooting

**`could not create an unprivileged user namespace` (exit 125).** nullroute needs
unprivileged user namespaces; the kernel or a security layer refused one. The
message names the usual causes:

- *Ubuntu 23.10 and later*: AppArmor restricts them
  (`sysctl kernel.apparmor_restrict_unprivileged_userns`). Fixing this needs an
  administrator: either lift the restriction or give the `nullroute` binary an
  AppArmor profile that allows `userns`.
- *Other distributions*: `sysctl user.max_user_namespaces` (0 disables them) or, on
  some Debian kernels, `kernel.unprivileged_userns_clone`.
- *Inside a container*: Docker's default seccomp profile blocks `unshare`, so
  `docker run debian /path/to/nullroute run -- true` fails with this message
  (checked); with `--security-opt seccomp=unconfined` it works. As root inside the
  container nullroute is [not a boundary](#what-nullroute-is-not), so also pass
  `--user UID:GID` (checked: works as uid 1000). Nested rootless Podman and
  Docker work when the outer environment allows user namespaces (not tested).
- *WSL*: WSL 2 works (this is where nullroute is developed). WSL 1 has no network
  namespaces.

**My command can't reach the network.** That is the point. Connecting to an IP
address fails with "Network is unreachable"; a name lookup fails with "Name or
service not known" and a `blocked DNS lookup of NAME` line. To let something
through, name it: `--allow api.example.com` for the internet, `--port 5432` for a
service on this machine's localhost. `nullroute run --inspect --dry-run -- true`
shows what a given set of flags sets up, and `--strict` turns any blocked attempt
into exit 1 even if the command swallowed the error.

**`Temporary failure in name resolution`.** Without `--no-dns` nullroute's
resolver answers every lookup (names that are not allowed get "Name or service
not known"), so this message means a lookup bypassed it: you passed `--no-dns`, or
the client talks to a hard-coded resolver (`dig @8.8.8.8`, DNS-over-HTTPS) that
has no route out. It is a message about the sandbox, not about the name.

**A connection to an allowed name is refused or closed.** Only the allowed ports
are relayed: without `:PORT`, 80 and 443. For a database use
`--allow db.example.com:5432`. An IP address in `--allow` works through the proxy
only, not for a direct `connect()`. A request whose `Host` header or TLS server
name names a different host than the one you connected to is refused (see
[What that doesn't stop](#letting-chosen-hosts-through---allow)).

**Exit code 1 (or 125): the command's or nullroute's?** Add `--report-json
report.json` and read `strict_failed` and `exit_code` ([docs/report-json.md](docs/report-json.md)):
`strict_failed: true` means the command succeeded and `--strict` failed the run.
`125`, `126` and `127` are nullroute's own when the message on stderr starts with
`nullroute:`.

**`docker` fails with `nullroute blocked access to /run/docker.sock`.** Container
sockets are hidden by default. Use `--seal-docker` (containers get no network) or
`--allow-socket /run/docker.sock` (they get full network access).

**A warning that an allowed address is private.** `--allow 10.0.0.5`, or a name that
resolves into RFC 1918, carrier-grade NAT or unique-local space, is reachable on
purpose; the warning is there in case that is a corporate name you did not mean to
open up. `-q` silences it.

## Examples

Turnkey, runnable examples are in [`examples/`](examples/):

- [`examples/01-python-test-leak`](examples/01-python-test-leak/): Catching unmocked external API calls in test suites and enforcing `--strict` in CI.
- [`examples/02-npm-postinstall-sandbox`](examples/02-npm-postinstall-sandbox/): Sandboxing untrusted package hooks with defense-in-depth Unix socket hygiene.
- [`examples/03-local-service-port`](examples/03-local-service-port/): Bridging host databases/containers via `--port` with bidirectional loopback isolation.
- [`examples/04-allowlist-surgical-bridge`](examples/04-allowlist-surgical-bridge/): Surgical egress allowlisting and breach reporting (`--report-json`).

Each example is self-contained and runs with `./run.sh`. With a built binary each takes about a second or less (0.1 to 0.6 s measured; the ones that use the public internet depend on your connection), and `NULLROUTE_EXAMPLES_OFFLINE=1` skips those steps.

## Development

```bash
cargo test --locked                          # integration tests run the real binary
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all
cargo check --locked --target x86_64-unknown-linux-musl   # CI also checks aarch64 musl/gnu
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full list of checks CI runs.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
