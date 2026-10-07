# nullroute

Run a command with outbound network access sealed off. Language-agnostic: it
works the same for `pytest`, `go test`, `cargo test`, `npm test` or any binary,
with no code changes, fixtures or monkeypatching.

```bash
nullroute run -- pytest -x
nullroute run -- go test ./...
nullroute run --port 5432,6379 -- pytest   # local Postgres + Redis still reachable
```

Inside, the command has a loopback interface and nothing else. Connecting to any
other host fails immediately with "network unreachable", and DNS lookups fail.
The exit code is passed through, so it drops into CI unchanged.

## Reaching local services: `--port`

The sandbox has its own loopback, so a database on your machine's
`127.0.0.1:5432` is invisible inside by default. `--port 5432` bridges exactly
that port: inside, `localhost:5432` (IPv4 or IPv6) reaches the host's
`localhost:5432`. Repeat the flag or comma-separate: `--port 5432 --port 6379`,
`--port 5432,6379`. This covers Docker containers published on the host
(`-p 127.0.0.1:5432:5432`).

If nothing is listening on the host, the connection is closed and nullroute warns
once per port.

## Letting chosen hosts through: `--allow`

```bash
nullroute run --allow api.github.com,*.stripe.dev -- pytest
```

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

**Only proxy-aware clients can use the allowlist.** curl, wget, git, pip, Python
`urllib`/`requests`/`httpx`, Go's `net/http` and Node 24's `fetch` (nullroute
sets `NODE_USE_ENV_PROXY=1`) all honour the variables; curl, Python `urllib`, git
and Node `fetch` are tested. Anything that ignores them (raw sockets, most
database drivers, `curl --noproxy '*'`) hits the sealed network and fails with
"network unreachable". The failure mode is closed, never open.

Other details:

- `NO_PROXY=localhost,127.0.0.1,::1`, so `--port` services are reached directly.
- Host names are resolved on the host. A name that resolves to a loopback
  address is refused even if allowed (use `--port` for local services).
- Plain-HTTP requests are sent with `Connection: close`: one request per
  proxied connection.
- The proxy listens on `127.0.0.1:3128` inside the sandbox (or the next port
  that isn't a `--port`). An existing `HTTP(S)_PROXY` is overridden; chaining to
  a corporate upstream proxy isn't supported yet.

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

Counts are connections, so one `docker ps` can count several times (the Docker
CLI reconnects).

| Flag | Effect |
|---|---|
| `--strict` | Exit 1 if anything was blocked, even if the command succeeded. Catches tests that swallow network errors. A command that already failed keeps its own exit code. |
| `-q`, `--quiet` | Skip the live lines; keep the summary. |
| `--report-json FILE` | Write the report as JSON for CI artifacts (always written, `"blocked": []` when clean). |

Not listed: a direct connection to an IP address fails inside the kernel
("network unreachable") without reaching nullroute. Proxy requests and hidden
sockets are listed.

**Signals.** Ctrl-C reaches the command as usual; nullroute itself ignores
SIGINT/SIGQUIT so it can still print the report, then exits with the command's
status (130). SIGTERM and SIGHUP sent to nullroute are forwarded to the command.

## Seeing the sandbox: `--inspect`

`--inspect` prints the sandbox topology to stderr before the command starts,
then runs the command as usual (stdout and the exit code are untouched):

```text
$ nullroute run --inspect --seal-docker --port 5432 --allow api.github.com -- pytest
nullroute: inspect: sandbox topology
  namespaces:      user, net, mount
  loopback:        lo: UP (127.0.0.1, ::1)
  bridged ports:   5432
  unix sockets:
    blocked (403 decoy):
      /run/containerd/containerd.sock
    sealed (--seal-docker proxy):
      /run/docker.sock
  upstream proxy:  http://127.0.0.1:3128 (allow: api.github.com)
...test output...
```

| Line | Meaning |
|---|---|
| `namespaces` | Linux namespaces the command gets: always `user` and `net`; `mount` only when a socket is hidden or sealed. |
| `loopback` | The sandbox's own `lo`, brought up before the command runs. |
| `bridged ports` | `--port` values (sorted, deduplicated), or `none`. |
| `blocked (403 decoy)` | Sockets replaced by a decoy that answers `403` (defaults + `--hide-socket`, minus `--allow-socket`). |
| `sealed (--seal-docker proxy)` | Docker sockets proxied with containers forced to `NetworkMode=none`. |
| `upstream proxy` | Where the `--allow` proxy listens inside the sandbox, and the allowed hosts, or `none`. |

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

| Flag | Effect |
|---|---|
| `--allow-socket PATH` | Keep a default-hidden socket reachable (repeatable). |
| `--hide-socket PATH` | Hide another socket too, e.g. an SSH agent or a local proxy (repeatable). |
| `--dry-run` | Print the sockets that would be hidden and the ports forwarded, then exit. |
| `--inspect` | Print the full sandbox topology to stderr before running (see above). |

### Letting Docker tests run, with sealed containers

`--seal-docker` is the middle ground between hiding docker.sock (the command
can't use Docker) and `--allow-socket` (it can, and its containers get full
network). The command uses Docker normally, but nullroute rewrites each
container-create request to `NetworkMode: none` and refuses `network connect`:

```bash
nullroute run --seal-docker -- pytest        # tests may start containers; none get network
nullroute run --seal-docker-socket /custom/docker.sock -- ...   # non-standard path
```

The sealed container still runs and can mount volumes, but it has no network at
all: not the internet, not other containers, and not the host's `--port`
services. `docker build` works. A
requested `--network` (including `host`) is overridden to `none`.

**This is not a Docker security boundary.** It stops the ordinary ways a
container gets a network through the CLI; it does not cover every Docker API
path, and a `--privileged` container can still escape. It's "CI containers
shouldn't phone home", not "run hostile images safely". containerd and BuildKit
sockets speak a different protocol and are still hidden (not sealed) by default.

## Status: v0.7, Linux only

| | |
|---|---|
| Hermetic mode (no network but the sandbox's own loopback) | ✅ |
| No root needed | ✅ (unprivileged user namespaces) |
| Runs as you, not as root inside | ✅ |
| Exit code / signal passthrough | ✅ (`128+N` for signals, `125` if nullroute itself fails) |
| Reach chosen services on the host's localhost (`--port`) | ✅ TCP, IPv4 + IPv6 |
| Reach a Docker container by its container IP | ❌ (publish it on localhost and use `--port`) |
| Hide Unix-socket escapes (`docker.sock` etc.) | ✅ on by default for container runtimes |
| Sandbox containers the command starts (`--seal-docker`) | ✅ forced to `NetworkMode=none`; not a boundary for hostile images |
| Allowlist (`--allow api.github.com,*.stripe.dev`) | ✅ HTTP(S) via proxy; other protocols stay sealed |
| Report what was blocked (+ `--strict`, `--report-json`) | ✅ proxy and socket blocks; not direct IP connects |
| Show the sandbox topology (`--inspect`) | ✅ namespaces, loopback, ports, sockets, proxy |
| macOS | ❌ no network namespaces; needs a different mechanism |

### What nullroute is not

nullroute stops **accidental** network access. It is not a security boundary
for hostile code. The command still sees your whole filesystem and runs as you,
and only the sockets listed above are hidden by default: other local daemons
with a Unix socket (D-Bus, an SSH agent, a local proxy) stay reachable unless you
`--hide-socket` them. For untrusted code use a real sandbox such as a VM, gVisor
or bubblewrap with a locked-down filesystem.

## How it works

`nullroute` forks, and in the child, before running your command:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`: a new user namespace (so no root is
   needed) plus a new network namespace, which starts with only a loopback device.
2. Maps your real uid/gid into the user namespace, so tools don't think they're root.
3. Brings `lo` up (it starts down).
4. `exec`s your command. It holds no capabilities after exec, so it can't add
   interfaces, change routes, or create another namespace to get out.

This is enforced by the kernel, not by environment variables or library hooks, so
it also covers raw sockets, UDP, subprocesses and statically linked binaries.

Socket hiding adds a mount namespace (`CLONE_NEWNS`): nullroute binds a Unix
listener in a private temp dir for each hidden socket, and the child, after
entering the new namespaces, makes all mounts private and bind-mounts each decoy
over its target path. Nothing changes on the host. The command can't undo it:
after exec it holds no capabilities, and unmounting needs `CAP_SYS_ADMIN`.

`--port` works by having the child, once inside the new namespace, open a
listening socket on `127.0.0.1:PORT` (and `[::1]:PORT`) and hand it to the parent
over a Unix socketpair (`SCM_RIGHTS`) before running your command. A socket
stays in the namespace it was created in, so the parent, still on the host's
network, accepts connections on it and relays each one to the host's
`localhost:PORT`. Only the named ports are bridged, and only TCP.

## Requirements

Unprivileged user namespaces must be enabled. On Ubuntu 23.10+ AppArmor restricts
them by default (`kernel.apparmor_restrict_unprivileged_userns=1`); nullroute prints a
hint if namespace creation is refused.

## Development

```bash
cargo test                                   # integration tests run the real binary
cargo clippy --all-targets -- -D warnings
cargo fmt
```
