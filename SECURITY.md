# Security policy

## Supported versions

nullroute is pre-1.0 and hasn't had a release yet. Security fixes go into the
default branch and, once releases exist, into the latest release only.

| Version | Supported |
|---|---|
| latest release (once there is one) | yes |
| `master` | yes |
| anything older | no |

## Reporting a vulnerability

**Please don't open a public issue or pull request for a security problem.**

Report it privately with GitHub's private vulnerability reporting: open the
repository's **Security** tab, choose **Report a vulnerability**, and fill in the
form. Only the maintainer and you can see the report.

If that button isn't available, open an issue that says only that you have a
security report (no details) and ask for a private way to send it.

A useful report has: what you ran (the nullroute command line and the command
inside), what you expected, what happened instead, the nullroute version or
commit, and the kernel and distribution. A proof of concept that fits in a few
lines is ideal.

nullroute is a small project maintained on a best-effort basis. Expect an
acknowledgement within about a week; how long a fix takes depends on severity.
Reporters are credited in the changelog unless they'd rather not be.

## Threat model, in short

nullroute stops **accidental** network access by commands you run: tests that
call real services, build scripts that download things, libraries that phone
home. It does this with the kernel (a new user and network namespace with only a
loopback device) plus a few specific hardening steps (hidden Unix sockets,
`no_new_privs`, a small seccomp filter), not with environment variables or library
hooks. See the
[README](README.md#what-nullroute-is-not) for the full list of what is and isn't
protected.

**It is not a security boundary for hostile code.** The command still runs as
you, sees your filesystem, and shares your PID namespace; a malicious program is
expected to be able to do harm that nullroute doesn't try to prevent. For
untrusted code, use a VM, gVisor or bubblewrap with a locked-down filesystem.

### In scope

Ways for a command to reach the network or a host service that nullroute is
documented to deny, even if the command isn't malicious but merely clever or
buggy. For example:

- reaching the network (or the host's loopback) from inside the sandbox
  without `--port`, `--allow` or an explicitly permitted socket;
- getting past the `--allow` allowlist: a host that isn't allowed, the
  loopback, link-local and cloud-metadata destinations the proxy and DNS
  sinkhole refuse, or DNS lookups that leave the sandbox;
- getting past the default-hidden or masked Unix sockets: container runtimes
  (Docker, Podman, containerd, BuildKit, CRI-O, k3s, LXD, libvirt, Docker
  Desktop, Colima, Rancher Desktop, Lima, OrbStack), the system D-Bus, the
  session D-Bus, the systemd user manager, snapd, SSH and keyring agents
  (`$SSH_AUTH_SOCK`), gpg-agent and dirmngr, and systemd-resolved and nscd (the
  README lists the paths); a service that can be asked to act on the host's
  network from one of those is in scope, an unlisted one is a feature request;
- getting past the seccomp filter or `no_new_privs`: creating an `AF_VSOCK`,
  Bluetooth, NFC or QIPCRTR socket, `TIOCSTI`/`TIOCLINUX` on the controlling
  terminal, or io_uring, without `--no-seccomp`;
- under `--seal-docker`, getting a container, build, service or plugin a
  network, or running code in, starting or attaching to an existing container that
  has one without `--seal-docker-allow-existing`, or making the Docker daemon contact something that
  `--seal-docker-pulls` should have refused (the gaps documented in the README
  aren't bugs);
- the command outliving nullroute, or signals being lost at startup;
- memory-safety or parsing bugs in the proxy, the DNS sinkhole or the Docker
  API filter that an untrusted peer could trigger.

### Out of scope

- Anything that needs a hostile command to attack the host by other means than
  the network (filesystem access, other processes, kernel exploits).
- Limits documented in the README's "What nullroute is not" and in the Docker
  sections (for example inherited file descriptors, running as root,
  credentials the command inherits, display servers and other Unix sockets that
  aren't on the default list, signalling or inspecting your other processes
  (there is no PID namespace), shared IPC and `/dev/shm`, registry mirrors,
  remote logging drivers).
- Vulnerabilities in dependencies that don't affect nullroute (the build runs
  `cargo deny` against the RustSec advisory database, weekly).
