# Contributing

Thanks for looking at nullroute. Bug reports and pull requests are welcome. For
a security problem, please follow [SECURITY.md](SECURITY.md) instead of opening
a public issue.

## Building and testing

nullroute is Linux-only and needs Rust **1.88 or newer** (the MSRV, set as
`rust-version` in `Cargo.toml`).

```bash
cargo build --locked
cargo test --locked                                  # integration tests run the real binary
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo check --locked --target x86_64-unknown-linux-musl   # also: aarch64-unknown-linux-{musl,gnu}
cargo deny --all-features check                      # needs cargo-deny
cargo package --locked --list                        # what the crate would contain
```

The integration tests need:

- **Unprivileged user namespaces.** On Ubuntu 23.10+ AppArmor restricts them;
  CI runs `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
  Run the tests as an ordinary user, not root.
- **Docker with an `alpine` image** (`docker pull alpine`) for the
  `--seal-docker` tests. Without it they print a loud "SKIPPED ... did not
  test anything" banner and pass; set `NULLROUTE_REQUIRE_DOCKER=1` (CI does) to
  make that a failure. Each Docker test that runs prints
  `docker-test-ran: NAME`, and CI checks that all of them did.

To test an older toolchain: `cargo +1.88 test --locked`. CI also runs the suite
with `cargo test --release`; tests that need a debug-only hook
(`NULLROUTE_TEST_*`) are `#[ignore]`d there with a reason.

## What CI checks

Every pull request must pass (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

- `rustfmt` and `clippy` with warnings as errors;
- the test suite on stable, on the MSRV (1.88), on a `--release` build and on
  `x86_64-unknown-linux-musl`, with every Docker test required to have run;
- `cargo check` and `clippy` for the musl and aarch64 targets;
- that a non-Linux target fails with a single clear error;
- `cargo-deny` against `deny.toml` (RustSec advisories, licences, bans, sources).

Keep `Cargo.lock` committed and use `--locked`. New dependencies need to pass
`cargo deny`; licences outside the allow-list in `deny.toml` need a reason.
Third-party GitHub Actions are pinned to a full commit SHA with the tag in a
trailing comment; Dependabot proposes updates.

## Pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
  messages and PR titles (`fix(docker): ...`, `feat: ...`, `docs: ...`, `ci: ...`).
- Add or update tests for behaviour changes, and update the README when you
  change what the tool does or doesn't protect. Every claim there should match
  what the binary actually does.
- Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for
  user-visible changes.
- Anything that changes the sandbox's guarantees (what is blocked or let through)
  should say so explicitly in the description.

## Design notes

[`docs/design/`](docs/design/README.md) holds write-ups of open design questions (running as
root and inherited file descriptors, a PID namespace for the command, the exit-code policy), with the
evidence behind each recommendation. Read the relevant note before changing that area, and update it
when a proposal is implemented or rejected. They are not part of the published crate.

## Releasing (maintainer)

The release workflow (`.github/workflows/release.yml`) only **builds**: it runs
on a `v*` tag (or manually), checks the tag against `Cargo.toml`, runs the CI
checks, runs `cargo package` as a packaging check, and leaves the archives and
`SHA256SUMS` as artifacts of the workflow run. It has a read-only token, uses no
secrets, and publishes nothing. Publishing is done by hand:

1. Bump `version` in `Cargo.toml` and `Cargo.lock`; in `CHANGELOG.md`, move the
   `Unreleased` entries under a new `## [X.Y.Z] - YYYY-MM-DD` heading (the
   release workflow checks for it) and update the two link lines at the bottom.
   0.1.0 did this already.
2. Merge that to the default branch once CI is green.
3. Tag the merge commit `vX.Y.Z` and push the tag. Wait for the "Release build"
   run to go green.
4. Download the `release-assets-X.Y.Z` artifact, verify it
   (`sha256sum --check SHA256SUMS`), and smoke-test an archive.
5. Create the GitHub release from the tag and attach the archives and
   `SHA256SUMS`; run `cargo publish` from the same commit.
