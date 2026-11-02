# Platform support

Zallet's support for a platform is expressed as a **tier**. The tier states what the
project promises for that platform: what is built and tested in CI, what is shipped as
a release artifact, and how bug reports and security findings affecting only that
platform are prioritized during triage.

The tiers follow the same shape as the [Rust project's platform support
tiers](https://doc.rust-lang.org/rustc/platform-support.html): Tier 1 is "guaranteed
to work", Tier 2 is "guaranteed to build and pass tests", and Tier 3 is "may work,
best effort".

## Tier 1 — guaranteed to work (release artifacts)

Every release ships signed, attested, reproducibly-built artifacts for these
platforms, and the release pipeline smoke-tests the binaries before publishing. A
regression on a Tier 1 platform blocks the release. Security findings are triaged at
full severity.

| Target | Build toolchain | Release artifacts |
|--------|-----------------|-------------------|
| `x86_64-unknown-linux-musl` | [StageX](https://codeberg.org/stagex/stagex/) (full-source bootstrapped; static) | standalone tarball, Debian packages, Docker image (`linux/amd64`) |
| `aarch64-unknown-linux-musl` | Nix (pinned flake; static) | standalone tarball, Debian packages, Docker image (`linux/arm64`) |

Artifact details:

- **Standalone binaries** — static musl builds of `zallet` and `zallet-zebra`,
  packaged as tarballs, GPG-signed, with SLSA provenance
  attestations. Because they are fully static they run on any Linux distribution;
  see [Supply Chain Security (SLSA)](../slsa/slsa.md) for the reproducibility model
  and verification commands.
- **Debian packages** — published to the project APT repository for Debian
  `bullseye` and `bookworm` (and their Ubuntu contemporaries); the release pipeline
  smoke-tests the packaged binaries in a `bookworm` container on both
  architectures. See [Debian packages](installation/debian.md).
- **Docker images** — a multi-arch (`linux/amd64`, `linux/arm64`) manifest on
  Docker Hub. See [Docker](installation/docker.md).

Building from source on a mainstream glibc Linux distribution is equally supported:
CI builds and runs the full test suite on x86_64 glibc Linux, using the Rust
toolchain pinned in `rust-toolchain.toml`.

The `zebra` chain backend (Linux-only, reads a co-located `zebrad`'s state database)
is supported on Tier 1 platforms. See [Choosing a chain
backend](installation/README.md#choosing-a-chain-backend).

## Tier 2 — guaranteed to build and pass tests: macOS

CI builds the shared wallet library (`zallet-core`) and the `zallet` launcher and
runs their full unit-test suite on macOS for every PR, and a failure blocks merging.
The Zallet developers use macOS day to day, so problems are found and fixed promptly.
However:

- **No chain backend currently runs on macOS.** The `zebra` backend is Linux-only,
  so Zallet cannot sync a wallet on macOS.
- No release artifacts are published.
- CI covers Apple silicon (`aarch64-apple-darwin`, the architecture of the
  `macOS-latest` runners). Intel macOS (`x86_64-apple-darwin`) is expected to work
  but is not exercised by CI.

Security findings that only manifest on macOS are triaged and fixed, ordered behind
comparable Tier 1 findings.

## Tier 3 — best effort: Windows

Windows (`x86_64-pc-windows-msvc`) currently **builds the shared wallet library and
the launcher and passes their unit-test suite in CI**, but the project makes no
further commitment:

- No release artifacts are published, and no packaging or installation path is
  documented or supported.
- No chain backend currently runs on Windows (the `zebra` backend is Linux-only).
- Platform-specific hardening lags Unix. Zallet's file-permission protections
  (data directory, wallet database, encryption identity) are implemented with Unix
  modes; their Windows ACL equivalents are being added finding-by-finding rather
  than systematically. Running Zallet on Windows today assumes the data directory
  is in a location other local users cannot read.
- Windows-only findings are triaged as best effort: tracked, severity-assessed with
  the platform preconditions taken into account, and fixed as capacity allows.

## Everything else

Platforms not listed above (other BSDs, other architectures, `x86_64-pc-windows-gnu`,
Android, iOS, …) are unsupported. Zallet may or may not compile there; issues that
reproduce only on unlisted platforms may be closed as out of scope. Proposals to add
a platform should come with a plan for CI coverage, which is the minimum bar for
Tier 3 listing.

## What a tier promises

| | Tier 1 | Tier 2 (macOS) | Tier 3 (Windows) |
|---|:---:|:---:|:---:|
| CI builds and runs tests on every PR | ✓ | ✓ | ✓ |
| Regression blocks release | ✓ | ✓ | — |
| Release artifacts (signed, attested) | ✓ | — | — |
| Documented installation path | ✓ | source build | — |
| Systematic platform hardening | ✓ | ✓ (shares Unix code paths) | — |
| Security findings triaged at full priority | ✓ | ordered behind Tier 1 | best effort |
