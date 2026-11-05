# Releasing Zallet

This document describes how to cut a Zallet release. It is written for
maintainers with write access to `zcash/zallet`.

## Release model

Three packages ship in release lockstep under one version number:

| Package | Workspace | Audience |
|---|---|---|
| `zallet` (launcher) | Root | End users |
| `zallet-core` | Root | Backend implementors |
| `zallet-zebra` | `backends/zebra/` | Operators (Zebra backend) |

The workspaces each have their own `Cargo.lock`. The packages' dependencies MUST
be upgraded in lockstep, enforced by `utils/check-lockstep.sh` in CI. Use
`utils/bump-version.sh` (not hand-edits) to bump all three at once.

## Before you start

Run the full pre-flight suite across every workspace (root, then each
backend via `--manifest-path`):

```bash
# Format check
cargo fmt --all -- --check
cargo fmt --manifest-path backends/zebra/Cargo.toml -- --check

# Lint
cargo clippy --all-targets -- -D warnings
cargo clippy --manifest-path backends/zebra/Cargo.toml --all-targets -- -D warnings

# Test
cargo test
cargo test --manifest-path backends/zebra/Cargo.toml

# Verify lockstep
utils/check-lockstep.sh
```

Check `MIN_COMPATIBLE_ZALLET_VERSION` in
`zallet-core/src/components/database.rs`. Bump it only if this release changes
the wallet database format in a way older Zallet versions cannot read. Its
tests encode the current value; update them if you bump it.

## Bump the version

Always dry-run first to review the diff:

```bash
utils/bump-version.sh <version> --dry-run
```

Then apply with a real date (use `--date today` so the changelog heading ships
with the release date, not the `PLANNED` placeholder):

```bash
utils/bump-version.sh <version> --date today
```

The script updates:

- The three `Cargo.toml` manifests (`zallet`, `zallet-core`,
  `backends/zebra/Cargo.toml`).
- trycmd fixtures (`as_of_version` fields) in `backends/*/tests`.
- Book and README prose naming the current release version.
- All three CHANGELOGs: promotes `## [Unreleased]` to
  `## [<version>] - <date>` and leaves a fresh empty `## [Unreleased]` heading.
- Every workspace lockfile, via `utils/sync-lockfiles.sh` (which also runs
  `check-lockstep.sh`).

### Phase changes (alpha to beta, beta to stable)

The script detects a release phase change and warns, but does not automate it.
A phase change renames user-facing CLI flags (`--this-is-<phase>-code-...`),
their clap fields, Fluent terms and message ids, test fixtures, CI invocations,
and the "Current phase" sections of `README.md` and `book/src/README.md`.
Historical references (past CHANGELOG headings, `MIN_COMPATIBLE_ZALLET_VERSION`)
are left intact. See commit `bf1917e` for the alpha-to-beta precedent.

## Review the changelogs

Three changelog files, routed by audience:

| File | Documents | Audience |
|---|---|---|
| `CHANGELOG.md` | JSON-RPC methods, CLI, config, wallet DB format, release artifacts | People who run Zallet |
| `zallet-core/CHANGELOG.md` | `zallet-core` public Rust API | Backend implementors |
| `backends/zebra/CHANGELOG.md` | `zallet-zebra` binary | Operators (Zebra backend) |

Rules (see `AGENTS.md` for the full guide):

- Route an entry by who needs to read it, not by which crate the diff touched.
- Entries MUST NOT describe implementation details, internal refactors, or
  test-fixture reworks. Documentation-only changes do not get entries.
- A change serving two audiences goes in both files, written differently.
- The `## [Unreleased]` heading is permanent and stays at the top of every file,
  even when empty following a release.
- All three packages ship in lockstep, so every release heading appears in every
  file. A component with no changes for its audience gets an empty section.

## cargo vet

If the lockfile regeneration pulled in new transitive dependencies, run
`cargo vet` in each workspace:

```bash
cargo vet
cargo vet --manifest-path backends/zebra/Cargo.toml
```

Add `[[exemptions.*]]` or `[[trusted.*]]` entries to `supply-chain/config.toml`
(and the per-backend `supply-chain/config.toml` files) as needed. Run
`cargo vet fmt` before `cargo vet --locked` when trusted entries span workspaces
with different dependency graphs.

## Commit and open the release PR

```bash
git checkout -b release/v<version>
git add -A
git commit -m "Release zallet version <version>"
git push origin release/v<version>
```

Open a PR from `zcash:release/v<version>`. Maintainer releases bypass the
`AGENTS.md` contribution gate (the gate is for external contributors without
write access). Link the PR description to the release tracking issue showing all
prerequisites are done.

This project uses a merge-based workflow. PRs are merged with merge commits
(not squash or rebase-merge).

## Merge and tag

After the PR is approved and CI is green:

```bash
git checkout main
git pull
git tag v<version>
git push origin main --tags
```

The tag push triggers `.github/workflows/release.yml`, which builds and
publishes all release artifacts automatically.

If a release pipeline run fails transiently, re-run it without re-tagging:

```bash
gh workflow run release.yml -f tag=v<version>
```

## Automated release pipeline

Triggered by the `v*.*.*` tag push, `release.yml` runs:

1. **set_env** — validates the tag is semver, sets the platform list (amd64 via
   StageX, arm64 via Nix) and APT distribution targets (bullseye, bookworm).
2. **container** — builds the amd64 runtime image via StageX (full-source
   bootstrapped), pushes to `docker.io/zodlinc/zallet` by digest.
3. **container_arm64** — builds the arm64 runtime via Nix (rebuild-reproducible,
   since StageX's seed is x86-only), pushes by digest.
4. **manifest** — stitches both arches into a multi-arch OCI index, tags
   `latest` + `v<version>` + commit SHA, and attests SLSA provenance on the
   final index digest.
5. **binaries_deb_release** (matrix: amd64 + arm64) — extracts the two binaries
   (`zallet`, `zallet-zebra`) from the image, smoke-tests each
   (`zallet -h` in a Debian container), builds a standalone tarball per arch,
   builds a `.deb` per arch (via `cargo deb --no-build`), GPG-signs each
   artifact (`sysadmin@zodl.com`), generates SPDX SBOMs and build-provenance
   attestations, and uploads everything as release artifacts.
6. **apt_publish** — regenerates the APT index from the `.deb` pool with
   `aptly`, publishes to the `apt.z.cash` S3 bucket (bullseye + bookworm,
   both architectures in one consistent index).
7. **publish** — creates or updates the GitHub Release with auto-generated
   notes and all artifacts (tarballs, `.deb`s, signatures, SBOMs, attestation
   bundles).

The pipeline requires these secrets (configured in the repo or via OIDC):

- `ZODLINC_DOCKERHUB_USERNAME` / `ZODLINC_DOCKERHUB_PASSWORD` — Docker Hub push.
- `AWS_ROLE_ARN` / `AWS_APT_BUCKET` — APT index publishing to S3.
- `/release/gpg-signing-key` (AWS Secrets Manager) — GPG signing key for
  tarballs and `.deb`s.

## Post-release verification

After the pipeline completes:

1. **GitHub Release** — verify it exists at
   `https://github.com/zcash/zallet/releases/tag/v<version>` with all expected
   assets: two tarballs (amd64 + arm64), two `.deb`s, and their corresponding
   `.asc` signatures, `.sbom.spdx` files, `.intoto.jsonl` attestation bundles,
   and `.provenance.json` metadata.
2. **Docker Hub** — verify `docker.io/zodlinc/zallet:v<version>` is a multi-arch
   manifest (both `linux/amd64` and `linux/arm64`).
3. **APT repository** — verify `apt.z.cash` serves the new `.deb` in its
   bullseye and bookworm indices.
4. **Trackers** — update any release tracking issues (dagny, GitHub, beads) to
   reflect that the release has shipped.
