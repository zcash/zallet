# Supply Chain Security (SLSA)

Zallet’s release automation is designed to satisfy the latest [SLSA v1.0](https://slsa.dev/spec/v1.0) “Build L3” expectations: every artifact is produced on GitHub Actions with an auditable workflow identity, emits a provenance statement, and is reproducible. This page documents how the workflows operate and provides the exact commands required to validate the resulting images, binaries, attestations, and repository metadata.

> **Per-architecture reproducibility model.** The release is multi-arch, and the two architectures are built by **different** reproducible toolchains — a deliberate, documented asymmetry:
>
> - **`linux/amd64`** is built with the [StageX](https://codeberg.org/stagex/stagex/) full-source-bootstrapped toolchain. StageX bootstraps the entire compiler chain from a tiny (~512-byte), hand-auditable `hex0` seed, so it additionally addresses the *trusting-trust* problem. This is the highest-assurance tier.
> - **`linux/arm64`** is built with **Nix** (pinned flake: `nixpkgs` rev + `crane` + exact `rustc`), producing a static `aarch64-unknown-linux-musl` binary. StageX cannot target arm64 today — its `stage0` bootstrap seed is x86-only — so arm64 uses Nix instead. Nix gives **rebuild-reproducibility** (identical pinned inputs → byte-identical output, verifiable with `diffoscope`), but its toolchain traces back to a pre-built binary bootstrap seed, so it does **not** by itself close trusting-trust.
>
> Both arches are therefore reproducible in the build-twice sense; only amd64 is bootstrap-grade. This page notes where the two paths differ.

## Release architecture overview

### Workflows triggered on a `vX.Y.Z` tag

- **`.github/workflows/release.yml`** orchestrates the full release. It computes metadata (`set_env`), builds the StageX-based **amd64** image (`container` job), builds the Nix-based **arm64** runtime (`container_arm64` job), stitches both into a single multi-arch image (`manifest` job), and fans out to the binaries-and-Debian job (`binaries_release`) before publishing all deliverables on the tagged GitHub Release.
- **`.github/workflows/build-and-push-docker-hub.yaml`** builds the **amd64** OCI image deterministically with StageX, exports the runtime artifact, **pushes by digest** (no tags) to Docker Hub, signs the digest with Cosign (keyless OIDC), uploads the SBOM, and generates provenance via `actions/attest-build-provenance`.
- **`.github/workflows/build-arm64-nix.yml`** builds the **arm64** static-musl binary with Nix on a native `ubuntu-24.04-arm` runner (reading the `zodl-nix-cache` S3 binary cache so the musl toolchain is downloaded, not recompiled), lays it out in the same `export`-stage layout, pushes the arm64 image variant by digest, and appends the arm64 runtime to the shared artifact.
- **`manifest` job (in `release.yml`)** assembles the amd64 + arm64 per-arch digests into one multi-arch OCI index per tag with `docker buildx imagetools create`, then re-attests SLSA provenance on the final index digest. Pushing each arch by digest keeps tags atomic (a tag never exists as single-arch).
- **`.github/workflows/binaries-and-deb-release.yml`** consumes the exported binaries (both arches), performs smoke tests inside Debian containers, emits standalone binaries plus `.deb` packages, GPG-signs everything with the Zcash release key (decrypted from AWS Secrets Manager `/release/gpg-signing-key`), generates SPDX SBOMs, and attaches `intoto.jsonl` attestations. A single downstream **`apt_publish` job** ingests every arch's `.deb` and publishes ONE merged, signed APT index (`-architectures=amd64,arm64`) with a single S3 sync — avoiding the parallel-matrix race that would otherwise leave the published `dists/` index listing only one architecture.
- **Reproducible builds** are invoked before/within these workflows: **amd64** via StageX (`make build`/`utils/build.sh`, Dockerfile `export` stage); **arm64** via the `flake.nix` `#zallet` output. Both emit the exact binaries consumed later, so images, standalone binaries, and Debian packages share the same reproducible artifacts per architecture.

### Deliverables and metadata per release

| Artifact | Where it ships | Integrity evidence |
| --- | --- | --- |
| Multi-arch OCI image (`docker.io/zodlinc/zallet`) | Docker Hub | Cosign signature, Rekor entry, auto-pushed SLSA provenance, SBOM |
| Exported runtime bundle | GitHub Actions artifact (`zallet-runtime-oci-*`) | Detached from release, referenced for auditing |
| Standalone binaries (`zallet-${VERSION}-linux-{amd64,arm64}`) | GitHub Release assets | GPG `.asc`, SPDX SBOM, `intoto.jsonl` provenance |
| Debian packages (`zallet_${VERSION}_{amd64,arm64}.deb`) | GitHub Release assets + apt.z.cash | GPG `.asc`, SPDX SBOM, `intoto.jsonl` provenance |
| APT repository | Uploaded to apt.z.cash | APT `Release.gpg`, package `.asc`, cosigned source artifacts |

## Targeted SLSA guarantees

- **Builder identity:** GitHub Actions workflows run with `permissions: id-token: write`, enabling keyless Sigstore certificates bound to the workflow path (`https://github.com/zcash/zallet/.github/workflows/<workflow>.yml@refs/tags/vX.Y.Z`).
- **Provenance predicate:** `actions/attest-build-provenance@v3` emits [`https://slsa.dev/provenance/v1`](https://slsa.dev/provenance/v1) predicates for every OCI image (including the final multi-arch index), standalone binary, and `.deb`. Each predicate captures the git tag, commit SHA, build arguments, and resolved platform.
- **Reproducibility (amd64):** StageX enforces a full-source-bootstrapped deterministic build. Re-running `make build` in a clean tree produces a bit-identical image whose digest matches the published amd64 digest. This is bootstrap-grade — the toolchain itself is built from a hand-auditable seed.
- **Reproducibility (arm64):** the Nix build is rebuild-reproducible: `nix build .#zallet` from the pinned `flake.lock` (same `nixpkgs` rev + `crane` + `rustc`) produces a byte-identical `aarch64-unknown-linux-musl` binary, verifiable by building twice and comparing with `diffoscope`. It is **not** bootstrap-grade — Nix's toolchain derives from a pre-built binary bootstrap seed — so arm64 closes "did the published binary come from this source" but not the deeper trusting-trust question that StageX's amd64 path does. Note also that Nix gives determinism *by sandbox enforcement*, not by proof: an impure `build.rs` can still break it (e.g. `zaino-state`'s `build.rs` shells out to `git`), which is why the arm64 result is **verified** by a build-twice diff rather than assumed.
- **GPG signing key:** standalone binaries, `.deb` packages, and the APT `Release.gpg` are signed **only** with the ZODL release key (`sysadmin@zodl.com`, fetched from AWS Secrets Manager `/release/gpg-signing-key`). This is intentional: it does **not** dual-sign with the legacy ECC key (`sysadmin@z.cash`). The older `apt.z.cash` pipeline dual-signed (ECC + ZODL) during the key-transition window so users with either key in their keyring could verify; the ECC key's planned revocation is mid-2026, after which ZODL-only is the steady state. Users verify against the ZODL public key published at `https://apt.z.cash/zcash.asc`.

## Building Zallet yourself

The supply-chain machinery above governs **the artifacts we publish** — it does not constrain how *you* build Zallet. There are three tiers, ordered by assurance vs. convenience; pick whichever fits your needs. None of them is a prerequisite for the others.

| Tier | Command | Arch | Output | Guarantee |
| --- | --- | --- | --- | --- |
| **1. Cargo** (developer) | `cargo build --release --bin zallet --features rpc-cli,zcashd-import` | host arch | local binary | none beyond Cargo's lockfile |
| **2. Docker** (standard) | `docker buildx build --platform linux/amd64,linux/arm64 -t zallet .` | amd64 + arm64 | container image | rebuild-reproducible (digest-pinned bases, SOURCE_DATE_EPOCH) |
| **3a. Nix** (reproducible) | `nix build .#zallet` | amd64 **or** arm64 (native) | static-musl binary | bit-for-bit reproducible |
| **3b. StageX** (bootstrap-grade) | the `Dockerfile.stagex` build the CI runs | amd64 | static-musl image | full-source-bootstrapped + reproducible |

### Tier 1 — plain Cargo

Nothing special: `cargo build`/`cargo install` work as in any Rust project. This is the right path for local development and is unaffected by any of the release tooling.

### Tier 2 — the standard `Dockerfile` (multi-arch, "build it yourself")

The repository's default `Dockerfile` is a plain, multi-stage build on official `rust` + `debian-slim` images. It honours Docker's `$TARGETARCH`, so a single command builds **both** architectures (including on Apple Silicon):

```bash
docker build -t zallet .                                   # host arch
docker buildx build --platform linux/amd64,linux/arm64 .   # both
```

This image is **rebuild-reproducible**: the `rust` and `debian` bases are digest-pinned, `SOURCE_DATE_EPOCH` (passed from the commit time) drives all build timestamps, absolute build paths are remapped out of the binary, and the apt/ldconfig caches are dropped. Two builds of the same commit with the same base digests produce the same bytes — verify by building twice and comparing, or with `--output type=image,rewrite-timestamp=true`. It does **not** bootstrap its toolchain (it pins a prebuilt `rust` + `debian`, like most reproducible-build setups), so it is not bootstrap-grade the way tier 3b (StageX, amd64) is — use tier 3 to reproduce the exact published release artifact.

### Tier 3a — Nix (reproducible, both arches)

The `flake.nix` exposes a `zallet` package for both `x86_64-linux` and `aarch64-linux`, each producing a **static-musl, bit-for-bit reproducible** binary on a native host of that architecture:

```bash
# Install Nix (Determinate installer), then:
nix build github:zcash/zallet#zallet      # builds for the host arch
./result/bin/zallet --version

# Verify reproducibility (rebuilds and compares):
nix build github:zcash/zallet#zallet --rebuild
```

For **arm64**, this is the easiest reproducible path by far — on an arm64 machine it is just "install Nix + `nix build`", with no Docker, no containerd image store, and no pinned base images. (Producing an arm64 binary *from* an x86 host requires cross-compilation or emulation, which is no longer a two-command flow; the simple path assumes you are on the target architecture.)

### Tier 3b — StageX (`Dockerfile.stagex`, bootstrap-grade, amd64)

`Dockerfile.stagex` is the full-source-bootstrapped amd64 build the release pipeline uses to publish the amd64 image. It is the highest-assurance tier (it additionally addresses trusting-trust) and requires Docker 26+ with the containerd image store enabled. See the architecture overview above for why amd64 uses StageX and arm64 uses Nix.

## Verification playbook

The following sections cover every command required to validate a tagged release end-to-end (similar to [Argo CD’s signed release process](https://argo-cd.readthedocs.io/en/stable/operator-manual/signed-release-assets/), but tailored to the Zallet workflows and the SLSA v1.0 predicate).

### Tooling prerequisites

- `cosign` ≥ 2.1 (Sigstore verification + SBOM downloads)
- `rekor-cli` ≥ 1.2 (transparency log inspection)
- `crane` or `skopeo` (digest lookup)
- `oras` (optional SBOM pull)
- `gh` CLI (or `curl`) for release assets
- `jq`, `coreutils` (`sha256sum`)
- `gnupg`, `gpgv`, and optionally `dpkg-sig`
- Docker 25+ with containerd snapshotter (matches the CI setup) for deterministic rebuilds

Example installation on Debian/Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y jq gnupg coreutils
go install -v github.com/sigstore/rekor/cmd/rekor-cli@latest
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
go install github.com/google/go-containerregistry/cmd/crane@latest
export PATH="$PATH:$HOME/go/bin"
```

### Environment bootstrap

```bash
export VERSION=v1.2.3
export REPO=zcash/zallet
export IMAGE=docker.io/zodlinc/zallet
export IMAGE_WORKFLOW="https://github.com/${REPO}/.github/workflows/build-and-push-docker-hub.yaml@refs/tags/${VERSION}"
export BIN_WORKFLOW="https://github.com/${REPO}/.github/workflows/binaries-and-deb-release.yml@refs/tags/${VERSION}"
export OIDC_ISSUER="https://token.actions.githubusercontent.com"
export IMAGE_PLATFORMS="linux/amd64,linux/arm64"             # multi-arch: amd64 via StageX, arm64 via Nix
export BINARY_SUFFIXES="linux-amd64,linux-arm64"             # both suffixes ship per release
export DEB_ARCHES="amd64,arm64"                              # both .deb architectures ship per release
export BIN_SIGNER_WORKFLOW="github.com/${REPO}/.github/workflows/binaries-and-deb-release.yml@refs/tags/${VERSION}"
mkdir -p verify/dist
export PATH="$PATH:$HOME/go/bin"

# Tip: running the commands below inside `bash <<'EOF' … EOF` helps keep failures isolated,
# but the snippets now return with `false` so an outer shell stays alive even without it.

# Double-check that `${IMAGE}` points to the exact repository printed by the release workflow
# (e.g. `docker.io/zodlinc/zallet`). If the namespace is wrong, `cosign download`
# will look at a different repository and report "no signatures associated" even though the
# tagged digest was signed under the real namespace.
```

### 1. Validate the git tag

```bash
git fetch origin --tags
git checkout "${VERSION}"
git verify-tag "${VERSION}"
git rev-parse HEAD
```

Confirm that the commit printed by `git rev-parse` matches the `subject.digest.gitCommit` recorded in every provenance file (see section **6**).

### 2. Verify the OCI image pushed to Docker Hub

```bash
export IMAGE_DIGEST=$(crane digest "${IMAGE}:${VERSION}")
cosign verify \
  --certificate-identity "${IMAGE_WORKFLOW}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  --output json \
  "${IMAGE}@${IMAGE_DIGEST}" | tee verify/dist/image-cosign.json

cosign verify-attestation \
  --type https://slsa.dev/provenance/v1 \
  --certificate-identity "${IMAGE_WORKFLOW}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  --output json \
  "${IMAGE}@${IMAGE_DIGEST}" | tee verify/dist/image-attestation.json

jq -r '.payload' \
  verify/dist/image-attestation.json | base64 -d \
  > verify/dist/zallet-${VERSION}-image.slsa.intoto.jsonl

for platform in ${IMAGE_PLATFORMS//,/ }; do
  platform="$(echo "${platform}" | xargs)"
  [ -z "${platform}" ] && continue
  platform_tag="${platform//\//-}"
  cosign verify-attestation \
    --type spdxjson \
    --certificate-identity "${IMAGE_WORKFLOW}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    --output json \
    "${IMAGE}@${IMAGE_DIGEST}" | tee "verify/dist/image-sbom-${platform_tag}.json"

  jq -r '.payload' \
    "verify/dist/image-sbom-${platform_tag}.json" | base64 -d \
    > "verify/dist/zallet-${VERSION}-image-${platform_tag}.sbom.spdx.json"
done

# Docker Hub does not store Sigstore transparency bundles alongside signatures,
# so the Cosign JSON output typically does NOT contain Bundle.Payload.logIndex.
# Instead, we recover the Rekor entry by searching for the image digest.

digest_no_prefix="${IMAGE_DIGEST#sha256:}"

rekor_uuid="$(
  rekor-cli search \
    --sha "${digest_no_prefix}" \
    --format json | jq -r '.UUIDs[0]'
)"

if [[ -z "${rekor_uuid}" || "${rekor_uuid}" == "null" ]]; then
  echo "Unable to locate Rekor entry for digest ${IMAGE_DIGEST} – stop verification here." >&2
  false
fi

rekor-cli get --uuid "${rekor_uuid}"
```

Cosign v3 removed the deprecated `--rekor-output` flag, so the JSON emitted by
`cosign verify --output json` is now the canonical way to inspect the verification
result. When the registry supports Sigstore transparency bundles, Cosign can expose
the Rekor log index directly under `optional.Bundle.Payload.logIndex`, but Docker Hub
does not persist those bundles, so the `optional` section is usually empty.

Because of that, the Rekor entry is recovered by searching for the image’s content
digest instead:

* `rekor-cli search --sha <digest>` returns the list of matching UUIDs.
* `rekor-cli get --uuid <uuid>` retrieves the full transparency log entry, including
  the Fulcio certificate, signature and integrated timestamp.

If the Rekor search returns no UUIDs for the digest, verification must stop, because
there is no transparency log entry corresponding to the signed image. In that case,
inspect the “Build, Attest, Sign and publish Docker Image” workflow and confirm that
the **“Cosign sign image by digest (keyless OIDC)”** step ran successfully for this
tag and digest.

The attestation verifier now expects the canonical SLSA predicate URI
(`https://slsa.dev/provenance/v1`), which distinguishes the SLSA statement from the
additional `https://sigstore.dev/cosign/sign/v1` bundle shipped alongside the image.
Cosign 3.0 returns the attestation envelope directly from `cosign verify-attestation`,
so the instructions above capture that JSON and decode the `payload` field instead of
calling `cosign download attestation`. SBOM validation reuses the same mechanism with
the `spdxjson` predicate and a `platform` annotation, so the loop above verifies and
decodes each per-platform SBOM attestation.

The SBOMs verified here are the same artifacts generated during the build
(`sbom: true`). You can further inspect them with tools like `jq` or `syft` to validate
dependencies and policy compliance.

### 3. Verify standalone binaries exported from the StageX image

```bash
gh release download "${VERSION}" --repo "${REPO}" \
  --pattern "zallet-${VERSION}-linux-*" \
  --dir verify/dist

curl -sSf https://apt.z.cash/zcash.asc | gpg --import -

for arch in ${BINARY_SUFFIXES//,/ }; do
  arch="$(echo "${arch}" | xargs)"
  [ -z "${arch}" ] && continue

  artifact="verify/dist/zallet-${VERSION}-${arch}"

  echo "Verifying GPG signature for ${artifact}..."
  gpg --verify "${artifact}.asc" "${artifact}"

  echo "Computing SHA256 for ${artifact}..."
  sha256sum "${artifact}" | tee "${artifact}.sha256"

  echo "Verifying GitHub SLSA provenance attestation for ${artifact}..."
  gh attestation verify "${artifact}" \
    --repo "${REPO}" \
    --predicate-type "https://slsa.dev/provenance/v1" \
    --signer-workflow "${BIN_SIGNER_WORKFLOW}"

  echo
done
```


```bash
grep -F "PackageChecksum" "verify/dist/zallet-${VERSION}-linux-amd64.sbom.spdx"
```

### 4. Verify Debian packages before consumption or mirroring

```bash
gh release download "${VERSION}" --repo "${REPO}" \
  --pattern "zallet_${VERSION}_*.deb*" \
  --dir verify/dist

for arch in ${DEB_ARCHES//,/ }; do
  arch="$(echo "${arch}" | xargs)"
  [ -z "${arch}" ] && continue

  deb="verify/dist/zallet_${VERSION}_${arch}.deb"

  echo "Verifying GPG signature for ${deb}..."
  gpg --verify "${deb}.asc" "${deb}"

  echo "Inspecting DEB metadata for ${deb}..."
  dpkg-deb --info "${deb}" | head

  echo "Computing SHA256 for ${deb}..."
  sha256sum "${deb}" | tee "${deb}.sha256"

  echo "Verifying GitHub SLSA provenance attestation for ${deb}..."
  gh attestation verify "${deb}" \
    --repo "${REPO}" \
    --predicate-type "https://slsa.dev/provenance/v1" \
    --signer-workflow "${BIN_SIGNER_WORKFLOW}"

  echo
done
```

The `.deb` SBOM files (`.sbom.spdx`) capture package checksums; compare them with `sha256sum zallet_${VERSION}_${arch}.deb`.

### 5. Validate apt.z.cash metadata

```bash
# 1. Get the Zcash signing key
curl -sSfO https://apt.z.cash/zcash.asc

# 2. Turn it into a keyring file in .gpg format
gpg --dearmor < zcash.asc > zcash-apt.gpg

# 3. Verify both dists using that keyring
for dist in bullseye bookworm; do
  curl -sSfO "https://apt.z.cash/dists/${dist}/Release"
  curl -sSfO "https://apt.z.cash/dists/${dist}/Release.gpg"
  gpgv --keyring ./zcash-apt.gpg "Release.gpg" "Release"
  grep -A3 zallet "Release"
done
```

This ensures the repository metadata match the GPG key decrypted inside the `binaries-and-deb-release` workflow.

### 6. Inspect provenance predicates (SLSA v1.0)

For any provenance file downloaded above, e.g.:

```bash
FILE=verify/dist/zallet_${VERSION}_amd64.deb

# 1) Builder ID
jq -r '.predicate.runDetails.builder.id' "${FILE}.intoto.jsonl"

# 2) Version (from the workflow ref)
jq -r '.predicate.buildDefinition.externalParameters.workflow.ref
       | sub("^refs/tags/"; "")' "${FILE}.intoto.jsonl"

# 3) Git commit used for the build
jq -r '.predicate.buildDefinition.resolvedDependencies[]
       | select(.uri | startswith("git+"))
       | .digest.gitCommit' "${FILE}.intoto.jsonl"

# 4) Artifact digest from provenance
jq -r '.subject[].digest.sha256' "${FILE}.intoto.jsonl"
```

Cross-check that:

- `builder.id` matches the workflow that produced the artifact (`${IMAGE_WORKFLOW}` for OCI images, `${BIN_WORKFLOW}` for standalone binaries and `.deb` packages).
- `subject[].digest.sha256` matches the artifact’s `sha256sum`. (e.g image digest)
- `materials[].digest.sha1` equals the `git rev-parse` result from Step 1.

Automated validation:

```bash
  gh attestation verify "${FILE}" \
    --repo "${REPO}" \
    --predicate-type "https://slsa.dev/provenance/v1" \
    --signer-workflow "${BIN_SIGNER_WORKFLOW}"
```

### 7. Reproduce the deterministic build locally

The image is multi-arch and each architecture reproduces with its own toolchain. Extract the per-platform digest you want to check from the published manifest list:

```bash
crane manifest "${IMAGE}@${IMAGE_DIGEST}" \
  | jq -r '.manifests[] | "\(.platform.architecture) \(.digest)"'
```

#### amd64 — StageX (full-source bootstrap)

```bash
git clean -fdx
git checkout "${VERSION}"
make build IMAGE_TAG="${VERSION}"
skopeo inspect docker-archive:build/oci/zallet.tar | jq -r '.Digest'
```

`make build` invokes `utils/build.sh`, which builds a single-platform (`linux/amd64`) OCI tarball at `build/oci/zallet.tar`. Its digest should match the `amd64` per-platform digest extracted above.

#### arm64 — Nix (rebuild-reproducible, static musl)

Run on an aarch64 host (or any host with the arm64 Nix substituters available). Build twice and confirm the binary is byte-identical:

```bash
git checkout "${VERSION}"
nix build .#zallet                      # uses the pinned flake.lock
sha256sum ./result/bin/zallet
nix store delete "$(readlink -f ./result)" && nix build .#zallet --rebuild
sha256sum ./result/bin/zallet           # must match the first hash
```

A matching hash across the two clean builds is the arm64 reproducibility guarantee. (The arm64 image variant wraps this exact binary in a `scratch` image, so its per-platform digest follows from the binary plus the reproducible image settings.) Because Nix enforces determinism by sandboxing rather than proving it, this build-twice check — not trust in Nix — is what establishes the result; `diffoscope ./result-a/bin/zallet ./result-b/bin/zallet` pinpoints any divergence if the hashes ever differ.

After importing:

```bash
make import IMAGE_TAG="${VERSION}"
docker run --rm zallet:${VERSION} zallet --version
```

Running this reproduction as part of downstream promotion pipelines provides additional assurance that the published image and binaries stem from the deterministic StageX build.

## Supplemental provenance metadata (`.provenance.json`)

Every standalone binary and Debian package in a GitHub Release includes a supplemental
`*.provenance.json` file alongside the SLSA-standard `*.intoto.jsonl` attestation. For example:

```
zallet-v1.2.3-linux-amd64
zallet-v1.2.3-linux-amd64.asc
zallet-v1.2.3-linux-amd64.sbom.spdx
zallet-v1.2.3-linux-amd64.intoto.jsonl       ← SLSA standard attestation
zallet-v1.2.3-linux-amd64.provenance.json    ← supplemental metadata (non-standard)
```

The `.provenance.json` file is **not** a SLSA-standard predicate. It is a human-readable
JSON document that records the source Docker image reference and digest, the git commit SHA,
the GitHub Actions run ID, and the SHA-256 of the artifact — useful as a quick audit trail
but not suitable for automated SLSA policy enforcement. Use the `*.intoto.jsonl` attestation
(verified via `gh attestation verify` as shown in sections 3 and 4) for any automated
compliance checks.

## Residual work

- Extend the attestation surface (e.g., SBOM attestations, vulnerability scans) if higher SLSA levels or in-toto policies are desired downstream.
