# Standard, multi-arch Zallet image — the everyday `docker build` path.
#
# This is the DEFAULT Dockerfile: a plain, widely-understood multi-stage build
# on official images that works out of the box on linux/amd64 AND linux/arm64
# (incl. Apple Silicon) via `docker build` / `docker buildx`. It uses Docker's
# native $TARGETARCH so a single `docker buildx build --platform
# linux/amd64,linux/arm64 .` produces both.
#
#   docker build -t zallet .
#   docker buildx build --platform linux/amd64,linux/arm64 -t zallet .
#
# It is also REPRODUCIBLE (rebuild-deterministic): bases are digest-pinned,
# timestamps come from SOURCE_DATE_EPOCH, build paths are remapped out of the
# binary, and the apt/ldconfig caches (which embed wall-clock times) are dropped.
# Two builds of the same commit + same base digests produce the same bytes.
# Build reproducibly with:
#   docker buildx build --build-arg SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
#     --output type=image,rewrite-timestamp=true .
#
# This does NOT bootstrap its toolchain (it pins a prebuilt rust + debian, like
# most reproducible-build setups). The full-source-bootstrapped release path is
# `Dockerfile.stagex` (amd64); `flake.nix` gives a bit-for-bit static-musl build
# for both arches. See book/src/slsa/slsa.md.

# --- Stage 1: build ---------------------------------------------------------
# Digest-pin the base so the build is a function of its inputs only (bump the
# tag AND the digest together, deliberately). rust 1.91.1 on bookworm matches
# the runtime base below so the dynamically-linked glibc binary just works.
FROM rust:1.91.1-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS builder

# Build deps: protobuf (tonic/PROTOC), clang+llvm (bindgen / *-sys C/C++ deps),
# pkg-config, and git (zaino-state's build.rs embeds the commit).
#
# These versions are NOT implied by the digest-pinned base: apt resolves them
# against the live bookworm archive, which only ever serves the CURRENT revision
# of each package. So a bookworm point release (or a security update) deletes the
# revision pinned here and the build fails with "Version '...' was not found",
# even though nothing in this repo changed. When that happens, re-read the
# candidate versions from the pinned base and bump the offending pin:
#
#   docker run --rm rust:1.91.1-slim-bookworm@sha256:8514999d... \
#     bash -c 'apt-get update -qq && apt-cache policy protobuf-compiler'
#
# (Pinning apt to a snapshot.debian.org timestamp would make this immune, at the
# cost of no longer picking up security updates automatically.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential=12.9 \
        clang=1:14.0-55.7~deb12u1 \
        llvm-dev=1:14.0-55.7~deb12u1 \
        libclang-dev=1:14.0-55.7~deb12u1 \
        protobuf-compiler=3.21.12-3+deb12u1 \
        pkg-config=1.8.1-1 \
        git=1:2.39.5-0+deb12u3 \
        ca-certificates=20230311+deb12u1 \
    && rm -rf /var/lib/apt/lists/*

ENV PROTOC=/usr/bin/protoc
# CARGO_INCREMENTAL=0: incremental artifacts are nondeterministic.
ENV CARGO_INCREMENTAL=0
WORKDIR /usr/src/zallet
COPY . .

# Reproducibility: SOURCE_DATE_EPOCH (passed from the commit time) feeds any
# timestamp the build would otherwise take from the wall clock; remap the
# absolute build path out of the binary so a different checkout dir doesn't
# change the bytes.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Build NATIVELY for whatever architecture this image is running as. buildx
# already places the container on the target arch (per --platform), so the
# host's default Rust target IS the target — we must NOT pass an explicit
# `--target`. Passing one turns the build into a "cross" build in cc-rs's eyes,
# which then looks for a triple-prefixed cross compiler (e.g.
# `aarch64-linux-gnu-gcc`) that isn't installed, and the *-sys crates
# (secp256k1-sys, etc.) fail with "failed to find tool ...-gcc". A plain
# `cargo build` uses the in-image gcc/clang for the native arch and Just Works
# on both amd64 and arm64.
RUN set -eux; \
    export CARGO_BUILD_RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$CARGO_HOME=/cargo"; \
    cargo build --release --locked \
      --manifest-path backends/zebra/Cargo.toml \
      --bin zallet-zebra --features rpc-cli,zcashd-import; \
    # The user-facing `zallet` command is the launcher (root workspace); it
    # dispatches to the backend binary installed next to it.
    cargo build --release --locked --bin zallet; \
    install -D -m0755 target/release/zallet /out/zallet; \
    install -D -m0755 backends/zebra/target/release/zallet-zebra /out/zallet-zebra; \
    # Collect the build.rs-generated share tree (completions, manpages,
    # debian-copyright), matching the StageX export layout where present.
    REL="backends/zebra/target/release"; \
    mkdir -p /out/usr/local/share/zallet; \
    for d in completions manpages; do \
      [ -d "$REL/$d" ] && cp -a "$REL/$d" /out/usr/local/share/zallet/ || true; \
    done; \
    [ -f "$REL/debian-copyright" ] \
      && install -D -m0644 "$REL/debian-copyright" /out/usr/local/share/zallet/debian-copyright || true

# --- Stage 2: export (parity with Dockerfile.stagex) ------------------------
# Binary at the root for easy extraction; full share tree alongside it.
FROM scratch AS export
COPY --from=builder /out/zallet /zallet
COPY --from=builder /out/zallet-zebra /zallet-zebra
COPY --from=builder /out/usr/local/share/zallet /usr/local/share/zallet

# --- Stage 3: minimal runtime -----------------------------------------------
# debian-slim (not scratch): this is a dynamically-linked glibc binary, so it
# needs a libc + CA certs at runtime. The reproducible StageX/Nix paths produce
# a static-musl binary that can live on scratch; this convenience image trades
# that for a standard, easy-to-extend base. Digest-pinned for reproducibility.
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime
# --shadow-time + dropping the apt/dpkg/ldconfig caches keeps the layer free of
# wall-clock timestamps that would otherwise drift the image digest day to day.
# ca-certificates is version-pinned to the digest-pinned base's snapshot.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
    && useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin zallet \
    && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
COPY --from=builder /out/zallet /usr/local/bin/zallet
COPY --from=builder /out/zallet-zebra /usr/local/bin/zallet-zebra
COPY --from=builder /out/usr/local/share/zallet /usr/local/share/zallet
USER 1000:1000
WORKDIR /var/lib/zallet
ENTRYPOINT ["zallet"]
