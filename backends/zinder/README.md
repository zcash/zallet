# Zinder backend P1 compatibility tracer

This directory is an unshippable integration tracer. It has no Zallet binary,
launcher, configuration, or packaging integration. Its current purpose is to
compile the frozen Zinder typed client and make the P1 capability and
chain-epoch recovery contracts executable while a cross-repository dependency
boundary is resolved.

## Frozen inputs

- Zallet: `4d28731dcf33df00f86762d1bfd455943db5819c`
- Zinder: `71e20d481845c7df93eea67b3ccc89c3d4b9d4f2`
- Zallet draft PR #591: `59b6415a` (comparison only)

## Proven seam

With Rust 1.95, `zinder-client` exposes typed APIs for endpoint and network
identity, network-upgrade activations, a visible tip, tree state, shielded
subtree roots, individual full blocks, bounded full-block ranges, and
chain-epoch pin expiry. P1 preflight requires those exact capabilities and
reports the complete missing set. `CHAIN_EPOCH_PIN_UNAVAILABLE` maps to the
client's `RefreshChainEpoch` policy, which requires discarding the expired
snapshot and restarting the bounded scan from a fresh snapshot.

## Blocking incompatibilities

The P1 `zallet_core::components::chain::{Chain, ChainView}` implementation
cannot compile at the frozen revisions:

1. Zallet declares Rust 1.88. The frozen Zinder crates declare Rust 1.95, so
   Cargo rejects `zinder-client`, `zinder-core`, and `zinder-proto` before
   compilation under Zallet's toolchain.
2. Zallet patches its librustzcash family to git revision
   `0531f9d89450d5def16d4c320972e4ce960f9175`. Its path dependencies bring
   `zcash_address` and `zcash_protocol` 0.10.0 from that git source. Zinder
   uses the published `zcash_protocol` 0.10.1 family. Cargo treats the same
   Rust types from those two sources as distinct; network, address, value, and
   block types therefore cannot cross the graph.
3. Removing Zallet's patches is not a workaround. Cargo then selects newer
   release-candidate transitive crates, including `zcash_client_backend`
   0.24.0-rc.4 and `zcash_primitives` 0.30.0, while the frozen Zallet code
   targets the rc.1/0.29-era APIs. That graph fails with API and nominal-type
   mismatches.

Selective patching cannot split the git workspace cleanly: patched Zallet
crates retain path dependencies on the git-source address and protocol crates.
Vendoring protobufs or introducing a second transport client would mask this
incompatibility and create a competing public contract, so this tracer does
neither.

## Required coordinated decision

Before implementing `Chain` and `ChainView`, the repositories must share:

- one supported Rust toolchain policy; and
- one source and compatible version family for public librustzcash types.

The preferred cutover is to move Zallet to Rust 1.95 and a librustzcash
revision or release family compatible with the frozen Zinder client, then
re-run this tracer as a joint Cargo graph. Lowering Zinder's toolchain and
dependency family is an alternative only if Zinder can still satisfy its
workspace and release requirements. The boundary should be fixed at the
dependency source rather than bridged with conversion shims.

Once those prerequisites compile, the next tracer increment implements only
the P1 `Chain` and fixed `ChainView` paths. Transparent history, mempool
observation, and broadcast remain explicitly out of scope.

## Reproduction

The typed-client seam passes with:

```console
cargo +1.95.0 test --manifest-path backends/zinder/Cargo.toml --all-targets --all-features
```

The Zallet toolchain incompatibility is reproduced with:

```console
cargo +1.88.0 check --manifest-path backends/zinder/Cargo.toml --all-targets --all-features
```
