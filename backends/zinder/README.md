# Zinder backend P1 compatibility tracer

This directory is an unshippable integration tracer. It has no Zallet binary,
launcher, production configuration, or packaging integration. It proves the
backend half of one P1 vertical slice: the bounded shielded-scan methods in
Zallet's `Chain` and `ChainView` traits can read one pinned Zinder chain epoch
through the native typed client. It does not implement the full `Chain`
behavior needed by `zallet start`.

## Frozen inputs

- Zallet base: `4d28731dcf33df00f86762d1bfd455943db5819c`
- P1 Zallet core integration: `c1513772e0ecde73589be23e54d8b9169b170ad3`
- Pinned Zinder client: `479805765d4c277115e534bf26f0a3ed6144bb73`
- Zallet draft PR #591: `59b6415a` (comparison only)

## Dependency graph

The tracer uses Rust 1.95 because the frozen Zinder crates declare that MSRV.
This does not require a root Zallet toolchain change: backend crates are
independent workspaces, and the current Zallet core still compiles under the
newer toolchain.

Zallet's frozen librustzcash packages remain at
`0531f9d89450d5def16d4c320972e4ce960f9175`. The exception is the public
`zcash_protocol` type boundary:

- the `zcash_protocol` crates.io patch is intentionally omitted;
- the frozen git source's path package is replaced with published
  `zcash_protocol 0.10.1`; and
- Zinder's `^0.10.1` dependency resolves to that same registry package.

The old packages constrain their path dependency with `^0.10.0`, so 0.10.1
satisfies them without changing the rest of Zallet's librustzcash API
generation. `cargo tree -i zcash_protocol@0.10.1` must show exactly one
protocol package and source before this cutover is accepted.

Moving the entire librustzcash family to the current `zcash_protocol-0.10.1`
release commit (`033a0a9b8c32d82006d67984ed145f4827ca5219`) was tested and
rejected. That revision is newer than Zallet's frozen API generation and
requires the intervening lock and proposal API changes. Keeping two protocol
sources, adding nominal-type conversion shims, vendoring protobufs, or adding
a second transport would preserve the wrong boundary and are also rejected.

## P1 contract

Construction performs a real native `ServerInfo` request and refuses to return
a chain value unless the endpoint advertises all eight P1 requirements. The
endpoint may advertise additional capabilities when its composed providers can
truthfully serve them; the tracer checks inclusion, not set equality.

- server information;
- network-upgrade activations;
- visible-tip identity;
- tree state;
- Sapling and Orchard subtree roots;
- Ironwood subtree roots;
- individual full blocks; and
- bounded full-block ranges.

If either full-block capability is absent, preflight directs the operator to
set `raw_blob_policy=all` for Zinder ingest and query. Existing canonical data
must be rebuilt under that retention policy and deployed with a blue-green
replacement; retention cannot be upgraded safely in place.

The implementation maps Zallet's half-open ranges to Zinder's inclusive
ranges, clamps bounded streams to the captured tip, decodes Sapling, Orchard,
and Ironwood frontiers and subtree roots, and parses retained consensus block
bytes with Zallet's configured network parameters.

Each `ZinderChainView` owns one `OwnedChainSnapshot`. A
`CHAIN_EPOCH_PIN_UNAVAILABLE` error becomes `ChainError::ViewExpired` while
retaining the original typed `IndexerError` as its error source. The adapter
never retries one read against a different chain epoch.

The trait implementation is deliberately incomplete. Fork-point lookup, block
header lookup, streaming from a height through the tip, transaction broadcast,
mempool observation, transaction lookup and status, and transparent history
are assigned to later vertical slices. Their required trait methods return
explicit `Unsupported` errors. In particular, P1 neither requires nor calls
Zinder's block-ID-by-selector operation.

## Current Zallet boundary

On this consolidated P1 Zallet source, the bounded scan kernel calls
`tree_state_as_of` and `stream_blocks` on one `ChainView`; setup also uses the
three subtree-root methods, `snapshot`, `tip`, and an individual `get_block`
for best-effort tip metadata. Construction reads `ServerInfo`, and consensus
preflight reads the reported network upgrades. Those calls are the P1 tracer
boundary.

The full sync runtime has additional requirements. Its steady-state path calls
`find_fork_point`, may fall back to `get_block_header`, streams with
`stream_blocks_to_tip`, and then observes the mempool. Those methods are
outside P1, so registering this crate as a backend for `zallet start` would
fail explicitly. Satisfying the Rust traits proves type compatibility, not
operational completeness.

Zallet core treats only `ChainError::ViewExpired` as a reason to discard a
fixed-history view. Initial scan, steady-state scan, and history recovery then
capture a fresh view and retry the entire bounded range. Other unavailable,
invalid-data, and backend failures retain their existing categories and do not
enter this recovery path. The scan kernel buffers the predecessor tree state
and complete block range before decryption or wallet-database mutation, so a
mid-range expiry cannot mix epochs or partially apply the failed range. The
backend does not add an adapter-local retry.

## Gate A

Unit and compile-time contract tests cover the frozen capability set, range
translation, tree-state decoding, explicit whole-sync failures, and retention
of typed epoch expiry. They do not certify the production consumer. Gate A
additionally requires a real bounded Zallet scan through a current Zinder
runtime:

1. Start a Zinder composition that advertises at least the exact eight P1
   requirements listed above and retains raw blocks. Additional truthful
   capabilities are allowed.
2. Construct the tracer against that endpoint and the matching Zallet network.
3. Through an explicit P1 consumer-test seam, run Zallet's subtree-root update,
   snapshot, predecessor tree-state read, and bounded full-block scan kernel.
4. Verify the applied range is complete and pinned to one chain epoch.
5. Expire that epoch and verify the whole bounded range restarts with a fresh
   view rather than mixing results across epochs.

The consumer-test seam and typed whole-range retry belong in Zallet core or its
external integration harness; this backend-only crate cannot make those
private sync decisions. Gate A must not substitute a full `zallet start`
attempt, because that would test intentionally unsupported whole-sync methods.

The focused backend checks are:

```console
cargo +1.95.0 fmt --manifest-path backends/zinder/Cargo.toml -- --check
cargo +1.95.0 test --manifest-path backends/zinder/Cargo.toml --all-targets
cargo +1.95.0 check --manifest-path backends/zinder/Cargo.toml --all-targets
cargo +1.95.0 clippy --manifest-path backends/zinder/Cargo.toml --all-targets -- -D warnings
cargo +1.95.0 tree --manifest-path backends/zinder/Cargo.toml -i zcash_protocol@0.10.1
```

Passing these checks is necessary but does not replace the real-consumer Gate
A scan.
