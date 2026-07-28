# Zinder wallet-runtime chain integration

This directory contains the unshippable P2a chain-read backend. It has no
Zallet binary, launcher, production configuration, or packaging integration.
It implements Zallet's shielded chain-read requirements against a pinned Zinder
chain epoch through the native typed client. Transaction submission,
mempool observation, mined-transaction lookup, and transparent history remain
unimplemented, so the backend cannot yet support `zallet start`.

## Frozen inputs

- Zallet base: `8f56351c35c16e93dfd5ac0a9a621ee411f733c5`
- P1 Zallet core integration: `c1513772e0ecde73589be23e54d8b9169b170ad3`
- Pinned Zinder client: `d8afdb9dd0bfbf5b57f44a110b293a84add5f4ef`

## Dependency graph

The backend uses Rust 1.95 because the pinned Zinder crates declare that MSRV.
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

## Wallet-runtime capability contract

Construction performs a real native `ServerInfo` request and refuses to return
a chain value unless the endpoint advertises all 9 current wallet-runtime
requirements. The endpoint may advertise additional capabilities when its
composed providers can truthfully serve them; the backend checks inclusion,
not set equality.

- server information;
- network-upgrade activations;
- visible-tip identity;
- canonical block identity by height or hash selector;
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
ranges, clamps streams to the captured tip, and requests full blocks in
demand-driven pages of at most 1,000 entries without changing snapshots. It
resolves fork candidates by hash from highest to lowest, decodes complete
consensus headers and blocks from retained block blobs, validates each blob's
height, hash, and parent identity, and decodes Sapling, Orchard, and Ironwood
frontiers and subtree roots.

Each `ZinderChainView` owns one `OwnedChainSnapshot`. A
`CHAIN_EPOCH_PIN_UNAVAILABLE` error becomes `ChainError::ViewExpired` while
retaining the original typed `IndexerError` as its error source. The adapter
never retries one read against a different chain epoch.

The trait implementation is deliberately incomplete. Transaction broadcast,
mempool observation, transaction lookup and status, and transparent history
are assigned to later vertical slices. Their required trait methods return
explicit `Unsupported` errors.

## Current Zallet boundary

The bounded scan kernel calls
`tree_state_as_of` and `stream_blocks` on one `ChainView`; setup also uses the
three subtree-root methods, `snapshot`, `tip`, and an individual `get_block`
for best-effort tip metadata. Construction reads `ServerInfo`, and consensus
preflight reads the reported network upgrades.

The steady-state path additionally calls `find_fork_point`, may fall back to
`get_block_header`, and streams with `stream_blocks_to_tip`; those chain-read
methods share the same pinned snapshot and retained-block validation. Mempool
observation remains outside this slice, so registering the crate for
`zallet start` would still fail explicitly. Satisfying the Rust traits and
unit contracts proves type compatibility, not operational completeness.

Zallet core treats only `ChainError::ViewExpired` as a reason to discard a
fixed-history view. Initial scan, steady-state scan, and history recovery then
capture a fresh view and retry the entire bounded range. Other unavailable,
invalid-data, and backend failures retain their existing categories and do not
enter this recovery path. The scan kernel buffers the predecessor tree state
and complete block range before decryption or wallet-database mutation, so a
mid-range expiry cannot mix epochs or partially apply the failed range. The
backend does not add an adapter-local retry.

## Retained Gate A bounded-scan evidence

Unit and compile-time contract tests cover the wallet-runtime capability set,
fork lookup, complete block-header decoding, demand-driven range paging,
tree-state decoding, explicit unsupported operations, and retention of typed
epoch expiry. The retained Gate A seam only certifies a real bounded Zallet
scan and epoch reacquisition through a current Zinder runtime; it does not
certify the P2a fork, header, or stream-to-tip behavior, and its historical
eight-capability contract is not the current nine-capability admission set.
Running the retained seam now requires:

1. Start a Zinder composition that advertises at least the exact 9
   requirements listed above and retains raw blocks. Additional truthful
   capabilities are allowed.
2. Construct the backend against that endpoint and the matching Zallet network.
3. Through an explicit P1 consumer-test seam, run Zallet's subtree-root update,
   snapshot, predecessor tree-state read, and bounded full-block scan kernel.
4. Verify the applied range is complete and pinned to a single chain epoch.
5. Expire that epoch and verify the whole bounded range restarts with a fresh
   view rather than mixing results across epochs.

The consumer-test seam and typed whole-range retry remain in Zallet core; this
backend-only crate only supplies the admitted chain and invokes that seam from
ignored tests. This evidence must not substitute for P2a current-Zallet
certification or a full `zallet start` attempt, which still requires
transaction submission, mempool observation, mined-transaction lookup,
transparent history, and production runtime-process integration.

### Unshippable certification executable

The non-default `bounded-scan-certification` feature forwards to Zallet core's
test-only bounded-scan seam and adds 3 ignored library tests. It does not
add a binary, launcher backend, production hook, or support claim. Build the
single libtest executable without running it:

```console
cargo +1.95.0 test --manifest-path backends/zinder/Cargo.toml \
  --features bounded-scan-certification --locked --no-run \
  --message-format=json
```

The external harness invokes exactly 1 ignored test per fresh OS process:

```text
chain::tests::endpoint_without_full_blocks_fails_before_wallet_open
chain::tests::endpoint_certifies_birthday_through_tip
chain::tests::expired_epoch_reacquires_complete_bounded_scan
```

Each process receives an absolute real Zallet TOML path in
`ZIT_ZALLET_CONFIG`, an absolute certification data directory in
`ZIT_CERTIFICATION_DATADIR`, and an absolute nonexistent JSON destination in
`ZIT_CERTIFICATION_RESULT`. The common endpoint and half-open range variables
are `ZIT_ZINDER_ENDPOINT`, `ZIT_REQUESTED_START_HEIGHT`, and
`ZIT_REQUESTED_END_HEIGHT_EXCLUSIVE`. The positive test is executed twice in
fresh processes against the same initialized wallet directory to certify
restart persistence; the wallet must already contain a real account whose
birthday equals the requested start.

Epoch-rotation certification additionally requires
`ZIT_RETRY_END_HEIGHT_EXCLUSIVE`, an absolute fresh
`ZIT_RANGE_BARRIER_DIR`, and `ZIT_BLOCK_FIRST_RANGE_REQUEST=true`. This
scenario admits exactly 1 new block, so the retry end must be 1 greater than
`ZIT_REQUESTED_END_HEIGHT_EXCLUSIVE`. When a barrier directory is supplied
for a non-rotation run,
`ZIT_BLOCK_FIRST_RANGE_REQUEST=false` records its single range attempt without
blocking it. The private hook records schema-v1
`range-request-attempt-N.json` files immediately before each native range RPC.
On the blocked first attempt it also records `predecessor-loaded.json` and
waits at most 60 seconds for the harness to create
`continue-range-request`.

All result and marker JSON is written through a same-directory temporary file
and an atomic no-clobber persist. Existing result or marker files are errors;
the harness must provide fresh evidence paths rather than overwrite a prior
run.

The focused backend checks are:

```console
cargo +1.95.0 fmt --manifest-path backends/zinder/Cargo.toml -- --check
cargo +1.95.0 test --manifest-path backends/zinder/Cargo.toml --all-targets
cargo +1.95.0 check --manifest-path backends/zinder/Cargo.toml --all-targets
cargo +1.95.0 clippy --manifest-path backends/zinder/Cargo.toml --all-targets -- -D warnings
cargo +1.95.0 tree --manifest-path backends/zinder/Cargo.toml -i zcash_protocol@0.10.1
```

Passing these checks is necessary but does not replace the retained
real-consumer Gate A scan or P2a current-Zallet certification.
