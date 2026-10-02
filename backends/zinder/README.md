# Zinder wallet-runtime backend

This directory contains Zallet's `zallet-zinder` native backend process. When
`backend = "zinder"` is configured, the standard launcher dispatches to this
sibling executable. It reads `[zinder].wallet_query_endpoint` from Zallet
configuration, fails before network access when the field is absent, and
connects only through the typed native wallet-query client from the released
Zinder 0.6.0 client package.

## Dependency graph

The backend uses Rust 1.95 because the released Zinder 0.6.0 crates declare that MSRV.
This does not require a root Zallet toolchain change: backend crates are
independent workspaces, and the current Zallet core still compiles under the
newer toolchain.

The backend workspace pins the wallet-critical librustzcash packages to the
same source revision used by the current Zallet, Zebra, and Zaino lockfiles:
`375fc8e51acb2903777f3512bf92b28dc0ac42ef`. This keeps persisted wallet types
and migrations source-coherent across the independent workspaces. The Zinder
boundary itself is exact: `zinder-client = 0.6.0` and the test-only
`zinder-core = 0.6.0`; those are the released Zinder 0.6.0 packages, not a
compatibility alias for an earlier release.

## Wallet-runtime capability contract

Construction performs a real native `ServerInfo` request and refuses to return
a chain value unless the endpoint advertises all 16 current wallet-runtime
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
- bounded full-block ranges;
- canonical transaction lookup;
- transaction broadcast;
- transparent-address unspent outputs;
- ascending transparent-address transaction history;
- visible-chain events;
- mempool snapshots; and
- mempool events.

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

Canonical transaction lookup is bound to the view's captured epoch and rejects
missing raw bytes, malformed bytes, and bytes whose transaction ID differs
from the requested ID. Mempool follow opens the visible-chain event stream
before paging the snapshot, verifies that every page has the captured epoch
and source tip, then resumes the mempool event stream from the snapshot's
durable anchor. Snapshot and event replay are idempotently de-duplicated. A
mempool stream completes cleanly only after a visible-tip change; transport,
protocol, and unexpected stream-completion failures are yielded as typed
stream errors.

Transparent spend detection compares the wallet's tracked outputs with the
complete epoch-pinned address UTXO set. When an output has been spent, the
backend follows ascending address-history pages within the same captured view
and hydrates each transaction through the canonical transaction lookup.
Transaction broadcast serializes the wallet transaction once, submits those
bytes through the configured endpoint, and verifies the transaction ID in an
accepted response. Duplicate and queued responses are successful submissions;
rejection errors name the reason reported by Zinder and retain the node message.

## Current Zallet boundary

The bounded scan kernel calls
`tree_state_as_of` and `stream_blocks` on one `ChainView`; setup also uses the
three subtree-root methods, `snapshot`, `tip`, and an individual `get_block`
for best-effort tip metadata. Construction reads `ServerInfo`, and consensus
preflight reads the reported network upgrades.

The steady-state path additionally calls `find_fork_point`, may fall back to
`get_block_header`, streams with `stream_blocks_to_tip`, and follows the
mempool after the captured tip. Those chain-read methods share the same pinned
snapshot and retained-block validation. Satisfying the Rust traits and unit
contracts proves type compatibility, not current-Zallet certification.

Zallet core treats typed `ChainError::ViewExpired` as the precise reason to
discard a fixed-history view; legacy `ChainError::Unavailable` remains
retryable for backends that cannot classify a transient failure more precisely.
Initial scan, steady-state scan, and history recovery then capture a fresh view
and retry the entire bounded range. Invalid-data and backend failures retain
their existing categories and do not enter this recovery path. The scan kernel
buffers the predecessor tree state
and complete block range before decryption or wallet-database mutation, so a
mid-range expiry cannot mix epochs or partially apply the failed range. The
backend does not add an adapter-local retry.

## Retained Gate A bounded-scan evidence

Unit and compile-time contract tests cover the wallet-runtime capability set,
fork lookup, complete block-header decoding, demand-driven range paging,
tree-state decoding, explicit unsupported operations, and retention of typed
epoch expiry. The retained Gate A seam only certifies a real bounded Zallet
scan and epoch reacquisition through a current Zinder runtime; it does not
certify the P2a process, transaction, or mempool behavior.
Running the retained seam now requires:

1. Start a Zinder composition that advertises the required wallet-runtime set
   and retains raw blocks. Additional truthful
   capabilities are allowed.
2. Construct the backend against that endpoint and the matching Zallet network.
3. Through an explicit P1 consumer-test seam, run Zallet's subtree-root update,
   snapshot, predecessor tree-state read, and bounded full-block scan kernel.
4. Verify the applied range is complete and pinned to a single chain epoch.
5. Expire that epoch and verify the whole bounded range restarts with a fresh
   view rather than mixing results across epochs.

The consumer-test seam and typed whole-range retry remain in Zallet core; this
backend supplies the admitted chain and invokes that seam from ignored tests.
This evidence must not substitute for current-Zallet certification or a full
`zallet start` attempt. Broadcast and transparent behavior remain outside this
retained Gate A slice.

### Bounded-scan certification feature

The non-default `bounded-scan-certification` feature forwards to Zallet core's
bounded-scan seam and adds 3 ignored library tests. It is a certification
feature, not an additional runtime contract. Build the single libtest
executable without running it:

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
`ZIT_RANGE_BARRIER_DIR`, and `ZIT_RANGE_REQUEST_PAUSE_START_HEIGHT` equal to
`ZIT_REQUESTED_START_HEIGHT`. This scenario admits exactly 1 new block, so the
retry end must be 1 greater than `ZIT_REQUESTED_END_HEIGHT_EXCLUSIVE`. When a
barrier directory is supplied without `ZIT_RANGE_REQUEST_PAUSE_START_HEIGHT`,
it records range attempts without blocking them. The private hook records schema-v1
`range-request-attempt-N.json` files immediately before each native range RPC.
On the first request beginning at the configured inclusive height it also
records `range-request-paused.json` and waits at most 60 seconds for the
harness to create `continue-range-request`.

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
cargo +1.95.0 tree --manifest-path backends/zinder/Cargo.toml -i zcash_protocol@0.10.4
```

Passing these checks is necessary but does not replace the retained
real-consumer Gate A scan or P2a current-Zallet certification.
