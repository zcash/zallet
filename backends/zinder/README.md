# Zinder backend P1 compatibility tracer

This directory is an unshippable integration tracer. It has no Zallet binary,
launcher, production configuration, or packaging integration. Its purpose is
to prove one complete P1 vertical slice: Zallet's existing `Chain` and
`ChainView` abstractions can perform an epoch-consistent bounded shielded scan
through Zinder's native typed client.

## Frozen inputs

- Zallet: `4d28731dcf33df00f86762d1bfd455943db5819c`
- Zinder: `71e20d481845c7df93eea67b3ccc89c3d4b9d4f2`
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

Construction performs a real native `ServerInfo` request and refuses to start
unless the endpoint advertises every P1 capability:

- server information;
- network-upgrade activations;
- visible-tip identity;
- tree state;
- Sapling and Orchard subtree roots;
- Ironwood subtree roots;
- individual full blocks; and
- bounded full-block ranges.

The implementation maps Zallet's half-open ranges to Zinder's inclusive
ranges, clamps every stream to the captured tip, decodes Sapling, Orchard, and
Ironwood frontiers and subtree roots, and parses retained consensus block
bytes with Zallet's configured network parameters.

Each `ZinderChainView` owns one `OwnedChainSnapshot`. A
`CHAIN_EPOCH_PIN_UNAVAILABLE` error becomes `ChainError::Unavailable`; Zallet
must discard that whole view and capture a new one. The adapter never retries
one read against a different chain epoch.

Transaction broadcast, mempool observation, transaction lookup, and
transparent history are assigned to later vertical slices. Their required
trait methods return explicit P1-scope errors.

## Gate A

Unit and compile-time contract tests cover capability selection, range
translation, tree-state decoding, P1-only failures, and typed epoch expiry.
They do not certify the production consumer. Gate A additionally requires a
real bounded Zallet scan through a current Zinder runtime:

1. Start a Zinder composition that advertises the exact P1 capability set and
   retains raw blocks.
2. Construct `ZinderBackend` with that endpoint and the matching Zallet
   network.
3. Run Zallet's existing subtree-root update, snapshot, predecessor tree-state
   read, and bounded full-block scan path.
4. Verify the applied range is complete and pinned to one chain epoch.
5. Expire that epoch and verify Zallet abandons the view rather than mixing
   results across epochs.

The focused local checks are:

```console
cargo +1.95.0 fmt --manifest-path backends/zinder/Cargo.toml -- --check
cargo +1.95.0 test --manifest-path backends/zinder/Cargo.toml --all-targets
cargo +1.95.0 check --manifest-path backends/zinder/Cargo.toml --all-targets
cargo +1.95.0 clippy --manifest-path backends/zinder/Cargo.toml --all-targets -- -D warnings
cargo +1.95.0 tree --manifest-path backends/zinder/Cargo.toml -i zcash_protocol@0.10.1
```

Passing these checks is necessary but does not replace the real-consumer Gate
A scan.
