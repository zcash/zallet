# zallet-core Changelog

All notable changes to the **`zallet-core` public Rust API** are documented in
this file. It is written for people building against the crate, in particular
those implementing a chain backend against the `Chain` and `ChainView` seam.

Changes to the wallet's own user interface — the JSON-RPC methods, the CLI, the
configuration file, the wallet database, and the release artifacts — are in the
[repository-root changelog](../CHANGELOG.md), regardless of which crate
implements them. Most user-visible behaviour is implemented here, so that file is
usually the one to read for what a release does.

All packages in the repository move in release lockstep and share one version
number. This file begins at 0.1.0-beta.2, the first release after `zallet-core`
gained its own changelog; earlier history for the whole project is in the
root changelog.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Prior to the 1.0.0 release, no Semantic Versioning is followed; all releases
should be considered breaking changes.

## [Unreleased]

### Added

- `ChainRuntime::run_import_address` (in wallet builds with the
  `transparent-key-import` feature), running the chain-dependent body of the
  new `zallet import-address` CLI command. Backend crates receive it through
  the blanket impl over `ChainFactory` and need no changes.
- `components::chain::TreePool` and `components::chain::empty_tree_is_legitimate`,
  for backends implementing `ChainView::tree_state_as_of`. Together they answer
  whether a validator reporting *no* note commitment tree for a pool at a given
  height legitimately means the empty tree (the pool has not activated yet) or is
  a read failure that must be surfaced.

  Backends must not substitute a placeholder frontier for one they could not
  read. `ChainView::tree_state_as_of`'s documentation now spells out why: the
  frontiers it returns are the wallet's only protection against note commitment
  tree corruption, because `put_blocks`' apparent validation of them is circular
  in Zallet's usage — the scanned block's final tree size is derived from the
  same chain state the check compares it against. A wrong frontier is therefore
  committed without complaint and only surfaces later as an unrecoverable
  `shardtree` conflict.

### Changed

- Migrated to `zcash_client_backend`/`zcash_client_sqlite` 0.24.0-rc.7 /
  0.22.0-rc.7 (as of rc.5, output-locking — `lock_outputs`, `unlock_output`,
  `clear_locked_outputs`, `get_locked_outputs` — is extracted off `WalletWrite`
  into a new `OutputLockStore` supertrait; internal `DbConnection` now
  implements `OutputLockStore` directly, alongside its existing `WalletRead`,
  `InputSource`, `WalletWrite`, and `WalletCommitmentTrees` impls). The
  wallet-critical librustzcash crates are temporarily consumed via a
  `[patch.crates-io]` git pin (see the workspace `Cargo.toml`) that adds
  `WalletWrite::import_standalone_transparent_address`
  (zcash/librustzcash#2941); a backend workspace must carry the same patch
  so the cohort resolves to a single source.

- Chain backends can now report `ChainError::ViewExpired` when a fixed-history
  view has been invalidated. Wallet sync reacquires a view only for this
  precise condition instead of conflating it with general source
  unavailability.

- `ChainView::get_mempool_stream` now yields fallible transaction items.
  Steady-state sync propagates an item error instead of treating that item as
  ordinary stream completion. Existing backend error classification is unchanged.

## [0.1.0-beta.2] - 2026-07-28

### Changed

- Migrated to the librustzcash 0.24.0-rc.4 cohort: `zcash_client_backend`
  0.24.0-rc.4, `zcash_client_sqlite` 0.22.0-rc.4, `zcash_primitives` 0.30,
  `zcash_proofs` 0.30, `zcash_keys` 0.16, and `zcash_transparent` 0.10. Types
  from these crates appear directly in the backend seam — `Chain` and
  `ChainView` exchange `Transaction`, `BlockHeight`, `TransparentAddress`, and
  `TransactionStatus` — and types from two semver-incompatible versions of a
  crate do not unify, so a backend implementation must move to the same versions
  in lockstep.
- Returning `ChainError::InvalidData` from a `Chain` implementation while
  servicing a transaction data request now aborts sync, whereas
  `ChainError::Unavailable` and `ChainError::Backend` are logged and the request
  retried on a later iteration. Previously a failure of any kind shut the wallet
  down, so the distinction between the variants had no observable effect on the
  caller. An implementation should reserve `InvalidData` for responses that
  cannot become valid by retrying.
