# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
During the alpha period, no Semantic Versioning is followed; all releases should
be considered breaking changes.

## [Unreleased]

### Added

- The `zebra` chain backend (and the `zaino` backend's read-state-service mode)
  now support regtest. The read-state service builds a Zebra Regtest network
  whose network-upgrade activation heights mirror the wallet's configured
  `regtest_nuparams`, so it interprets the co-located zebrad's on-disk state
  under matching consensus rules. Previously these backends rejected regtest at
  startup with an "does not support regtest" error.
- `z_viewtransaction` now reports Ironwood spends and outputs. Ironwood notes are
  Orchard-shaped and are trial-decrypted with the account's Orchard viewing keys
  under the Ironwood note-encryption domain, and Ironwood spends are resolved
  against the `ironwood_received_notes` table. Previously the method elided
  Ironwood actions entirely (they were reported for neither spends, outputs, nor
  sent-to addresses).
- `z_getnotescount` now reports Ironwood notes under a new `ironwood` field,
  alongside `sapling` and `orchard`. Previously Ironwood notes were counted in no
  field at all. (This required advancing the librustzcash pin, whose
  `WalletRead::get_account_metadata` gained Ironwood note-count support.)
- `getrawtransaction` and `decoderawtransaction` now surface the Ironwood bundle
  of a v6 transaction under a new `ironwood` key. Ironwood actions are
  Orchard-shaped, so the object has the same shape as the existing `orchard` one.
  Previously the Ironwood bundle was omitted from the decoded output.

### Changed

- Advanced the librustzcash pin (to `29c7fb2`) and, in lockstep, moved the
  `shardtree` dependency to the published `0.7` release, dropping the temporary
  `shardtree`/`incrementalmerkletree` git `[patch.crates-io]` (now unnecessary).

### Fixed

- `steady_state` sync no longer crashes the whole wallet when the backend's best
  chain reorgs away a block the wallet had already stored (`BlockConflict`).
  Previously this error wasn't recognized as retryable, so it propagated as a
  fatal error and required a full restart to recover. It's now handled the same
  way as other reorgs: the wallet's last known-good position is run through the
  existing fork-point search (which walks back as far as it actually needs to,
  rather than assuming the reorg is exactly one block deep), then rewinds and
  resumes syncing automatically.
- `initialize()`'s startup catch-up scan could also crash the wallet on a
  transient stale-view error (e.g. a reorg in progress right as the wallet
  started) that `steady_state`'s main loop already tolerates. It now retries the
  same way.
- The `zebra` chain backend's `tree_state_as_of` always reported the Ironwood
  note commitment tree as empty, regardless of the queried height. This was
  correct before NU6.3 activated on any chain the backend could reach, but once
  a chain crossed activation, every sync batch boundary re-derived the Ironwood
  frontier as empty instead of reading the real (non-empty) tree, corrupting
  the wallet's local shardtree state on the very next batch (surfacing as a
  checkpoint or root conflict in `zcash_client_sqlite`, or an `Inserted root
  conflicts with existing root` error from `shardtree`). The tree is now read
  from the backend the same way as Sapling and Orchard, via
  `ReadRequest::IronwoodTree`.

## [0.1.0-alpha.4] - 2026-06-25

### Added

- `zallet generate-encryption-identity` command, which generates the wallet's age
  encryption identity using the `age` library that Zallet already embeds. This
  removes the need for the external `rage` / `rage-keygen` tool when setting up a
  wallet. It supports both plain and passphrase-encrypted identities; in
  non-interactive contexts the passphrase is read from the
  `ZALLET_IDENTITY_PASSPHRASE` environment variable.
- Cookie file authentication for the JSON-RPC interface. A random credential
  is generated on startup and written to `{datadir}/.cookie`, enabling
  `zallet rpc` to authenticate automatically without manual password setup.
  Cookie auth coexists with configured `[[rpc.auth]]` users.
- RPC methods:
  - `decoderawtransaction`
  - `decodescript`
  - `getwalletstatus`
  - `verifymessage`
  - `z_converttex`
  - `z_exportkey` (Sapling extended spending keys only)
  - `z_importaddress`
  - `z_importkey` (Sapling extended spending keys only)
  - `z_shieldcoinbase`

### Changed
- **This release is not compatible with wallets created by earlier alpha
  releases.** The embedded Zaino chain indexer made a backwards-incompatible
  change to its database format (zingolabs/zaino#914), which this release pulls
  in. Zallet now refuses to open wallet databases last used by `0.1.0-alpha.3`
  or earlier; start again with a fresh Zallet wallet or a new data directory.
- MSRV updated to 1.88
- Updated the Zaino chain indexer to a pre-release `rc-0.4.0` build
  (zingolabs/zaino#1238) that retains NU 6.2 support and adds optional
  ("ephemeral") finalised state. The embedded indexer now runs in ephemeral
  mode, serving finalised chain data directly from the validator instead of
  maintaining a persistent finalised-state database.
- The wallet sync engine has been migrated to Zaino's `ChainIndex` interface,
  and now scans full blocks instead of compact blocks:
  - Shielded outputs are trial-decrypted by a batched decryption engine.
  - Transparent outputs are detected directly while scanning blocks, instead
    of by polling the backing node's address index on every chain tip change.
  - Chain queries made by RPC methods now operate against a stable snapshot of
    the chain state.
- `getrawtransaction` now correctly reports the fields `asm`, `reqSigs`, `kind`,
  and `addresses` for transparent outputs.
- `z_viewtransaction`: The `outgoing` field is now omitted on outputs that
  `zcashd` didn't include in its response.
- `z_viewtransaction` now detects funds shielded straight from a transparent
  address by very old `zcashd` wallets, by re-deriving the legacy
  `ovkForShieldingFromTaddr` outgoing viewing key from each of the wallet's HD
  seeds (requires the wallet to be unlocked).
- Significant performance improvements to `zallet migrate-zcashd-wallet`.
- `zallet migrate-zcashd-wallet` now accepts `--no-scan` to skip chain scanning
  during migration.
- `zallet rpc` now sends credentials via the `Authorization` header instead of
  embedding them in the HTTP URL.

### Fixed
- `walletlock` now awaits aborted relock tasks before returning, preventing a race
  where a rapid `walletpassphrase` after `walletlock` could leave the wallet locked
  despite reporting success.
- `listaddresses` no longer returns an internal error when the wallet contains
  standalone imported transparent keys (e.g. from a `zcashd` migration).
- No longer crashes in regtest mode when a Sapling or NU5 activation height is
  not defined.
- Zallet now refuses to open wallet databases from incompatible earlier alpha
  releases instead of attempting to migrate them.
- The network-mismatch startup error now reports the path of the wallet database
  and explains that a database is permanently tied to one network, so the cause
  and the available remedies are clear.
- `z_sendmany` no longer drop standalone transparent signing keys when the same
  address backs multiple proposal inputs. Keys are now accumulated per address
  rather than overwritten.
- Transparent UTXO ingestion now records `tx_index` for coinbase transactions
  by routing each observed transaction through `decrypt_and_store_transaction`
  in addition to `put_received_transparent_utxo`. This enables
  `z_shieldcoinbase` (and any other consumer of
  `TransparentOutputFilter::CoinbaseOnly`) to correctly identify coinbase
  outputs.
- `z_sendmany` no longer fails with `Query returned no rows` when a proposal
  includes inputs at HD-derived transparent addresses.
  The keystore's standalone-key decryption is now invoked only for addresses
  that were imported standalone; HD-derived addresses are signed for using
  the account's unified spending key.
- `zallet migrate-zcashd-wallet` now migrates transparent addresses that were
  added to the `zcashd` wallet via `importpubkey` or `importaddress <redeemScript>`.
- `zallet migrate-zcashd-wallet` now migrates view-only Sapling keys that were
  added to the `zcashd` wallet via `z_importviewingkey`. Each imported viewing
  key becomes its own view-only account.

## [0.1.0-alpha.3] - 2025-12-15

### Changed

- Finished implementing the following stubbed-out JSON-RPC methods:
  - `z_listaccounts`

### Fixed

- `zallet rpc` can communicate with Zallet again, by using a username and
  password from `zallet.toml` if any are present.

## [0.1.0-alpha.2] - 2025-10-31

### Added

- JSON-RPC authorization mechanisms, matching zcashd:
  - Multi-user (supporting both bare and hashed passwords in `zallet.toml`).

### Fixed

- Several balance calculation bugs have been fixed.
- Bugs related to detection and selection of unspent outputs have been fixed.
- JSON-RPC 1.x responses now use the expected HTTP error codes.
- JSON-RPC error codes now match zcashd more often.

## [0.1.0-alpha.1] - 2025-09-18

Inital alpha release.
