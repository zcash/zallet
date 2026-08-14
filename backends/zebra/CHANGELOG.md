# zallet-zebra Changelog

All notable changes specific to the **`zallet-zebra` binary** are documented in
this file. This backend reads a local `zebrad`'s state directly, so its changes
are mostly about which `zebrad` it interoperates with and how. It is written for
operators running this backend.

Changes to the wallet's user interface — the JSON-RPC methods, the CLI, the
configuration file, the wallet database, and the release artifacts — are in the
[repository-root changelog](../../CHANGELOG.md), and apply to this backend too.

All packages in the repository move in release lockstep and share one version
number. This file begins at 0.1.0-beta.2, the first release after `zallet-zebra`
gained its own changelog; earlier history for the whole project is in the root
changelog.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Prior to the 1.0.0 release, no Semantic Versioning is followed; all releases
should be considered breaking changes.

## [Unreleased]

### Added

- A watchdog now supervises the read-state syncer: if the wallet's chain tip
  stops advancing while the validator's height keeps growing, it logs an
  error identifying the stall (and the likely upstream cause) instead of the
  wallet silently serving stale data, and chain "no tip yet" errors include
  the diagnosis.

### Fixed

- The backend no longer livelocks when `zebrad` (v6.2.1–v6.3.0) drops the
  `non_finalized_state_change` stream during its initial send — the regression
  reported as [ZcashFoundation/zebra#11265], which zebrad logs as
  `slow consumer, dropping non_finalized_state_change stream after buffer filled`
  and which left the wallet's chain tip frozen while both processes spun in a
  full-speed resubscribe cycle. The read-state syncer (`zebra-rpc`, temporarily
  consumed from a patched branch) now catches up to the validator's best tip
  over unary `get_block` calls before every subscription, so the stream's
  initial send stays far below the server-side buffer that triggers the drop;
  it backs off between failed subscription attempts; and it keeps publishing
  the finalized tip until the first non-finalized block actually commits, so a
  failing stream can no longer freeze the reported tip.

[ZcashFoundation/zebra#11265]: https://github.com/ZcashFoundation/zebra/issues/11265

- The chain view no longer substitutes an empty note commitment tree when
  `zebrad` reports no treestate for a finalized block at or after the pool's
  activation height. Previously any such read — for Sapling, Orchard, or
  Ironwood — was silently treated as "this pool is not active yet, so its tree
  is empty".

  That placeholder frontier was then committed to the wallet's note commitment
  tree. Nothing catches it: `put_blocks` appears to validate the chain state it
  is handed, but the scanned block's final tree size is itself derived from that
  chain state, so the check is circular and a wrong frontier of any size passes.
  The damage only surfaced later, when a correct frontier disagreed with what
  had been stored, as an `Insert(Conflict(..))` from `shardtree` — reported as
  `PutBlocksCommitmentTree`. Because `put_blocks` is transactional, the failing
  write rolled back and every subsequent start hit the same conflict, leaving
  the wallet crash-looping until it was manually rewound with
  `zallet repair truncate-wallet`.

  `zebrad` treats a missing post-activation tree as an invariant violation
  rather than an empty tree, but only on its by-height lookup path; this backend
  reads by block hash, which resolves the hash to a height first and reports no
  tree if that resolution fails, bypassing the check. Such reads are now
  reported as a transient chain error, so sync retries instead of corrupting the
  wallet. Reads below a pool's activation height, where an absent tree genuinely
  means the empty tree, are unaffected.

## [0.1.0-beta.2] - 2026-07-28

### Changed

- Now built against `zebra-state` 12 (with the `indexer` feature) and
  `zebra-rpc` 15, up from `zebra-state` 10 and `zebra-rpc` 11, matching the
  Zebra cohort that builds against `zcash_primitives` 0.30.

  The on-disk state format this backend requires is **unchanged** at version
  28.0.0, so an existing `zebrad` state cache is still readable and does not
  need to be resynced. As before, the `zebrad` writing that cache must be built
  with the `indexer` feature and configured with an `indexer_listen_addr`; see
  the [setup guide](../../book/src/guide/setup.md) for the full requirements.
