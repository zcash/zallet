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

## [0.1.0-beta.3] - 2026-08-24

### Fixed

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

- Wallet scans now discard and reacquire a fixed chain view when a pinned block,
  Sapling tree, Orchard tree, or Ironwood tree has reorged away.

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
