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

### Fixed

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
