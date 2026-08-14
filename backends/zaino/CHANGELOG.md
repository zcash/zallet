# zallet-zaino Changelog

All notable changes specific to the **`zallet-zaino` binary** are documented in
this file. This backend embeds the Zaino chain indexer, so its changes are mostly
about which Zaino it is built against and what that implies for the indexer's own
on-disk data. It is written for operators running this backend.

Changes to the wallet's user interface — the JSON-RPC methods, the CLI, the
configuration file, the wallet database, and the release artifacts — are in the
[repository-root changelog](../../CHANGELOG.md), and apply to this backend too.

All packages in the repository move in release lockstep and share one version
number. This file begins at 0.1.0-beta.2, the first release after `zallet-zaino`
gained its own changelog; earlier history for the whole project is in the root
changelog.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Prior to the 1.0.0 release, no Semantic Versioning is followed; all releases
should be considered breaking changes.

## [Unreleased]

### Fixed

- The optional `[indexer.read_state_service]` mode no longer livelocks when
  `zebrad` (v6.2.1–v6.3.0) drops the `non_finalized_state_change` stream
  during its initial send
  ([ZcashFoundation/zebra#11265](https://github.com/ZcashFoundation/zebra/issues/11265)):
  the zebra crates are temporarily consumed from a patched branch whose
  read-state syncer catches up to the validator's tip over unary `get_block`
  calls before subscribing, backs off between failed subscription attempts,
  and keeps publishing the finalized tip until the first non-finalized block
  commits. The default JSON-RPC mode is unaffected.

- The chain view no longer substitutes an empty note commitment tree when the
  validator reports no treestate for a pool at or after that pool's activation
  height. Previously any such read — for Sapling, Orchard, or Ironwood — was
  treated as "this pool is not active yet, so its tree is empty", which stored a
  placeholder frontier that nothing validates and that only surfaced later, as
  an unrecoverable `shardtree` conflict, once a correct frontier disagreed with
  it. Such reads are now reported as a transient chain error so sync retries.
  Reads below a pool's activation height are unaffected.

  This backend was not implicated in the reports that prompted the fix, which
  were all on `zallet-zebra`; the same unguarded fallback existed here.

## [0.1.0-beta.2] - 2026-07-28

### Changed

- Now built against `zaino-state` 0.5 and `zaino-common` / `zaino-fetch` 0.4, up
  from `zaino-state` 0.3 and `zaino-common` / `zaino-fetch` 0.2, and against the
  `zebra-chain` 11.3 / `zebra-rpc` 15.0 / `zebra-state` 12.0.1 cohort that builds
  against `zcash_primitives` 0.30.
- The temporary Zaino source pin now points at the `zodl-inc/zaino` branch
  carrying that librustzcash bump, rather than at `zingolabs/zaino`. As before,
  the pin exists because Zaino must surface the Ironwood (NU6.3) note commitment
  treestate from `get_treestate` for Ironwood notes to be spendable; an empty
  frontier conflicts with the wallet's advancing tree and sync fails with
  `CheckpointConflict`. The pin is removed once that work lands in a Zaino
  release (zingolabs/zaino#1428).
