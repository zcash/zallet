#!/usr/bin/env bash
# Regenerate the workspace lockfiles from their manifests and verify that
# wallet-critical dependencies resolve in lockstep across all of them.
#
# Each chain backend lives in its own workspace with its own lockfile
# (zcash/zallet#540), but every binary (the `zallet` launcher and
# `zallet-zebra`) opens the SAME wallet database. The
# librustzcash stack (zcash_client_sqlite and the crates whose types it
# persists) must therefore resolve to one identical version in every workspace,
# or the binaries could apply different schema migrations to the shared database.
# utils/check-lockstep.sh enforces that invariant.
#
# The librustzcash crates are consumed as released crates.io versions, so the
# source of truth is the version requirement declared in each manifest, not a
# shared [patch.crates-io] git rev. This script does NOT edit those
# requirements: it reconciles each lockfile with its manifest so the committed
# lockfiles match what the manifests resolve to, then runs the lockstep check.
#
#   utils/sync-lockfiles.sh
#
# Run this after bumping any shared dependency. When you bump a librustzcash
# crate you MUST apply the identical version requirement to every manifest
# (root Cargo.toml plus backends/zebra/Cargo.toml) by hand first; the lockstep check fails if they drift. Then run this to
# regenerate the lockfiles.
#
# On an already-in-lockstep tree this is a no-op (CI runs it and asserts an empty
# `git diff`), so a non-empty diff means the committed lockfiles had drifted from
# what the manifests resolve to.
set -euo pipefail
cd "$(dirname "$0")/.."

# Workspace dirs whose lockfiles are reconciled together.
DIRS=(. backends/zebra)

# Reconcile each lockfile with its manifest. `cargo metadata` re-resolves only
# what changed and rewrites Cargo.lock without churning unrelated dependencies.
# (`cargo update -p <name>` is unusable here: crates such as zcash_primitives
# exist at two versions in the graph, making a bare package spec ambiguous.)
for d in "${DIRS[@]}"; do
  echo "  ${d}: cargo metadata (reconciling lockfile)"
  ( cd "$d" && cargo metadata --format-version 1 >/dev/null )
done

# Self-verify that the graphs are in lockstep.
echo
exec "$(dirname "$0")/check-lockstep.sh"
