#!/usr/bin/env bash
# Sync the librustzcash [patch.crates-io] pin to a single git rev across all
# three workspace manifests (root, backends/zebra, backends/zaino) and refresh
# each lockfile so the wallet-critical crates resolve identically.
#
# This is the ONLY supported way to move the librustzcash ref. All three
# binaries open the same wallet database, so zcash_client_sqlite (and the rest
# of the librustzcash stack) MUST resolve to one identical rev in every
# workspace; utils/check-lockstep.sh enforces that in CI. Hand-editing a single
# manifest drifts the resolution graphs and breaks the lockstep check. Run this
# instead:
#
#   utils/sync-librustzcash.sh <git-rev>
#
# With no argument it reuses the rev currently pinned in the root Cargo.toml,
# which re-syncs the backends and regenerates the lockfiles idempotently (this
# is what CI runs to verify the tree is in lockstep).
#
# Only the librustzcash pins are touched: the age/zewif/zaino pins point at
# other repositories and are left untouched.
set -euo pipefail
cd "$(dirname "$0")/.."

# Workspace dirs and their manifests, index-aligned.
DIRS=(. backends/zebra backends/zaino)
MANIFESTS=(Cargo.toml backends/zebra/Cargo.toml backends/zaino/Cargo.toml)
LIBRUSTZCASH_GIT='https://github.com/zcash/librustzcash.git'

# The librustzcash rev currently pinned at the root, used as the default target.
current_root_rev() {
  awk -v url="$LIBRUSTZCASH_GIT" '
    index($0, url) && match($0, /rev = "[0-9a-f]+"/) {
      s = substr($0, RSTART, RLENGTH)
      gsub(/rev = "|"/, "", s)
      print s
      exit
    }
  ' Cargo.toml
}

REV="${1:-$(current_root_rev)}"

if [[ ! "$REV" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "error: '$REV' is not a valid git rev (expected 7-40 hex chars)." >&2
  echo "usage: $(basename "$0") <librustzcash-git-rev>" >&2
  exit 2
fi

echo "Syncing librustzcash pin to $REV across ${#MANIFESTS[@]} manifests..."

# 1. Rewrite the rev on every line that patches a crate from librustzcash.git.
#    Portable in-place edit (works with both BSD and GNU sed).
esc_url="${LIBRUSTZCASH_GIT//./\\.}"
for m in "${MANIFESTS[@]}"; do
  tmp="$(mktemp)"
  sed -E "s#(${esc_url}\", rev = \")[0-9a-f]{7,40}#\\1${REV}#g" "$m" > "$tmp"
  mv "$tmp" "$m"
done

# 2. Reconcile each lockfile with the edited manifest. Changing a [patch] rev
#    makes cargo re-resolve only the affected crates on the next lockfile-aware
#    command, so `cargo metadata` regenerates each Cargo.lock without churning
#    unrelated dependencies. (`cargo update -p <name>` is unusable here: a crate
#    such as zcash_transparent exists at two versions in the graph, making a
#    bare package spec ambiguous.)
for d in "${DIRS[@]}"; do
  echo "  ${d}: cargo metadata (reconciling lockfile)"
  ( cd "$d" && cargo metadata --format-version 1 >/dev/null )
done

# 3. Self-verify that the three graphs are back in lockstep.
echo
exec "$(dirname "$0")/check-lockstep.sh"
