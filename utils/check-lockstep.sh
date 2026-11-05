#!/usr/bin/env bash
# Verify wallet-critical dependency lockstep across the resolution graphs
# (root, backends/zebra).
#
# The split-workspace design (issue #540) deliberately lets each backend
# lockfile diverge on its own chain-source dependency tree (zebra-*) — that is
# the point of the split, so a zebra bump touches only backends/zebra. Those
# crates are intentionally NOT checked here.
#
# Everything that touches persisted wallet state must NOT diverge: every
# binary opens the same wallet database, so a drifted zcash_client_sqlite (or
# rusqlite, or any other wallet-critical crate) could apply different schema
# migrations depending on which binary ran first. This script fails CI when any
# such crate resolves to a different set of versions/sources in one lockfile, and
# when the shipped package versions drift out of release lockstep.
set -euo pipefail
cd "$(dirname "$0")/.."

LOCKFILES=(Cargo.lock backends/zebra/Cargo.lock)
MANIFESTS=(Cargo.toml backends/zebra/Cargo.toml)

# Packages whose versions must move in release lockstep.
PACKAGES=(
  zallet/Cargo.toml
  zallet-core/Cargo.toml
  backends/zebra/Cargo.toml
)

# The wallet-critical librustzcash stack: zcash_client_sqlite (which owns the
# database schema and migrations) plus the crates whose types it persists. These
# are consumed as released crates.io versions rather than a shared [patch] git
# rev, so their names can no longer be scraped from the patch block -- they are
# listed explicitly here. Package names are as they appear in Cargo.lock (i.e.
# the published crate name, not any local `package = "..."` alias).
WALLET_CRATES=(
  equihash
  f4jumble
  orchard
  sapling-crypto
  zcash_address
  zcash_client_backend
  zcash_client_sqlite
  zcash_encoding
  zcash_history
  zcash_keys
  zcash_note_encryption
  zcash_primitives
  zcash_proofs
  zcash_protocol
  zcash_script
  zcash_spec
  zcash_transparent
  zip321
)

# Additional lockstep set: the union of [patch.crates-io] package names across
# the workspace manifests (honouring `package = "..."` renames) so that a
# shared patched crate such as `age` stays consistent, plus wallet-database
# crates that are neither patched nor part of the librustzcash stack.
EXTRA_CRATES=(rusqlite)

patch_crates() {
  awk '
    /^\[patch\.crates-io\]/ { inpatch = 1; next }
    /^\[/ { inpatch = 0 }
    inpatch && /^[A-Za-z0-9_-]+[[:space:]]*=/ {
      name = $1
      if (match($0, /package[[:space:]]*=[[:space:]]*"[^"]+"/)) {
        renamed = substr($0, RSTART, RLENGTH)
        gsub(/package[[:space:]]*=[[:space:]]*"|"$/, "", renamed)
        name = renamed
      }
      print name
    }
  ' "$@" | sort -u
}

# Prints the full, sorted set of "version source" lines a crate resolves to in a
# lockfile (one per line; source may be empty), or nothing if the crate is absent
# from that graph. Released crates permit more than one major version in a single
# graph, so a crate can legitimately have several entries -- the whole set must
# match across lockfiles, not just an arbitrary first entry.
resolved() {
  local crate="$1" lockfile="$2"
  awk -v crate="$crate" '
    # Only [[package]] stanzas count: [[patch.unused]] stanzas also carry
    # name/version lines but describe patches absent from the graph. A stanza
    # ends at a blank line or the next [[...]] header.
    function flush() {
      if (inpkg && name == crate) print version, source
      inpkg = 0; name = ""; version = ""; source = ""
    }
    /^\[\[package\]\]/ { flush(); inpkg = 1; next }
    /^\[\[/ { flush(); next }
    /^$/ { flush(); next }
    inpkg && $1 == "name" { gsub(/"/, "", $3); name = $3 }
    inpkg && $1 == "version" { gsub(/"/, "", $3); version = $3 }
    inpkg && $1 == "source" { gsub(/"/, "", $3); source = $3 }
    END { flush() }
  ' "$lockfile" | sort
}

fail=0

# The zebra-* tree is the divergence the split exists to allow (see the header
# above): a backend pinning its own chain-source crates via [patch.crates-io]
# must not drag the other workspaces into lockstep with it.
mapfile -t lockstep_crates < <(patch_crates "${MANIFESTS[@]}" | grep -Ev '^zebra-')
lockstep_crates+=("${WALLET_CRATES[@]}" "${EXTRA_CRATES[@]}")
# De-duplicate in case an explicit wallet crate is also patched.
mapfile -t lockstep_crates < <(printf '%s\n' "${lockstep_crates[@]}" | sort -u)

for crate in "${lockstep_crates[@]}"; do
  declare -A seen=()
  present=0
  for lf in "${LOCKFILES[@]}"; do
    # The resolved set is multiline; collapse it to a single comparable
    # signature. An empty signature means the crate is absent from this graph.
    r="$(resolved "$crate" "$lf" | paste -sd'|' -)"
    if [[ -n "$r" ]]; then
      present=$((present + 1))
      seen["$r"]+="$lf "
    fi
  done
  if [[ "${#seen[@]}" -gt 1 ]]; then
    echo "LOCKSTEP VIOLATION: $crate resolves to different versions across lockfiles:" >&2
    for r in "${!seen[@]}"; do
      echo "  {${r//|/, }}  <- ${seen[$r]}" >&2
    done
    fail=1
  elif [[ "$present" -eq 0 ]]; then
    echo "note: wallet-critical crate $crate is not present in any lockfile" >&2
  fi
  unset seen
done

version_of() {
  awk '$1 == "version" { gsub(/"/, "", $3); print $3; exit }' "$1"
}

first_version="$(version_of "${PACKAGES[0]}")"
for pkg in "${PACKAGES[@]}"; do
  v="$(version_of "$pkg")"
  if [[ "$v" != "$first_version" ]]; then
    echo "LOCKSTEP VIOLATION: package version drift: ${PACKAGES[0]}=$first_version but $pkg=$v" >&2
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "" >&2
  echo "Wallet-critical dependencies must resolve identically in every" >&2
  echo "lockfile; align the version requirements across the root and backend" >&2
  echo "manifests, then run utils/sync-lockfiles.sh. See utils/check-lockstep.sh." >&2
  exit 1
fi

echo "Lockstep OK: ${#lockstep_crates[@]} crates + ${#PACKAGES[@]} package versions consistent across ${#LOCKFILES[@]} lockfiles."
