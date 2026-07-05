#!/usr/bin/env bash
# Verify wallet-critical dependency lockstep across the three resolution graphs
# (root, backends/zebra, backends/zaino).
#
# The split-workspace design (issue #540) deliberately lets the two backend
# lockfiles diverge on the zebra-* and zaino-* dependency trees — that is the
# point of the split, so a zebra bump touches only backends/zebra and a Zaino
# bump only backends/zaino. Those crates are intentionally NOT checked here.
#
# Everything that touches persisted wallet state must NOT diverge: all three
# binaries open the same wallet database, so a drifted zcash_client_sqlite (or
# rusqlite, or any crate in the librustzcash patch block) could apply different
# schema migrations depending on which binary ran first. This script fails CI
# when any such crate resolves to a different version/source in one lockfile,
# and when the shipped package versions drift out of release lockstep.
set -euo pipefail
cd "$(dirname "$0")/.."

LOCKFILES=(Cargo.lock backends/zebra/Cargo.lock backends/zaino/Cargo.lock)
MANIFESTS=(Cargo.toml backends/zebra/Cargo.toml backends/zaino/Cargo.toml)

# Packages whose versions must move in release lockstep.
PACKAGES=(
  zallet/Cargo.toml
  zallet-core/Cargo.toml
  backends/zebra/Cargo.toml
  backends/zaino/Cargo.toml
  crates/zebra-read-state/Cargo.toml
)

# The lockstep set: the union of [patch.crates-io] package names across the
# three workspace manifests (honouring `package = "..."` renames), plus crates
# that touch the shared wallet database but are not patched.
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

# Prints "version source" (source may be empty) for a crate in a lockfile, or
# nothing if the crate is absent from that graph.
resolved() {
  local crate="$1" lockfile="$2"
  awk -v crate="$crate" '
    # Only [[package]] stanzas count: [[patch.unused]] stanzas also carry
    # name/version lines but describe patches absent from the graph.
    /^\[\[package\]\]/ { inpkg = 1; name = ""; version = ""; source = ""; next }
    /^\[\[/ { inpkg = 0 }
    inpkg && $1 == "name" { gsub(/"/, "", $3); name = $3 }
    inpkg && $1 == "version" { gsub(/"/, "", $3); version = $3 }
    inpkg && $1 == "source" { gsub(/"/, "", $3); source = $3 }
    /^$/ && inpkg && name == crate { print version, source; exit }
    END { if (inpkg && name == crate) print version, source }
  ' "$lockfile"
}

fail=0

mapfile -t lockstep_crates < <(patch_crates "${MANIFESTS[@]}")
lockstep_crates+=("${EXTRA_CRATES[@]}")

for crate in "${lockstep_crates[@]}"; do
  declare -A seen=()
  present=0
  for lf in "${LOCKFILES[@]}"; do
    r="$(resolved "$crate" "$lf")"
    if [[ -n "$r" ]]; then
      present=$((present + 1))
      seen["$r"]+="$lf "
    fi
  done
  if [[ "${#seen[@]}" -gt 1 ]]; then
    echo "LOCKSTEP VIOLATION: $crate resolves differently across lockfiles:" >&2
    for r in "${!seen[@]}"; do
      echo "  $r  <- ${seen[$r]}" >&2
    done
    fail=1
  elif [[ "$present" -eq 0 ]]; then
    echo "note: patched crate $crate is not present in any lockfile (unused patch?)" >&2
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
  echo "Wallet-critical dependencies must resolve identically in all three" >&2
  echo "lockfiles; re-sync the [patch.crates-io] blocks and run 'cargo update" >&2
  echo "-p <crate>' in the divergent workspace. See utils/check-lockstep.sh." >&2
  exit 1
fi

echo "Lockstep OK: ${#lockstep_crates[@]} crates + ${#PACKAGES[@]} package versions consistent across ${#LOCKFILES[@]} lockfiles."
