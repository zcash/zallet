#!/usr/bin/env bash
# Bump every release-lockstep package to a new version and update everything
# that records it.
#
#   utils/bump-version.sh 0.1.0-beta.2
#
# Three packages ship as one release and MUST carry one identical version: the
# `zallet` launcher, `zallet-core`, and the backend (`zallet-zebra`). They live
# in separate workspaces (zcash/zallet#540), so no single `cargo` invocation can
# bump them together, and a hand-edit that misses one is only caught later by
# utils/check-lockstep.sh. This script edits all three, plus the derived
# artefacts that embed the version:
#
#   - the trycmd fixtures, whose `as_of_version` is the backend's
#     CARGO_PKG_VERSION (see backends/zebra/tests/acceptance.rs);
#   - the "latest Zallet <phase> release (<version>)" prose in the book;
#   - each component's CHANGELOG, whose `## [Unreleased]` section is promoted to
#     a release heading dated PLANNED (the bump happens on a release branch,
#     before the release date is known; --date sets a real one). A component with
#     no changes for its own audience gets an empty section, which is expected;
#     the packages ship in lockstep, so every file carries every release heading;
#   - every workspace lockfile, via utils/sync-lockfiles.sh.
#
# `tools/gen-copyright` is deliberately NOT bumped: it is a build-time tool with
# its own version, not part of the shipped release.
#
# The script does not commit, tag, or push; it leaves the bump in the working
# tree and prints the release steps it cannot decide for you.
set -euo pipefail
cd "$(dirname "$0")/.."

# Packages whose versions must move in release lockstep. Keep in sync with
# PACKAGES in utils/check-lockstep.sh, which enforces this at CI time.
PACKAGES=(
  zallet/Cargo.toml
  zallet-core/Cargo.toml
  backends/zebra/Cargo.toml
)

# Trees searched for prose that names the current release version.
DOC_PATHS=(README.md book/src)

# Changelogs whose [Unreleased] section is promoted. Each component keeps its own
# for its own audience (the root file is the `zallet` user interface), but all of
# them carry the same release heading because the packages ship in lockstep.
CHANGELOGS=(
  CHANGELOG.md
  zallet-core/CHANGELOG.md
  backends/zebra/CHANGELOG.md
)

# The release date is not known when the version is bumped: the bump lands on a
# release branch and the tag follows review. The heading carries this placeholder
# until then.
DATE="PLANNED"
DRY_RUN=0
DO_CHANGELOG=1
DO_LOCKFILES=1
NEW=""

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: utils/bump-version.sh <new-version> [options]

  --date YYYY-MM-DD   Date for the CHANGELOG release heading. Defaults to the
                      PLANNED placeholder; pass `today` for today's UTC date.
  --skip-changelog    Leave the changelogs alone (e.g. re-running after a partial bump).
  --skip-lockfiles    Do not regenerate the lockfiles; still runs check-lockstep.sh.
  -n, --dry-run       Show the diff that would be applied and exit without writing.
  -h, --help          This message.
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --date) [[ $# -ge 2 ]] || die "--date needs an argument"; DATE="$2"; shift 2 ;;
    --skip-changelog) DO_CHANGELOG=0; shift ;;
    --skip-lockfiles) DO_LOCKFILES=0; shift ;;
    -n|--dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage ;;
    -*) die "unknown option: $1" ;;
    *) [[ -z "$NEW" ]] || die "unexpected extra argument: $1"; NEW="$1"; shift ;;
  esac
done

[[ -n "$NEW" ]] || usage

# Cargo requires semver; a malformed version would be rejected only once the
# lockfile regeneration ran, after every file had already been rewritten.
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] \
  || die "not a semver version: $NEW"

[[ "$DATE" == "today" ]] && DATE="$(date -u +%Y-%m-%d)"
[[ "$DATE" == "PLANNED" || "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
  || die "not a YYYY-MM-DD date: $DATE"

# --- Reading and writing -----------------------------------------------------

# The `version` key of a manifest's [package] table. Restricted to that table so
# a `version` inside [patch.crates-io] or a dependency entry can never match.
package_version() {
  awk '
    /^\[package\]/ { inpkg = 1; next }
    /^\[/ { inpkg = 0 }
    inpkg && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
  '
}

# Replaces a file with the content on stdin, reporting what changed. Under
# --dry-run nothing is written and the diff is shown instead.
apply() {
  local path="$1" tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if cmp -s "$path" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    diff -u --label "a/$path" --label "b/$path" "$path" "$tmp" || true
    rm -f "$tmp"
  else
    # Preserve the original mode; mktemp creates 0600.
    cat "$tmp" >"$path"
    rm -f "$tmp"
    echo "  updated $path"
  fi
  return 0
}

# --- Determine the versions being replaced -----------------------------------

# Prose and fixtures spell the version out, so replacing them needs the string
# being superseded. Take it from every lockstep manifest AND from their state at
# HEAD: a tree part-way through a hand-rolled bump has more than one, and the
# committed version is the one the derived files were generated against.
declare -A stale_set=()
committed=""
for pkg in "${PACKAGES[@]}"; do
  [[ -f "$pkg" ]] || die "missing manifest: $pkg (run from a full checkout)"
  v="$(package_version <"$pkg")"
  [[ -n "$v" ]] || die "no [package] version found in $pkg"
  [[ "$v" == "$NEW" ]] || stale_set["$v"]=1

  if h="$(git show "HEAD:$pkg" 2>/dev/null | package_version)" && [[ -n "$h" ]]; then
    [[ "$h" == "$NEW" ]] || stale_set["$h"]=1
    # zallet-core is the reference for "what the last commit called itself".
    [[ "$pkg" == "zallet-core/Cargo.toml" ]] && committed="$h"
  fi
done
[[ -n "$committed" ]] || committed="$(package_version <zallet-core/Cargo.toml)"

if [[ "${#stale_set[@]}" -eq 0 ]]; then
  echo "All lockstep packages are already at $NEW; checking derived files anyway."
else
  echo "Bumping to $NEW (replacing: ${!stale_set[*]})"
fi

# The pre-release identifier ("alpha", "beta", ...); empty once a release is
# final, which reads as "stable".
prerelease_phase() {
  sed -n 's/^[0-9.]*-\([0-9A-Za-z]*\).*/\1/p' <<<"$1"
}
new_phase="$(prerelease_phase "$NEW")"
old_phase="$(prerelease_phase "$committed")"

if [[ "$old_phase" != "$new_phase" ]]; then
  cat >&2 <<EOF

WARNING: release phase change, ${old_phase:-stable} -> ${new_phase:-stable}.
This script does NOT automate it, because it renames user-facing CLI flags.
The previous phase change (commit bf1917e) also had to update:
  - the --this-is-${old_phase:-PHASE}-code-... gate flags, their clap fields, the
    Fluent terms and message ids, and every fixture and CI job passing them;
  - the "Current phase" sections of README.md and book/src/README.md, and the
    installation guide's packaging warning.
EOF
fi
echo

# The superseded versions, one per line, for the awk passes below. Command
# substitution cannot carry them: `$(cat file)` strips trailing newlines, which
# would silently truncate the blank line at the end of a golden fixture.
STALE_FILE="$(mktemp)"
trap 'rm -f "$STALE_FILE"' EXIT
[[ "${#stale_set[@]}" -gt 0 ]] && printf '%s\n' "${!stale_set[@]}" >"$STALE_FILE"

# --- 1. Manifests ------------------------------------------------------------

echo "Package manifests:"
for pkg in "${PACKAGES[@]}"; do
  awk -v new="$NEW" '
    /^\[package\]/ { inpkg = 1; print; next }
    /^\[/ { inpkg = 0 }
    inpkg && $1 == "version" && !done { print "version = \"" new "\""; done = 1; next }
    { print }
  ' "$pkg" | apply "$pkg" || echo "  unchanged $pkg"
done
echo

# --- 2. trycmd fixtures ------------------------------------------------------

# `as_of_version` in a golden config is the backend's own CARGO_PKG_VERSION, so
# substituting the literal is exactly what regenerating the fixture would do.
echo "Test fixtures (as_of_version):"
fixtures=()
while IFS= read -r f; do fixtures+=("$f"); done < <(
  grep -rl --include='*.toml' '^as_of_version = ' backends/*/tests 2>/dev/null | sort
)
if [[ "${#fixtures[@]}" -eq 0 ]]; then
  echo "  none found"
else
  for f in "${fixtures[@]}"; do
    # Keyed on FILENAME rather than the usual `NR == FNR`: with nothing to
    # replace (a re-run after the bump was committed) the stale file is empty,
    # and NR == FNR would then be true for the fixture itself -- loading its
    # lines into the lookup table and printing nothing, i.e. truncating it.
    awk -v new="$NEW" -v stalefile="$STALE_FILE" '
      FILENAME == stalefile { stale["as_of_version = \"" $0 "\""] = 1; next }
      $0 in stale { print "as_of_version = \"" new "\""; next }
      { print }
    ' "$STALE_FILE" "$f" | apply "$f" || echo "  unchanged $f"
  done
fi
echo

# --- 3. Prose that names the current release ---------------------------------

# Only the anchored "latest Zallet <phase> release (<version>)" form is rewritten.
# A blanket search-and-replace would corrupt the deliberately historical mentions:
# past CHANGELOG headings and MIN_COMPATIBLE_ZALLET_VERSION both name old
# versions on purpose.
echo "Documentation:"
doc_hits=()
for old in "${!stale_set[@]}"; do
  while IFS= read -r f; do doc_hits+=("$f"); done < <(
    grep -rlF --include='*.md' "release ($old)" "${DOC_PATHS[@]}" 2>/dev/null
  )
done
if [[ "${#doc_hits[@]}" -eq 0 ]]; then
  echo "  no version-naming prose found"
else
  # The phase word travels with the version: "latest Zallet alpha release
  # (0.1.0-alpha.4)" must not become "latest Zallet alpha release (0.1.0-beta.1)".
  sed_args=()
  for old in "${!stale_set[@]}"; do
    sed_args+=(-e
      "s/(latest Zallet )[0-9A-Za-z]+( release \()${old//./\\.}(\))/\1${new_phase:-stable}\2$NEW\3/g")
  done
  while IFS= read -r f; do
    sed -E "${sed_args[@]}" "$f" | apply "$f" || echo "  unchanged $f"
  done < <(printf '%s\n' "${doc_hits[@]}" | sort -u)
fi
echo

# --- 4. CHANGELOG ------------------------------------------------------------

if [[ "$DO_CHANGELOG" -eq 1 ]]; then
  echo "Changelogs:"
  for cl in "${CHANGELOGS[@]}"; do
    [[ -f "$cl" ]] || die "missing changelog: $cl"
    grep -q '^## \[Unreleased\]' "$cl" || die "no '## [Unreleased]' heading in $cl"

    if existing="$(grep -m1 "^## \[$NEW\]" "$cl")"; then
      # Re-running with a real --date is how the PLANNED placeholder is settled.
      awk -v heading="## [$NEW] - $DATE" -v want="## [$NEW]" '
        index($0, want) == 1 && !done { print heading; done = 1; next }
        { print }
      ' "$cl" | apply "$cl" \
        || echo "  unchanged $cl (already has \"$existing\")"
      continue
    fi

    # Everything currently under [Unreleased] becomes the release; [Unreleased]
    # stays as an empty heading for the next cycle.
    # Note: awk's `exit` still runs END, so the verdict is carried in a flag
    # rather than by exiting from the matching rule.
    if ! awk '
      /^## \[Unreleased\]/ { inunrel = 1; next }
      inunrel && /^## \[/ { inunrel = 0 }
      inunrel && NF { found = 1 }
      END { exit found ? 0 : 1 }
    ' "$cl"; then
      # Expected whenever a component saw no changes for its own audience this
      # cycle, so this is a note rather than a warning.
      echo "  note: $cl has no [Unreleased] entries; releasing an empty section." >&2
    fi
    awk -v heading="## [$NEW] - $DATE" '
      /^## \[Unreleased\]/ && !done { print; print ""; print heading; done = 1; next }
      { print }
    ' "$cl" | apply "$cl" || echo "  unchanged $cl"
  done
  echo
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run: nothing written, lockfiles not regenerated."
  exit 0
fi

# --- 5. Lockfiles ------------------------------------------------------------

# The workspace lockfiles each record the bumped packages' versions, so they must be
# reconciled before the tree builds. sync-lockfiles.sh finishes by running
# check-lockstep.sh, which is what catches a manifest this script failed to bump.
if [[ "$DO_LOCKFILES" -eq 1 ]]; then
  echo "Lockfiles:"
  utils/sync-lockfiles.sh
else
  echo "Skipping lockfile regeneration; verifying lockstep only:"
  utils/check-lockstep.sh
fi

# --- Residual steps ----------------------------------------------------------

cat <<EOF

Bumped to $NEW. Remaining release steps, which need a human decision:

  * CHANGELOG: confirm the [$NEW] section describes only public API changes.
  * MIN_COMPATIBLE_ZALLET_VERSION (zallet-core/src/components/database.rs):
    bump to $NEW only if this release changes the wallet database in a way
    older Zallet versions cannot read. Its tests encode the current value.
  * cargo vet: if the lockfile regeneration pulled in new dependencies, run
    \`cargo vet\` in each of . and backends/zebra.
  * Commit the result, then tag \`v$NEW\` to trigger .github/workflows/release.yml.
EOF

if [[ "$DO_CHANGELOG" -eq 1 && "$DATE" == "PLANNED" ]]; then
  cat <<EOF
  * The [$NEW] changelog heading is dated PLANNED. Settle it when you tag:
    \`utils/bump-version.sh $NEW --date today --skip-lockfiles\`
EOF
fi

if [[ "$old_phase" != "$new_phase" ]]; then
  echo "  * The phase change to ${new_phase:-stable} reported above is still outstanding."
fi
