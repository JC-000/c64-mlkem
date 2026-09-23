#!/bin/sh
# check_precalc.sh — contract §8.4: src/precalc_table.inc is a byte-for-byte
# copy of the contract's root precalc_table.inc AT THE CONTRACT HEAD, and is
# never hand-edited.
#
#   check_precalc.sh <contract repo dir>
#
# The comparand is `origin/HEAD:precalc_table.inc` from the contract repo's git
# object store, NOT the file in its working tree: that checkout may sit on any
# branch, and a stale working copy would make a stale local copy compare equal.
# Run `git -C <dir> fetch --tags origin` first for a current origin/HEAD; this
# check never touches the network.
#
# Fails (exit 1) on a difference and on an unreadable comparand — a missing
# contract checkout is not a pass.
set -eu
cd "$(dirname "$0")/.."

dir=${1:-}
local_copy=src/precalc_table.inc
refresh="git -C $dir fetch --tags origin && git -C $dir show origin/HEAD:precalc_table.inc > $local_copy"

[ -n "$dir" ] && [ -d "$dir" ] || {
    echo "FAIL: check-precalc: contract repo not found at '${dir}'. Set CONTRACT_DIR=<path to c64-lib-contract>."
    exit 1
}

tmp=$(mktemp "${TMPDIR:-/tmp}/check_precalc.XXXXXX")
trap 'rm -f "$tmp"' EXIT
if ! git -C "$dir" show origin/HEAD:precalc_table.inc > "$tmp" 2>/dev/null || [ ! -s "$tmp" ]; then
    echo "FAIL: check-precalc: cannot read origin/HEAD:precalc_table.inc from $dir"
    echo "      (fetch it: git -C $dir fetch --tags origin; git -C $dir remote set-head origin -a)"
    exit 1
fi
ver=$(git -C "$dir" show origin/HEAD:SPEC.md 2>/dev/null | sed -n 's/^\*\*Version:\*\* *\([^ ]*\).*/\1/p' | head -n 1)

if cmp -s "$tmp" "$local_copy"; then
    echo "check-precalc: OK $local_copy is byte-identical to contract head (SPEC ${ver:-?}) precalc_table.inc (§8.4)"
    exit 0
fi

echo "FAIL: check-precalc: $local_copy differs from the contract head (SPEC ${ver:-?}) precalc_table.inc."
echo '      §8.4: "Adopters copy it verbatim ... and MUST NOT hand-edit their copy". Refresh with:'
echo "        $refresh"
echo "      then rebuild (it is .include'd by src/lib_manifest.s). First differing byte:"
cmp "$tmp" "$local_copy" | sed 's/^/        /' || true
exit 1
