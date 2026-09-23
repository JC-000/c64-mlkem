#!/bin/sh
# check_precalc.sh — contract §8.4: src/precalc_table.inc is a byte-for-byte
# copy of the contract's root precalc_table.inc AT THE PINNED CONTRACT REF, and
# is never hand-edited ("Adopters copy it verbatim ... and MUST NOT hand-edit
# their copy").
#
#   check_precalc.sh <contract repo dir> <contract ref>
#
# The comparand is `<ref>:precalc_table.inc` from the contract repo's git
# object store — a TAG, pinned by CONTRACT_PRECALC_REF in the Makefile — never
# the moving origin/HEAD and never the working tree. An upstream comment edit
# therefore cannot turn this repo red with no change here, and the result does
# not depend on when anyone last fetched. The pin moves deliberately, when
# this library adopts a new contract tag. This check never touches the network.
#
# Fails (exit 1) on a difference and on an unreadable comparand — a missing
# contract checkout or a missing ref is not a pass.
set -eu
cd "$(dirname "$0")/.."

dir=${1:-}
ref=${2:-}
local_copy=src/precalc_table.inc
refresh="git -C $dir show $ref:precalc_table.inc > $local_copy"

[ -n "$dir" ] && [ -d "$dir" ] || {
    echo "FAIL: check-precalc: contract repo not found at '${dir}'. Set CONTRACT_DIR=<path to c64-lib-contract>."
    exit 1
}
[ -n "$ref" ] || { echo "FAIL: check-precalc: no contract ref given (CONTRACT_PRECALC_REF)"; exit 1; }

tmp=$(mktemp "${TMPDIR:-/tmp}/check_precalc.XXXXXX")
trap 'rm -f "$tmp"' EXIT
if ! git -C "$dir" show "$ref:precalc_table.inc" > "$tmp" 2>/dev/null || [ ! -s "$tmp" ]; then
    echo "FAIL: check-precalc: cannot read $ref:precalc_table.inc from $dir"
    echo "      (missing tag? git -C $dir fetch --tags origin)"
    exit 1
fi
ver=$(git -C "$dir" show "$ref:SPEC.md" 2>/dev/null | sed -n 's/^\*\*Version:\*\* *\([^ ]*\).*/\1/p' | head -n 1)

if cmp -s "$tmp" "$local_copy"; then
    echo "check-precalc: OK $local_copy is byte-identical to contract $ref (SPEC ${ver:-?}) precalc_table.inc (§8.4)"
    exit 0
fi

echo "FAIL: check-precalc: $local_copy differs from contract $ref (SPEC ${ver:-?}) precalc_table.inc."
echo '      §8.4: "Adopters copy it verbatim ... and MUST NOT hand-edit their copy". Refresh with:'
echo "        $refresh"
echo "      then rebuild (it is .include'd by src/lib_manifest.s). First differing byte:"
cmp "$tmp" "$local_copy" | sed 's/^/        /' || true
exit 1
