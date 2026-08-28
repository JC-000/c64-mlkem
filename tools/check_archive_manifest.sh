#!/bin/sh
# check_archive_manifest.sh — contract §6.4: the manifest describes the archive
# it ships in. Extracts mlkem_lib_manifest.o from ONE archive and pins its §5 /
# §8.0 / §8.4 export VALUES with od65.
#
#   check_archive_manifest.sh <archive> <PRIMITIVES> <CONSUMES> <RESIDENT> <rows>
#
#   PRIMITIVES / CONSUMES   expected §8.0 masks (decimal)
#   RESIDENT                expected LIB_MLKEM_RESIDENT_BYTES
#   rows                    expected number of §8.4 LIB_PRECALC_TABLE rows;
#                           each emits exactly three LIB_MLKEM_PRECALC_*
#                           exports and NO bare LIB_PRECALC_* export
#
# Reads the extracted OBJECT, never the archive: od65 pointed at an .a prints
# "(no xo65 object file)" and exits 0 with no symbols — a silent pass.
set -eu
cd "$(dirname "$0")/.."

a=$1; want_prim=$2; want_cons=$3; want_res=$4; want_rows=$5
member=mlkem_lib_manifest.o
[ -f "$a" ] || { echo "FAIL: $a missing"; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check_archive_manifest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
abs_a="$(pwd)/$a"
ar65 t "$abs_a" | grep -qx "$member" || { echo "FAIL: $a has no $member member"; exit 1; }
(cd "$tmp" && ar65 x "$abs_a" "$member")
[ -s "$tmp/$member" ] || { echo "FAIL: could not extract $member from $a"; exit 1; }

# od65 prints `Name: "sym"` then `Value: 0x... (dec)`; flatten to `sym dec`.
dump=$(od65 --dump-exports "$tmp/$member" \
       | sed -n 's/^ *Name: *"\([^"]*\)".*/\1/p; s/^ *Value: *0x[0-9A-Fa-f]* *(\([0-9]*\)).*/\1/p' \
       | paste -d " " - -)

val() { printf '%s\n' "$dump" | awk -v n="$1" '$1 == n { print $2; found = 1 } END { if (!found) print "MISSING" }'; }

fail=0
expect() {
    got=$(val "$1")
    if [ "$got" != "$2" ]; then
        echo "FAIL: $a: $1 = $got, expected $2 (contract §6.4: the manifest must describe this member set)"
        fail=1
    fi
}
expect LIB_MLKEM_SHARED_PRIMITIVES "$want_prim"
expect LIB_MLKEM_SHARED_CONSUMES   "$want_cons"
expect LIB_MLKEM_RESIDENT_BYTES    "$want_res"
expect LIB_MLKEM_COLD_BYTES        0
expect LIB_MLKEM_ZP_USAGE_BYTES    16
expect LIB_MLKEM_REU_BANKS_USED    0

rows=$(printf '%s\n' "$dump" | grep -c '^LIB_MLKEM_PRECALC_.*_SIZE ' || true)
if [ "$rows" -ne "$want_rows" ]; then
    echo "FAIL: $a: $rows §8.4 row(s) exported, expected $want_rows"; fail=1
fi
triples=$(printf '%s\n' "$dump" | grep -c '^LIB_MLKEM_PRECALC_' || true)
if [ "$triples" -ne $((want_rows * 3)) ]; then
    echo "FAIL: $a: $triples LIB_MLKEM_PRECALC_* exports, expected $((want_rows * 3)) (three per row)"; fail=1
fi
if printf '%s\n' "$dump" | grep -q '^LIB_PRECALC_'; then
    echo "FAIL: $a: bare LIB_PRECALC_* export present (zero-consumer carve-out; LIB_NO_BARE_EXPORTS)"; fail=1
fi
# The sqtab row is consumption surface: present iff the consumes bit is set.
has_sqtab=$(printf '%s\n' "$dump" | grep -c '^LIB_MLKEM_PRECALC_sqtab_SIZE ' || true)
if [ "$((want_cons & 1))" -ne "$has_sqtab" ]; then
    echo "FAIL: $a: \"sqtab\" row present=$has_sqtab but SHARED_CONSUMES bit 0=$((want_cons & 1)) (§8.1: row iff consumed)"; fail=1
fi

[ "$fail" -eq 0 ] || exit 1
echo "check-archives: OK $a manifest: PRIMITIVES=$want_prim CONSUMES=$want_cons RESIDENT=$want_res rows=$want_rows (§6.4)"
