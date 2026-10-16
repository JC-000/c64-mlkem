#!/bin/sh
# check_version.sh — the four contract §1 version equates, and the segment
# model the ABI counter vouches for.
#
#   check_version.sh <mlkem.a> <mlkem-keccak.a> <abi> "<driver objs>" \
#                    "<ld65 -u pulls>"
#
# 1. In EACH archive's mlkem_lib_version.o (extracted first: od65 on an .a
#    prints "(no xo65 object file)" and exits 0, a silent pass), MAJOR /
#    MINOR / PATCH must equal the VERSION file and LIB_MLKEM_ABI_VERSION
#    must equal <abi>, the expected constant in the Makefile. The member
#    must export EXACTLY these four symbols (SPEC §1 TU isolation: "the four
#    equates and nothing else").
# 2. Link legs against mlkem.a: a v0.5.1-style cfg (no LIB_MLKEM_POLY_BSS)
#    must FAIL with ld65's "Missing memory area assignment" message; the same
#    cfg with the segment must link. This is what the ABI 3 number promises.
# 3. Proof the guard fires: copies of the archives with the member rebuilt at
#    ABI 2, at a wrong PATCH, and with an extra export, must fail step 1.
#
# No `$` in any -D value anywhere here (CLAUDE.md trap).
set -u
cd "$(dirname "$0")/.."

a=$1; ak=$2; want_abi=$3; drivers=$4; pulls=$5
member=mlkem_lib_version.o
[ -f "$a" ] && [ -f "$ak" ] || { echo "FAIL: archive missing"; exit 2; }
ver=$(tr -d ' \r\n' < VERSION)
want_major=${ver%%.*}; rest=${ver#*.}; want_minor=${rest%%.*}; want_patch=${rest#*.}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check_version.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# equates <archive>: prints failures, returns 1 on any.
equates() {
    arch=$1
    d=$(mktemp -d "$tmp/x.XXXXXX")
    abs="$(cd "$(dirname "$arch")" && pwd)/$(basename "$arch")"
    ar65 t "$abs" | grep -qx "$member" || { echo "FAIL: $arch has no $member"; return 1; }
    (cd "$d" && ar65 x "$abs" "$member")
    [ -s "$d/$member" ] || { echo "FAIL: could not extract $member from $arch"; return 1; }
    dump=$(od65 --dump-exports "$d/$member" \
           | sed -n 's/^ *Name: *"\([^"]*\)".*/\1/p; s/^ *Value: *0x[0-9A-Fa-f]* *(\([0-9]*\)).*/\1/p' \
           | paste -d " " - -)
    rc=0
    nexp=$(printf '%s\n' "$dump" | grep -c .)
    if [ "$nexp" -ne 4 ]; then
        echo "FAIL: $arch: $member exports $nexp symbols, expected exactly 4 (TU isolation, SPEC §1)"; rc=1
    fi
    for pair in MAJOR:$want_major MINOR:$want_minor PATCH:$want_patch ABI:$want_abi; do
        n=LIB_MLKEM_${pair%%:*}_VERSION; [ "${pair%%:*}" = ABI ] || n=LIB_MLKEM_VERSION_${pair%%:*}
        got=$(printf '%s\n' "$dump" | awk -v n="$n" '$1 == n { print $2; f = 1 } END { if (!f) print "MISSING" }')
        if [ "$got" != "${pair#*:}" ]; then
            echo "FAIL: $arch: $n = $got, expected ${pair#*:}"; rc=1
        fi
    done
    return $rc
}

fail=0
for arch in "$a" "$ak"; do
    if equates "$arch"; then
        echo "  ok  $arch: version $ver, LIB_MLKEM_ABI_VERSION = $want_abi"
    else
        fail=1
    fi
done

# --- link legs ---------------------------------------------------------
sed 's/optional = yes, //' cfg/mlkem.cfg > "$tmp/four.cfg"
grep -v 'LIB_MLKEM_POLY_BSS:' "$tmp/four.cfg" > "$tmp/three.cfg"
grep -q 'LIB_MLKEM_POLY_BSS:' "$tmp/four.cfg" || { echo "FAIL: cfg/mlkem.cfg lost its POLY_BSS line"; exit 1; }
# shellcheck disable=SC2086
out=$(ld65 -C "$tmp/three.cfg" $pulls -o "$tmp/three.prg" $drivers "$a" 2>&1)
if [ $? -eq 0 ]; then
    echo "FAIL: a three-segment (v0.5.1-style) cfg LINKED; ABI $want_abi promises it cannot"; fail=1
elif ! printf '%s' "$out" | grep -q "Missing memory area assignment for segment 'LIB_MLKEM_POLY_BSS'"; then
    echo "FAIL: three-segment link failed, but not on the POLY_BSS message:"; printf '%s\n' "$out" | tail -3; fail=1
else
    echo "  ok  three-segment cfg fails: Missing memory area assignment for segment 'LIB_MLKEM_POLY_BSS'"
fi
# shellcheck disable=SC2086
if out=$(ld65 -C "$tmp/four.cfg" $pulls -o "$tmp/four.prg" $drivers "$a" 2>&1); then
    echo "  ok  four-segment cfg links"
else
    echo "FAIL: four-segment cfg does not link:"; printf '%s\n' "$out" | tail -3; fail=1
fi

# --- the guard must fire ------------------------------------------------
abs_a="$(cd "$(dirname "$a")" && pwd)/$(basename "$a")"
abs_k="$(cd "$(dirname "$ak")" && pwd)/$(basename "$ak")"
mkdir "$tmp/mut"
for variant in "ABI:s/^LIB_MLKEM_ABI_VERSION *= *[0-9]*/LIB_MLKEM_ABI_VERSION   = 2/" \
               "PATCH:s/^LIB_MLKEM_VERSION_PATCH *= *[0-9]*/LIB_MLKEM_VERSION_PATCH = 9/" \
               "EXTRA-EXPORT:s/^LIB_MLKEM_ABI_VERSION   = 3/LIB_MLKEM_ABI_VERSION   = 3\nLIB_MLKEM_EXTRA = 1\n.export LIB_MLKEM_EXTRA: abs/"; do
    name=${variant%%:*}; expr=${variant#*:}
    sed "$expr" src/lib_version.s > "$tmp/mut/lib_version.s"
    if cmp -s src/lib_version.s "$tmp/mut/lib_version.s"; then
        echo "FAIL: self-test $name mutation changed nothing (src/lib_version.s shape moved)"; fail=1; continue
    fi
    (cd "$tmp/mut" && ca65 -o "$member" lib_version.s) || { echo "FAIL: self-test cannot assemble"; fail=1; continue; }
    cp "$abs_a" "$tmp/mut/m.a"; cp "$abs_k" "$tmp/mut/k.a"
    (cd "$tmp/mut" && ar65 r m.a "$member" && ar65 r k.a "$member")
    if equates "$tmp/mut/m.a" >/dev/null && equates "$tmp/mut/k.a" >/dev/null; then
        echo "FAIL: self-test: archives rebuilt with a wrong $name PASSED the check"; fail=1
    else
        echo "  ok  self-test: a mutated $name in lib_version.o is caught"
    fi
done

[ "$fail" -eq 0 ] || exit 1
echo "check-version: OK (equates pinned in both archives, ABI $want_abi segment model enforced at link, guard proven to fire)"
