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
#    must export EXACTLY these four symbols (SPEC §1 TU isolation, as applied
#    by this repo in src/lib_version.s).
# 2. Link legs against mlkem.a: a v0.5.1-style cfg (no LIB_MLKEM_POLY_BSS)
#    must FAIL with ld65's "Missing memory area assignment" message; the same
#    cfg with the segment must link. This is what the ABI 3 number promises.
# 3. Proof the guard fires: copies of the archives with the member rebuilt at
#    ABI 2, at a wrong PATCH, without `: abs`, and with an extra constant or
#    label export, must each fail step 1.
#
# No `$` in any -D value anywhere here (CLAUDE.md trap).
set -u
cd "$(dirname "$0")/.."

a=$1; ak=$2; want_abi=$3; drivers=$4; pulls=$5
member=mlkem_lib_version.o
[ -f "$a" ] && [ -f "$ak" ] || { echo "FAIL: archive missing"; exit 2; }
# Exactly one non-empty line; strip only leading blanks and trailing blanks /
# CR. Interior whitespace or CR is an error, not something to squeeze out.
nlines=$(awk '{ gsub(/[ \t\r]/, ""); if (length($0)) n++ } END { print n + 0 }' VERSION)
[ "$nlines" -eq 1 ] || { echo "FAIL: VERSION must hold exactly one non-empty line (has $nlines)"; exit 2; }
ver=$(awk 'length($0) { gsub(/\r$/, ""); print; exit }' VERSION | sed 's/^[ 	]*//; s/[ 	]*$//')
case $ver in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "FAIL: VERSION is not MAJOR.MINOR.PATCH: '$ver'"; exit 2 ;;
esac
case $ver in
    *[!0-9.]*) echo "FAIL: VERSION has characters other than digits and dots: '$ver'"; exit 2 ;;
esac
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
    # One record per export: `name value address-size`. A record is flushed
    # at the next `Index:` line (and at the end), so an export with no Value
    # line is still counted and shows as value NA.
    dump=$(od65 --dump-exports "$d/$member" | awk '
        function flush() { if (name != "") print name, (val == "" ? "NA" : val), (asz == "" ? "NA" : asz) }
        /^ *Index:/ { flush(); name = ""; val = ""; asz = "" }
        /Address size:/ { asz = $3 }
        /Name:/ { name = $2; gsub(/"/, "", name) }
        /Value:/ { v = $0; sub(/^.*\(/, "", v); sub(/\).*$/, "", v); val = v }
        END { flush() }')
    rc=0
    nexp=$(printf '%s\n' "$dump" | grep -c .)
    if [ "$nexp" -ne 4 ]; then
        echo "FAIL: $arch: $member exports $nexp symbols, expected exactly 4 (SPEC §1 TU isolation, as applied by src/lib_version.s)"; rc=1
    fi
    # `: abs` is required: without it ca65 infers zeropage and every
    # consumer .import warns "Address size mismatch" (address size 0x02).
    bad=$(printf '%s\n' "$dump" | awk 'NF && $3 != "0x02" { print $1 "(" $3 ")" }')
    if [ "$nexp" -eq 0 ]; then
        echo "FAIL: $arch: $member exports nothing"; rc=1
    elif [ -n "$bad" ]; then
        echo "FAIL: $arch: not exported as absolute (: abs): $bad"; rc=1
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
# mutate <name>: reads src/lib_version.s on stdin, writes the mutant on stdout.
mutate() {
    case $1 in
    ABI)          sed 's/^LIB_MLKEM_ABI_VERSION *= *[0-9]*/LIB_MLKEM_ABI_VERSION   = 2/' ;;
    PATCH)        sed 's/^LIB_MLKEM_VERSION_PATCH *= *[0-9]*/LIB_MLKEM_VERSION_PATCH = 9/' ;;
    NO-ABS)       sed 's/^\.export LIB_MLKEM_ABI_VERSION:.*/.export LIB_MLKEM_ABI_VERSION/' ;;
    EXTRA-EXPORT) awk '{ print } /^LIB_MLKEM_ABI_VERSION *=/ { print "LIB_MLKEM_EXTRA = 1"; print ".export LIB_MLKEM_EXTRA: abs" }' ;;
    LABEL-EXPORT) awk '{ print } END { print ".export LIB_MLKEM_LBL"; print "LIB_MLKEM_LBL: rts" }' ;;
    esac
}
mkdir "$tmp/mut"
# Positive control: unmutated copies of the archives must PASS the check, or a
# copy/ar65 problem would make every mutated case look "caught".
if ! cp "$abs_a" "$tmp/mut/m.a" || ! cp "$abs_k" "$tmp/mut/k.a"; then
    echo "FAIL: self-test positive control: cannot copy the archives"; fail=1
elif equates "$tmp/mut/m.a" && equates "$tmp/mut/k.a"; then
    echo "  ok  self-test: unmutated archive copies pass (positive control)"
else
    echo "FAIL: self-test positive control: unmutated archive copies do not pass"; fail=1
fi
# expected_msg <name>: the FAIL text the check must produce for that mutation.
expected_msg() {
    case $1 in
    ABI)          echo "LIB_MLKEM_ABI_VERSION = 2" ;;
    PATCH)        echo "LIB_MLKEM_VERSION_PATCH = 9" ;;
    NO-ABS)       echo "not exported as absolute" ;;
    EXTRA-EXPORT) echo "exports 5 symbols" ;;
    LABEL-EXPORT) echo "exports 5 symbols" ;;
    esac
}
for name in ABI PATCH NO-ABS EXTRA-EXPORT LABEL-EXPORT; do
    rm -f "$tmp/mut/$member" "$tmp/mut/lib_version.s"
    mutate "$name" < src/lib_version.s > "$tmp/mut/lib_version.s"
    if cmp -s src/lib_version.s "$tmp/mut/lib_version.s"; then
        echo "FAIL: self-test $name mutation changed nothing (src/lib_version.s shape moved)"; fail=1; continue
    fi
    (cd "$tmp/mut" && ca65 -o "$member" lib_version.s) || { echo "FAIL: self-test cannot assemble $name"; fail=1; continue; }
    if ! cp "$abs_a" "$tmp/mut/m.a" || ! cp "$abs_k" "$tmp/mut/k.a"; then
        echo "FAIL: self-test $name: cannot copy the archives"; fail=1; continue
    fi
    if ! (cd "$tmp/mut" && ar65 r m.a "$member" && ar65 r k.a "$member"); then
        echo "FAIL: self-test $name: ar65 could not replace the member"; fail=1; continue
    fi
    want=$(expected_msg "$name")
    if out=$(equates "$tmp/mut/m.a" 2>&1 && equates "$tmp/mut/k.a" 2>&1); then
        echo "FAIL: self-test: archives rebuilt with a mutated $name PASSED the check"; fail=1
    elif printf '%s\n' "$out" | grep -qF "$want"; then
        echo "  ok  self-test: a mutated $name in lib_version.o is caught ('$want')"
    else
        echo "FAIL: self-test $name: the check failed, but not with '$want':"; printf '%s\n' "$out" | head -3; fail=1
    fi
done

[ "$fail" -eq 0 ] || exit 1
echo "check-version: OK (equates pinned in both archives, ABI $want_abi segment model enforced at link, guard proven to fire)"
