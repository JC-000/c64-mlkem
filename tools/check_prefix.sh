#!/bin/sh
# check_prefix.sh — every exported symbol in every shipped archive is under a
# prefix this library is entitled to.
#
# Why this exists: contract §2/§6.5 make exported names a flat, cross-library
# namespace, and ML-KEM's reference naming walks straight into three sibling
# registrations — `poly_` (c64-ChaCha20-Poly1305), `mul_` (c64-x25519), `ct_`
# (chacha), `sha_` (c64-nist-curves) — all of which c64-https links. The #82/#83
# collisions were found from a CONSUMER's link, not the library's CI; this is
# the library-side guard so P2 cannot repeat that. HANDOFF-P2.md standing
# invariant: every P2 symbol is under `mlkem_`; anything else is registered
# upstream in the same PR that introduces it — and added to the allow-list
# below in that same commit, with the SPEC clause that permits it.
#
# Permitted:
#   mlkem_*        §2 registry grant (contract v0.10.7)
#   LIB_MLKEM_*    §1 / §5 / §8.0 / §8.4 prefixed manifest families
#   keccak_*       P1's registered public names (confirmed at the #123 intake
#                  not to be prefix-matched by nist-curves' `sha_`)
#   §8 canonical names — permitted ONLY as the exact spellings the contract
#   makes normative, and only once the library is a §8.x provider:
#     mul_tables_init                      §8.1 canonical init (owner build)
#     ct_mul_8x8, mul_8x8                  §8.3 body + back-compat alias
#     smc_sum_a_imm, smc_diff_a_imm        §8.3 SMC operand sites (v0.10.6)
#     poly_prod_lo, poly_prod_hi           §8.3 product scratch (v0.10.6)
#   Nothing else. In particular NO bare `LIB_VERSION_*` / `LIB_ABI_VERSION`
#   and NO bare `LIB_PRECALC_*` (both §1-carve-out-class; the surface must be
#   byte-identical with and without -D LIB_NO_BARE_EXPORTS=1).
#
# Reads OBJECTS, never archives: od65 pointed at an .a prints "(no xo65 object
# file)" and exits 0 with no symbols — a silent false negative (SPEC §8.4,
# "Auditing a shipped archive"). Members are extracted with `ar65 x` first and
# the script fails if extraction yields nothing.
set -eu
cd "$(dirname "$0")/.."

ALLOW_RE='^(mlkem_|LIB_MLKEM_|keccak_)'
CANON_LIST='mul_tables_init ct_mul_8x8 mul_8x8 smc_sum_a_imm smc_diff_a_imm poly_prod_lo poly_prod_hi'

archives=$(ls build/lib/*.a 2>/dev/null || true)
[ -n "$archives" ] || { echo "FAIL: no archives under build/lib — run make lib lib-keccak first"; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check_prefix.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail=0
total=0
for a in $archives; do
    d="$tmp/$(basename "$a" .a)"
    mkdir -p "$d"
    abs_a="$(pwd)/$a"
    members=$(ar65 t "$abs_a")
    [ -n "$members" ] || { echo "FAIL: $a lists no members"; fail=1; continue; }
    for m in $members; do
        (cd "$d" && ar65 x "$abs_a" "$m")
    done
    n=$(ls "$d"/*.o 2>/dev/null | wc -l | tr -d ' ')
    [ "$n" -gt 0 ] || { echo "FAIL: extracted no objects from $a"; fail=1; continue; }

    for o in "$d"/*.o; do
        # od65 prints one `Name: "sym"` line per export; the whitespace after
        # the colon varies with the field width, so match the quoted name only.
        for sym in $(od65 --dump-exports "$o" | sed -n 's/^ *Name: *"\([^"]*\)".*/\1/p'); do
            total=$((total + 1))
            if printf '%s' "$sym" | grep -Eq "$ALLOW_RE"; then continue; fi
            ok=0
            for c in $CANON_LIST; do [ "$sym" = "$c" ] && ok=1; done
            if [ "$ok" -eq 1 ]; then continue; fi
            echo "FAIL: $a:$(basename "$o") exports '$sym' — not under mlkem_/LIB_MLKEM_/keccak_ and not a §8 canonical name (register the prefix upstream in the same PR, then allow-list it here)"
            fail=1
        done
    done
done

[ "$total" -gt 0 ] || { echo "FAIL: no exports found at all — od65 parse broke?"; exit 1; }
[ "$fail" -eq 0 ] || exit 1
echo "check-prefix: OK ($total exports across $(echo $archives | wc -w | tr -d ' ') archives, all under a permitted prefix)"
