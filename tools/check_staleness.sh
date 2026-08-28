#!/bin/sh
# check_staleness.sh — contract §6.3 invalidation branch, both legs, on every
# §6.2 knob this repo honors.
#
# §6.3 (v0.11.1) requires that a knob a target CAN honor invalidates whatever it
# reconfigures. The failure it guards against is silent: over a warm tree make
# sees no reason to rebuild, exits 0, and ships the previously-configured
# artifact. Measured in this repo before the fix.
#
# BOTH legs are required for every knob. The clause is explicit that a guard
# which has degraded to an unconditional rebuild still passes a check
# exercising only leg 1, and that the pinning check must assert the ARTIFACT
# flipped rather than that something rebuilt.
#
#   leg 1  changing a knob flips the artifact
#   leg 2  repeating the same knob rebuilds nothing and yields the same artifact
#
# Knobs:
#   A  CONTRACT_ZP_DEFINES  mlkem_zp_src=0x40        (§6.2 slot, P1)
#   B  CONTRACT_DEFINES     LIB_SHARED_SQTAB_BASE=0x9400  (§8.1 window, P2 —
#      the 0.11.1 text names a stale sqtab base as "a wrong address for the
#      §8.1 window"; the multiply bakes the page byte into its abs,x sites,
#      so a stale object IS a wrong address)
#   C  MLKEM_KECCAK_ONLY    the mlkem-keccak.a manifest configuration. Not a
#      CONTRACT_DEFINES knob (the Makefile rejects it there, §6.3 rejection
#      branch) but a per-target one: `make lib` and `make lib-keccak` must
#      each ship a manifest describing their own member set (§6.4) AND
#      alternating between them on a warm tree must neither rebuild nor
#      overwrite the other's manifest. Compared on od65 export VALUES.
#
# PRG knobs compare linked PRGs, never archives: ca65 stamps a wall-clock
# OPT_DATETIME into every object, so .o/.a bytes differ across time-separated
# builds regardless of configuration (contract §6.3 checkability note).
set -eu
cd "$(dirname "$0")/.."
PRG=build/mlkem.prg

hash_prg() { [ -f "$PRG" ] || { echo "FATAL: $PRG missing"; exit 2; }; shasum -a 256 "$PRG" | cut -d' ' -f1; }

# Flattened `sym value` lines of one archive's manifest member (values, not bytes).
manifest_values() {
    d=$(mktemp -d "${TMPDIR:-/tmp}/staleness.XXXXXX")
    (cd "$d" && ar65 x "$OLDPWD/$1" mlkem_lib_manifest.o)
    od65 --dump-exports "$d/mlkem_lib_manifest.o" \
        | sed -n 's/^ *Name: *"\([^"]*\)".*/\1/p; s/^ *Value: *0x[0-9A-Fa-f]* *(\([0-9]*\)).*/\1/p' \
        | paste -d " " - - | sort
    rm -rf "$d"
}

fail=0

# --- PRG knobs A and B: same protocol each -------------------------------
rm -rf build
make all >/dev/null
base=$(hash_prg)

for knob in 'CONTRACT_ZP_DEFINES=-D mlkem_zp_src=0x40' 'CONTRACT_DEFINES=-D LIB_SHARED_SQTAB_BASE=0x9400'; do
    make "$knob" all >/dev/null
    b=$(hash_prg)
    out=$(make "$knob" all 2>&1)
    c=$(hash_prg)

    if [ "$base" = "$b" ]; then
        echo "FAIL leg 1 [$knob]: changed knob did not flip the artifact (stale build shipped)"
        fail=1
    else
        echo "  leg 1 ok [$knob]: changed knob flips the linked artifact"
    fi
    if [ "$b" != "$c" ]; then
        echo "FAIL leg 2 [$knob]: repeating the same knob produced a different artifact"
        fail=1
    elif printf '%s' "$out" | grep -q 'ca65'; then
        echo "FAIL leg 2 [$knob]: unchanged knob rebuilt — guard has degraded to an unconditional rebuild"
        fail=1
    else
        echo "  leg 2 ok [$knob]: unchanged knob does not rebuild"
    fi
done

# --- knob C: the per-archive manifest ---------------------------------------
make all >/dev/null                         # back to the default configuration
make lib lib-keccak >/dev/null
full=$(manifest_values build/lib/mlkem.a)
kecc=$(manifest_values build/lib/mlkem-keccak.a)

if [ "$full" = "$kecc" ]; then
    echo "FAIL leg 1 [MLKEM_KECCAK_ONLY]: mlkem.a and mlkem-keccak.a ship the same manifest values (§6.4: one manifest must not describe two member sets)"
    fail=1
elif ! printf '%s\n' "$kecc" | grep -q '^LIB_MLKEM_SHARED_CONSUMES 0$' || \
     ! printf '%s\n' "$full" | grep -q '^LIB_MLKEM_SHARED_CONSUMES 1$'; then
    echo "FAIL leg 1 [MLKEM_KECCAK_ONLY]: expected SHARED_CONSUMES 1 in mlkem.a and 0 in mlkem-keccak.a"
    fail=1
else
    echo "  leg 1 ok [MLKEM_KECCAK_ONLY]: the two archives ship different manifests"
fi

# Alternate on a warm tree: nothing may rebuild, and neither manifest may change.
out=$(make lib 2>&1; make lib-keccak 2>&1; make lib 2>&1)
full2=$(manifest_values build/lib/mlkem.a)
kecc2=$(manifest_values build/lib/mlkem-keccak.a)
if printf '%s' "$out" | grep -q 'ca65'; then
    echo "FAIL leg 2 [MLKEM_KECCAK_ONLY]: alternating lib / lib-keccak on a warm tree re-assembled something"
    fail=1
elif [ "$full" != "$full2" ] || [ "$kecc" != "$kecc2" ]; then
    echo "FAIL leg 2 [MLKEM_KECCAK_ONLY]: alternating lib / lib-keccak changed a manifest (shared object path?)"
    fail=1
else
    echo "  leg 2 ok [MLKEM_KECCAK_ONLY]: alternating lib / lib-keccak rebuilds nothing and keeps both manifests"
fi

[ "$fail" -eq 0 ] || exit 1
echo "check-staleness: OK (§6.3 invalidation branch, both legs, three knobs)"
