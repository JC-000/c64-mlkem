#!/bin/sh
# check_staleness.sh — repo-local configuration invalidation, both legs, on
# every §6.2 knob this repo honors.
#
# A knob a target CAN honor must invalidate whatever it reconfigures. The
# failure it guards against is silent: over a warm tree make sees no reason to
# rebuild, exits 0, and ships the previously-configured artifact. Measured in
# this repo before the fix.
#
# BOTH legs are required for every knob: a guard which has degraded to an
# unconditional rebuild still passes a check exercising only leg 1. The check
# must assert the ARTIFACT flipped rather than that something rebuilt.
#
#   leg 1  changing a knob flips the artifact
#   leg 2  repeating the same knob rebuilds nothing and yields the same artifact
#
# Knobs:
#   A  CONTRACT_ZP_DEFINES  mlkem_zp_src=0x40        (§6.2 slot, P1)
#   B  CONTRACT_DEFINES     LIB_SHARED_SQTAB_BASE=0x9400  (§8.1 window, P2 —
#      the multiply bakes the page byte into its abs,x sites, so a stale
#      object IS a wrong address)
#   C  MLKEM_KECCAK_ONLY    the mlkem-keccak.a manifest configuration. Not a
#      CONTRACT_DEFINES knob (the Makefile rejects it there at parse time)
#      but a per-target one: `make lib` and `make lib-keccak` must
#      each ship a manifest describing their own member set (§6.4) AND
#      alternating between them on a warm tree must neither rebuild nor
#      overwrite the other's manifest. Compared on od65 export VALUES.
#
# Rejected knobs (a knob no target can honor must FAIL at parse time, never
# build): MLKEM_KECCAK_ONLY and MLKEM_TEST_HOOKS through the consumer
# variables. Each must exit non-zero with its own message and leave build/
# untouched — same config stamp, same file list, same archive bytes (a guard
# that stopped firing flips the stamp and wipes the tree before any recipe).
# Then the positive side: plain `make all lib` still ships 2 exports from
# mlkem_keccak.o, and the standalone tree still carries the hooks.
#
# PRG knobs compare linked PRGs, never archives: ca65 stamps a wall-clock
# OPT_DATETIME into every object, so .o/.a bytes differ across time-separated
# builds regardless of configuration.
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

# --- rejected knobs: parse-time error, nothing built or overwritten --------
make all lib lib-keccak >/dev/null          # default tree to compare against
snapshot() { cat build/.config-sig; echo; find build -type f | sort; \
             shasum -a 256 build/lib/mlkem.a build/lib/mlkem-keccak.a build/obj/mlkem_keccak.o 2>&1; }
before=$(snapshot)
for knob in 'CONTRACT_DEFINES=-D MLKEM_TEST_HOOKS=1' 'CA65FLAGS=-D MLKEM_TEST_HOOKS=1' \
            'CONTRACT_ZP_DEFINES=-D MLKEM_TEST_HOOKS=1' \
            'CONTRACT_DEFINES=-D MLKEM_KECCAK_ONLY=1' 'CA65FLAGS=-D MLKEM_KECCAK_ONLY=1'; do
    name=${knob#*-D }; name=${name%%=*}
    if out=$(make "$knob" lib lib-keccak 2>&1); then
        echo "FAIL reject [$knob]: make exited 0 (the define was accepted)"
        fail=1
    elif ! printf '%s' "$out" | grep -q "\*\*\* $name is selected by"; then
        echo "FAIL reject [$knob]: non-zero exit without the rejection message:"
        printf '%s\n' "$out" | tail -3
        fail=1
    elif [ "$(snapshot)" != "$before" ]; then
        echo "FAIL reject [$knob]: rejected, but build/ changed (stamp, file list or archive bytes)"
        fail=1
    else
        echo "  reject ok [$knob]: parse-time error, build/ untouched"
        continue
    fi
    make all lib lib-keccak >/dev/null      # a failed leg must not cascade
    before=$(snapshot)
done

out=$(make all lib 2>&1) || { echo "FAIL: plain make all lib failed after the rejections"; printf '%s\n' "$out" | tail -3; fail=1; }
n=$(od65 --dump-exports build/obj/mlkem_keccak.o | grep -c 'Name:' || true)
if [ "$n" != 2 ]; then
    echo "FAIL positive [make lib]: shipped mlkem_keccak.o exports $n symbols, expected 2 (test hooks in the archive?)"
    fail=1
elif ! od65 --dump-exports build/tobj/keccak.o | grep -q '"keccak_theta"'; then
    echo "FAIL positive [make]: standalone build/tobj/keccak.o lacks the keccak_theta test hook (TEST_DEFINES route broken)"
    fail=1
else
    echo "  positive ok: shipped mlkem_keccak.o exports 2; standalone tree keeps its test hooks"
fi

[ "$fail" -eq 0 ] || exit 1
echo "check-staleness: OK (config invalidation, both legs, three knobs; two rejected knobs fire)"
