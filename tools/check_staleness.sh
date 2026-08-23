#!/bin/sh
# check_staleness.sh — contract §6.3 invalidation branch, both legs.
#
# §6.3 (v0.11.1) requires that a knob a target CAN honor invalidates whatever it
# reconfigures. The failure it guards against is silent: over a warm tree make
# sees no reason to rebuild, exits 0, and ships the previously-configured
# artifact. Measured in this repo before the fix.
#
# BOTH legs are required. The clause is explicit that a guard which has degraded
# to an unconditional rebuild still passes a check exercising only leg 1, and
# that the pinning check must assert the ARTIFACT flipped rather than that
# something rebuilt.
#
#   leg 1  changing a knob flips the linked artifact
#   leg 2  repeating the same knob rebuilds nothing and yields the same artifact
#
# Compares linked PRGs, never archives: ca65 stamps a wall-clock OPT_DATETIME
# into every object, so .o/.a bytes differ across time-separated builds
# regardless of configuration (contract §6.3 checkability note).
set -eu
cd "$(dirname "$0")/.."
PRG=build/mlkem.prg
KNOB='CONTRACT_ZP_DEFINES=-D mlkem_zp_src=0x40'

hash_prg() { [ -f "$PRG" ] || { echo "FATAL: $PRG missing"; exit 2; }; shasum -a 256 "$PRG" | cut -d' ' -f1; }

rm -rf build
make all >/dev/null
a=$(hash_prg)

make "$KNOB" all >/dev/null
b=$(hash_prg)

out=$(make "$KNOB" all 2>&1)
c=$(hash_prg)

fail=0
if [ "$a" = "$b" ]; then
    echo "FAIL leg 1: changed knob did not flip the artifact (stale build shipped)"
    fail=1
else
    echo "  leg 1 ok: changed knob flips the linked artifact"
fi

if [ "$b" != "$c" ]; then
    echo "FAIL leg 2: repeating the same knob produced a different artifact"
    fail=1
elif printf '%s' "$out" | grep -q 'ca65'; then
    echo "FAIL leg 2: unchanged knob rebuilt — guard has degraded to an unconditional rebuild"
    fail=1
else
    echo "  leg 2 ok: unchanged knob does not rebuild"
fi

[ "$fail" -eq 0 ] || exit 1
echo "check-staleness: OK (§6.3 invalidation branch, both legs)"
