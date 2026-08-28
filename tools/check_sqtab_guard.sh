#!/bin/sh
# check_sqtab_guard.sh — contract §6.7 constraint 3: the image guard must be
# PROVEN to fire in the placing configuration.
#
# src/main.s (ships in no archive) asserts __MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE
# with lderror. A guard that is present but never fires is indistinguishable
# from one that is missing, so this builds once with the sqtab window placed
# deliberately INSIDE the image (0x0900, just past the BASIC stub) and requires
# the LINK to fail with the guard's own message, then rebuilds the default
# configuration and requires it to pass.
#
# LIB_SHARED_SQTAB_BASE rides CONTRACT_DEFINES, so each build below changes the
# §6.3 configuration signature and starts from a clean object tree; the last
# step leaves the tree in the default configuration.
set -u
cd "$(dirname "$0")/.."

MSG='image overruns the sqtab window'

out=$(make CONTRACT_DEFINES="-D LIB_SHARED_SQTAB_BASE=0x0900" all 2>&1)
rc=$?
if [ "$rc" -eq 0 ]; then
    echo "FAIL: link SUCCEEDED with sqtab at 0x0900 inside the image — the §6.7 guard does not fire"
    make all >/dev/null 2>&1
    exit 1
fi
if ! printf '%s' "$out" | grep -q "$MSG"; then
    echo "FAIL: link failed, but not on the §6.7 guard's message ('$MSG'):"
    printf '%s\n' "$out" | tail -5
    make all >/dev/null 2>&1
    exit 1
fi
echo "  overrun leg ok: sqtab at 0x0900 fails the link on '$MSG'"

if ! make all >/dev/null 2>&1; then
    echo "FAIL: default configuration does not link after the overrun probe"
    exit 1
fi
[ -f build/mlkem.prg ] || { echo "FAIL: build/mlkem.prg missing after the default rebuild"; exit 1; }
echo "  default leg ok: image fits below LIB_SHARED_SQTAB_BASE"
echo "check-sqtab-guard: OK (§6.7 constraint 3, guard proven to fire)"
