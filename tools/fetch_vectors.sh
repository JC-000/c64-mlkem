#!/bin/sh
# fetch_vectors.sh — download the NIST test vectors this repo does not track,
# and (re)build the tracked ML-KEM ACVP sets.
#
# 1. CAVP LongMsg sets (SHA-3 / SHAKE). The ShortMsg / Monte / VariableOut
#    sets (~1.2 MB) are tracked in git; the LongMsg sets are ~4.8 MB and are
#    fetched on demand instead. tools/vectors is .gitignore'd for *LongMsg.rsp.
#
# 2. ACVP ML-KEM (FIPS 203) sets from usnistgov/ACVP-Server, pinned to a
#    commit (below), filtered to the ML-KEM-768 parameter set only. Filtered
#    they are ~670 KB, so they ARE tracked, like the ShortMsg sets; this script
#    only re-fetches them with -f (or when missing). The full internalProjection
#    files carry all three parameter sets (~2 MB) and are not kept.
#
# tools/vectors/KeccakF-1600-IntermediateValues.txt is ALSO tracked — it is
# the per-step Keccak oracle and small (110 KB).
#
# Idempotent: skips anything already present. Pass -f to re-download all.

set -e
DIR="$(cd "$(dirname "$0")" && pwd)/vectors"
CAVP="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3"

# ACVP-Server commit the tracked ML-KEM-768 JSON was filtered from. Bump
# deliberately, re-run with -f, and record the new value in vectors/README.md.
ACVP_COMMIT="975de31eb83d87039ec88934fdc47d8c312b892d"
ACVP_RAW="https://raw.githubusercontent.com/usnistgov/ACVP-Server/$ACVP_COMMIT/gen-val/json-files"

FLEET_VENV=/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3
if [ -x "$FLEET_VENV" ]; then PYTHON="$FLEET_VENV"; else PYTHON="$(command -v python3)"; fi

FORCE=0
[ "$1" = "-f" ] && FORCE=1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- 1. CAVP LongMsg ---------------------------------------------------------

[ $FORCE = 1 ] && rm -f "$DIR"/*LongMsg.rsp

if ls "$DIR"/*LongMsg.rsp >/dev/null 2>&1; then
    echo "LongMsg vectors already present in $DIR (use -f to re-fetch)"
else
    echo "fetching NIST CAVP SHA-3 / SHAKE LongMsg vectors..."
    curl -fsSL -o "$TMP/sha3.zip"  "$CAVP/sha-3bytetestvectors.zip"
    curl -fsSL -o "$TMP/shake.zip" "$CAVP/shakebytetestvectors.zip"
    unzip -q -o "$TMP/sha3.zip"  -d "$TMP/x"
    unzip -q -o "$TMP/shake.zip" -d "$TMP/x"
    for f in "$TMP"/x/*LongMsg.rsp; do
        cp "$f" "$DIR/"
        echo "  $(basename "$f")"
    done
fi

# --- 2. ACVP ML-KEM-768 ----------------------------------------------------

for mode in keyGen encapDecap; do
    out="$DIR/ML-KEM-768-$mode-FIPS203.json"
    if [ $FORCE = 0 ] && [ -s "$out" ]; then
        echo "$(basename "$out") already present (use -f to re-fetch)"
        continue
    fi
    src="ML-KEM-$mode-FIPS203/internalProjection.json"
    echo "fetching ACVP $src @ ${ACVP_COMMIT%????????????????????????????????}..."
    curl -fsSL -o "$TMP/$mode.json" "$ACVP_RAW/$src"
    # Keep only the ML-KEM-768 groups; everything else about the file (top-level
    # metadata, group and test fields, order) is passed through untouched.
    "$PYTHON" - "$TMP/$mode.json" "$out" <<'EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
j = json.load(open(src))
j["testGroups"] = [g for g in j["testGroups"] if g.get("parameterSet") == "ML-KEM-768"]
assert j["testGroups"], "no ML-KEM-768 groups in " + src
with open(dst, "w") as f:
    json.dump(j, f, indent=1)
    f.write("\n")
n = sum(len(g["tests"]) for g in j["testGroups"])
print(f"  {dst.rsplit('/', 1)[-1]}: {len(j['testGroups'])} groups, {n} tests")
EOF
done
echo "done -> $DIR"
