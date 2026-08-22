#!/bin/sh
# fetch_vectors.sh — download the NIST CAVP LongMsg vector sets.
#
# The ShortMsg / Monte / VariableOut sets (~1.2 MB) are tracked in git; the
# LongMsg sets are ~4.8 MB and are fetched on demand instead. tools/vectors is
# .gitignore'd for *LongMsg.rsp only.
#
# tools/vectors/KeccakF-1600-IntermediateValues.txt is ALSO tracked — it is the
# per-step oracle and small (110 KB).
#
# Idempotent: skips anything already present. Pass -f to re-download.

set -e
DIR="$(cd "$(dirname "$0")" && pwd)/vectors"
CAVP="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3"

[ "$1" = "-f" ] && rm -f "$DIR"/*LongMsg.rsp

if ls "$DIR"/*LongMsg.rsp >/dev/null 2>&1; then
    echo "LongMsg vectors already present in $DIR (use -f to re-fetch)"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetching NIST CAVP SHA-3 / SHAKE LongMsg vectors..."
curl -fsSL -o "$TMP/sha3.zip"  "$CAVP/sha-3bytetestvectors.zip"
curl -fsSL -o "$TMP/shake.zip" "$CAVP/shakebytetestvectors.zip"

unzip -q -o "$TMP/sha3.zip"  -d "$TMP/x"
unzip -q -o "$TMP/shake.zip" -d "$TMP/x"

for f in "$TMP"/x/*LongMsg.rsp; do
    cp "$f" "$DIR/"
    echo "  $(basename "$f")"
done
echo "done -> $DIR"
