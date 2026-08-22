#!/usr/bin/env python3
"""check_manifest.py — measured segment sizes vs the §5 footprint equates.

Contract §6.6 makes the footprint equates SAFE-DIRECTION: each declared value
MUST be >= the measured segment sum for the archive it ships in, rounded UP
(fleet convention: the next 256-byte boundary). A consumer asserts
`declared <= budget`, so safe-direction means declared-passes implies
actual-passes.

This reports the measured numbers and whether the current equates are still
safe. It does NOT rewrite lib_manifest.s — bumping a footprint equate is a
release-notes event (§6.6 requires per-(profile x variant) deltas), so a human
decides.

Usage: check_manifest.py <mapfile> <lib_manifest.s>
"""
import re
import sys


def parse_map(path):
    """ld65 -m map: pull the 'Segment list' section -> {name: size}."""
    segs = {}
    in_list = False
    for line in open(path):
        if line.startswith("Segment list:"):
            in_list = True
            continue
        if in_list:
            if line.startswith("-") or not line.strip():
                continue
            if re.match(r"^\w[\w ]*list:", line):
                break
            m = re.match(r"^(\S+)\s+([0-9A-F]{6})\s+([0-9A-F]{6})\s+([0-9A-F]{6})", line)
            if m:
                segs[m.group(1)] = int(m.group(4), 16)
    return segs


def parse_equates(path):
    src = open(path).read()
    out = {}
    for k in ("LIB_MLKEM_RESIDENT_BYTES", "LIB_MLKEM_COLD_BYTES",
              "LIB_MLKEM_ZP_USAGE_BYTES", "LIB_MLKEM_REU_BANKS_USED"):
        m = re.search(rf"^{k}\s*=\s*(\d+)", src, re.M)
        if m:
            out[k] = int(m.group(1))
    return out


def roundup(n, to=256):
    return ((n + to - 1) // to) * to


def main():
    mapfile, manifest = sys.argv[1], sys.argv[2]
    segs = parse_map(mapfile)
    eq = parse_equates(manifest)

    # RESIDENT = library code + rodata that must stay CPU-resident.
    resident = segs.get("LIB_MLKEM_CODE", 0) + segs.get("LIB_MLKEM_RODATA", 0)
    cold = segs.get("LIB_MLKEM_COLD_CODE", 0) + segs.get("LIB_MLKEM_INIT_CODE", 0)
    bss = segs.get("LIB_MLKEM_BSS", 0)

    print("measured (from ld65 map):")
    print(f"  LIB_MLKEM_CODE       {segs.get('LIB_MLKEM_CODE', 0):6d} B")
    print(f"  LIB_MLKEM_RODATA     {segs.get('LIB_MLKEM_RODATA', 0):6d} B")
    print(f"  LIB_MLKEM_BSS        {bss:6d} B  (not a footprint equate; state buffer)")
    print(f"  -> resident          {resident:6d} B   (rounds up to {roundup(resident)})")
    print(f"  -> cold              {cold:6d} B   (rounds up to {roundup(cold)})")
    print()
    print("declared (src/lib_manifest.s):")
    for k, v in eq.items():
        print(f"  {k:28} {v}")
    print()

    fail = False
    for name, measured in (("LIB_MLKEM_RESIDENT_BYTES", resident),
                           ("LIB_MLKEM_COLD_BYTES", cold)):
        declared = eq.get(name, 0)
        if declared < measured:
            print(f"UNSAFE: {name} = {declared} < measured {measured}. "
                  f"Raise it to {roundup(measured)} (§6.6 safe-direction).")
            fail = True
        elif declared < roundup(measured):
            print(f"note: {name} = {declared} is safe but not on a 256-B "
                  f"boundary; fleet convention would use {roundup(measured)}.")

    # P1 code budget from HANDOFF.md: <= ~3 KB code+rodata.
    BUDGET = 3 * 1024
    print(f"\nP1 code+rodata budget: {resident} / {BUDGET} B "
          f"({100.0 * resident / BUDGET:.1f}%)")
    if resident > BUDGET:
        print("OVER the P1 budget — unrolling/table decisions need revisiting.")
        fail = True

    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
