#!/usr/bin/env python3
"""check_manifest.py — contract §5 (SPEC 1.2.3) footprint equates vs the
PLACED SPAN of the segments they cover, per shipped archive.

§5 at 1.2.3, the rules this tool implements (quoted verbatim where a rule is
enforced below):

  R1 "Footprint equates MUST be safe-direction: round up, never down."
     -> FAIL when a declared equate is below the measured figure.
  R2 "Each figure measures the segments it covers **as placed** — the extent
     they occupy in a real link, including alignment fill **internal** to
     them — **not** the sum of member object sizes."
     -> the measured figure is the sum over covered segments of each
        segment's placed extent (End - Start + 1 in an ld65 map of a probe
        link of the SHIPPED archive). The object-size sum is printed for
        comparison only; it is never the basis.
  R3 "Charge what is inside each segment, and nothing between or before
     them."
     -> the gap between two covered segments and the padding before the
        first one are EXCLUDED. Both are printed, labelled as excluded, and
        never added. Internal fill (fragment alignment fill within one
        segment) is INCLUDED.
  R4 "This governs the basis, not the scope. Which segments a figure covers
     is unchanged."
     -> the scope table SCOPE below: RESIDENT = "Code+rodata footprint that
        remains CPU-resident in every consumer" = LIB_MLKEM_CODE +
        LIB_MLKEM_RODATA. COLD = "Code+rodata footprint a consumer MAY
        overlay-page" = no segment in this library (it ships none).
        LIB_MLKEM_BSS feeds no §5 figure; it is reported, not checked.

Each archive gets its own manifest (§6.4) and its own probe link; the
declared values are read from THAT archive's mlkem_lib_manifest.o member with
od65 (the shipped bytes), never from the source text.

Measurement guards — each turns a silent under-measurement into a FAIL:
  G1 every member of the archive appears in the probe map's module list
     (an unpulled member would make the span understate the archive);
  G2 no non-archive object (driver, zp_config) places bytes in a LIB_MLKEM_*
     segment (the span would then measure bytes the library does not ship);
  G3 every LIB_MLKEM_* segment in the probe map is classified in SCOPE or
     SCOPE_EXEMPT (a new segment cannot silently escape both figures);
  G4 each covered segment's start alignment is >= every fragment alignment
     inside it, so its internal fill is fixed by the library and not by where
     this probe happened to place it (otherwise the probe span is not a
     library property and another consumer's link could measure larger);
  G5 the map's Size column equals End - Start + 1 for every covered segment.

The standalone test PRG (-D MLKEM_TEST_HOOKS=1) is reported for information:
it ships in no archive, so §5 does not describe it.

Usage:
  check_manifest.py --test-map MAP
                    --probe NAME ARCHIVE MAP [--probe NAME ARCHIVE MAP ...]
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

WINDOW = 7680                 # c64-https CRYPTO_OVERLAY, code+rodata (HANDOFF-P2 decision 1)
MANIFEST_MEMBER = "mlkem_lib_manifest.o"

# R4: which segments each §5 footprint figure covers. The basis rule (R2/R3)
# changed at 1.2.3; this scope did not.
SCOPE = {
    "LIB_MLKEM_RESIDENT_BYTES": ("LIB_MLKEM_CODE", "LIB_MLKEM_RODATA"),
    "LIB_MLKEM_COLD_BYTES": (),
}
# Library segments deliberately outside every §5 footprint figure (RAM state,
# not code+rodata). Anything LIB_MLKEM_* not listed here or in SCOPE fails G3.
SCOPE_EXEMPT = ("LIB_MLKEM_BSS",)
LIB_SEG_PREFIX = "LIB_MLKEM_"


def roundup(n, to=256):
    return ((n + to - 1) // to) * to


def parse_segments(path):
    """ld65 -m map 'Segment list' -> ordered {name: (start, end, size, align)}."""
    segs, in_list = {}, False
    for line in open(path):
        if line.startswith("Segment list:"):
            in_list = True
            continue
        if not in_list:
            continue
        if line.startswith("Exports list") or line.startswith("Imports list"):
            break
        m = re.match(r"^(\S+)\s+([0-9A-F]{6})\s+([0-9A-F]{6})\s+([0-9A-F]{6})\s+([0-9A-F]{5,6})\s*$", line)
        if m:
            segs[m.group(1)] = tuple(int(m.group(i), 16) for i in range(2, 6))
    return segs


def parse_modules(path):
    """ld65 -m map 'Modules list' -> {(archive|None, module): {segment: (size, align)}}."""
    mods, cur, in_list = {}, None, False
    for line in open(path):
        if line.startswith("Modules list:"):
            in_list = True
            continue
        if not in_list:
            continue
        if line.startswith("Segment list:"):
            break
        m = re.match(r"^(\S+?)(?:\(([^)]*)\))?:$", line.rstrip())
        if m:
            # archive members print as `archive.a(member.o):`
            cur = (m.group(1), m.group(2)) if m.group(2) else (None, m.group(1))
            mods[cur] = {}
            continue
        m = re.match(r"^\s+(\S+)\s+Offs=([0-9A-F]+)\s+Size=([0-9A-F]+)\s+Align=([0-9A-F]+)", line)
        if m and cur:
            mods[cur][m.group(1)] = (int(m.group(3), 16), int(m.group(4), 16))
    return mods


def archive_members(archive):
    out = subprocess.run(["ar65", "t", archive], capture_output=True, text=True, check=True).stdout
    return [l.strip() for l in out.splitlines() if l.strip()]


def declared_equates(archive):
    """The §5 values the archive SHIPS: od65 on its extracted manifest member.
    (od65 on the .a itself prints no symbols and exits 0 — a silent pass.)"""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["ar65", "x", os.path.abspath(archive), MANIFEST_MEMBER],
                       cwd=tmp, check=True, capture_output=True)
        obj = os.path.join(tmp, MANIFEST_MEMBER)
        if not os.path.exists(obj):
            return None
        dump = subprocess.run(["od65", "--dump-exports", obj],
                              capture_output=True, text=True, check=True).stdout
    names = re.findall(r'^\s*Name:\s*"([^"]*)"', dump, re.M)
    vals = re.findall(r"^\s*Value:\s*0x[0-9A-Fa-f]+\s*\((\d+)\)", dump, re.M)
    return dict(zip(names, (int(v) for v in vals)))


def check_archive(name, archive, probe_map):
    """Returns (fail, resident_placed) and prints the per-aggregate table."""
    fail = False
    segs = parse_segments(probe_map)
    mods = parse_modules(probe_map)
    arch_mods = {mod: s for (arc, mod), s in mods.items() if arc is not None}
    drv_mods = {mod: s for (arc, mod), s in mods.items() if arc is None}

    print(f"== {name}  ({archive}; probe map {probe_map})")

    # G1: the probe pulled every member of this archive.
    missing = [m for m in archive_members(archive) if m not in arch_mods]
    if missing:
        print(f"FAIL [G1]: {name}: member(s) {', '.join(missing)} absent from the probe link;"
              " the placed span would understate the archive. Add a -u pull for them.")
        fail = True

    # G2: nothing outside the archive places bytes in a library segment.
    for mod, s in drv_mods.items():
        for seg, (size, _) in s.items():
            if seg.startswith(LIB_SEG_PREFIX) and size:
                print(f"FAIL [G2]: {name}: non-archive object {mod} places {size} B in {seg};"
                      " the probe span would measure bytes the library does not ship.")
                fail = True

    # G3: every library segment is classified.
    covered = {s for segs_ in SCOPE.values() for s in segs_}
    for seg in segs:
        if seg.startswith(LIB_SEG_PREFIX) and seg not in covered and seg not in SCOPE_EXEMPT:
            print(f"FAIL [G3]: {name}: segment {seg} is in no §5 figure and not exempt;"
                  " classify it in SCOPE (tools/check_manifest.py).")
            fail = True

    declared = declared_equates(archive)
    if declared is None:
        print(f"FAIL: {name}: no {MANIFEST_MEMBER} member to read declared values from")
        return True, 0

    def frag_sum(seg):
        return sum(s.get(seg, (0, 0))[0] for s in arch_mods.values())

    resident_placed = 0
    for equate, cover in SCOPE.items():
        placed = objsum = 0
        present = [s for s in cover if s in segs]
        for seg in present:
            start, end, size, align = segs[seg]
            span = end - start + 1 if size else 0
            if size and span != size:                                   # G5
                print(f"FAIL [G5]: {name}: {seg} map Size {size} != End-Start+1 {span}")
                fail = True
            falign = max([s[seg][1] for s in arch_mods.values() if seg in s] or [1])
            if size and falign > align:                                 # G4
                print(f"FAIL [G4]: {name}: {seg} starts {align}-aligned but holds a {falign}-aligned"
                      " fragment: its internal fill depends on consumer placement, so no probe"
                      " span is a library property. Give the segment cfg align >= that.")
                fail = True
            fs = frag_sum(seg)
            print(f"   {seg:18} placed {span:6d} B  (objects {fs:6d} B + internal fill {span - fs:4d} B,"
                  f" ${start:04X}-${end:04X}, align {align})")
            placed += span
            objsum += fs
        # R3: what is excluded, shown so a reviewer can see it was not charged.
        spans = sorted((segs[s][0], segs[s][1], s) for s in present if segs[s][2])
        for (s0, e0, n0), (s1, _, n1) in zip(spans, spans[1:]):
            print(f"   excluded (R3): {s1 - e0 - 1} B gap between {n0} and {n1}")
        if spans:
            print(f"   excluded (R3): pre-segment padding before {spans[0][2]} is not charged")
        d = declared.get(equate)
        if d is None:
            print(f"FAIL: {name}: {equate} not exported by its manifest member")
            fail = True
            continue
        verdict = "OK" if d >= placed else "UNSAFE"
        print(f"   {equate:26} declared {d:6d}  object-sum {objsum:6d}  placed span {placed:6d}"
              f"  -> {verdict}")
        if d < placed:                                                  # R1
            print(f"FAIL [R1]: {name}: {equate} = {d} < placed span {placed}. Raise it to"
                  f" {roundup(placed)} (§5: safe-direction, next 256-B boundary).")
            fail = True
        elif d < roundup(placed):
            print(f"note: {name}: {equate} = {d} is safe but not on a 256-B boundary;"
                  f" fleet convention would use {roundup(placed)}.")
        if equate == "LIB_MLKEM_RESIDENT_BYTES":
            resident_placed = placed

    if "LIB_MLKEM_BSS" in segs:
        s, e, size, a = segs["LIB_MLKEM_BSS"]
        print(f"   LIB_MLKEM_BSS      placed {size:6d} B  (objects {frag_sum('LIB_MLKEM_BSS')} B;"
              " no §5 figure covers it — reported only)")
    print()
    return fail, resident_placed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-map", required=True)
    ap.add_argument("--probe", nargs=3, action="append", required=True,
                    metavar=("NAME", "ARCHIVE", "MAP"))
    args = ap.parse_args()

    fail = False
    results = {}
    for name, archive, pmap in args.probe:
        f, res = check_archive(name, archive, pmap)
        fail |= f
        results[name] = res

    tsegs = parse_segments(args.test_map)
    t_res = sum(tsegs[s][2] for s in SCOPE["LIB_MLKEM_RESIDENT_BYTES"] if s in tsegs)
    p_res = results.get("mlkem.a", 0)
    print(f"info: standalone test PRG (-D MLKEM_TEST_HOOKS=1, ships in no archive) code+rodata"
          f" placed span {t_res} B (+{t_res - p_res} B of hook entry points over mlkem.a).")

    # HANDOFF-P2 decision 1: the whole library targets the c64-https
    # CRYPTO_OVERLAY window, 7,680 B code+rodata. That is the NOMINAL window;
    # what is actually free in it is a P4 (consumer-side) question — README.
    print(f"code+rodata vs the 7,680 B CRYPTO_OVERLAY window: "
          f"{p_res} / {WINDOW} B ({100.0 * p_res / WINDOW:.1f}%), {WINDOW - p_res} B headroom (shipped)")
    if p_res > WINDOW:
        print("OVER the window — a per-operation image split (HANDOFF-P2 decision 1 fallback) is required.")
        fail = True

    print("check-manifest: " + ("FAIL" if fail else "OK (§5 1.2.3 placed-span basis, both archives)"))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
