#!/usr/bin/env python3
"""check_manifest.py — measured segment sizes vs the §5 footprint equates.

Contract §6.6 makes the footprint equates SAFE-DIRECTION: each declared value
MUST be >= the measured segment sum for the archive it ships in, rounded UP
(fleet convention: the next 256-byte boundary). A consumer asserts
`declared <= budget`, so safe-direction means declared-passes implies
actual-passes.

Two maps are read:

  <test map>   the standalone test PRG (-D MLKEM_TEST_HOOKS=1): every TU,
               plus the per-layer / K-PKE hook entry points. The larger of
               the two; a declared value must cover it as well.
  <probe map>  build/mlkem-lib.map — the driver objects linked against the
               SHIPPED mlkem.a with every public entry forced in (-u), so it
               is exactly the byte set a consumer links. Its module list also
               gives the per-member sizes, from which the mlkem-keccak.a
               subset (lib_version, lib_manifest, state, keccak, sponge) is
               summed for that archive's own footprint pair.

src/lib_manifest.s declares LIB_MLKEM_RESIDENT_BYTES twice, under
`.ifdef MLKEM_KECCAK_ONLY` (first) and `.else` (second); both are checked
against their own member set. This reports and FAILS on an unsafe value; it
does NOT rewrite lib_manifest.s — bumping a footprint equate is a
release-notes event (§6.6 requires per-(profile x variant) deltas), so a
human decides.

Usage: check_manifest.py <test map> <probe map> <lib_manifest.s>
"""
import re
import sys

WINDOW = 7680                 # c64-https CRYPTO_OVERLAY, code+rodata (HANDOFF-P2 decision 1)
KECCAK_MEMBERS = ("mlkem_lib_version.o", "mlkem_lib_manifest.o", "mlkem_state.o",
                  "mlkem_keccak.o", "mlkem_sponge.o")


def parse_segments(path):
    """ld65 -m map: 'Segment list' -> {name: size}."""
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


def parse_modules(path):
    """ld65 -m map: 'Modules list' -> {module: {segment: size}}. Sizes exclude
    alignment fill, which the segment total includes."""
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
            cur = m.group(2) or m.group(1)
            mods[cur] = {}
            continue
        m = re.match(r"^\s+(\S+)\s+Offs=([0-9A-F]+)\s+Size=([0-9A-F]+)", line)
        if m and cur:
            mods[cur][m.group(1)] = int(m.group(3), 16)
    return mods


def parse_equates(path):
    src = open(path).read()
    out = {}
    for k in ("LIB_MLKEM_RESIDENT_BYTES", "LIB_MLKEM_COLD_BYTES",
              "LIB_MLKEM_ZP_USAGE_BYTES", "LIB_MLKEM_REU_BANKS_USED"):
        vals = [int(v) for v in re.findall(rf"^{k}\s*=\s*(\d+)", src, re.M)]
        if vals:
            out[k] = vals
    return out


def roundup(n, to=256):
    return ((n + to - 1) // to) * to


def resident_of(segs):
    return segs.get("LIB_MLKEM_CODE", 0) + segs.get("LIB_MLKEM_RODATA", 0)


def main():
    test_map, probe_map, manifest = sys.argv[1], sys.argv[2], sys.argv[3]
    tsegs = parse_segments(test_map)
    psegs = parse_segments(probe_map)
    pmods = parse_modules(probe_map)
    eq = parse_equates(manifest)

    t_res = resident_of(tsegs)
    p_res = resident_of(psegs)
    cold = psegs.get("LIB_MLKEM_COLD_CODE", 0) + psegs.get("LIB_MLKEM_INIT_CODE", 0)

    print("measured, shipped mlkem.a (probe link, no test hooks):")
    print(f"  LIB_MLKEM_CODE       {psegs.get('LIB_MLKEM_CODE', 0):6d} B")
    print(f"  LIB_MLKEM_RODATA     {psegs.get('LIB_MLKEM_RODATA', 0):6d} B")
    print(f"  LIB_MLKEM_BSS        {psegs.get('LIB_MLKEM_BSS', 0):6d} B  (not a footprint equate; state buffers)")
    print(f"  -> resident          {p_res:6d} B   (rounds up to {roundup(p_res)})")
    print(f"  -> cold              {cold:6d} B   (rounds up to {roundup(cold)})")
    print("measured, standalone test PRG (-D MLKEM_TEST_HOOKS=1):")
    print(f"  -> resident          {t_res:6d} B   (+{t_res - p_res} B of hook entry points)")

    print("\nper member (probe link; sizes exclude alignment fill):")
    print(f"  {'member':24} {'code':>6} {'rodata':>6} {'bss':>6}")
    k_res = 0
    for name, segs in pmods.items():
        if not name.startswith("mlkem_"):
            continue
        c, r, b = (segs.get("LIB_MLKEM_CODE", 0), segs.get("LIB_MLKEM_RODATA", 0),
                   segs.get("LIB_MLKEM_BSS", 0))
        print(f"  {name:24} {c:6d} {r:6d} {b:6d}")
        if name in KECCAK_MEMBERS:
            k_res += c + r
    print(f"  mlkem-keccak.a member set resident: {k_res} B (rounds up to {roundup(k_res)})")

    print("\ndeclared (src/lib_manifest.s):")
    for k, v in eq.items():
        print(f"  {k:28} {' / '.join(str(x) for x in v)}")
    print()

    fail = False
    res = eq.get("LIB_MLKEM_RESIDENT_BYTES", [])
    if len(res) != 2:
        print(f"FAIL: expected two LIB_MLKEM_RESIDENT_BYTES equates (Keccak-only, full); found {len(res)}")
        return 1
    checks = [("LIB_MLKEM_RESIDENT_BYTES (mlkem-keccak.a)", res[0], k_res),
              ("LIB_MLKEM_RESIDENT_BYTES (mlkem.a)", res[1], max(p_res, t_res)),
              ("LIB_MLKEM_COLD_BYTES", eq.get("LIB_MLKEM_COLD_BYTES", [0])[0], cold)]
    for name, declared, measured in checks:
        if declared < measured:
            print(f"UNSAFE: {name} = {declared} < measured {measured}. "
                  f"Raise it to {roundup(measured)} (§6.6 safe-direction).")
            fail = True
        elif declared < roundup(measured):
            print(f"note: {name} = {declared} is safe but not on a 256-B "
                  f"boundary; fleet convention would use {roundup(measured)}.")

    # HANDOFF-P2 decision 1: the whole library targets the c64-https
    # CRYPTO_OVERLAY window, 7,680 B code+rodata. That is the NOMINAL window;
    # what is actually free in it is a P4 (consumer-side) question — README.
    print(f"\ncode+rodata vs the 7,680 B CRYPTO_OVERLAY window: "
          f"{p_res} / {WINDOW} B ({100.0 * p_res / WINDOW:.1f}%), "
          f"{WINDOW - p_res} B headroom (shipped); "
          f"{t_res} / {WINDOW} B ({100.0 * t_res / WINDOW:.1f}%) with test hooks")
    if p_res > WINDOW:
        print("OVER the window — a per-operation image split (HANDOFF-P2 decision 1 fallback) is required.")
        fail = True

    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
