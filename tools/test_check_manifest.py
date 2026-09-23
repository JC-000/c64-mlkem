#!/usr/bin/env python3
"""test_check_manifest.py — self-test of tools/check_manifest.py and of the
Makefile wiring that makes it (and check-precalc) part of `make test`.

A checker nobody tests is a checker a one-line edit can switch off: the
adversarial review of contract/1.2.3 found 10 of 12 checker mutants and every
wiring mutant surviving `make test`. Each case below exists to kill a named
mutant class, and names it.

Fixtures (hermetic: no build tree, no VICE, a few seconds):
  tools/fixtures/check_manifest/mlkem-lib.map         probe link of mlkem.a
  tools/fixtures/check_manifest/mlkem-keccak-lib.map  probe link of mlkem-keccak.a
  tools/fixtures/check_manifest/mlkem.map             test-hooks PRG
    (v0.5.1 layout, trimmed before the Exports list; the checker never reads
    past the Segment list.) Placed spans: mlkem.a CODE 6311 + RODATA 897
    (888 of objects + 9 internal fill) = 7208, 23 B gap between them;
    mlkem-keccak.a 1755 + 192 = 1947.
  Archives are assembled here with ca65/ar65: one member per module the map
  names (empty), plus an mlkem_lib_manifest.o exporting the declared values
  under test — so the declared value lives ONLY in the shipped member.
  G1-G5 maps are doctored from the probe map in code below.

Usage: test_check_manifest.py [--checker PATH] [--makefile PATH]
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "check_manifest")
PMAP = os.path.join(FIX, "mlkem-lib.map")
KMAP = os.path.join(FIX, "mlkem-keccak-lib.map")
TMAP = os.path.join(FIX, "mlkem.map")

FAILS = []


def expect(cond, what):
    print(("  ok    " if cond else "  FAIL  ") + what)
    if not cond:
        FAILS.append(what)


def members_of(map_path, archive_basename):
    """Archive members named in a map's module list, in order."""
    pat = re.compile(r"^\S*" + re.escape(archive_basename) + r"\(([^)]+)\):$")
    out = []
    for line in open(map_path):
        m = pat.match(line.rstrip())
        if m:
            out.append(m.group(1))
    return out


def build_archive(tmp, tag, members, manifest_src):
    """An archive whose members are empty objects named like the real ones,
    except mlkem_lib_manifest.o, which assembles `manifest_src`."""
    d = os.path.join(tmp, tag)
    os.makedirs(d)
    for mem in members:
        src = os.path.join(d, mem[:-2] + ".s")
        with open(src, "w") as f:
            f.write(manifest_src if mem == "mlkem_lib_manifest.o" else "")
        subprocess.run(["ca65", "-o", os.path.join(d, mem), src], check=True)
    a = os.path.join(d, tag + ".a")
    subprocess.run(["ar65", "r", a] + [os.path.join(d, m) for m in members], check=True,
                   capture_output=True)
    return a


def manifest(resident, cold=0):
    return (f"LIB_MLKEM_RESIDENT_BYTES = {resident}\n.export LIB_MLKEM_RESIDENT_BYTES: abs\n"
            f"LIB_MLKEM_COLD_BYTES = {cold}\n.export LIB_MLKEM_COLD_BYTES: abs\n")


# A manifest whose FIRST od65 export record is a label (no Value line).
# od65 lists the label first and the equates in reverse definition order:
#   LIB_MLKEM_AAA (label) | ZZZ 0 | COLD 8000 | RESIDENT 7000
# Zipping Name lines against Value lines pairs RESIDENT with COLD's 8000
# (>= 7208, a false pass); a per-record parse must refuse it.
MISALIGNED = ("LIB_MLKEM_ZZZ = 0\n.export LIB_MLKEM_ZZZ: abs\n"
              "LIB_MLKEM_COLD_BYTES = 8000\n.export LIB_MLKEM_COLD_BYTES: abs\n"
              "LIB_MLKEM_RESIDENT_BYTES = 7000\n.export LIB_MLKEM_RESIDENT_BYTES: abs\n"
              ".segment \"LIB_MLKEM_RODATA\"\nLIB_MLKEM_AAA: .byte 0\n.export LIB_MLKEM_AAA\n")


def run(checker, mlkem_a, pmap, keccak_a, kmap=KMAP):
    cmd = [sys.executable, checker, "--test-map", TMAP,
           "--probe", "mlkem.a", mlkem_a, pmap,
           "--probe", "mlkem-keccak.a", keccak_a, kmap]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def doctor(tmp, name, old, new, count=1, regex=False):
    base = open(PMAP).read()
    txt = re.sub(old, new, base, count=count, flags=re.M) if regex else base.replace(old, new, count)
    assert txt != base, f"fixture doctoring {name} matched nothing — re-derive it from the map"
    p = os.path.join(tmp, name + ".map")
    open(p, "w").write(txt)
    return p


def test_checker(checker):
    full = members_of(PMAP, "mlkem.a")
    kecc = members_of(KMAP, "mlkem-keccak.a")
    assert "mlkem_codec.o" in full and "mlkem_lib_manifest.o" in kecc, "fixture maps changed shape"

    with tempfile.TemporaryDirectory() as tmp:
        A = {n: build_archive(tmp, f"mlkem_{n}", full, manifest(n))
             for n in (7424, 7208, 7207, 7200, 7220, 7000, 6400)}
        K = {n: build_archive(tmp, f"mlkem-keccak_{n}", kecc, manifest(n)) for n in (2048, 1947, 1946, 1900)}
        mis = build_archive(tmp, "mlkem_misaligned", full, MISALIGNED)

        print("R1/R2/R3 — basis and boundary")
        rc, out = run(checker, A[7424], PMAP, K[2048])
        expect(rc == 0, "shipped values (7424 / 2048) pass  [over-strict mutants]")
        rc, out = run(checker, A[7208], PMAP, K[1947])
        expect(rc == 0, "declared == placed span (7208 / 1947) passes  [off-by-one, span+1, gap charged]")
        rc, out = run(checker, A[7207], PMAP, K[2048])
        expect(rc != 0 and "FAIL [R1]: mlkem.a" in out, "mlkem.a 7207 = span-1 fails R1  [span without +1]")
        rc, out = run(checker, A[7424], PMAP, K[1946])
        expect(rc != 0 and "FAIL [R1]: mlkem-keccak.a" in out, "mlkem-keccak.a 1946 = span-1 fails R1")
        rc, out = run(checker, A[7200], PMAP, K[2048])
        expect(rc != 0 and "FAIL [R1]" in out,
               "7200 (>= object sum 7199, < span 7208) fails  [sum of object sizes]")
        rc, out = run(checker, A[7220], PMAP, K[2048])
        expect(rc == 0, "7220 (>= span 7208, < span + 23 B gap) passes  [inter-segment gap charged]")
        rc, out = run(checker, A[6400], PMAP, K[2048])
        expect(rc != 0 and "FAIL [R1]" in out,
               "6400 (>= CODE 6311, < CODE+RODATA 7208) fails  [RODATA exempted/dropped from RESIDENT]")
        expect(rc == 1, "a FAIL exits exactly 1  [exit 0 on FAIL]")

        print("declared values come from the SHIPPED member, parsed per record")
        rc, out = run(checker, A[7000], PMAP, K[2048])
        expect(rc != 0 and "declared   7000" in out,
               "archive declaring 7000 fails although src/lib_manifest.s says 7424  [source text read]")
        rc, out = run(checker, mis, PMAP, K[2048])
        expect(rc != 0 and "cannot read declared values" in out,
               "export record without a Value line is refused, not zipped  [Name/Value zip misalignment]")

        print("both archives are checked")
        rc, out = run(checker, A[7424], PMAP, K[1900])
        expect(rc != 0 and "FAIL [R1]: mlkem-keccak.a" in out,
               "mlkem-keccak.a declaring 1900 < 1947 fails  [second --probe ignored]")

        print("measurement guards G1-G5 (each on a map doctored for that guard only)")
        cases = {
            "G1": doctor(tmp, "G1", r"\S*mlkem\.a\(mlkem_codec\.o\):\n(    .*\n)+", "", regex=True),
            "G2": doctor(tmp, "G2", "bench.o:\n",
                         "bench.o:\n    LIB_MLKEM_CODE    Offs=000000  Size=000010  Align=00001  Fill=0000\n"),
            "G3": doctor(tmp, "G3", "\nBSS  ", "\nLIB_MLKEM_INIT        002501  002501  000001  00001\nBSS  "),
            "G4": doctor(tmp, "G4", r"^(LIB_MLKEM_RODATA\s+\S+\s+\S+\s+\S+\s+)00040", r"\g<1>00001",
                         regex=True),
            "G5": doctor(tmp, "G5", r"^(LIB_MLKEM_RODATA\s+\S+\s+\S+\s+)000381", r"\g<1>000300",
                         regex=True),
        }
        what = {"G1": "codec member absent from the probe", "G2": "driver places 16 B in LIB_MLKEM_CODE",
                "G3": "unclassified LIB_MLKEM_INIT segment", "G4": "RODATA start align 1 < fragment 64",
                "G5": "RODATA Size column != End-Start+1"}
        for g, p in cases.items():
            rc, out = run(checker, A[7424], p, K[2048])
            expect(rc != 0 and f"FAIL [{g}]" in out, f"{g}: {what[g]}  [{g} disabled]")


def prereqs(mk, target):
    """Prerequisites of `target:` in a Makefile, joining backslash lines."""
    txt = mk.replace("\\\n", " ")
    m = re.search(rf"^{re.escape(target)}:(?!=)([^\n]*)", txt, re.M)
    return m.group(1).split() if m else None


def recipe(mk, target):
    txt = mk.replace("\\\n", " ")
    m = re.search(rf"^{re.escape(target)}:[^\n]*\n((?:\t[^\n]*\n)+)", txt, re.M)
    return m.group(1) if m else ""


def test_wiring(makefile):
    mk = open(makefile).read()
    print("Makefile wiring")
    t = prereqs(mk, "test") or []
    for need in ("check-manifest", "check-precalc", "check-manifest-selftest", "check-precalc-selftest"):
        expect(need in t, f"`test:` depends on {need}  [{need} removed from test]")
    cm = prereqs(mk, "check-manifest") or []
    expect("$(LIB_PROBE)" in cm and "$(LIB_PROBE_KECCAK)" in cm,
           "check-manifest depends on both probe links  [keccak probe not built]")
    r = recipe(mk, "check-manifest")
    expect(re.search(r"--probe\s+mlkem\.a\s+\$\(ARCHIVE\)\s+\$\(LIB_PROBE_MAP\)", r) is not None,
           "check-manifest passes --probe mlkem.a $(ARCHIVE) $(LIB_PROBE_MAP)")
    expect(re.search(r"--probe\s+mlkem-keccak\.a\s+\$\(ARCHIVE_KECCAK\)\s+\$\(LIB_PROBE_KECCAK_MAP\)", r)
           is not None, "check-manifest passes --probe mlkem-keccak.a  [keccak probe dropped]")
    expect(re.search(r"^\s*@?-", r, re.M) is None and "|| true" not in r,
           "check-manifest recipe does not ignore the checker's exit status")
    r = recipe(mk, "check-precalc")
    expect("$(CONTRACT_PRECALC_REF)" in r and "$(CONTRACT_DIR)" in r and "|| true" not in r
           and re.search(r"^\s*@?-", r, re.M) is None,
           "check-precalc passes CONTRACT_DIR and the pinned ref, exit status honoured")
    m = re.search(r"^CONTRACT_PRECALC_REF\s*\?=\s*(\S+)", mk, re.M)
    expect(m is not None and re.fullmatch(r"v\d+\.\d+\.\d+", m.group(1) or "") is not None,
           "CONTRACT_PRECALC_REF is pinned to a vX.Y.Z tag  [pin moved to a branch/HEAD]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checker", default=os.path.join(HERE, "check_manifest.py"))
    ap.add_argument("--makefile", default=os.path.join(HERE, "..", "Makefile"))
    a = ap.parse_args()
    test_checker(a.checker)
    test_wiring(a.makefile)
    if FAILS:
        print(f"check-manifest-selftest: FAIL ({len(FAILS)} case(s))")
        return 1
    print("check-manifest-selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
