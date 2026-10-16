#!/usr/bin/env python3
"""test_decaps_seed.py — mlkem_decaps_seed: ML-KEM-768 Decaps from the 64-byte
KeyGen seed d || z, with no dk (2,400 B) or ek (1,184 B) buffer, on the 6502
over the c64-test-harness in VICE.

Written red-first, before the entry existed: on a tree without it this suite
exits 1 with the missing label named.

===========================================================================
ABI under test
===========================================================================

    mlkem_decaps_seed   in  seed -> d || z (64 B, the SAME d and z that
                                    mlkem_keygen takes as seed and z)
                            ct   -> c (1,088 B)
                        out key  -> K (32 B)                   A = 0 always

    K == mlkem_decaps(dk = KeyGen(d, z).dk, c), bit for bit, including the
    implicit-rejection value J(z || c) for a ciphertext that does not
    re-encrypt. mlkem_arg_ek, mlkem_arg_dk and mlkem_arg_z are neither read
    nor written: every call points all three at decoy buffers and checks
    they come back unchanged. [decoys] varies what the decoys hold — two
    junk patterns, and well-formed ek / dk / z of a DIFFERENT key — and
    requires the identical, correct K each time, so an entry that reads any
    of the three (z in particular, which only the rejection value shows)
    goes red on its own cases, independent of whatever a pointer was left at
    by an earlier call.
    The parameter block is not modified (P1); canaries follow every buffer
    (C1); seed and c are inputs and must come back unchanged.

===========================================================================
Oracles, and what the ACVP vectors can and cannot pin here
===========================================================================

The ACVP decapsulation group publishes dk, not (d, z), and dk -> (d, z) is
one-way, so those ten vectors cannot be fed to a seed-taking entry as they
stand. What this suite runs instead:

  [kgdec]   every ACVP keyGen vector's (d, z) — whose dk ACVP pins — with a
            valid ciphertext encapsulated to that vector's ek (K must equal
            Encaps' K), and a modified ciphertext (K must equal J(z || c')).
  [acvpct]  all ten ACVP decapsulation ciphertexts ("valid" and "modified
            ciphertext") under keyGen tcId 1's seed; against that key every
            one of them is an implicit rejection, so K = J(z || c), and the
            expected value is also checked against Alg. 18 on the ACVP dk.
  [equiv]   random seeds and ciphertexts: the 6502's own mlkem_keygen ->
            mlkem_decaps (ACVP-verified by test_mlkem.py) and
            mlkem_decaps_seed must agree with each other and with the model.
  [hazmat]  cryptography.hazmat MLKEM768PrivateKey.from_seed_bytes(d || z):
            their encapsulate() -> our K; and a tampered ct -> their
            decapsulate() (an independent implicit-rejection oracle) == ours.
  [decoys]  one keyGen seed, valid and modified c, with mlkem_arg_ek/_dk/_z
            aimed at junk pattern A, junk pattern B, and the real ek, dk and
            z of another seed: K must be correct and identical in all three.
  [timing]  constant time in c: valid, bit 0 of byte 0 flipped, bit 7 of
            byte 1087 flipped must measure IDENTICALLY with the calibrated
            CIA instrument (the same protocol as test_mlkem.py T1). Also
            prints mlkem_keygen / mlkem_decaps on the same inputs.

Usage:
    python3 tools/test_decaps_seed.py [--full] [--only S[,S]] [--no-timing]

    --full   all 25 keyGen seeds, all 10 ACVP ciphertexts, 6 random seeds,
             4 hazmat seeds.

Honors C64_SKIP_BUILD=1. Exit 1 on any failure or missing label.
"""

import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem_ref as M
import test_mlkem as T
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, read_bytes, write_bytes,
    wait_for_text,
)

EK, DK, CT = M.EK_BYTES, M.DK_BYTES, M.CT_BYTES
BUF_SEED = 0x7EC0          # 64 B + canary .. $7F10 (BUF_Z is not used here)
BUF_KEY, BUF_CT = T.BUF_KEY, T.BUF_CT
DECOY_EK, DECOY_DK = T.BUF_EK, T.BUF_DK
ODD_CT, ODD_KEY, ODD_SEED = T.ODD, T.ODD + 0x4B1, T.ODD + 0x4F3   # .. $7A44
DECOY_Z = 0x7F40           # 32 B + canary .. $7F70
DECOY = bytes((0xA7 ^ (13 * k)) & 0xFF for k in range(DK))
DECOY_B = bytes((0x3C + 101 * k) & 0xFF for k in range(DK))

ENTRY = "mlkem_decaps_seed"
REQUIRED = [ENTRY, "mlkem_keygen", "mlkem_decaps", "mlkem_status"] + T.ARG_BLOCK

_fails, _checks = [], 0


def check(cond, label):
    global _checks
    _checks += 1
    if not cond:
        _fails.append(label)
        print(f"    FAIL  {label}")
    return cond


def cmp_bytes(tag, what, got, want):
    d = T.first_diff(got, want)
    return check(d is None, f"{tag}: {what} {d}")


def flip(c, byte, bit):
    c2 = bytearray(c)
    c2[byte] ^= 1 << bit
    return bytes(c2)


class Seed(T.C64):
    """test_mlkem's driver plus the seed entry."""

    def decaps_seed(self, seed, c, seed_at=BUF_SEED, ct_at=BUF_CT, key_at=BUF_KEY,
                    decoys=None):
        """decoys = (ek bytes, dk bytes, z bytes) placed behind mlkem_arg_ek,
        _dk and _z for this call; default: junk pattern A."""
        assert len(seed) == 64
        d_ek, d_dk, d_z = decoys or (DECOY[:EK], DECOY, DECOY[DK - 32:])
        self.put(seed_at, seed)
        self.put(ct_at, c)
        self.arm(key_at, 32)
        write_bytes(self.t, DECOY_EK, d_ek)
        write_bytes(self.t, DECOY_DK, d_dk)
        write_bytes(self.t, DECOY_Z, d_z)
        self.arg("seed", seed_at); self.arg("ct", ct_at); self.arg("key", key_at)
        self.arg("ek", DECOY_EK); self.arg("dk", DECOY_DK); self.arg("z", DECOY_Z)
        a, status = self.call(ENTRY)
        k = self.get(key_at, 32)
        side = {
            "canaries after K / c / seed (C1)":
                self.canary_ok(key_at, 32) and self.canary_ok(ct_at, CT)
                and self.canary_ok(seed_at, 64),
            "seed unchanged": self.get(seed_at, 64) == seed,
            "c unchanged": self.get(ct_at, CT) == c,
            "ek/dk/z decoys untouched": self.get(DECOY_EK, EK) == d_ek
                and self.get(DECOY_DK, DK) == d_dk and self.get(DECOY_Z, 32) == d_z,
            "parameter block preserved (P1)": self.args_intact(),
            f"A={a} mlkem_status={status}, want 0": a == 0 and status == 0,
        }
        return k, side


def run_case(c64, tag, seed, c, want, **kw):
    k, side = c64.decaps_seed(seed, c, **kw)
    ok = cmp_bytes(tag, "K", k, want)
    for what, good in side.items():
        ok &= check(good, f"{tag}: {what}")
    return ok, k


# ---------------------------------------------------------------------------

def suite_kgdec(c64, full):
    vecs = T.acvp_keygen()
    vecs = vecs if full else vecs[:2]
    print(f"\n[kgdec] ACVP keyGen (d, z) -> valid + modified ciphertext, "
          f"{len(vecs)} seed(s){'' if full else ' (--full: all 25)'}")
    for i, t in enumerate(vecs):
        d, z = T.hx(t["d"]), T.hx(t["z"])
        ek, dk = T.hx(t["ek"]), T.hx(t["dk"])
        if not check(M.mlkem_keygen(d, z) == (ek, dk),
                     f"oracle: keyGen tcId {t['tcId']} model != ACVP"):
            continue
        m = T.fixed_bytes(f"decaps-seed m {t['tcId']}")
        k_enc, c = M.mlkem_encaps(ek, m)
        tag = f"{ENTRY} [keyGen tcId {t['tcId']} valid c]"
        odd = (i == 1)
        kw = dict(seed_at=ODD_SEED, ct_at=ODD_CT, key_at=ODD_KEY) if odd else {}
        ok, _ = run_case(c64, tag, d + z, c, k_enc, **kw)
        if ok:
            print(f"    ok    {tag}{' (odd addresses)' if odd else ''}")
        c2 = flip(c, (37 * (i + 1)) % CT, i % 8)
        want = M.J(z + c2)
        assert want == M.mlkem_decaps(dk, c2) != k_enc
        tag = f"{ENTRY} [keyGen tcId {t['tcId']} modified c]"
        ok, k = run_case(c64, tag, d + z, c2, want)
        if k == k_enc:
            check(False, f"{tag}: returned the VALID K' for a modified ciphertext")
        if ok:
            print(f"    ok    {tag}  (J(z||c'))")


def suite_acvpct(c64, full):
    kg = T.acvp_keygen()[0]
    d, z, dk = T.hx(kg["d"]), T.hx(kg["z"]), T.hx(kg["dk"])
    vecs = T.acvp_encapdecap()["decapsulation"]
    if not full:
        vecs = [next(t for t in vecs if t["reason"] == r)
                for r in ("valid decapsulation", "modified ciphertext")]
    print(f"\n[acvpct] ACVP decapsulation ciphertexts under keyGen tcId {kg['tcId']}'s seed, "
          f"{len(vecs)} vector(s){'' if full else ' (--full: all 10)'}")
    for t in vecs:
        c = T.hx(t["c"])
        want = M.mlkem_decaps(dk, c)
        check(want == M.J(z + c), f"oracle: decapsulation tcId {t['tcId']} c is not a "
                                  f"rejection under a foreign key?")
        tag = f"{ENTRY} [decapsulation tcId {t['tcId']} c, {t['reason']}]"
        ok, _ = run_case(c64, tag, d + z, c, want)
        if ok:
            print(f"    ok    {tag}  (J(z||c))")


def suite_equiv(c64, full):
    n = 6 if full else 2
    rnd = random.Random(0xDEC5EED)
    print(f"\n[equiv] {ENTRY} == 6502 mlkem_keygen -> mlkem_decaps, {n} random seed(s) "
          f"x (valid, modified, random) c{'' if full else ' (--full: 6)'}")
    for i in range(n):
        d = bytes(rnd.randrange(256) for _ in range(32))
        z = bytes(rnd.randrange(256) for _ in range(32))
        ek, dk = M.mlkem_keygen(d, z)
        m = bytes(rnd.randrange(256) for _ in range(32))
        k_enc, c = M.mlkem_encaps(ek, m)
        cts = [("valid", c),
               ("modified", flip(c, rnd.randrange(CT), rnd.randrange(8))),
               ("random", bytes(rnd.randrange(256) for _ in range(CT)))]
        if not full:
            cts = cts[:2] if i == 0 else cts[1:]
        ek6, dk6, cn = c64.keygen(d, z)
        check(cn and (ek6, dk6) == (ek, dk), f"equiv seed #{i}: 6502 mlkem_keygen != model")
        for name, cx in cts:
            want = M.mlkem_decaps(dk, cx)
            k_dk, a, _ = c64.decaps(dk6, cx)
            tag = f"{ENTRY} [equiv seed #{i}, {name} c]"
            ok = check(k_dk == want, f"{tag}: 6502 mlkem_decaps disagrees with the model")
            ok2, k = run_case(c64, tag, d + z, cx, want)
            ok &= ok2 and check(k == k_dk, f"{tag}: seed entry != mlkem_decaps(dk) on the 6502")
            if ok:
                print(f"    ok    {tag}  ({'K' if want == k_enc else 'J(z||c)'})")


def suite_hazmat(c64, full):
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric import mlkem
    except ImportError as e:
        check(False, f"hazmat: cryptography.hazmat mlkem unavailable ({e})")
        return
    n = 4 if full else 1
    print(f"\n[hazmat] cryptography {cryptography.__version__} from_seed_bytes(d||z), "
          f"{n} seed(s){'' if full else ' (--full: 4)'}")
    rnd = random.Random(0x4D4C4B454D ^ 0x5EED)
    for i in range(n):
        seed = bytes(rnd.randrange(256) for _ in range(64))
        sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
        ss, ct = sk.public_key().encapsulate()
        tag = f"{ENTRY} [hazmat seed #{i}, their encapsulate()]"
        ok, _ = run_case(c64, tag, seed, ct, ss)
        if ok:
            print(f"    ok    {tag}")
        ct2 = flip(ct, rnd.randrange(CT), rnd.randrange(8))
        theirs = sk.decapsulate(ct2)
        tag = f"{ENTRY} [hazmat seed #{i}, tampered ct vs their decapsulate()]"
        ok, _ = run_case(c64, tag, seed, ct2, theirs)
        check(theirs != ss, f"{tag}: hazmat accepted a tampered ct?")
        if ok:
            print(f"    ok    {tag}")


def suite_decoys(c64, full):
    t = T.acvp_keygen()[0]
    d, z = T.hx(t["d"]), T.hx(t["z"])
    ek, dk = T.hx(t["ek"]), T.hx(t["dk"])
    other = T.acvp_keygen()[1]
    o_ek, o_dk, o_z = T.hx(other["ek"]), T.hx(other["dk"]), T.hx(other["z"])
    assert o_z != z
    k_enc, c = M.mlkem_encaps(ek, T.fixed_bytes("decaps-seed decoys m"))
    c2 = flip(c, 500, 3)
    sets = [("junk pattern A", (DECOY[:EK], DECOY, DECOY[DK - 32:])),
            ("junk pattern B", (DECOY_B[:EK], DECOY_B, DECOY_B[DK - 32:])),
            (f"real ek/dk/z of keyGen tcId {other['tcId']}", (o_ek, o_dk, o_z))]
    print(f"\n[decoys] keyGen tcId {t['tcId']}: mlkem_arg_ek/_dk/_z aimed at "
          f"{len(sets)} decoy sets, valid and modified c")
    for cname, cx, want in (("valid c", c, k_enc), ("modified c", c2, M.J(z + c2))):
        got = {}
        for sname, dec in sets:
            tag = f"{ENTRY} [decoys: {sname}, {cname}]"
            ok, k = run_case(c64, tag, d + z, cx, want, decoys=dec)
            got[sname] = k
            if ok:
                print(f"    ok    {tag}")
        check(len(set(got.values())) == 1,
              f"{ENTRY} [decoys, {cname}]: K depends on what ek/dk/z point at")


def suite_timing(c64, full):
    import bench_keccak as B
    t, l = c64.t, c64.l
    if any(l.address(n) is None for n in T.BENCH_LABELS):
        check(False, "timing: bench instrument labels missing; constant time not measured")
        return
    print(f"\n[timing] {ENTRY} constant-time in c, calibrated CIA instrument")
    overhead, st_o, _ = B.measure_stable(t, l, None)
    spin_raw, st_s, _ = B.measure_stable(t, l, "bench_spin_1000")
    if not (st_o and st_s and spin_raw - overhead == B.SPIN_EXPECTED):
        check(False, f"timing: instrument calibration off (spin net {spin_raw - overhead}, "
                     f"want {B.SPIN_EXPECTED}); not reporting cycles")
        return
    print(f"    calibration OK (overhead {overhead}, spin {spin_raw - overhead})")

    kg = T.acvp_keygen()[0]
    d, z = T.hx(kg["d"]), T.hx(kg["z"])
    ek, dk = M.mlkem_keygen(d, z)
    k_enc, c = M.mlkem_encaps(ek, T.fixed_bytes("decaps-seed timing m"))
    inputs = [("valid c", c), ("c ^ bit 0 of byte 0", flip(c, 0, 0)),
              (f"c ^ bit 7 of byte {CT - 1}", flip(c, CT - 1, 7))]
    counts, stable, right = {}, True, True
    for name, cx in inputs:
        def setup(cx=cx):
            c64.put(BUF_SEED, d + z)
            c64.put(BUF_CT, cx)
            c64.arm(BUF_KEY, 32)
            c64.arg("seed", BUF_SEED); c64.arg("ct", BUF_CT); c64.arg("key", BUF_KEY)
        v, st, vals = B.measure_stable(t, l, ENTRY, tries=2, setup=setup)
        stable &= st
        right &= read_bytes(t, BUF_KEY, 32) == M.mlkem_decaps(dk, cx)
        counts[name] = v - overhead
        print(f"    {ENTRY} {name:24} {v - overhead:>12,} cycles"
              f"{'' if st else '  UNSTABLE ' + str(vals)}")
    distinct = sorted(set(counts.values()))
    line = "; ".join(f"{k}={v:,}" for k, v in counts.items())
    check(right, f"{ENTRY}: a timed call returned the wrong K")
    if check(stable, f"{ENTRY}: measurement reproducible (VICE is deterministic)") and \
       check(len(distinct) == 1, f"{ENTRY}: constant-time in c: {line}"):
        print(f"    ok    {ENTRY}: {distinct[0]:,} cycles, identical for valid and "
              f"one-bit-modified c")

    # Same inputs through the two-call path, for the comparison.
    def setup_kg():
        c64.put(T.BUF_SEED, d); c64.put(T.BUF_Z, z)
        c64.arg("seed", T.BUF_SEED); c64.arg("z", T.BUF_Z)
        c64.arg("ek", T.BUF_EK); c64.arg("dk", T.BUF_DK)

    def setup_de():
        c64.put(T.BUF_DK, dk); c64.put(BUF_CT, c)
        c64.arg("dk", T.BUF_DK); c64.arg("ct", BUF_CT); c64.arg("key", BUF_KEY)

    kgc, st1, _ = B.measure_stable(t, l, "mlkem_keygen", tries=2, setup=setup_kg)
    dec, st2, _ = B.measure_stable(t, l, "mlkem_decaps", tries=2, setup=setup_de)
    kgc, dec = kgc - overhead, dec - overhead
    print(f"    mlkem_keygen                       {kgc:>12,} cycles")
    print(f"    mlkem_decaps                       {dec:>12,} cycles")
    print(f"    keygen + decaps                    {kgc + dec:>12,} cycles; "
          f"{ENTRY} is {distinct[0] - dec:+,} over decaps alone")


SUITES = {"kgdec": suite_kgdec, "acvpct": suite_acvpct, "equiv": suite_equiv,
          "hazmat": suite_hazmat, "decoys": suite_decoys, "timing": suite_timing}


def main():
    args = sys.argv[1:]
    full = "--full" in args
    timing = "--no-timing" not in args
    only = None
    if "--only" in args:
        only = set(args[args.index("--only") + 1].split(","))
        if only - set(SUITES):
            print(f"unknown suite(s): {sorted(only - set(SUITES))}; choose from {sorted(SUITES)}")
            return 2
    if not T.self_check_model():
        return 1

    os.chdir(T.PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        r = subprocess.run(["make"], capture_output=True, cwd=T.PROJECT_ROOT)
        if r.returncode != 0:
            print(r.stderr.decode()[-2000:])
            print("Build failed")
            return 1
    labels = Labels.from_file(T.LABELS_PATH)
    missing = [n for n in REQUIRED if labels.address(n) is None]
    if missing:
        print(f"FAIL  required export(s) not in build/labels.txt: {', '.join(missing)}")
        print("FAILED (red: mlkem_decaps_seed not implemented)")
        return 1
    clash = [(n, a) for n, a in labels.items()
             if T.SCRATCH_LO <= a < T.SCRATCH_HI and not n.startswith("__")]
    if clash or labels["__MAIN_LAST__"] > T.SCRATCH_LO:
        print(f"FATAL: image/labels overlap the harness scratch: {clash[:5]}")
        return 1

    config = ViceConfig(prg_path=T.PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])
    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        if wait_for_text(transport, "C64-MLKEM P", timeout=60.0, verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        c64 = Seed(transport, labels)
        for name, fn in SUITES.items():
            if name == "timing" and not timing:
                continue
            if only is None or name in only:
                fn(c64, full)
        mgr.release(inst)

    print(f"\n{_checks} checks in {time.time() - t0:.1f}s")
    if _fails:
        print(f"FAILED ({len(_fails)}):")
        for f in _fails[:30]:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
