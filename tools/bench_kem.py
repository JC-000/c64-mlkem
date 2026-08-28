#!/usr/bin/env python3
"""bench_kem.py — cycle-exact cost of ML-KEM-768 KeyGen / Encaps / Decaps and
of the NTT primitives, with the Keccak share separated out.

P2's headline deliverable: it replaces the roadmap's 15-45M non-Keccak
estimate with a measurement, next to P1's Keccak number, against the 40-70M
keygen+decaps budget.

Same instrument and the SAME CALIBRATION REFUSAL as bench_keccak.py: CIA1
TA+TB chained as a 32-bit phi2 counter, display blanked and frame-synced, one
warm-up discarded, every number measured twice and required to reproduce
exactly. Nothing is printed unless bench_spin_1000 calibrates.

What is measured:

  keccak_f1600                   one permutation, in THIS link (the count
                                 shifts by tens of cycles with where ld65
                                 placed the round-constant table)
  mlkem_poly_ntt / _intt / _basemul
                                 one call each on a random polynomial
  mlkem_keygen / mlkem_encaps / mlkem_decaps
                                 ACVP vector tcId 1 of each group (keygen d,z;
                                 encaps ek,m; decaps dk,c) — the same inputs
                                 tools/test_mlkem.py --full reports, so the
                                 two must agree to the cycle

The Keccak share is NOT measured by subtraction (there is nothing to subtract
against). It is the permutation COUNT for that exact input, taken from the
model (tools/mlkem_ref.py: SampleNTT's block count is data-dependent on the
public rho), times the permutation cost measured above. The sponge's own
per-block bookkeeping (~3,850 cycles/block, P1) is left in "everything else".
The arithmetic share is likewise NTT/INTT/basemul counts x measured cost.

Usage: python3 tools/bench_kem.py
Honors C64_SKIP_BUILD=1.
"""

import json
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem_ref as M
from bench_keccak import measure_stable, SPIN_EXPECTED
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, read_bytes, write_bytes, jsr,
    wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "mlkem.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VECTOR_DIR = os.path.join(PROJECT_ROOT, "tools", "vectors")

# Scratch above the image (~$3E00) and below the sqtab window ($9000): the
# same layout tools/test_mlkem.py uses, so the measured numbers are taken on
# identical addresses. Polynomials are page-aligned (hard ABI requirement).
BUF_EK, BUF_DK, BUF_CT = 0x6000, 0x6500, 0x7000
BUF_KEY, BUF_SEED, BUF_Z = 0x7E80, 0x7EC0, 0x7F00
POLY_A, POLY_B = 0x8000, 0x8200
SCRATCH_LO, SCRATCH_HI = 0x6000, 0x8400

RATE = {"sha3_256": 136, "sha3_512": 72, "shake128": 168, "shake256": 136}
K = 3


def hx(s):
    return bytes.fromhex(s)


def acvp(name):
    with open(os.path.join(VECTOR_DIR, name)) as fh:
        return json.load(fh)["testGroups"]


# --- permutation count from the model --------------------------------------

def perms(absorb_len, rate, squeeze_len):
    """Permutations one sponge call costs. The 6502 sponge permutes once per
    full rate block absorbed and once per rate block squeezed (the pad block
    counts as the first squeeze); a lazy vs eager absorb of an exactly-full
    block gives the same total."""
    return absorb_len // rate + (squeeze_len + rate - 1) // rate


def sample_ntt_blocks(rho):
    """SHAKE128 blocks the 6502's SampleNTT squeezes for all k*k entries of
    A: one block per 168 consumed bytes, fetched only when needed."""
    total = 0
    for i in range(K):
        for j in range(K):
            n = M.sample_ntt_bytes_consumed(rho, i, j)
            total += (n + 167) // 168
    return total


def perms_keygen(d, z):
    ek, _ = M.mlkem_keygen(d, z)
    rho = ek[-32:]
    return (perms(33, RATE["sha3_512"], 64)              # G(d || k)
            + sample_ntt_blocks(rho)                     # A from SHAKE128
            + 2 * K * perms(33, RATE["shake256"], 128)   # PRF for s, e
            + perms(1184, RATE["sha3_256"], 32))         # H(ek)


def perms_kpke_encrypt(rho):
    return (sample_ntt_blocks(rho)                       # A^T from SHAKE128
            + (2 * K + 1) * perms(33, RATE["shake256"], 128))   # PRF y, e1, e2


def perms_encaps(ek):
    rho = ek[-32:]
    return (perms(1184, RATE["sha3_256"], 32)            # H(ek)
            + perms(64, RATE["sha3_512"], 64)            # G(m || H(ek))
            + perms_kpke_encrypt(rho))


def perms_decaps(dk):
    # Alg. 18: K-PKE.Decrypt (no hashing), G(m' || h) with the STORED h (no
    # H(ek) — the §7.3 check is the caller's), J(z || c), re-encrypt.
    rho = dk[1152 + 1152:1152 + 1184]
    return (perms(64, RATE["sha3_512"], 64)              # G(m' || h)
            + perms(32 + 1088, RATE["shake256"], 32)     # J(z || c)
            + perms_kpke_encrypt(rho))


# NTT-level operation counts (FIPS 203 Alg. 13-15, k = 3).
OPS = {
    # (ntt, intt, basemul)
    "mlkem_keygen": (2 * K, 0, K * K),                       # s, e; A s
    "mlkem_encaps": (K, K + 1, K * K + K),                   # y; u, v; A^T y, t^T y
    "mlkem_decaps": (K + K, 1 + K + 1, K + K * K + K),       # decrypt: u; s^T u; v-.. ; then encrypt
}


def main():
    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        r = subprocess.run(["make"], capture_output=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(r.stderr.decode()[-2000:])
            return 1

    labels = Labels.from_file(LABELS_PATH)
    last = labels["__MAIN_LAST__"]
    if last > SCRATCH_LO:
        print(f"FATAL: image end ${last:04X} overlaps the scratch range ${SCRATCH_LO:04X}-${SCRATCH_HI:04X}")
        return 1

    kg = [t for g in acvp("ML-KEM-768-keyGen-FIPS203.json") for t in g["tests"]][0]
    ed = {g["function"]: g["tests"] for g in acvp("ML-KEM-768-encapDecap-FIPS203.json")}
    en = ed["encapsulation"][0]
    de = ed["decapsulation"][0]
    d, z = hx(kg["d"]), hx(kg["z"])
    ek_en, m_en = hx(en["ek"]), hx(en["m"])
    dk_de, c_de = hx(de["dk"]), hx(de["c"])

    expected = {
        "mlkem_keygen": (M.mlkem_keygen(d, z), perms_keygen(d, z)),
        "mlkem_encaps": (M.mlkem_encaps(ek_en, m_en), perms_encaps(ek_en)),
        "mlkem_decaps": (M.mlkem_decaps(dk_de, c_de), perms_decaps(dk_de)),
    }

    rng = random.Random(0x5EED)
    poly_a = M.poly_to_c64([rng.randrange(M.Q) for _ in range(M.N)])
    poly_b = M.poly_to_c64([rng.randrange(M.Q) for _ in range(M.N)])

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        if wait_for_text(t, "C64-MLKEM", timeout=60.0, verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(t, 0x0339, bytes([0x4C, 0x39, 0x03]))

        def zp16(name, addr):
            write_bytes(t, labels[name], bytes([addr & 0xFF, addr >> 8]))

        print("Calibration")
        overhead, st_o, v_o = measure_stable(t, labels, None)
        spin_raw, st_s, v_s = measure_stable(t, labels, "bench_spin_1000")
        spin = spin_raw - overhead
        print(f"  empty window (instrument overhead) : {overhead} cycles   {'stable' if st_o else 'UNSTABLE ' + str(v_o)}")
        print(f"  bench_spin_1000 net                : {spin} cycles (expected {SPIN_EXPECTED})   {'stable' if st_s else 'UNSTABLE ' + str(v_s)}")
        if not (st_o and st_s) or spin != SPIN_EXPECTED:
            print("\nFAIL: calibration off — the counter does not count what it claims. Not reporting ML-KEM numbers.")
            mgr.release(inst)
            return 1
        print("  calibration OK — the counter is cycle-exact.\n")

        results, stable = {}, True

        def bench(name, label, setup, tries=2):
            nonlocal stable
            v, st, vals = measure_stable(t, labels, label, tries=tries, setup=setup)
            stable &= st
            results[name] = v - overhead
            print(f"  {name:22} {v - overhead:>12,} cycles   {'stable' if st else 'UNSTABLE ' + str(vals)}")

        print("Primitives")
        bench("keccak_f1600", "keccak_f1600", None, tries=3)

        def setup_poly():
            write_bytes(t, POLY_A, poly_a)
            write_bytes(t, POLY_B, poly_b)
            zp16("mlkem_zp_dst", POLY_A)
            zp16("mlkem_zp_src", POLY_B)
        bench("mlkem_poly_ntt", "mlkem_poly_ntt", setup_poly)
        bench("mlkem_poly_intt", "mlkem_poly_intt", setup_poly)
        bench("mlkem_poly_basemul", "mlkem_poly_basemul", setup_poly)

        def args(**kw):
            for name, addr in kw.items():
                zp16("mlkem_arg_" + name, addr)

        def setup_kg():
            write_bytes(t, BUF_SEED, d); write_bytes(t, BUF_Z, z)
            args(seed=BUF_SEED, z=BUF_Z, ek=BUF_EK, dk=BUF_DK)

        def setup_en():
            write_bytes(t, BUF_EK, ek_en); write_bytes(t, BUF_SEED, m_en)
            args(ek=BUF_EK, seed=BUF_SEED, ct=BUF_CT, key=BUF_KEY)

        def setup_de():
            write_bytes(t, BUF_DK, dk_de); write_bytes(t, BUF_CT, c_de)
            args(dk=BUF_DK, ct=BUF_CT, key=BUF_KEY)

        print("\nML-KEM-768 (ACVP tcId 1 inputs)")
        bench("mlkem_keygen", "mlkem_keygen", setup_kg)
        # The measured call's outputs are still in the buffers: check them so
        # a number is never reported for a call that computed the wrong thing.
        ek, dk = read_bytes(t, BUF_EK, 1184), read_bytes(t, BUF_DK, 2400)
        ok_kg = (ek, dk) == expected["mlkem_keygen"][0]
        bench("mlkem_encaps", "mlkem_encaps", setup_en)
        kk, ct = read_bytes(t, BUF_KEY, 32), read_bytes(t, BUF_CT, 1088)
        ok_en = (kk, ct) == expected["mlkem_encaps"][0]
        bench("mlkem_decaps", "mlkem_decaps", setup_de)
        kd = read_bytes(t, BUF_KEY, 32)
        ok_de = kd == expected["mlkem_decaps"][0]
        mgr.release(inst)

    if not stable:
        print("\nFAIL: a measurement did not reproduce; VICE is deterministic, so the instrument is wrong.")
        return 1
    if not (ok_kg and ok_en and ok_de):
        print(f"\nFAIL: measured call produced wrong output (keygen {ok_kg}, encaps {ok_en}, decaps {ok_de}); not reporting.")
        return 1

    kf = results["keccak_f1600"]
    ntt, intt, bm = results["mlkem_poly_ntt"], results["mlkem_poly_intt"], results["mlkem_poly_basemul"]
    print()
    print("=" * 78)
    print(f"  {'':14} {'cycles':>12} {'Keccak-f':>6} {'= cycles':>12} {'share':>6}   {'NTT/INTT/basemul':>18} {'= cycles':>12} {'share':>6}   {'rest':>12}")
    tot = {}
    for fn in ("mlkem_keygen", "mlkem_encaps", "mlkem_decaps"):
        c = results[fn]
        n_perm = expected[fn][1]
        kc = n_perm * kf
        o_ntt, o_intt, o_bm = OPS[fn]
        ac = o_ntt * ntt + o_intt * intt + o_bm * bm
        rest = c - kc - ac
        tot[fn] = (c, kc, ac)
        print(f"  {fn[6:]:14} {c:>12,} {n_perm:>6} {kc:>12,} {100.0 * kc / c:>5.1f}%   "
              f"{o_ntt:>4}/{o_intt:>3}/{o_bm:>3}       {ac:>12,} {100.0 * ac / c:>5.1f}%   {rest:>12,}")
    kd_c = tot["mlkem_keygen"][0] + tot["mlkem_decaps"][0]
    kd_k = tot["mlkem_keygen"][1] + tot["mlkem_decaps"][1]
    print("=" * 78)
    print(f"  keygen + decaps : {kd_c:,} cycles = {kd_c / 1e6:.1f}M "
          f"({kd_c / 1_022_727:.1f} s at 1.023 MHz), of which Keccak-f[1600] {kd_k / 1e6:.1f}M ({100.0 * kd_k / kd_c:.1f}%)")
    lo, hi = 40_000_000, 70_000_000
    where = "INSIDE" if lo <= kd_c <= hi else "OUTSIDE"
    print(f"  roadmap budget {lo // 1_000_000}-{hi // 1_000_000}M for keygen+decaps: measurement falls {where}")
    print(f"  keccak_f1600 in this link: {kf:,} cycles (P1 headline 456,605; rodata placement shifts it)")
    print(f"  ntt {ntt:,}  intt {intt:,}  basemul {bm:,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
