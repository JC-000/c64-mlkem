#!/usr/bin/env python3
"""bench_sampler.py — cycle-exact cost of the WP2 samplers and codecs.

Same instrument and the same calibration refusal as bench_keccak.py: CIA1
TA+TB chained as a 32-bit phi2 counter, display blanked and frame-synced, one
warm-up discarded, every number measured three times and required to
reproduce exactly. Nothing is printed unless bench_spin_1000 calibrates.

What is measured, per routine, on a 256-coefficient polynomial:

  mlkem_sample_ntt     whole call for a seed whose stream needs 3 blocks and
                       one that needs 4, then the same with N x keccak_f1600
                       removed — the "excluding Keccak" number the brief asks
                       for (the sponge's own squeeze copy stays in, since the
                       sampler pays it).
  mlkem_sample_cbd2, mlkem_byte_encode_12, mlkem_byte_decode_12,
  mlkem_compress_{1,4,10}, mlkem_decompress_{1,4,10}
                       one call each, on FOUR different inputs (all-zero,
                       all-max, two random). The constant-time routines must
                       return the SAME count on all four; a differing count is
                       reported as a CT FAIL and the script exits nonzero.

Usage: python3 tools/bench_sampler.py
Honors C64_SKIP_BUILD=1.
"""

import hashlib
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem_ref as M
from bench_keccak import measure_stable, SPIN_EXPECTED
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "mlkem.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

Q, N = 3329, 256
IN_BUF, POLY_A, POLY_B = 0x8000, 0x8400, 0x8800   # clear of sqtab at $9000-$93FF


def rho(n):
    return hashlib.sha3_256(b"c64-mlkem wp2 %d" % n).digest()


# (label, rho, i, j) -> stream blocks, taken from test_sampler.py's seed table
NTT_SEEDS = [("3 blocks (471 B)", rho(0), 0, 1, 3),
             ("4 blocks (510 B)", rho(0), 1, 2, 4)]


def main():
    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        r = subprocess.run(["make"], capture_output=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(r.stderr.decode()[-2000:])
            return 1

    labels = Labels.from_file(LABELS_PATH)
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])
    rnd = random.Random(0xB2)
    ct_fail = False

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        if wait_for_text(t, "C64-MLKEM P", timeout=60.0, verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(t, 0x0339, bytes([0x4C, 0x39, 0x03]))

        def ptr(slot, addr):
            write_bytes(t, labels[slot], bytes([addr & 0xFF, addr >> 8]))

        print("Calibration")
        overhead, st_o, _ = measure_stable(t, labels, None)
        spin_raw, st_s, _ = measure_stable(t, labels, "bench_spin_1000")
        spin = spin_raw - overhead
        print(f"  instrument overhead {overhead}, bench_spin_1000 net {spin} "
              f"(expected {SPIN_EXPECTED})")
        if not (st_o and st_s) or spin != SPIN_EXPECTED:
            print("FAIL: calibration off; not reporting any number.")
            mgr.release(inst)
            return 1
        print("  calibration OK\n")

        keccak, st_k, _ = measure_stable(t, labels, "keccak_f1600")
        keccak -= overhead
        print(f"keccak_f1600                      : {keccak:>9,} cycles")

        print("\nmlkem_sample_ntt (per polynomial)")
        for label, r, i, j, blocks in NTT_SEEDS:
            seed = r + bytes([j, i])

            def setup(seed=seed):
                jsr(t, labels["mlkem_shake128_init"])
                write_bytes(t, IN_BUF, seed)
                ptr("mlkem_zp_src", IN_BUF)
                write_bytes(t, labels["mlkem_sponge_len"], bytes([len(seed), 0]))
                jsr(t, labels["mlkem_absorb"])
                ptr("mlkem_zp_dst", POLY_A)

            v, st, vals = measure_stable(t, labels, "mlkem_sample_ntt", setup=setup)
            v -= overhead
            print(f"  {label:18}: {v:>9,} total, {v - blocks * keccak:>8,} "
                  f"excluding {blocks} x keccak_f1600"
                  f"{'' if st else '   UNSTABLE ' + str(vals)}")

        def poly_inputs():
            return [("all-zero", [0] * N), ("all q-1", [Q - 1] * N),
                    ("random #0", [rnd.randrange(Q) for _ in range(N)]),
                    ("random #1", [rnd.randrange(Q) for _ in range(N)])]

        def dbit_inputs(d):
            m = (1 << d) - 1
            return [("all-zero", [0] * N), ("all max", [m] * N),
                    ("random #0", [rnd.randrange(m + 1) for _ in range(N)]),
                    ("random #1", [rnd.randrange(m + 1) for _ in range(N)])]

        def byte_inputs(n):
            return [("all-zero", bytes(n)), ("all 0xFF", bytes([0xFF] * n)),
                    ("random #0", bytes(rnd.randrange(256) for _ in range(n))),
                    ("random #1", bytes(rnd.randrange(256) for _ in range(n)))]

        cases = [
            ("mlkem_sample_cbd2", byte_inputs(128), True),
            ("mlkem_byte_encode_12", [(l, M.poly_to_c64(f)) for l, f in poly_inputs()], True),
            ("mlkem_byte_decode_12", byte_inputs(384), True),
        ]
        for d in (1, 4, 10):
            cases.append((f"mlkem_compress_{d}",
                          [(l, M.poly_to_c64(f)) for l, f in poly_inputs()], True))
            cases.append((f"mlkem_decompress_{d}",
                          [(l, M.poly_to_c64(f)) for l, f in dbit_inputs(d)], True))

        print("\nCodecs (one 256-coefficient polynomial per call; four inputs each)")
        for name, inputs, must_ct in cases:
            counts = []
            for label, data in inputs:
                def setup(data=data):
                    write_bytes(t, POLY_A, data)
                    ptr("mlkem_zp_src", POLY_A)
                    ptr("mlkem_zp_dst", POLY_B)
                v, st, vals = measure_stable(t, labels, name, setup=setup)
                counts.append(v - overhead)
                if not st:
                    print(f"  {name}: UNSTABLE {vals}")
                    ct_fail = True
            same = len(set(counts)) == 1
            verdict = "constant" if same else f"VARIES {counts}"
            if must_ct and not same:
                ct_fail = True
                verdict = "CT FAIL " + verdict
            print(f"  {name:22}: {counts[0]:>9,} cycles  ({counts[0] / N:6.1f} per coeff)  {verdict}")

        mgr.release(inst)

    if ct_fail:
        print("\nFAIL: a constant-time routine's cycle count depends on its input.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
