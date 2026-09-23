#!/usr/bin/env python3
"""rig_bench.py — cycle-exact cost of Keccak-f[1600] and ML-KEM-768 on Ultimate 64 Elite.

Measures the exact cycle count of the 6502 code using the CIA1 Timer A+B
chained 32-bit phi2 down-counter. At stock speed (1 MHz), the count must
match the VICE emulator numbers exactly. This is because the measurement
window blanks the display and syncs two frames (eliminating badline DMA
variations), masks IRQs inside the window, and runs on a deterministic
CPU cycle count independent of PAL/NTSC timing.

HOST POLLS STEAL CYCLES ON THE U64E. Measured: Keccak x8 polled every 5 ms
inside its window read +1,597 / +1,612 / +2,156 cycles over the quiet
2,717,504, and not reproducibly. So every measurement is started and then
left alone for 1.05x its expected duration + 0.5 s before the first
completion poll (quiet_s). If a count ever runs longer than that, the polls
land inside the window and the count goes non-reproducible — which the
stability gate reports as a FAIL rather than a number. The probe section
re-measures that effect on every run.

At --mhz N > 1 (U64 turbo) the CIA still counts the ~1 MHz system clock
while the CPU runs faster, so the counts are ticks, not CPU cycles; the rig
then asserts only output correctness and reproducibility, and prints the
VICE/ticks ratio as information.

Requires U64_HOST (the bench U64E is 10.43.23.81); not part of `make test`.
Usage: python3 tools/rig_bench.py [--mhz N] [--keccak-only]
Honors C64_SKIP_BUILD=1 and MLKEM_BUILD_DIR (see rig_common.py).
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bench_keccak import build_thunk, SPIN_EXPECTED
import mlkem_ref as M
from rig_common import Rig, RigError, build_if_needed, load_labels, VECTOR_DIR
from c64_test_harness import read_bytes, write_bytes

VICE_KECCAK = 339_688
VICE = {
    "mlkem_keygen": 21_801_702,
    "mlkem_encaps": 24_880_455,
    "mlkem_decaps": 29_597_879,
}
PAL_HZ = 985_248

BUF_EK = 0x6000
BUF_DK = 0x6500
BUF_CT = 0x7000
BUF_KEY = 0x7E80
BUF_SEED = 0x7EC0
BUF_Z = 0x7F00


def measure(rig, target, repeat=1, quiet_s=0.0, cadence=0.05, timeout=300.0, setup=None):
    if setup:
        setup()
    thunk = build_thunk(rig.l, target, repeat)
    rig.run_thunk(thunk, timeout=timeout, quiet_s=quiet_s, cadence=cadence)
    return int.from_bytes(read_bytes(rig.t, rig.l["bench_cycles"], 4), "little")


def measure_stable(rig, target, repeat=1, tries=3, quiet_s=0.0, cadence=0.05, timeout=300.0, setup=None, after=None):
    if setup:
        setup()
    measure(rig, target, repeat, quiet_s, cadence, timeout, setup=None)
    if after:
        after()
    vals = []
    for _ in range(tries):
        if setup:
            setup()
        vals.append(measure(rig, target, repeat, quiet_s, cadence, timeout, setup=None))
        if after:
            after()
    return vals[0], len(set(vals)) == 1, vals


def main():
    parser = argparse.ArgumentParser(description="Cycle-exact benchmark on Ultimate 64 Elite")
    parser.add_argument("--mhz", type=int, default=1, help="CPU speed in MHz (default 1)")
    parser.add_argument("--keccak-only", action="store_true", help="Skip ML-KEM measurements")
    args = parser.parse_args()

    build_if_needed()

    rig = Rig(load_labels(0x6000, 0x8400), mhz=args.mhz)
    with rig:
        print("Calibration")
        overhead, st_o, _ = measure_stable(rig, None)
        spin_raw, st_s, _ = measure_stable(rig, "bench_spin_1000")
        spin = spin_raw - overhead
        print(f"  overhead={overhead}, spin={spin} (expected {SPIN_EXPECTED})")

        if args.mhz == 1:
            if not (st_o and st_s) or spin != SPIN_EXPECTED:
                print("FAIL: calibration failed. Not reporting numbers.")
                return 1
            print("  calibration OK\n")
        else:
            print("  (turbo: skipping calibration gate)\n")

        q_keccak = VICE_KECCAK / PAL_HZ / args.mhz * 1.05 + 0.5
        print("Keccak-f[1600]")
        x1_raw, st_1, _ = measure_stable(rig, "keccak_f1600", tries=3, quiet_s=q_keccak)
        x1 = x1_raw - overhead
        # The x8 window is 8x as long: its quiet time must be too, or the
        # completion polls land inside the window and steal cycles.
        q_keccak8 = 8 * VICE_KECCAK / PAL_HZ / args.mhz * 1.05 + 0.5
        x8_raw, st_8, _ = measure_stable(rig, "keccak_f1600", repeat=8, tries=2, quiet_s=q_keccak8)
        x8 = x8_raw - overhead
        print(f"  x1={x1} (stable={st_1}), x8={x8} (stable={st_8})")

        if not (st_1 and st_8):
            print("FAIL: Keccak measurement not reproducible.")
            return 1
        if args.mhz == 1:
            if x1 != VICE_KECCAK or x8 != 8 * VICE_KECCAK:
                print(f"FAIL: Keccak mismatch. x1={x1} (VICE {VICE_KECCAK}, diff {x1 - VICE_KECCAK:+}), "
                      f"x8={x8} (VICE {8*VICE_KECCAK}, diff {x8 - 8 * VICE_KECCAK:+})")
                return 1
            print(f"  Keccak-f[1600] = {x1:,} cycles, EXACT match with VICE\n")
        else:
            print(f"  (turbo: CIA ticks, not CPU cycles: VICE/x1 = {VICE_KECCAK / max(x1, 1):.4f}, "
                  f"VICE*8/x8 = {8 * VICE_KECCAK / max(x8, 1):.4f})\n")

        print("Poll-perturbation probe")
        x8_poll_raw, _, _ = measure_stable(rig, "keccak_f1600", repeat=8, tries=1, quiet_s=0.0, cadence=0.005)
        x8_poll = x8_poll_raw - overhead
        print(f"  net={x8_poll}, quiet_net={x8}, diff={x8_poll - x8}\n")

        if args.keccak_only:
            return 0

        print("ML-KEM-768 (ACVP tcId 1)")
        with open(os.path.join(VECTOR_DIR, "ML-KEM-768-keyGen-FIPS203.json")) as fh:
            kg = [t for g in json.load(fh)["testGroups"] for t in g["tests"]][0]
        with open(os.path.join(VECTOR_DIR, "ML-KEM-768-encapDecap-FIPS203.json")) as fh:
            ed = {g["function"]: g["tests"] for g in json.load(fh)["testGroups"]}
        en = ed["encapsulation"][0]
        de = ed["decapsulation"][0]
        d, z = bytes.fromhex(kg["d"]), bytes.fromhex(kg["z"])
        ek_en, m_en = bytes.fromhex(en["ek"]), bytes.fromhex(en["m"])
        dk_de, c_de = bytes.fromhex(de["dk"]), bytes.fromhex(de["c"])

        # Expected outputs straight from the ACVP JSON — not from the model.
        expected = {
            "mlkem_keygen": (bytes.fromhex(kg["ek"]), bytes.fromhex(kg["dk"])),
            "mlkem_encaps": (bytes.fromhex(en["k"]), bytes.fromhex(en["c"])),
            "mlkem_decaps": bytes.fromhex(de["k"]),
        }
        # The model must agree with the vectors, or the vector file is not
        # the one test-ref pinned.
        if (M.mlkem_keygen(d, z) != expected["mlkem_keygen"]
                or M.mlkem_encaps(ek_en, m_en) != expected["mlkem_encaps"]
                or M.mlkem_decaps(dk_de, c_de) != expected["mlkem_decaps"]):
            print("FATAL: mlkem_ref disagrees with the ACVP tcId 1 vectors")
            return 1

        def check_outputs(fn, exp):
            if fn == "mlkem_keygen":
                return (read_bytes(rig.t, BUF_EK, 1184), read_bytes(rig.t, BUF_DK, 2400)) == exp
            elif fn == "mlkem_encaps":
                return (read_bytes(rig.t, BUF_KEY, 32), read_bytes(rig.t, BUF_CT, 1088)) == exp
            elif fn == "mlkem_decaps":
                return read_bytes(rig.t, BUF_KEY, 32) == exp
            raise ValueError(fn)

        def setup_kg():
            write_bytes(rig.t, BUF_SEED, d)
            write_bytes(rig.t, BUF_Z, z)
            write_bytes(rig.t, BUF_EK, bytes([0xEE] * 1184))
            write_bytes(rig.t, BUF_DK, bytes([0xEE] * 2400))
            rig.ptr("mlkem_arg_seed", BUF_SEED)
            rig.ptr("mlkem_arg_z", BUF_Z)
            rig.ptr("mlkem_arg_ek", BUF_EK)
            rig.ptr("mlkem_arg_dk", BUF_DK)

        def setup_en():
            write_bytes(rig.t, BUF_EK, ek_en)
            write_bytes(rig.t, BUF_SEED, m_en)
            write_bytes(rig.t, BUF_CT, bytes([0xEE] * 1088))
            write_bytes(rig.t, BUF_KEY, bytes([0xEE] * 32))
            rig.ptr("mlkem_arg_ek", BUF_EK)
            rig.ptr("mlkem_arg_seed", BUF_SEED)
            rig.ptr("mlkem_arg_ct", BUF_CT)
            rig.ptr("mlkem_arg_key", BUF_KEY)

        def setup_de():
            write_bytes(rig.t, BUF_DK, dk_de)
            write_bytes(rig.t, BUF_CT, c_de)
            write_bytes(rig.t, BUF_KEY, bytes([0xEE] * 32))
            rig.ptr("mlkem_arg_dk", BUF_DK)
            rig.ptr("mlkem_arg_ct", BUF_CT)
            rig.ptr("mlkem_arg_key", BUF_KEY)

        results = {}
        failed = False

        for fn, label, setup_fn, exp in [
            ("mlkem_keygen", "mlkem_keygen", setup_kg, expected["mlkem_keygen"]),
            ("mlkem_encaps", "mlkem_encaps", setup_en, expected["mlkem_encaps"]),
            ("mlkem_decaps", "mlkem_decaps", setup_de, expected["mlkem_decaps"]),
        ]:
            q = VICE[fn] / PAL_HZ / args.mhz * 1.05 + 0.5
            runs = {"ok": 0, "bad": 0}

            def after_hook():
                runs["ok" if check_outputs(fn, exp) else "bad"] += 1

            v, st, vals = measure_stable(rig, label, tries=2, setup=setup_fn,
                                         quiet_s=q, cadence=0.5, timeout=300.0,
                                         after=after_hook)
            net = v - overhead
            # A count for a call that computed the wrong thing is never
            # reported. 3 = the warm-up plus tries=2, every one checked.
            if runs["bad"] or runs["ok"] != 3:
                print(f"  FAIL {fn}: output vs ACVP tcId 1 wrong in {runs['bad']} of "
                      f"{runs['ok'] + runs['bad']} runs; count withheld")
                failed = True
                continue
            if not st:
                print(f"  FAIL {fn}: not reproducible {[x - overhead for x in vals]}")
                failed = True
                continue
            results[fn] = net
            if args.mhz == 1:
                ok = net == VICE[fn]
                print(f"  {fn:15} {net:>12,} cycles   VICE {VICE[fn]:>12,}   diff {net - VICE[fn]:+,}"
                      f"   outputs == ACVP (3/3)   {'EXACT' if ok else 'FAIL'}")
                failed |= not ok
            else:
                print(f"  {fn:15} {net:>12,} CIA ticks at {args.mhz} MHz turbo (not CPU cycles)"
                      f"   VICE {VICE[fn]:,}   VICE/ticks {VICE[fn] / net:.4f}   outputs == ACVP (3/3)")

        if failed:
            print("\nFAIL: see above.")
            return 1

        if args.mhz != 1:
            # Measured on the U64E at 48: VICE/ticks = 47.00 for every
            # call, i.e. the CIA ticks once per 47 CPU cycles there and the
            # CPU runs the same cycle count as at 1 MHz. Informational only.
            print("\n(turbo: counts above are CIA ticks; no cycle summary)")
            return 0
        print("\nSummary")
        print("-" * 60)
        print(f"  {'Function':<15} {'Cycles':>12} {'VICE Ref':>12} {'Diff':>12}")
        print("-" * 60)
        for fn in ("mlkem_keygen", "mlkem_encaps", "mlkem_decaps"):
            net = results[fn]
            ref = VICE[fn]
            diff = net - ref
            print(f"  {fn:<15} {net:>12,} {ref:>12,} {diff:>12,}")
        print("-" * 60)
        return 0


if __name__ == "__main__":
    sys.exit(main())
