#!/usr/bin/env python3
"""bench_keccak.py — cycle-exact cost of one Keccak-f[1600] permutation.

This is P1's headline deliverable: it replaces the roadmap's 150k-350k
estimate with a measurement.

Instrument: CIA1 Timer A + Timer B chained as a 32-bit phi2 down-counter
(src/bench.s). The jiffy clock cannot be used — it is advanced by the KERNAL
IRQ, so a body running with IRQs masked reports 0, and a jiffy is ~17,045
cycles anyway.

The raw counter is NOT trusted blind. Two calibrations run first:

  1. an EMPTY window (bench_cycles_start immediately followed by
     bench_cycles_stop) measures the instrument's own fixed overhead;
  2. bench_spin_1000, whose cost is known by construction, must come out at
     exactly its computed value once that overhead is removed.

Only if (2) matches is the Keccak number reported. That check is what turns
"TB ticks every 65,536 TA cycles" from an arithmetic claim about CIA underflow
behaviour into a measured one.

VICE is cycle-deterministic, so every measurement is repeated and must
reproduce EXACTLY; a varying count means the measurement is wrong, not the
emulator.

Usage: python3 tools/bench_keccak.py
Honors C64_SKIP_BUILD=1.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "mlkem.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

THUNK_ADDR = 0x03B0          # cassette buffer, unused at runtime

# bench_spin_1000 is `ldx #0` then 256 x (dex + bne), then rts:
#   ldx #0                       2
#   256 x dex                  512
#   255 x bne taken            765
#     1 x bne not taken          2
#   rts                          6
#                             ----
#                             1287
# plus the `jsr` that enters it, which is inside the measured window:  +6
SPIN_EXPECTED = 1287 + 6


def build_thunk(labels, target=None, repeat=1, blank=True):
    """[vic_blank] jsr start ; [jsr target]*n ; jsr stop ; [vic_unblank] ; rts

    The display is blanked across the window by default, and bench_sync_frame
    then waits two full frames — the VIC-II samples DEN only at raster line
    $30, so blanking mid-frame leaves badline DMA running for the rest of that
    frame. Without the wait the count depends on where in the frame the blank
    landed, which is a property of what ran before, not of the code measured.
    """
    def j(addr):
        return bytes([0x20, addr & 0xFF, (addr >> 8) & 0xFF])
    code = b""
    if blank:
        code += j(labels["vic_blank"])
        code += j(labels["bench_sync_frame"])   # DEN is sampled at line $30
    code += j(labels["bench_cycles_start"])
    if target is not None:
        code += j(labels[target]) * repeat
    code += j(labels["bench_cycles_stop"])
    if blank:
        code += j(labels["vic_unblank"])
    code += bytes([0x60])
    return code


# One ML-KEM primitive runs for tens of millions of cycles (P2), well past the
# harness's 5 s default; the window is generous because a timeout here is a
# measurement failure, not a result.
JSR_TIMEOUT = 900.0


def measure(transport, labels, target=None, repeat=1, blank=True):
    write_bytes(transport, THUNK_ADDR, build_thunk(labels, target, repeat, blank))
    jsr(transport, THUNK_ADDR, timeout=JSR_TIMEOUT)
    raw = read_bytes(transport, labels["bench_cycles"], 4)
    return int.from_bytes(raw, "little")


def measure_stable(transport, labels, target=None, repeat=1, tries=3, blank=True,
                   setup=None):
    """Measure repeatedly; VICE is deterministic so all runs must agree.

    `setup` runs before each measurement and OUTSIDE the timed window, for
    cases that need the machine put back into a known state first.
    """
    # Discard one warm-up measurement. The first sample taken after the
    # machine has been doing something else can differ from the steady state
    # (observed on the sponge measurement: 461490 then 460459, 460459). The
    # counter itself is exact; it is the first-call machine state that is not
    # representative, so the honest fix is to measure the steady state and say
    # so rather than to average the two.
    if setup:
        setup()
    measure(transport, labels, target, repeat, blank)

    vals = []
    for _ in range(tries):
        if setup:
            setup()
        vals.append(measure(transport, labels, target, repeat, blank))
    return vals[0], len(set(vals)) == 1, vals


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

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        if wait_for_text(transport, "C64-MLKEM P1 READY", timeout=60.0,
                         verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("Calibration")
        overhead, stable_o, vals_o = measure_stable(transport, labels, None)
        print(f"  empty window (instrument overhead) : {overhead} cycles"
              f"   {'stable' if stable_o else 'UNSTABLE ' + str(vals_o)}")

        spin_raw, stable_s, vals_s = measure_stable(transport, labels, "bench_spin_1000")
        spin = spin_raw - overhead
        print(f"  bench_spin_1000 raw                : {spin_raw} cycles"
              f"   {'stable' if stable_s else 'UNSTABLE ' + str(vals_s)}")
        print(f"  bench_spin_1000 net                : {spin} cycles "
              f"(expected {SPIN_EXPECTED})")

        if not (stable_o and stable_s):
            print("\nFAIL: measurement is not reproducible; the instrument is wrong.")
            mgr.release(inst)
            return 1
        if spin != SPIN_EXPECTED:
            print(f"\nFAIL: calibration off by {spin - SPIN_EXPECTED} cycles. "
                  f"The 32-bit TA+TB chaining does not count what it claims; "
                  f"the Keccak number would be wrong too. Not reporting it.")
            mgr.release(inst)
            return 1
        print("  calibration OK — the counter is cycle-exact.\n")

        print("Keccak-f[1600], one permutation")
        one_raw, stable_1, vals_1 = measure_stable(transport, labels, "keccak_f1600")
        one = one_raw - overhead
        print(f"  x1  raw {one_raw}  net {one} cycles"
              f"   {'stable' if stable_1 else 'UNSTABLE ' + str(vals_1)}")

        eight_raw, stable_8, vals_8 = measure_stable(transport, labels,
                                                     "keccak_f1600", repeat=8)
        eight = eight_raw - overhead
        per = eight / 8.0
        print(f"  x8  raw {eight_raw}  net {eight} cycles -> {per:.1f} per call"
              f"   {'stable' if stable_8 else 'UNSTABLE ' + str(vals_8)}")

        # --- per-step breakdown -------------------------------------------
        # The MLKEM_TEST_HOOKS build exports each step mapping separately, so
        # the same instrument that measures the whole permutation can say
        # where the cycles actually go. One call each = one round's worth.
        print("\nPer-step breakdown (one round)")
        steps = []
        for name, label in (("theta", "keccak_theta"),
                            ("rho+pi", "keccak_rhopi"),
                            ("chi", "keccak_chi"),
                            ("iota", "keccak_iota")):
            v, st, vals = measure_stable(transport, labels, label)
            net = v - overhead
            steps.append((name, net, st))
        tot = sum(n for _, n, _ in steps)
        for name, net, st in steps:
            print(f"  {name:7} {net:7,} cycles/round  {net*24:9,} total  "
                  f"{100.0*net/tot:5.1f}%   {'' if st else 'UNSTABLE'}")
        print(f"  {'sum':7} {tot:7,} cycles/round  {tot*24:9,} total")

        # --- what the sponge costs on top of the permutation ---------------
        # One full SHA3-256 rate block (136 B) absorbed in one call runs
        # exactly one permutation, so the excess over `one` is the sponge's
        # own per-block overhead: the XOR-into-state loop plus bookkeeping.
        print("\nSponge overhead")
        write_bytes(transport, 0x2000, bytes(136))

        def reinit():
            jsr(transport, labels["mlkem_sha3_256_init"])
            write_bytes(transport, labels["mlkem_zp_src"], bytes([0x00, 0x20]))
            write_bytes(transport, labels["mlkem_sponge_len"], bytes([136, 0]))

        blk, stable_b, vals_b = measure_stable(transport, labels, "mlkem_absorb",
                                               setup=reinit)
        blk -= overhead
        print(f"  absorb of one 136-byte rate block : {blk:,} cycles"
              f"   {'stable' if stable_b else 'UNSTABLE ' + str(vals_b)}")
        print(f"  of which the permutation          : {one:,}")
        print(f"  sponge overhead per rate block    : {blk - one:,} cycles "
              f"({100.0 * (blk - one) / blk:.1f}%)")
        print(f"  => ~{(blk) / 136:,.0f} cycles per byte hashed")

        mgr.release(inst)

    if not (stable_1 and stable_8):
        print("\nFAIL: Keccak measurement not reproducible.")
        return 1

    drift = abs(per - one)
    print()
    print("=" * 62)
    print(f"  Keccak-f[1600] : {one:,} cycles per permutation")
    print(f"  per round      : {one / 24:,.0f} cycles")
    print(f"  at 1.023 MHz   : {one / 1_022_727 * 1000:.1f} ms")
    print("=" * 62)
    print(f"  x1 vs x8-amortised differ by {drift:.1f} cycles "
          f"({'consistent' if drift < 2 else 'INCONSISTENT'})")
    lo, hi = 150_000, 350_000
    where = ("inside" if lo <= one <= hi else "OUTSIDE")
    print(f"  roadmap estimate band {lo:,}-{hi:,}: measurement falls {where}")
    print(f"  ~55-60 permutations for ML-KEM-768 keygen+decaps -> "
          f"{one * 55 / 1e6:.1f}-{one * 60 / 1e6:.1f}M cycles of Keccak")
    return 0


if __name__ == "__main__":
    sys.exit(main())
