#!/usr/bin/env python3
"""test_keccak.py — differential test of the 6502 Keccak-f[1600] against the
validated Python model, driven over the c64-test-harness DMA interface.

This is the payoff of the two-level validation design (see README). Rather than
comparing only the final permutation output — which localises nothing — it
single-steps the assembly and compares the full 200-byte state after EVERY
step of EVERY round against tools/keccak_ref.py, which tools/test_keccak_ref.py
pins to XKCP's 240 published intermediate states.

A failure therefore names the round and the step mapping.

Because rho and pi are FUSED in the assembly (one destination-indexed copy),
there is no "after rho" state to compare; the fused step is checked against the
model's "after pi". That is 4 of the 5 published checkpoints per round.

The permutation writes its rho+pi output to keccak_B and chi consumes it, so
"after pi" is read from keccak_B and the other three from keccak_state.

Usage:
    python3 tools/test_keccak.py [--rounds N] [--quick]

    --rounds N  per-step trace only for the first N rounds (default: all 24)
    --quick     skip the per-step trace; run the whole-permutation checks only

Honors C64_SKIP_BUILD=1 (reuse the existing PRG instead of rebuilding).
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keccak_ref as K

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "mlkem.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

STATE_BYTES = 200

_fails = []
_checks = 0


def check(cond, label):
    global _checks
    _checks += 1
    if not cond:
        _fails.append(label)
        print(f"    FAIL  {label}")
    return cond


def lanes_to_bytes(lanes):
    return b"".join(l.to_bytes(8, "little") for l in lanes)


def bytes_to_lanes(b):
    return [int.from_bytes(b[8 * i:8 * i + 8], "little") for i in range(25)]


def first_diff(got, want):
    """Report the first differing LANE, which is more useful than a byte index."""
    for i in range(25):
        g = got[8 * i:8 * i + 8]
        w = want[8 * i:8 * i + 8]
        if g != w:
            x, y = i % 5, i // 5
            return (f"lane {i} (x={x},y={y}): got {g[::-1].hex()} "
                    f"want {w[::-1].hex()}")
    return "no lane differs (length mismatch?)"


# ---------------------------------------------------------------------------

def run_per_step(transport, labels, start_state, name, max_rounds):
    """Single-step the permutation, comparing after theta / rho+pi / chi / iota."""
    print(f"\n  per-step trace: {name}")
    trace = []
    K.permute(bytes_to_lanes(start_state), trace=trace)
    by_step = {(r, s): st for s, r, st in trace}

    write_bytes(transport, labels["keccak_state"], start_state)

    for r in range(max_rounds):
        write_bytes(transport, labels["kc_round"], bytes([r]))

        jsr(transport, labels["keccak_theta"])
        got = read_bytes(transport, labels["keccak_state"], STATE_BYTES)
        want = lanes_to_bytes(by_step[(r, "theta")])
        if not check(got == want, f"{name} round {r} after theta: {first_diff(got, want)}"):
            return False

        jsr(transport, labels["keccak_rhopi"])
        got = read_bytes(transport, labels["keccak_B"], STATE_BYTES)
        want = lanes_to_bytes(by_step[(r, "pi")])
        if not check(got == want, f"{name} round {r} after rho+pi: {first_diff(got, want)}"):
            return False

        jsr(transport, labels["keccak_chi"])
        got = read_bytes(transport, labels["keccak_state"], STATE_BYTES)
        want = lanes_to_bytes(by_step[(r, "chi")])
        if not check(got == want, f"{name} round {r} after chi: {first_diff(got, want)}"):
            return False

        jsr(transport, labels["keccak_iota"])
        got = read_bytes(transport, labels["keccak_state"], STATE_BYTES)
        want = lanes_to_bytes(by_step[(r, "iota")])
        if not check(got == want, f"{name} round {r} after iota: {first_diff(got, want)}"):
            return False

    print(f"    ok    {max_rounds} rounds x 4 steps all match")
    return True


def run_full(transport, labels, start_state, name):
    """Whole 24-round permutation in one call."""
    write_bytes(transport, labels["keccak_state"], start_state)
    jsr(transport, labels["keccak_f1600"])
    got = read_bytes(transport, labels["keccak_state"], STATE_BYTES)
    want = lanes_to_bytes(K.permute(bytes_to_lanes(start_state)))
    ok = check(got == want, f"keccak_f1600 {name}: {first_diff(got, want)}")
    if ok:
        print(f"    ok    keccak_f1600 {name}")
    return ok


def run_clear(transport, labels):
    write_bytes(transport, labels["keccak_state"], bytes(range(256))[:STATE_BYTES])
    jsr(transport, labels["keccak_clear"])
    got = read_bytes(transport, labels["keccak_state"], STATE_BYTES)
    if check(got == bytes(STATE_BYTES), "keccak_clear zeroes all 200 bytes"):
        print("    ok    keccak_clear")


def main():
    args = sys.argv[1:]
    quick = "--quick" in args
    max_rounds = 24
    if "--rounds" in args:
        max_rounds = int(args[args.index("--rounds") + 1])

    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        r = subprocess.run(["make"], capture_output=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(r.stderr.decode()[-2000:])
            print("Build failed")
            return 1
    if not os.path.exists(PRG_PATH):
        print(f"missing {PRG_PATH}")
        return 1

    labels = Labels.from_file(LABELS_PATH)

    # P1 uses no REU: +reu launches VICE with none attached. The c64-https
    # default passes -reu; cargo-culting it here would attach hardware this
    # library never touches.
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])

    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        if wait_for_text(transport, "C64-MLKEM P1 READY", timeout=60.0,
                         verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1

        # Safety trampoline: errant control flow lands somewhere defined.
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("\n[1/3] keccak_clear")
        run_clear(transport, labels)

        # The two states XKCP publishes traces for: the all-zero state, and
        # its own output fed back in (a fully non-trivial state).
        zero = bytes(STATE_BYTES)
        chained = lanes_to_bytes(K.permute(bytes_to_lanes(zero)))

        if not quick:
            print("\n[2/3] per-step differential trace")
            if run_per_step(transport, labels, zero, "all-zero input", max_rounds):
                run_per_step(transport, labels, chained, "chained input", max_rounds)
        else:
            print("\n[2/3] per-step differential trace — SKIPPED (--quick)")

        print("\n[3/3] whole-permutation checks")
        run_full(transport, labels, zero, "all-zero input")
        run_full(transport, labels, chained, "chained input")
        # Deterministic pseudo-random states: a fixed LCG, so a failure is
        # reproducible without carrying a vector file.
        seed = 0x2026_0822
        for n in range(4):
            buf = bytearray()
            for _ in range(STATE_BYTES):
                seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
                buf.append((seed >> 16) & 0xFF)
            run_full(transport, labels, bytes(buf), f"pseudo-random state #{n}")

        mgr.release(inst)

    dt = time.time() - t0
    print(f"\n{_checks} checks in {dt:.1f}s")
    if _fails:
        print(f"FAILED ({len(_fails)}):")
        for f in _fails[:10]:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
