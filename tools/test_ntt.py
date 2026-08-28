#!/usr/bin/env python3
"""test_ntt.py — WP1 red tests: mod-3329 field arithmetic and the NTT, driven
differentially against tools/mlkem_ref.py over the c64-test-harness in VICE.

Written adversarially from FIPS 203 and the oracle API BEFORE any 6502
implementation existed. The implementer turns it green and may not edit it;
disputes go to the supervisor.

===========================================================================
ASSUMED ABI  (the implementer matches this, or the supervisor reconciles)
===========================================================================

Polynomial layout — split-plane, 512 bytes, declared once in src/mlkem.inc and
mirrored by M.poly_to_c64 / M.poly_from_c64 (the ONLY conversion point):

    ptr + 0   .. ptr + 255   low  bytes of c[0..255]
    ptr + 256 .. ptr + 511   high bytes of c[0..255]

Every polynomial buffer is PAGE-ALIGNED (ptr low byte = $00). The harness only
ever hands out page-aligned buffers.

Pointers — the existing §6.2 slots, nothing new:

    mlkem_zp_dst   the in-place operand and the result
    mlkem_zp_src   the second operand of a binary op

Exports under test (all in place on (mlkem_zp_dst)):

    mlkem_poly_ntt       (dst) <- NTT(dst)              FIPS 203 Alg. 9
    mlkem_poly_intt      (dst) <- NTT^-1(dst)           FIPS 203 Alg. 10, incl. x3303
    mlkem_poly_basemul   (dst) <- MultiplyNTTs(dst, src) FIPS 203 Alg. 11/12
    mlkem_poly_add       (dst) <- dst + src   mod q
    mlkem_poly_sub       (dst) <- dst - src   mod q
    mlkem_poly_reduce    (dst) <- dst mod q, every coefficient, input domain
                         0..65535 unsigned (see SPEC POINTS below)
    mlkem_poly_tomont    OPTIONAL. If the label exists it is checked:
                         (dst) <- dst * 2^16 mod q

Per-layer hooks (MLKEM_TEST_HOOKS build only):

    mlkem_ntt_layer_num  one byte, the layer index L in 0..6
    mlkem_ntt_layer      applies NTT layer L in place on (dst).
                         L = 0 is len = 128 (zetas 1), L = 6 is len = 2
                         (zetas 64..127) — Alg. 9's loop order.
    mlkem_intt_layer     applies inverse-NTT layer L in place on (dst).
                         L = 0 is len = 2 (zetas 127..64), L = 6 is len = 128
                         (zeta 1) — Alg. 10's loop order. Layer 6 may either
                         EXCLUDE or INCLUDE the final x3303 (=128^-1)
                         scaling; both are accepted and the choice is printed.

Value representation at every exported boundary and every hook boundary:
canonical, 0 <= c < q, in the STANDARD (non-Montgomery) domain. Lazy or
Montgomery representations are internal; a hook must canonicalise before
returning. High byte therefore never exceeds $0C.

Register/ZP clobbers: A/X/Y, mlkem_zp_tmp, mlkem_zp_len are free. Whether
mlkem_zp_src/dst survive a call is UNSPECIFIED here — the harness rewrites
them before every call.

===========================================================================
SPEC POINTS where this file chose a behaviour the implementer must match
===========================================================================

  S1  Outputs are canonical [0, q). A coefficient >= q is a FAILURE even if
      it is congruent to the right value. (This is what makes the "missing
      final reduction" mutant detectable at all.)
  S2  mlkem_poly_reduce accepts the full unsigned 16-bit range. ML-KEM feeds
      it byte_decode_12 output (up to 4095), add/sub intermediates (< 2q) and
      a k=3 dot-product accumulation (< 6q); a routine that is only correct
      below 2q or 4q is not a reduce, it is a conditional subtract.
  S3  mlkem_poly_sub result for a < b wraps to a - b + q, never a negative
      two's-complement value.
  S4  basemul inputs are canonical; all-(q-1) x all-(q-1) is a legal input
      and must be exact. a0*b0 + zeta*a1*b1 with unreduced products exceeds
      2^24, so a 24-bit accumulator that skips the intermediate reduction
      fails this case by construction.
  S5  NTT, INTT and basemul must be CONSTANT-TIME in their inputs: the cycle
      count measured over the all-zero, all-(q-1) and random polynomials must
      be identical (they operate on the secret s, e, r). VICE is
      cycle-deterministic, so any difference is a data-dependent path.
  S6  Montgomery constant R = 2^16 if mlkem_poly_tomont exists.

Usage:
    python3 tools/test_ntt.py [--full] [--seed N] [--no-timing]

    --full       the large seeded random sweep (64 polys per function)
    --seed N     reseed the random cases (default fixed; printed either way)
    --no-timing  skip the CIA-instrumented cycle counts / constant-time check

Honors C64_SKIP_BUILD=1. Exit 1 on any failure, or when a required label is
absent (which is what "red" looks like before the implementation lands).
"""

import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import mlkem_ref as M
except ImportError as e:  # pragma: no cover
    print(f"FATAL: tools/mlkem_ref.py (the WP0 oracle) is not importable: {e}")
    sys.exit(1)

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "mlkem.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

Q = M.Q
N = M.N
POLY_BYTES = 2 * N

# Two page-aligned polynomial buffers well above any plausible P2 image
# (7,680 B window from $0801 + BSS). Checked against __MAIN_LAST__ at runtime.
BUF_A = 0x6000
BUF_B = 0x6400
CANARY = 0x6800          # 512 B of guard after BUF_B, must stay untouched

REQUIRED_LABELS = [
    "mlkem_zp_src", "mlkem_zp_dst",
    "mlkem_poly_ntt", "mlkem_poly_intt", "mlkem_poly_basemul",
    "mlkem_poly_add", "mlkem_poly_sub", "mlkem_poly_reduce",
    "mlkem_ntt_layer", "mlkem_intt_layer", "mlkem_ntt_layer_num",
]
OPTIONAL_LABELS = ["mlkem_poly_tomont"]
BENCH_LABELS = ["bench_cycles_start", "bench_cycles_stop", "bench_cycles",
                "bench_spin_1000", "vic_blank", "vic_unblank", "bench_sync_frame"]

DEFAULT_SEED = 0x2026_0828

_fails = []
_checks = 0


def check(cond, label):
    global _checks
    _checks += 1
    if not cond:
        _fails.append(label)
        print(f"    FAIL  {label}")
    return cond


# ---------------------------------------------------------------------------
# Local model helpers. The oracle exposes whole-transform ntt/intt; the
# per-layer decomposition below is what the hooks are compared against, and
# it is self-checked against M.ntt / M.intt before VICE is even started, so a
# wrong decomposition here fails loudly rather than blaming the 6502.
# ---------------------------------------------------------------------------

def ntt_layer(f, L):
    """FIPS 203 Alg. 9, one value of len. L=0 -> len=128, L=6 -> len=2."""
    f = list(f)
    ln = 128 >> L
    i = 1 << L
    for start in range(0, N, 2 * ln):
        z = M.ZETAS[i]
        i += 1
        for j in range(start, start + ln):
            t = (z * f[j + ln]) % Q
            f[j + ln] = (f[j] - t) % Q
            f[j] = (f[j] + t) % Q
    return f


def intt_layer(f, L):
    """FIPS 203 Alg. 10, one value of len, butterflies only. L=0 -> len=2."""
    f = list(f)
    ln = 2 << L
    i = 127 - sum(64 >> k for k in range(L))   # 127, 63, 31, 15, 7, 3, 1
    for start in range(0, N, 2 * ln):
        z = M.ZETAS[i]
        i -= 1
        for j in range(start, start + ln):
            t = f[j]
            f[j] = (t + f[j + ln]) % Q
            f[j + ln] = (z * (f[j + ln] - t)) % Q
    return f


INV128 = pow(128, -1, Q)     # 3303


def intt_scale(f):
    return [(x * INV128) % Q for x in f]


def self_check_model(rnd):
    """The local layer decomposition must reproduce the oracle exactly."""
    for trial in range(3):
        f = [rnd.randrange(Q) for _ in range(N)]
        g = f
        for L in range(7):
            g = ntt_layer(g, L)
        if g != M.ntt(f):
            print("FATAL: local ntt_layer decomposition disagrees with M.ntt")
            return False
        h = M.ntt(f)
        for L in range(7):
            h = intt_layer(h, L)
        if intt_scale(h) != M.intt(M.ntt(f)) or intt_scale(h) != f:
            print("FATAL: local intt_layer decomposition disagrees with M.intt")
            return False
        if M.poly_from_c64(M.poly_to_c64(f)) != f:
            print("FATAL: M.poly_to_c64 / M.poly_from_c64 do not round-trip")
            return False
    if len(M.poly_to_c64([0] * N)) != POLY_BYTES:
        print(f"FATAL: M.poly_to_c64 is not {POLY_BYTES} bytes; layout assumption broken")
        return False
    if INV128 != 3303:
        print("FATAL: 128^-1 mod q is not 3303?!")
        return False
    return True


# ---------------------------------------------------------------------------
# Input generators
# ---------------------------------------------------------------------------

def poly_const(v):
    return [v] * N


def poly_impulse(pos, v=1):
    f = [0] * N
    f[pos] = v
    return f


def poly_random(rnd, hi=Q):
    return [rnd.randrange(hi) for _ in range(N)]


IMPULSE_POSITIONS = (0, 1, 2, 3, 127, 128, 254, 255)


def edge_polys(rnd, n_random):
    """The shared edge set: zero, all q-1, impulses (1 and q-1), random."""
    cases = [("all-zero", poly_const(0)), ("all q-1", poly_const(Q - 1))]
    for p in IMPULSE_POSITIONS:
        cases.append((f"impulse[{p}]=1", poly_impulse(p, 1)))
    for p in (0, 255):
        cases.append((f"impulse[{p}]=q-1", poly_impulse(p, Q - 1)))
    # A power-of-two-ish value that a wrong sign/shift in a Barrett or
    # Montgomery step turns into something recognisable.
    cases.append(("all 2048", poly_const(2048)))
    for k in range(n_random):
        cases.append((f"random #{k}", poly_random(rnd)))
    return cases


def reduce_boundary_poly():
    """One polynomial carrying every k*q-1 / k*q / k*q+1 for k=1..19 plus the
    extremes. 19*q = 63,251 is the last multiple below 2^16. A Barrett
    quotient that is off by one shows at exactly these values, so they all
    go in ONE round trip."""
    vals = [0, 1, Q - 1, 0x7FFF, 0x8000, 0xFFFF, 0xFFFE, 0x0FFF, 0x1000]
    for k in range(1, 20):
        vals += [k * Q - 1, k * Q, k * Q + 1]
    # 4095 = byte_decode_12's largest value; 2q-1 and 4q-1 are the lazy bounds
    vals += [4095, 2 * Q - 1, 2 * Q, 4 * Q - 1, 4 * Q, 6 * Q - 1, 6 * Q]
    assert len(vals) <= N
    f = vals + [0xFFFF] * (N - len(vals))
    return f


# ---------------------------------------------------------------------------
# Device driver
# ---------------------------------------------------------------------------

class Dev:
    def __init__(self, transport, labels):
        self.t, self.l = transport, labels
        self.has_tomont = "mlkem_poly_tomont" in labels

    def _ptr(self, slot, addr):
        assert addr & 0xFF == 0, "polynomial buffers must be page-aligned"
        write_bytes(self.t, self.l[slot], bytes([addr & 0xFF, addr >> 8]))

    def put(self, addr, f):
        write_bytes(self.t, addr, M.poly_to_c64(f))

    def get(self, addr):
        return M.poly_from_c64(read_bytes(self.t, addr, POLY_BYTES))

    def call(self, fn, dst=BUF_A, src=None):
        self._ptr("mlkem_zp_dst", dst)
        if src is not None:
            self._ptr("mlkem_zp_src", src)
        jsr(self.t, self.l[fn])

    def unary(self, fn, f):
        self.put(BUF_A, f)
        self.call(fn)
        return self.get(BUF_A)

    def binary(self, fn, a, b):
        self.put(BUF_A, a)
        self.put(BUF_B, b)
        self.call(fn, dst=BUF_A, src=BUF_B)
        return self.get(BUF_A), self.get(BUF_B)

    def layer(self, fn, L):
        write_bytes(self.t, self.l["mlkem_ntt_layer_num"], bytes([L]))
        self.call(fn)
        return self.get(BUF_A)


def first_diff(got, want):
    for i in range(N):
        if got[i] != want[i]:
            extra = ""
            if got[i] >= Q:
                extra = f" (NON-CANONICAL: >= q; got mod q = {got[i] % Q})"
            return f"first diff at coeff {i}: got {got[i]} want {want[i]}{extra}"
    if len(got) != len(want):
        return "length mismatch"
    return "no coefficient differs"


def compare(got, want, what):
    """Exact comparison; also flags a coefficient >= q on its own (S1)."""
    if got == want:
        return True
    return check(False, f"{what}: {first_diff(got, want)}")


# ---------------------------------------------------------------------------
# Test sections
# ---------------------------------------------------------------------------

def test_unary(dev, fn, model, cases, extra_name=""):
    ok_n = 0
    for name, f in cases:
        got = dev.unary(fn, f)
        if compare(got, model(f), f"{fn}[{name}]{extra_name}"):
            ok_n += 1
    check(ok_n == len(cases), f"{fn}: {ok_n}/{len(cases)} cases match")
    if ok_n == len(cases):
        print(f"    ok    {fn}: {ok_n} cases")


def test_layers(dev, kind, cases):
    """Single-step the transform, comparing after every layer. Stops at the
    first bad layer so the report names it rather than a cascade."""
    fn = "mlkem_ntt_layer" if kind == "ntt" else "mlkem_intt_layer"
    step = ntt_layer if kind == "ntt" else intt_layer
    scaled_last = None
    good = 0
    for name, f in cases:
        dev.put(BUF_A, f)
        want = f
        all_ok = True
        for L in range(7):
            got = dev.layer(fn, L)
            want = step(want, L)
            if kind == "intt" and L == 6 and got != want:
                # Accept a layer 6 that folds in the 1/128 scaling (see ABI).
                if got == intt_scale(want):
                    scaled_last = True
                    want = intt_scale(want)
            if got != want:
                all_ok = False
                check(False, f"{fn} L={L} (len={128 >> L if kind == 'ntt' else 2 << L}) "
                             f"[{name}]: {first_diff(got, want)}")
                break
            if kind == "intt" and L == 6 and scaled_last is None:
                scaled_last = False
        if all_ok:
            good += 1
    check(good == len(cases), f"{fn}: {good}/{len(cases)} polys match through all 7 layers")
    if good == len(cases):
        note = ""
        if kind == "intt":
            note = " (layer 6 includes x3303)" if scaled_last else " (layer 6 excludes x3303)"
        print(f"    ok    {fn}: {good} polys x 7 layers{note}")


def test_roundtrip(dev, cases):
    good = 0
    for name, f in cases:
        dev.put(BUF_A, f)
        dev.call("mlkem_poly_ntt")
        dev.call("mlkem_poly_intt")
        got = dev.get(BUF_A)
        if compare(got, f, f"intt(ntt(f)) == f [{name}]"):
            good += 1
    check(good == len(cases), f"intt(ntt(f)) == f: {good}/{len(cases)}")
    if good == len(cases):
        print(f"    ok    intt(ntt(f)) == f on device: {good} polys")


def test_binary(dev, fn, model, pairs):
    good = 0
    for name, a, b in pairs:
        got, b_after = dev.binary(fn, a, b)
        ok = compare(got, model(a, b), f"{fn}[{name}]")
        # The src operand is an input; it must come back untouched.
        if b_after != b:
            ok = check(False, f"{fn}[{name}]: src operand modified, "
                              f"{first_diff(b_after, b)}")
        if ok:
            good += 1
    check(good == len(pairs), f"{fn}: {good}/{len(pairs)} cases match")
    if good == len(pairs):
        print(f"    ok    {fn}: {good} cases")


def basemul_pairs(rnd, n_random):
    pairs = [
        ("zero x random", poly_const(0), poly_random(rnd)),
        ("all q-1 x all q-1  (S4 accumulator width)", poly_const(Q - 1), poly_const(Q - 1)),
        ("all q-1 x all 1", poly_const(Q - 1), poly_const(1)),
        ("all 2048 x all 2048", poly_const(2048), poly_const(2048)),
    ]
    # Impulse pairs. (even, even) hits a0*b0 only; (odd, odd) hits the
    # zeta*a1*b1 term — with sign alternation between neighbouring pairs;
    # (even, odd) hits the cross term. Include the top pair where the zeta
    # index is 127 and a wrong zeta table end shows.
    for i, j in ((0, 0), (1, 1), (0, 1), (2, 3), (3, 3), (254, 254), (255, 255),
                 (254, 255), (129, 129), (128, 129)):
        pairs.append((f"impulse[{i}]=q-1 x impulse[{j}]=q-1",
                      poly_impulse(i, Q - 1), poly_impulse(j, Q - 1)))
    for k in range(n_random):
        pairs.append((f"random #{k}", poly_random(rnd), poly_random(rnd)))
    return pairs


def addsub_pairs(rnd, n_random):
    pairs = [
        ("zero, zero", poly_const(0), poly_const(0)),
        ("all q-1, all q-1", poly_const(Q - 1), poly_const(Q - 1)),
        ("zero, all q-1  (S3 wrap)", poly_const(0), poly_const(Q - 1)),
        ("all q-1, zero", poly_const(Q - 1), poly_const(0)),
        ("all 1, all q-1", poly_const(1), poly_const(Q - 1)),
        ("all 1665, all 1664", poly_const(1665), poly_const(1664)),
        ("all 1664, all 1665", poly_const(1664), poly_const(1665)),
    ]
    for k in range(n_random):
        pairs.append((f"random #{k}", poly_random(rnd), poly_random(rnd)))
    return pairs


def test_reduce(dev, rnd, n_random):
    cases = [("k*q boundaries + extremes", reduce_boundary_poly()),
             ("all 0xFFFF", poly_const(0xFFFF)),
             ("all q", poly_const(Q)),
             ("all 2q-1", poly_const(2 * Q - 1)),
             ("all q-1 (identity)", poly_const(Q - 1))]
    for k in range(n_random):
        cases.append((f"random u16 #{k}", poly_random(rnd, hi=0x10000)))
    for k in range(max(1, n_random // 2)):
        cases.append((f"random <2q #{k}", poly_random(rnd, hi=2 * Q)))
    test_unary(dev, "mlkem_poly_reduce", lambda f: [x % Q for x in f], cases)


def test_tomont(dev, cases):
    R = 1 << 16
    test_unary(dev, "mlkem_poly_tomont", lambda f: [(x * R) % Q for x in f], cases)


def test_canary(dev):
    got = read_bytes(dev.t, CANARY, 512)
    if check(got == bytes([0xA5] * 512), "guard page after BUF_B untouched"):
        print("    ok    no write past the end of a polynomial buffer")


# ---------------------------------------------------------------------------
# Timing (S5) — reuses the calibrated CIA instrument from bench_keccak.py.
# ---------------------------------------------------------------------------

def test_timing(dev, labels, rnd):
    import bench_keccak as B
    t, l = dev.t, dev.l

    overhead, st_o, _ = B.measure_stable(t, l, None)
    spin_raw, st_s, _ = B.measure_stable(t, l, "bench_spin_1000")
    if not (st_o and st_s and spin_raw - overhead == B.SPIN_EXPECTED):
        check(False, f"timing: instrument calibration off "
                     f"(spin net {spin_raw - overhead}, want {B.SPIN_EXPECTED}); "
                     f"not reporting NTT cycles")
        return

    inputs = [("all-zero", poly_const(0)), ("all q-1", poly_const(Q - 1)),
              ("random", poly_random(rnd)), ("impulse[255]=q-1", poly_impulse(255, Q - 1))]
    for fn in ("mlkem_poly_ntt", "mlkem_poly_intt", "mlkem_poly_basemul"):
        counts = {}
        stable = True
        for name, f in inputs:
            def setup(f=f):
                dev.put(BUF_A, f)
                dev.put(BUF_B, f if fn != "mlkem_poly_basemul" else poly_random(rnd))
                dev._ptr("mlkem_zp_dst", BUF_A)
                dev._ptr("mlkem_zp_src", BUF_B)
            v, st, vals = B.measure_stable(t, l, fn, setup=setup)
            stable &= st
            counts[name] = v - overhead
        distinct = sorted(set(counts.values()))
        line = ", ".join(f"{k}={v:,}" for k, v in counts.items())
        if check(stable, f"{fn}: measurement reproducible") and \
           check(len(distinct) == 1, f"{fn}: constant-time in its input (S5): {line}"):
            print(f"    ok    {fn}: {distinct[0]:,} cycles, identical across "
                  f"{len(inputs)} inputs")


# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    full = "--full" in args
    timing = "--no-timing" not in args
    seed = DEFAULT_SEED
    if "--seed" in args:
        seed = int(args[args.index("--seed") + 1], 0)
    rnd = random.Random(seed)
    n_random = 64 if full else 4
    print(f"seed {seed:#x}  ({'full' if full else 'default'} sweep, "
          f"{n_random} random polys per function)")

    if not self_check_model(random.Random(1)):
        return 1

    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        r = subprocess.run(["make"], capture_output=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(r.stderr.decode()[-2000:])
            print("Build failed")
            return 1
    if not os.path.exists(PRG_PATH):
        print(f"missing {PRG_PATH}")
        return 1

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED_LABELS if n not in labels]
    if missing:
        print("FATAL: required WP1 labels absent from build/labels.txt "
              "(no implementation, or hooks not exported under MLKEM_TEST_HOOKS):")
        for n in missing:
            print(f"  - {n}")
        print("RED: 0 checks run")
        return 1
    if "__MAIN_LAST__" in labels and labels["__MAIN_LAST__"] > BUF_A:
        print(f"FATAL: image end {labels['__MAIN_LAST__']:#06x} overlaps the "
              f"harness buffers at {BUF_A:#06x}; move BUF_A/BUF_B")
        return 1
    if timing and any(n not in labels for n in BENCH_LABELS):
        print("note: bench instrument labels missing; timing section skipped")
        timing = False

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])
    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        if wait_for_text(transport, "C64-MLKEM", timeout=60.0, verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        write_bytes(transport, CANARY, bytes([0xA5] * 512))

        dev = Dev(transport, labels)
        n_sections = 9 if dev.has_tomont else 8
        sec = 0

        def hdr(title):
            nonlocal sec
            sec += 1
            print(f"\n[{sec}/{n_sections}] {title}")

        hdr("mlkem_poly_ntt, whole transform")
        test_unary(dev, "mlkem_poly_ntt", M.ntt, edge_polys(rnd, n_random))

        hdr("mlkem_ntt_layer, per-layer trace")
        layer_cases = [("all q-1", poly_const(Q - 1)),
                       ("impulse[255]=q-1", poly_impulse(255, Q - 1)),
                       ("impulse[0]=1", poly_impulse(0, 1))]
        layer_cases += [(f"random #{k}", poly_random(rnd)) for k in range(2 if not full else 8)]
        test_layers(dev, "ntt", layer_cases)

        hdr("mlkem_poly_intt, whole transform (input = NTT-domain values)")
        test_unary(dev, "mlkem_poly_intt", M.intt, edge_polys(rnd, n_random))

        hdr("mlkem_intt_layer, per-layer trace")
        test_layers(dev, "intt", layer_cases)

        hdr("intt(ntt(f)) == f, both on device")
        rt = [("all q-1", poly_const(Q - 1)), ("impulse[1]=1", poly_impulse(1, 1))]
        rt += [(f"random #{k}", poly_random(rnd)) for k in range(n_random)]
        test_roundtrip(dev, rt)

        hdr("mlkem_poly_basemul vs model (FIPS 203 Alg. 11/12)")
        test_binary(dev, "mlkem_poly_basemul", M.basemul, basemul_pairs(rnd, n_random))

        hdr("mlkem_poly_add / mlkem_poly_sub")
        test_binary(dev, "mlkem_poly_add", M.poly_add, addsub_pairs(rnd, n_random))
        test_binary(dev, "mlkem_poly_sub", M.poly_sub, addsub_pairs(rnd, n_random))

        hdr("mlkem_poly_reduce over the full u16 domain (S2)")
        test_reduce(dev, rnd, n_random)

        if dev.has_tomont:
            hdr("mlkem_poly_tomont (R = 2^16, S6)")
            test_tomont(dev, edge_polys(rnd, 2))

        print("\n[guard] buffer overrun canary")
        test_canary(dev)

        if timing:
            print("\n[timing] cycles per call, constant-time check (S5)")
            test_timing(dev, labels, rnd)

        mgr.release(inst)

    print(f"\n{_checks} checks in {time.time() - t0:.1f}s")
    if _fails:
        print(f"FAILED ({len(_fails)}):")
        for f in _fails[:20]:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
