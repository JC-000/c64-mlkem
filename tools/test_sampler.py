#!/usr/bin/env python3
"""test_sampler.py — WP2 differential tests: ML-KEM samplers and codecs on the
6502 against the FIPS 203 model (tools/mlkem_ref.py), driven over the
c64-test-harness in VICE.

Written RED, from FIPS 203 and the oracle API in HANDOFF-P2.md, before any
implementation exists. The implementer turns it green and may not edit it.

ASSUMED ABI (the implementer must match this or take a dispute to the
supervisor; every assumption below is exercised by a test):

  Polynomial in memory
      512 bytes, exactly the layout that mlkem_ref.poly_to_c64 / poly_from_c64
      define (the brief recommends split-plane: 256 low bytes then 256 high
      bytes). This file never assumes the layout itself — it converts through
      the oracle — EXCEPT in the two fallbacks used when the oracle lacks the
      helper, which assume split-plane. Buffers passed in are page-aligned.
      A routine that writes a polynomial writes ALL 512 bytes (the high plane
      of a d<=8 compressed poly is zero, not stale) and NOTHING past them —
      every output buffer carries a 16-byte canary after it.

  Pointer convention (unchanged from P1's sponge): input polynomial / byte
      string at (mlkem_zp_src), output at (mlkem_zp_dst). Both are set by the
      caller before EVERY call; nothing here relies on a routine preserving
      them (mlkem_squeeze advances mlkem_zp_dst, and the sampler may reuse it).
      Routines clobber A/X/Y, mlkem_zp_tmp, mlkem_zp_len and mlkem_sponge_len.

  mlkem_sample_ntt        FIPS 203 Alg 7 over a LIVE SHAKE128 stream. The
      caller has already run mlkem_shake128_init and absorbed rho||j||i (34
      bytes) through mlkem_absorb; the sampler's only input is the sponge
      state. It squeezes as many bytes as rejection needs (3 rate blocks
      usually, 4 sometimes) and writes A[i][j] in NTT order to (mlkem_zp_dst).
      Output coefficients are the accepted 12-bit values, in [0, q).
      Once j == 256 it must stop even if d2 of the current triple is < q.

  mlkem_sample_cbd2       FIPS 203 Alg 8 with eta=2. 128 PRF bytes at
      (mlkem_zp_src) -> polynomial at (mlkem_zp_dst) with coefficients
      reduced to [0, q): a negative value v is stored as q+v.

  mlkem_byte_encode_12    Alg 5, d=12. Polynomial at src -> 384 bytes at dst.
  mlkem_byte_decode_12    Alg 6, d=12. 384 bytes at src -> polynomial at dst.
      PINNED BEHAVIOUR for a 12-bit field >= q: decode is a pure bit unpack and
      writes the raw 12-bit value (3329..4095) UNREDUCED. FIPS 203 Alg 6 takes
      the field mod q for d=12; this library does not, because the only place
      an out-of-range field can arrive is an attacker-supplied ek, and FIPS
      203 §7.2 makes that check the caller's job. WP3's Encaps input check is
      therefore an explicit per-coefficient `< q` compare, NOT the
      re-encode-and-compare trick (which is blind under raw pass-through).
      Consequence tested here: byte_encode_12(byte_decode_12(b)) == b for
      EVERY 384-byte b, including ones carrying fields >= q.

  mlkem_compress_{1,4,10}   Alg (4.7): y = round_half_up(2^d * x / q) mod 2^d,
      polynomial at src (coefficients in [0, q)) -> polynomial of d-bit values
      at dst. Not packed — packing is ByteEncode's job.
  mlkem_decompress_{1,4,10} Alg (4.8): x = round_half_up(q * y / 2^d),
      polynomial of d-bit values at src -> polynomial in [0, q) at dst.
      In-place (src == dst) is NOT required and not tested.

Usage:  python3 tools/test_sampler.py [--full] [--seed S] [--only NAME[,NAME]]
    --full   exhaustive sweeps (all 3329 inputs to every compress, per-position
             encode/decode impulses, 27 SampleNTT streams, 32 CBD inputs)
    --only   run a subset: sample_ntt, cbd, encode, decode, compress, decompress
Honors C64_SKIP_BUILD=1.
"""

import hashlib
import math
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import mlkem_ref as M
except ImportError:            # WP0 not merged yet: the local fallbacks carry the run
    M = None
    print("WARNING: tools/mlkem_ref.py not importable; using local fallbacks "
          "for every model function (the oracle pin does not apply)")

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "mlkem.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

Q = 3329
N = 256
POLY_BYTES = 512
CANARY_LEN = 16
CANARY = bytes((0xA5 + 7 * k) & 0xFF for k in range(CANARY_LEN))

# Scratch RAM, well above any plausible P2 image ($0801 + 7,680 code/rodata +
# a few KB of BSS < $4000). main() refuses to run if any label lands inside.
IN_BUF = 0x8000          # byte-string inputs (PRF bytes, encoded polys, seeds)
POLY_A = 0x9000          # page-aligned polynomial buffers
POLY_B = 0x9400
SCRATCH_LO, SCRATCH_HI = 0x8000, 0x9800 + POLY_BYTES + CANARY_LEN

REQUIRED_LABELS = [
    "mlkem_shake128_init", "mlkem_absorb", "mlkem_sponge_len",
    "mlkem_zp_src", "mlkem_zp_dst",
    "mlkem_sample_ntt", "mlkem_sample_cbd2",
    "mlkem_byte_encode_12", "mlkem_byte_decode_12",
    "mlkem_compress_1", "mlkem_compress_4", "mlkem_compress_10",
    "mlkem_decompress_1", "mlkem_decompress_4", "mlkem_decompress_10",
]

# ---------------------------------------------------------------------------
# Model. Every function is taken from mlkem_ref when it exists there, so the
# oracle pin (make test-ref) is what these tests inherit. The fallbacks are
# straight transcriptions of FIPS 203 and exist only so the harness runs
# before WP0 lands / for helpers the oracle does not export.
# ---------------------------------------------------------------------------

def _ref(name, fallback):
    f = getattr(M, name, None) if M is not None else None
    return f if f is not None else fallback


def _fb_sample_ntt(rho, i, j):
    """FIPS 203 Alg 7. Stream = SHAKE128(rho || j || i)."""
    xof = hashlib.shake_128(rho + bytes([j, i]))
    stream = xof.digest(168 * 16)
    a, pos, k = [], 0, 0
    while k < N:
        c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        d1 = c0 + 256 * (c1 % 16)
        d2 = (c1 >> 4) + 16 * c2
        if d1 < Q:
            a.append(d1); k += 1
        if d2 < Q and k < N:
            a.append(d2); k += 1
    return a


def _fb_sample_cbd(eta, b):
    assert len(b) == 64 * eta
    bits = [(b[t >> 3] >> (t & 7)) & 1 for t in range(8 * len(b))]
    f = []
    for i in range(N):
        x = sum(bits[2 * i * eta + t] for t in range(eta))
        y = sum(bits[2 * i * eta + eta + t] for t in range(eta))
        f.append((x - y) % Q)
    return f


def _fb_byte_encode(d, f):
    bits = []
    for a in f:
        for t in range(d):
            bits.append((a >> t) & 1)
    out = bytearray(32 * d)
    for t, bit in enumerate(bits):
        out[t >> 3] |= bit << (t & 7)
    return bytes(out)


def _fb_byte_decode(d, b):
    """Raw unpack: NO mod-q for d=12 (see the pinned behaviour above)."""
    assert len(b) == 32 * d
    bits = [(b[t >> 3] >> (t & 7)) & 1 for t in range(256 * d)]
    return [sum(bits[i * d + t] << t for t in range(d)) for i in range(N)]


def _fb_compress(d, x):
    # round-half-up of (2^d * x) / q, then mod 2^d — exact integer arithmetic
    return ((x * (1 << d) * 2 + Q) // (2 * Q)) % (1 << d)


def _fb_decompress(d, y):
    return (y * Q * 2 + (1 << d)) // (2 << d)


def _fb_poly_to_c64(f):
    return bytes(a & 0xFF for a in f) + bytes(a >> 8 for a in f)


def _fb_poly_from_c64(b):
    return [b[i] | (b[256 + i] << 8) for i in range(N)]


sample_ntt = _ref("sample_ntt", _fb_sample_ntt)
sample_cbd = _ref("sample_cbd", _fb_sample_cbd)
byte_encode = _ref("byte_encode", _fb_byte_encode)
compress = _ref("compress", _fb_compress)
decompress = _ref("decompress", _fb_decompress)
_oracle_byte_decode = _ref("byte_decode", _fb_byte_decode)
_oracle_poly_to_c64 = _ref("poly_to_c64", _fb_poly_to_c64)
_oracle_poly_from_c64 = _ref("poly_from_c64", _fb_poly_from_c64)


def byte_decode_raw(d, b):
    """The pinned 6502 behaviour: raw 12-bit fields, never reduced. The oracle's
    byte_decode may follow Alg 6 literally (mod q for d=12), so it is only
    trusted when every field is < q; otherwise the local unpack is used."""
    raw = _fb_byte_decode(d, b)
    if d != 12 or all(v < Q for v in raw):
        got = _oracle_byte_decode(d, b)
        assert got == raw, "oracle byte_decode disagrees with the local unpack"
    return raw


def poly_to_c64(f):
    if all(0 <= v < Q for v in f):
        return _oracle_poly_to_c64(f)
    try:                                 # values >= q (raw decode) may be rejected
        return _oracle_poly_to_c64(f)
    except Exception:
        return _fb_poly_to_c64(f)


def poly_from_c64(b):
    try:
        return _oracle_poly_from_c64(b)
    except Exception:
        return _fb_poly_from_c64(b)


# Self-check of the fallbacks against the oracle where both exist: if the two
# disagree on a random poly, stop before blaming the 6502.
def _cross_check_model():
    rnd = random.Random(1)
    f = [rnd.randrange(Q) for _ in range(N)]
    assert poly_from_c64(poly_to_c64(f)) == f
    assert byte_decode_raw(12, byte_encode(12, f)) == f
    for d in (1, 4, 10):
        for x in (0, 1, Q - 1, 1664, 1665):
            assert 0 <= compress(d, x) < (1 << d)
        for y in (0, (1 << d) - 1):
            assert 0 <= decompress(d, y) < Q
    b = bytes(rnd.randrange(256) for _ in range(128))
    assert len(sample_cbd(2, b)) == N
    assert len(sample_ntt(bytes(32), 0, 0)) == N


# ---------------------------------------------------------------------------

_fails = []
_checks = 0


def check(cond, label):
    global _checks
    _checks += 1
    if not cond:
        _fails.append(label)
        print(f"    FAIL  {label}")
    return cond


def first_diff(got, want):
    for i, (g, w) in enumerate(zip(got, want)):
        if g != w:
            return f"index {i}: got {g} want {w}"
    if len(got) != len(want):
        return f"length {len(got)} vs {len(want)}"
    return "identical"


def sample_ntt_stream_stats(rho, i, j):
    """How many XOF bytes / rate blocks Alg 7 consumes for this seed."""
    stream = hashlib.shake_128(rho + bytes([j, i])).digest(168 * 16)
    pos = k = 0
    while k < N:
        c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        if c0 + 256 * (c1 % 16) < Q:
            k += 1
            if k == N:
                break
        if (c1 >> 4) + 16 * c2 < Q:
            k += 1
    return pos, math.ceil(pos / 168)


class C64:
    """Thin driver: the caller-side half of the ABI documented above."""

    def __init__(self, transport, labels):
        self.t, self.l = transport, labels

    def _ptr(self, slot, addr):
        write_bytes(self.t, self.l[slot], bytes([addr & 0xFF, addr >> 8]))

    def set_src(self, addr):
        self._ptr("mlkem_zp_src", addr)

    def set_dst(self, addr):
        self._ptr("mlkem_zp_dst", addr)

    def arm_output(self, addr):
        """Pre-fill an output poly buffer with junk plus a trailing canary."""
        write_bytes(self.t, addr, bytes([0xEE] * POLY_BYTES) + CANARY)

    def canary_ok(self, addr):
        return read_bytes(self.t, addr + POLY_BYTES, CANARY_LEN) == CANARY

    def write_poly(self, addr, f):
        write_bytes(self.t, addr, poly_to_c64(f))

    def read_poly(self, addr):
        return poly_from_c64(read_bytes(self.t, addr, POLY_BYTES))

    def seed_shake128(self, data):
        jsr(self.t, self.l["mlkem_shake128_init"])
        write_bytes(self.t, IN_BUF, data)
        self.set_src(IN_BUF)
        write_bytes(self.t, self.l["mlkem_sponge_len"],
                    bytes([len(data) & 0xFF, len(data) >> 8]))
        jsr(self.t, self.l["mlkem_absorb"])

    def poly_op(self, func, src_poly, dst=POLY_B, src=POLY_A):
        """src poly -> (func) -> dst poly, with canary. Returns (poly, canary_ok)."""
        self.write_poly(src, src_poly)
        self.arm_output(dst)
        self.set_src(src)
        self.set_dst(dst)
        jsr(self.t, self.l[func])
        return self.read_poly(dst), self.canary_ok(dst)


def compare_poly(name, case, got, want, canary):
    ok = check(got == want, f"{name} [{case}]: {first_diff(got, want)}")
    ok &= check(canary, f"{name} [{case}]: wrote past the 512-byte output buffer")
    return ok


# ---------------------------------------------------------------------------
# SampleNTT
# ---------------------------------------------------------------------------

# Seeds found by searching the model (see the final report for the search):
# rho = SHA3-256(b"c64-mlkem wp2 <n>"), stream = SHAKE128(rho || j || i).
def _rho(n):
    return hashlib.sha3_256(b"c64-mlkem wp2 %d" % n).digest()


SAMPLE_NTT_CASES = [
    # (label,            rho,     i, j, expected XOF bytes, blocks)
    ("needs 4 blocks (510 B > 504)",             _rho(0),  1, 2, 510, 4),
    ("exactly 3 blocks, every byte used (504)",  _rho(1),  2, 0, 504, 3),
    ("256th coeff is 1st candidate of block 4",  _rho(11), 1, 1, 507, 4),
    ("256th coeff is d1, d2 < q must be dropped", _rho(0),  0, 1, 471, 3),
    ("stream carries a d == q (reject) and q-1 (accept)", _rho(13), 2, 0, 471, 3),
]


def test_sample_ntt(c64, full):
    print("\n[1/6] mlkem_sample_ntt — rejection sampling over the live SHAKE128 stream")
    cases = list(SAMPLE_NTT_CASES)
    for label, rho, i, j, nbytes, nblocks in cases:
        got_bytes, got_blocks = sample_ntt_stream_stats(rho, i, j)
        assert (got_bytes, got_blocks) == (nbytes, nblocks), \
            f"seed table stale for {label}: {got_bytes} B / {got_blocks} blocks"
    if full:
        for n in range(3):
            rho = _rho(1000 + n)
            for i in range(3):
                for j in range(3):
                    nb, nbl = sample_ntt_stream_stats(rho, i, j)
                    cases.append((f"random rho#{n} i={i} j={j}", rho, i, j, nb, nbl))

    for label, rho, i, j, nbytes, nblocks in cases:
        want = sample_ntt(rho, i, j)
        c64.seed_shake128(rho + bytes([j, i]))       # FIPS 203: rho || j || i
        c64.arm_output(POLY_A)
        c64.set_dst(POLY_A)
        jsr(c64.t, c64.l["mlkem_sample_ntt"])
        got = c64.read_poly(POLY_A)
        case = f"{label}; i={i} j={j} rho={rho.hex()[:16]}.. ({nbytes} B, {nblocks} blk)"
        compare_poly("mlkem_sample_ntt", case, got, want, c64.canary_ok(POLY_A))
        check(all(v < Q for v in got), f"mlkem_sample_ntt [{case}]: coefficient >= q accepted")
    print(f"    done  {len(cases)} streams")


# ---------------------------------------------------------------------------
# CBD
# ---------------------------------------------------------------------------

def test_cbd(c64, full):
    print("\n[2/6] mlkem_sample_cbd2 — 128 PRF bytes -> poly in [0,q)")
    rnd = random.Random(0x2CBD)
    inputs = [
        ("all-zero", bytes(128)),
        ("all-0xFF", bytes([0xFF] * 128)),
        ("0x03 (x=2,y=0 -> +2 in even coeffs)", bytes([0x03] * 128)),
        ("0x0C (x=0,y=2 -> q-2 in even coeffs)", bytes([0x0C] * 128)),
        ("0x30 (+2 in odd coeffs)", bytes([0x30] * 128)),
        ("0xC0 (q-2 in odd coeffs)", bytes([0xC0] * 128)),
        ("0x01 / 0x02 alternate (bit position within a pair)",
         bytes([0x01, 0x02] * 64)),
        ("last byte only nonzero", bytes(127) + b"\x0F"),
        ("last byte only nonzero (0x33)", bytes(127) + b"\x33"),
    ]
    for n in range(32 if full else 3):
        inputs.append((f"random #{n}", bytes(rnd.randrange(256) for _ in range(128))))

    for label, b in inputs:
        want = sample_cbd(2, b)
        write_bytes(c64.t, IN_BUF, b)
        c64.arm_output(POLY_A)
        c64.set_src(IN_BUF)
        c64.set_dst(POLY_A)
        jsr(c64.t, c64.l["mlkem_sample_cbd2"])
        got = c64.read_poly(POLY_A)
        compare_poly("mlkem_sample_cbd2", label, got, want, c64.canary_ok(POLY_A))
    print(f"    done  {len(inputs)} inputs")


# ---------------------------------------------------------------------------
# ByteEncode12 / ByteDecode12
# ---------------------------------------------------------------------------

def _encode_vectors(full):
    rnd = random.Random(0xEC12)
    vecs = [
        ("all-zero", [0] * N),
        ("all q-1", [Q - 1] * N),
        ("0 / q-1 alternating (even=0)", [0 if i % 2 == 0 else Q - 1 for i in range(N)]),
        ("0 / q-1 alternating (even=q-1)", [Q - 1 if i % 2 == 0 else 0 for i in range(N)]),
        ("position identity 13*i (all distinct)", [13 * i for i in range(N)]),
        ("nibble-asymmetric 0x3A5 / 0x5AC", [0x3A5 if i % 2 == 0 else 0x5AC for i in range(N)]),
        ("powers of two", [(1 << (i % 12)) for i in range(N)]),
    ]
    for n in range(4 if full else 2):
        vecs.append((f"random #{n}", [rnd.randrange(Q) for _ in range(N)]))
    if full:
        for p in range(N):
            f = [0] * N
            f[p] = Q - 1
            vecs.append((f"impulse q-1 at {p}", f))
    return vecs


def test_encode(c64, full):
    print("\n[3/6] mlkem_byte_encode_12 — poly -> 384 bytes")
    vecs = _encode_vectors(full)
    for label, f in vecs:
        want = byte_encode(12, f)
        c64.write_poly(POLY_A, f)
        write_bytes(c64.t, IN_BUF, bytes([0xEE] * 384) + CANARY)
        c64.set_src(POLY_A)
        c64.set_dst(IN_BUF)
        jsr(c64.t, c64.l["mlkem_byte_encode_12"])
        got = read_bytes(c64.t, IN_BUF, 384)
        check(got == want, f"mlkem_byte_encode_12 [{label}]: byte {first_diff(got, want)}")
        check(read_bytes(c64.t, IN_BUF + 384, CANARY_LEN) == CANARY,
              f"mlkem_byte_encode_12 [{label}]: wrote past 384 bytes")
    print(f"    done  {len(vecs)} vectors")


def test_decode(c64, full):
    print("\n[4/6] mlkem_byte_decode_12 — 384 bytes -> poly (raw fields, unreduced)")
    rnd = random.Random(0xDC12)
    vecs = [(label, byte_encode(12, f)) for label, f in _encode_vectors(full)]
    # Fields >= q: the pinned behaviour is raw pass-through.
    vecs.append(("all fields 0xFFF (>= q, raw)", bytes([0xFF] * 384)))
    vecs.append(("all fields exactly q (raw 3329)", _fb_byte_encode(12, [Q] * N)))
    mixed = [Q + (i * 37) % (4096 - Q) if i % 3 == 0 else (i * 13) % Q for i in range(N)]
    vecs.append(("every 3rd field >= q, rest < q", _fb_byte_encode(12, mixed)))
    for n in range(4 if full else 2):
        vecs.append((f"random bytes #{n}", bytes(rnd.randrange(256) for _ in range(384))))

    for label, b in vecs:
        want = byte_decode_raw(12, b)
        write_bytes(c64.t, IN_BUF, b)
        c64.arm_output(POLY_A)
        c64.set_src(IN_BUF)
        c64.set_dst(POLY_A)
        jsr(c64.t, c64.l["mlkem_byte_decode_12"])
        got = c64.read_poly(POLY_A)
        compare_poly("mlkem_byte_decode_12", label, got, want, c64.canary_ok(POLY_A))

    # Round trip on the 6502 alone: encode(decode(b)) == b for arbitrary b.
    # This is exactly the property raw pass-through guarantees and mod-q breaks.
    for n in range(2):
        b = bytes(rnd.randrange(256) for _ in range(384))
        write_bytes(c64.t, IN_BUF, b)
        c64.set_src(IN_BUF)
        c64.set_dst(POLY_A)
        jsr(c64.t, c64.l["mlkem_byte_decode_12"])
        write_bytes(c64.t, IN_BUF, bytes(384))
        c64.set_src(POLY_A)
        c64.set_dst(IN_BUF)
        jsr(c64.t, c64.l["mlkem_byte_encode_12"])
        got = read_bytes(c64.t, IN_BUF, 384)
        check(got == b, f"encode_12(decode_12(b)) != b [random #{n}]: byte {first_diff(got, b)}")
    print(f"    done  {len(vecs)} vectors + 2 round trips")


# ---------------------------------------------------------------------------
# Compress / Decompress
# ---------------------------------------------------------------------------

def compress_boundaries(d):
    """Every x in [1, q) where compress(d, x) != compress(d, x-1), i.e. the
    exact inputs on which round-half-up flips. Both sides of each edge are
    returned. Computed from the model so the set is right by construction."""
    xs = set()
    prev = compress(d, 0)
    for x in range(1, Q):
        cur = compress(d, x)
        if cur != prev:
            xs.add(x - 1)
            xs.add(x)
        prev = cur
    xs.update({0, Q - 1})
    return sorted(xs)


def chunks(values, fill):
    values = list(values)
    while values:
        blk, values = values[:N], values[N:]
        blk += [fill] * (N - len(blk))
        yield blk


def test_compress(c64, full):
    print("\n[5/6] mlkem_compress_{1,4,10} — round-half-up boundaries" +
          (" + exhaustive" if full else ""))
    rnd = random.Random(0xC0)
    for d in (1, 4, 10):
        fn = f"mlkem_compress_{d}"
        bnd = compress_boundaries(d)
        vecs = [(f"boundaries {k * N}..", blk) for k, blk in enumerate(chunks(bnd, 0))]
        if full:
            vecs += [(f"exhaustive {k * N}..", blk) for k, blk in enumerate(chunks(range(Q), Q - 1))]
        for n in range(3):
            vecs.append((f"random #{n}", [rnd.randrange(Q) for _ in range(N)]))
        for label, f in vecs:
            want = [compress(d, x) for x in f]
            got, canary = c64.poly_op(fn, f)
            compare_poly(fn, label, got, want, canary)
        print(f"    done  {fn}: {len(bnd)} boundary values in {len(vecs)} polys")


def test_decompress(c64, full):
    print("\n[6/6] mlkem_decompress_{1,4,10} — exhaustive over every d-bit input")
    rnd = random.Random(0xDC)
    for d in (1, 4, 10):
        fn = f"mlkem_decompress_{d}"
        vecs = [(f"exhaustive {k * N}..", blk)
                for k, blk in enumerate(chunks(range(1 << d), (1 << d) - 1))]
        # Reversed order too: catches an index/value confusion that a
        # monotone ramp cannot.
        vecs.append(("descending", [((1 << d) - 1 - i) % (1 << d) for i in range(N)]))
        for n in range(3 if full else 1):
            vecs.append((f"random #{n}", [rnd.randrange(1 << d) for _ in range(N)]))
        for label, f in vecs:
            want = [decompress(d, y) for y in f]
            got, canary = c64.poly_op(fn, f)
            compare_poly(fn, label, got, want, canary)
            check(all(v < Q for v in got), f"{fn} [{label}]: output coefficient >= q")
        print(f"    done  {fn}: {len(vecs)} polys")


# ---------------------------------------------------------------------------

SUITES = {
    "sample_ntt": test_sample_ntt,
    "cbd": test_cbd,
    "encode": test_encode,
    "decode": test_decode,
    "compress": test_compress,
    "decompress": test_decompress,
}


def main():
    args = sys.argv[1:]
    full = "--full" in args
    only = None
    if "--only" in args:
        only = set(args[args.index("--only") + 1].split(","))
        bad = only - set(SUITES)
        if bad:
            print(f"unknown suite(s): {sorted(bad)}; choose from {sorted(SUITES)}")
            return 2

    _cross_check_model()

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
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print("FAIL  required WP2 export(s) not in build/labels.txt:")
        for n in missing:
            print(f"      - {n}")
        print("FAILED (red: WP2 not implemented / not linked into the test PRG)")
        return 1
    clash = [(n, a) for n, a in labels.items() if SCRATCH_LO <= a < SCRATCH_HI]
    if clash:
        print(f"FATAL: labels inside the test scratch range "
              f"${SCRATCH_LO:04X}-${SCRATCH_HI:04X}: {clash[:5]}; move the scratch")
        return 1

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])
    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        # P1's banner says "P1"; P2's driver may say "P2". Sync on the prefix.
        if wait_for_text(transport, "C64-MLKEM P", timeout=60.0, verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        c64 = C64(transport, labels)
        for name, fn in SUITES.items():
            if only is None or name in only:
                fn(c64, full)
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
