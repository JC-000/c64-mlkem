#!/usr/bin/env python3
"""test_mlkem.py — WP3 red tests: K-PKE and ML-KEM-768 KeyGen / Encaps /
Decaps on the 6502, against three oracles, over the c64-test-harness in VICE.

Written adversarially from FIPS 203, the ACVP vectors, cryptography.hazmat
and tools/mlkem_ref.py BEFORE any 6502 implementation existed. The
implementer turns it green and may not edit it; disputes go to the
supervisor.

===========================================================================
ASSUMED ABI  (the implementer matches this, or the supervisor reconciles)
===========================================================================

Byte strings are the FIPS 203 wire formats, verbatim, at caller-supplied
addresses: ek 1,184 B, dk 2,400 B, c 1,088 B, K / d / z / m / r 32 B each.
No alignment requirement on ANY of them — the consumer (c64-https) will put
keys wherever its TLS state lives. The harness therefore uses page-aligned
buffers for most cases and DELIBERATELY ODD addresses for some.

Parameter block — too many pointers for mlkem_zp_src/dst alone, and the §2
zero-page inventory should not grow by ten bytes for three calls. The block
is six little-endian 16-bit pointers in LIB_MLKEM_BSS, exported by name so
the harness (and a consumer) writes each one by label. The routines read
them into mlkem_zp_src/dst as needed; the block itself is NOT modified by a
call (a consumer sets it once per session). Offsets are fixed and asserted,
so a consumer may also treat the block as one 12-byte struct at
mlkem_arg_ek:

    mlkem_arg_ek     +0   -> ek   (1,184 B)  [K-PKE hooks: ek_pke, same size]
    mlkem_arg_dk     +2   -> dk   (2,400 B)  [K-PKE hooks: dk_pke, 1,152 B]
    mlkem_arg_ct     +4   -> c    (1,088 B)
    mlkem_arg_key    +6   -> K    (32 B)     [kpke_decrypt: the recovered m]
    mlkem_arg_seed   +8   -> d (keygen) / m (encaps, kpke_encrypt)   32 B
    mlkem_arg_z     +10   -> z (keygen) / r (kpke_encrypt)           32 B

Exported entry points (shipped archive):

    mlkem_keygen     in  seed=d, z=z            out ek, dk        A = 0 always
    mlkem_encaps     in  ek, seed=m             out key=K, ct=c   A = status
    mlkem_decaps     in  dk, ct                 out key=K         A = 0 always

Status (mlkem_encaps only), in A on return, and also latched in the exported
byte mlkem_status so a caller that clobbers A can still read it:

    A = 0   ok: K and c written.
    A = 1   ek REJECTED by the FIPS 203 §7.2 modulus check — some 12-bit
            field of t_hat is >= q. NOTHING is written to K or c (both
            buffers are byte-for-byte what they were before the call), and
            no Keccak or arithmetic on m has taken place that could leave m
            derived material in the output buffers.
            WP2 pinned mlkem_byte_decode_12 as a RAW pass-through (a field
            >= q is stored unreduced), so the re-encode-and-compare trick of
            §7.2 is blind here: the check MUST be an explicit per-coefficient
            `< q` compare over all 3 x 256 decoded fields. It is public data;
            it may exit early.
    Length checks (§7.2 (1), §7.3) are NOT performed: the C64 API takes
    pointers, not (pointer, length) pairs, so length is the caller's
    invariant by construction.

mlkem_decaps never fails. A ciphertext that does not re-encrypt yields the
implicit-rejection key K = J(z || c) silently (Alg. 18 lines 9-11). The
ciphertext compare is a FULL-LENGTH accumulate-OR over all 1,088 bytes: its
cycle count must not depend on WHERE (or whether) c and c' differ — tested
(T1 below). The §7.3 hash check (H(ek) field of dk == H(ek)) is the CALLER's
per FIPS 203, and this library does NOT perform it: a dk with a corrupted
H(ek) field is processed mechanically by Alg. 18 with the stored h, and the
result is pinned to that (D2 below), so the behaviour is deterministic and
documented rather than undefined.

K-PKE hooks (MLKEM_TEST_HOOKS build only, same parameter block):

    mlkem_kpke_keygen    in  seed=d              out ek (ek_pke 1,184 B),
                                                     dk (dk_pke 1,152 B)
    mlkem_kpke_encrypt   in  ek (ek_pke), seed=m, z=r   out ct (1,088 B)
                         No modulus check here — that is mlkem_encaps's.
    mlkem_kpke_decrypt   in  dk (dk_pke, 1,152 B), ct   out key = m (32 B)

Register / ZP clobbers: A/X/Y, every mlkem_zp_* slot, mlkem_sponge_len,
keccak_state and all library BSS. Nothing outside the declared output
buffers is written (canaries after every output buffer — C1).

===========================================================================
SPEC POINTS where this file chose a behaviour the implementer must match
===========================================================================

  K1  mlkem_keygen output is byte-exact to ACVP: ek = t_hat‖rho,
      dk = dk_pke‖ek‖H(ek)‖z. A wrong H(ek) length or a missing k byte in
      G(d‖k) is reported with the first differing byte offset, which names
      the field (dk offsets: 0 dk_pke, 1152 ek, 2336 H(ek), 2368 z).
  E1  mlkem_encaps is deterministic in (ek, m): ACVP `m -> (K, c)` exact.
      Kyber-round-3 behaviour (hashing m first, G(H(m)‖H(ek))) is a K and c
      mismatch on every vector.
  E2  Rejection: A=1, K and c untouched, for every encapsulationKeyCheck
      vector with testPassed=false; A=0 and (K, c) exact for the valid ones
      with a harness-chosen m.
  D1  Implicit rejection returns EXACTLY J(z‖c) (ACVP "modified ciphertext"
      vectors) — never an error, never K', never zeros.
  D2  dk with a wrong H(ek) field: no check, mechanical Alg. 18 with the
      stored h. The expected value is computed by a local model that mirrors
      Alg. 18 without the §7.3 check.
  D3  A ciphertext differing from a valid one in ONE bit — first byte and
      last byte — must give J(z‖c') (kills a compare that stops early or
      only covers part of c).
  T1  mlkem_decaps is constant-time in c: the cycle count for a valid c, a
      c differing in bit 0 of byte 0, and a c differing in bit 7 of byte 1087
      must be IDENTICAL. Measured with the calibrated CIA instrument
      (bench_keccak.py); the calibration refusal is kept — an off
      calibration is a FAIL, not a skip.
  C1  No output routine writes past its declared output; 16-byte canaries
      after ek, dk, c, K are checked after every call.
  P1  The parameter block is not modified by any call.

Usage:
    python3 tools/test_mlkem.py [--full] [--only S[,S]] [--no-timing] [--seed N]

    --full       every ACVP vector (25 keyGen, 25 encaps, 10 decaps, 10 + 10
                 key checks), 4 hazmat seeds, keygen/encaps cycle counts.
                 Budget: ~150 VICE calls of 10-40M cycles each.
    --only       keygen, encaps, decaps, ekcheck, dkcheck, hazmat, hooks,
                 onebit, timing
    --no-timing  skip the CIA-instrumented constant-time check (T1)

Honors C64_SKIP_BUILD=1. Exit 1 on any failure, or when a required label is
absent (which is what "red" looks like before the implementation lands).
"""

import hashlib
import json
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
VECTOR_DIR = os.path.join(PROJECT_ROOT, "tools", "vectors")

EK, DK, CT, DK_PKE = M.EK_BYTES, M.DK_BYTES, M.CT_BYTES, 384 * M.K
H_OFF, Z_OFF = 768 * M.K + 32, 768 * M.K + 64          # dk field offsets

# One ML-KEM call runs for tens of millions of cycles; give VICE room even
# without warp.
JSR_TIMEOUT = 900.0

# Scratch RAM for the harness-side buffers. Well above any plausible P2
# image ($0801 + 7,680 B code/rodata + ~8 KB BSS < $4000) and below $8000 so
# nothing depends on RAM under a ROM. main() refuses to run if a label lands
# in the range.
SCRATCH_LO, SCRATCH_HI = 0x6000, 0x8000
BUF_EK = 0x6000            # 1184 + canary            .. $64A0
BUF_DK = 0x6500            # 2400 + canary            .. $6E70
BUF_CT = 0x7000            # 1088 + canary            .. $7450
ODD = 0x7501               # odd base for the misaligned cases: ek at ODD
                           # (.. $79B1 incl. canary), c at ODD + 0x4B1
                           # (.. $7E02), K at ODD + 0x903 (.. $7E34)
BUF_KEY = 0x7E80           # 32 + canary
BUF_SEED = 0x7EC0
BUF_Z = 0x7F00
CANARY_LEN = 16
CANARY = bytes((0x5A + 11 * k) & 0xFF for k in range(CANARY_LEN))

ARG_BLOCK = ["mlkem_arg_ek", "mlkem_arg_dk", "mlkem_arg_ct", "mlkem_arg_key",
             "mlkem_arg_seed", "mlkem_arg_z"]
REQUIRED_LABELS = ARG_BLOCK + [
    "mlkem_keygen", "mlkem_encaps", "mlkem_decaps", "mlkem_status",
    "mlkem_kpke_keygen", "mlkem_kpke_encrypt", "mlkem_kpke_decrypt",
]
BENCH_LABELS = ["bench_cycles_start", "bench_cycles_stop", "bench_cycles",
                "bench_spin_1000", "vic_blank", "vic_unblank", "bench_sync_frame"]

DEFAULT_SEED = 0x2026_0828
_fails, _checks = [], 0


def check(cond, label):
    global _checks
    _checks += 1
    if not cond:
        _fails.append(label)
        print(f"    FAIL  {label}")
    return cond


def hx(s):
    return bytes.fromhex(s)


def first_diff(got, want):
    if len(got) != len(want):
        return f"length {len(got)} want {len(want)}"
    for i, (a, b) in enumerate(zip(got, want)):
        if a != b:
            return f"differs at byte {i} (got {a:02X} want {b:02X})"
    return None


def cmp_bytes(tag, what, got, want):
    d = first_diff(got, want)
    return check(d is None, f"{tag}: {what} {d}")


# ---------------------------------------------------------------------------
# Vectors and model helpers
# ---------------------------------------------------------------------------

def load_acvp(name):
    path = os.path.join(VECTOR_DIR, name)
    with open(path) as fh:
        return json.load(fh)["testGroups"]


def acvp_keygen():
    out = []
    for g in load_acvp("ML-KEM-768-keyGen-FIPS203.json"):
        out.extend(g["tests"])
    return out


def acvp_encapdecap():
    by_fn = {}
    for g in load_acvp("ML-KEM-768-encapDecap-FIPS203.json"):
        by_fn.setdefault(g["function"], []).extend(g["tests"])
    return by_fn


def decaps_no_dk_check(dk, c):
    """FIPS 203 Alg. 18 exactly, WITHOUT the §7.3 hash check — what the
    library does with a dk whose H(ek) field is wrong (spec point D2)."""
    dk_pke, ek_pke = dk[:DK_PKE], dk[DK_PKE:DK_PKE + EK]
    h, z = dk[H_OFF:H_OFF + 32], dk[Z_OFF:Z_OFF + 32]
    m_prime = M.kpke_decrypt(dk_pke, c)
    k_prime, r_prime = M.G(m_prime + h)
    k_bar = M.J(z + c)
    c_prime = M.kpke_encrypt(ek_pke, m_prime, r_prime)
    return k_bar if c != c_prime else k_prime


def self_check_model():
    """The local D2 model must agree with the oracle on a valid dk, and the
    oracle must be pinned (a red test on a wrong oracle blames the 6502)."""
    d, z, m = (hashlib.sha256(b"wp3-selfcheck-" + t).digest() for t in (b"d", b"z", b"m"))
    ek, dk = M.mlkem_keygen(d, z)
    k, c = M.mlkem_encaps(ek, m)
    if decaps_no_dk_check(dk, c) != k or M.mlkem_decaps(dk, c) != k:
        print("FATAL: local decaps_no_dk_check disagrees with M.mlkem_decaps on a valid dk")
        return False
    c2 = bytearray(c)
    c2[0] ^= 1
    if decaps_no_dk_check(dk, bytes(c2)) != M.J(z + bytes(c2)):
        print("FATAL: local model does not implicitly reject")
        return False
    if (EK, DK, CT) != (1184, 2400, 1088):
        print("FATAL: oracle sizes are not ML-KEM-768's")
        return False
    return True


def fixed_bytes(tag):
    return hashlib.sha256(b"c64-mlkem wp3 " + tag.encode()).digest()


# ---------------------------------------------------------------------------
# 6502 driver: the caller-side half of the ABI
# ---------------------------------------------------------------------------

class C64:
    def __init__(self, transport, labels):
        self.t, self.l = transport, labels
        self.args = {}

    def arg(self, name, addr):
        self.args[name] = addr
        write_bytes(self.t, self.l[f"mlkem_arg_{name}"], bytes([addr & 0xFF, addr >> 8]))

    def put(self, addr, data, canary=True):
        write_bytes(self.t, addr, bytes(data) + (CANARY if canary else b""))

    def arm(self, addr, length):
        """Junk-fill an output buffer and place the canary after it."""
        write_bytes(self.t, addr, bytes([0xEE] * length) + CANARY)

    def get(self, addr, length):
        return read_bytes(self.t, addr, length)

    def canary_ok(self, addr, length):
        return read_bytes(self.t, addr + length, CANARY_LEN) == CANARY

    def args_intact(self):
        for name, addr in self.args.items():
            got = read_bytes(self.t, self.l[f"mlkem_arg_{name}"], 2)
            if got != bytes([addr & 0xFF, addr >> 8]):
                return False
        return True

    def call(self, label):
        jsr(self.t, self.l[label], timeout=JSR_TIMEOUT)
        a = self.t.read_registers()["A"]
        status = read_bytes(self.t, self.l["mlkem_status"], 1)[0]
        return a, status

    # --- the three primitives + hooks, harness-side convenience -----------

    def keygen(self, d, z, ek_at=BUF_EK, dk_at=BUF_DK, label="mlkem_keygen"):
        self.put(BUF_SEED, d)
        self.put(BUF_Z, z)
        self.arm(ek_at, EK)
        dk_len = DK if label == "mlkem_keygen" else DK_PKE
        self.arm(dk_at, dk_len)
        self.arg("seed", BUF_SEED); self.arg("z", BUF_Z)
        self.arg("ek", ek_at); self.arg("dk", dk_at)
        self.call(label)
        return (self.get(ek_at, EK), self.get(dk_at, dk_len),
                self.canary_ok(ek_at, EK) and self.canary_ok(dk_at, dk_len))

    def encaps(self, ek, m, ek_at=BUF_EK, ct_at=BUF_CT, key_at=BUF_KEY,
               r=None, label="mlkem_encaps"):
        self.put(ek_at, ek)
        self.put(BUF_SEED, m)
        if r is not None:
            self.put(BUF_Z, r)
            self.arg("z", BUF_Z)
        self.arm(ct_at, CT)
        self.arm(key_at, 32)
        self.arg("ek", ek_at); self.arg("seed", BUF_SEED)
        self.arg("ct", ct_at); self.arg("key", key_at)
        a, status = self.call(label)
        return (self.get(key_at, 32), self.get(ct_at, CT), a, status,
                self.canary_ok(ct_at, CT) and self.canary_ok(key_at, 32))

    def decaps(self, dk, c, dk_at=BUF_DK, ct_at=BUF_CT, key_at=BUF_KEY,
               label="mlkem_decaps"):
        self.put(dk_at, dk)
        self.put(ct_at, c)
        self.arm(key_at, 32)
        self.arg("dk", dk_at); self.arg("ct", ct_at); self.arg("key", key_at)
        a, status = self.call(label)
        return (self.get(key_at, 32), a,
                self.canary_ok(key_at, 32) and self.canary_ok(ct_at, CT)
                and self.canary_ok(dk_at, len(dk)))


# ---------------------------------------------------------------------------
# Suites
# ---------------------------------------------------------------------------

def suite_keygen(c64, full):
    vecs = acvp_keygen()
    vecs = vecs if full else vecs[:2]
    print(f"\n[keygen] ACVP keyGen, {len(vecs)} vector(s){'' if full else ' (--full: all 25)'}")
    for t in vecs:
        tag = f"mlkem_keygen [keyGen tcId {t['tcId']}]"
        t0 = time.time()
        ek, dk, cn = c64.keygen(hx(t["d"]), hx(t["z"]))
        ok = cmp_bytes(tag, "ek", ek, hx(t["ek"]))
        ok &= cmp_bytes(tag, "dk", dk, hx(t["dk"]))
        ok &= check(cn, f"{tag}: canary after ek/dk intact (C1)")
        ok &= check(c64.args_intact(), f"{tag}: parameter block preserved (P1)")
        if ok:
            print(f"    ok    {tag}  ({time.time() - t0:.1f}s)")


def suite_encaps(c64, full):
    vecs = acvp_encapdecap()["encapsulation"]
    vecs = vecs if full else vecs[:2]
    print(f"\n[encaps] ACVP encapsulation m -> (K, c), {len(vecs)} vector(s)"
          f"{'' if full else ' (--full: all 25)'}")
    for i, t in enumerate(vecs):
        tag = f"mlkem_encaps [encapsulation tcId {t['tcId']}]"
        # The second default vector runs on odd addresses (no alignment
        # requirement on the wire buffers).
        odd = (i == 1)
        ek_at, ct_at, key_at = (ODD, ODD + 0x4B1, ODD + 0x903) if odd else (BUF_EK, BUF_CT, BUF_KEY)
        k, c, a, status, cn = c64.encaps(hx(t["ek"]), hx(t["m"]), ek_at, ct_at, key_at)
        ok = check(a == 0 and status == 0, f"{tag}: status A={a} mlkem_status={status}, want 0 (valid ek)")
        ok &= cmp_bytes(tag, "c", c, hx(t["c"]))
        ok &= cmp_bytes(tag, "K", k, hx(t["k"]))
        ok &= check(cn, f"{tag}: canary after c/K intact (C1)")
        ok &= check(c64.args_intact(), f"{tag}: parameter block preserved (P1)")
        if ok:
            print(f"    ok    {tag}{' (odd addresses)' if odd else ''}")


def suite_decaps(c64, full):
    vecs = acvp_encapdecap()["decapsulation"]
    if not full:
        valid = next(t for t in vecs if t["reason"] == "valid decapsulation")
        modified = next(t for t in vecs if t["reason"] == "modified ciphertext")
        vecs = [valid, modified]
    print(f"\n[decaps] ACVP decapsulation, {len(vecs)} vector(s)"
          f"{'' if full else ' (1 valid + 1 modified ciphertext; --full: all 10)'}")
    for t in vecs:
        dk, c, want = hx(t["dk"]), hx(t["c"]), hx(t["k"])
        tag = f"mlkem_decaps [decapsulation tcId {t['tcId']} {t['reason']}]"
        z = dk[Z_OFF:Z_OFF + 32]
        rejected = (want == M.J(z + c))
        if t["reason"] == "modified ciphertext" and not rejected:
            print(f"    note  {tag}: the vector's K is not J(z||c) — vector/model disagree?")
        k, a, cn = c64.decaps(dk, c)
        ok = cmp_bytes(tag, "K" + (" (implicit rejection J(z||c))" if rejected else ""), k, want)
        ok &= check(a == 0, f"{tag}: A={a}, want 0 (decaps never reports an error)")
        ok &= check(cn, f"{tag}: canaries after K / c / dk intact (C1)")
        ok &= check(c64.args_intact(), f"{tag}: parameter block preserved (P1)")
        if ok:
            print(f"    ok    {tag}")


def suite_ekcheck(c64, full):
    vecs = acvp_encapdecap()["encapsulationKeyCheck"]
    if not full:
        bad = next(t for t in vecs if not t["testPassed"])
        good = next(t for t in vecs if t["testPassed"])
        vecs = [bad, good]
    print(f"\n[ekcheck] ACVP encapsulationKeyCheck (FIPS 203 §7.2 modulus check), "
          f"{len(vecs)} vector(s){'' if full else ' (--full: all 10)'}")
    for t in vecs:
        ek = hx(t["ek"])
        tag = f"mlkem_encaps [encapsulationKeyCheck tcId {t['tcId']} {t['reason']}]"
        m = fixed_bytes(f"ekcheck m {t['tcId']}")
        k, c, a, status, cn = c64.encaps(ek, m)
        if t["testPassed"]:
            wk, wc = M.mlkem_encaps(ek, m)
            ok = check(a == 0 and status == 0, f"{tag}: rejected a valid ek (A={a})")
            ok &= cmp_bytes(tag, "c", c, wc)
            ok &= cmp_bytes(tag, "K", k, wk)
        else:
            # Locate the offending coefficient so the failure names it.
            where = ""
            for i in range(M.K):
                for j, v in enumerate(M.byte_decode(12, ek[384 * i:384 * (i + 1)], reduce=False)):
                    if v >= M.Q:
                        where = f" (t_hat[{i}][{j}] = {v} >= q)"
                        break
                if where:
                    break
            ok = check(a == 1 and status == 1,
                       f"{tag}: accepted an ek with a coefficient >= q{where} "
                       f"(A={a} mlkem_status={status}, want 1)")
            ok &= check(c == bytes([0xEE] * CT), f"{tag}: c must be untouched on rejection (E2)")
            ok &= check(k == bytes([0xEE] * 32), f"{tag}: K must be untouched on rejection (E2)")
        ok &= check(cn, f"{tag}: canaries intact (C1)")
        if ok:
            print(f"    ok    {tag}")


def suite_dkcheck(c64, full):
    vecs = acvp_encapdecap()["decapsulationKeyCheck"]
    if not full:
        vecs = [next(t for t in vecs if not t["testPassed"])]
    print(f"\n[dkcheck] ACVP decapsulationKeyCheck: §7.3 is the caller's check; the "
          f"library runs Alg. 18 mechanically (D2), {len(vecs)} vector(s)"
          f"{'' if full else ' (--full: all 10)'}")
    for t in vecs:
        ek, dk = hx(t["ek"]), hx(t["dk"])
        tag = f"mlkem_decaps [decapsulationKeyCheck tcId {t['tcId']} {t['reason']}]"
        m = fixed_bytes(f"dkcheck m {t['tcId']}")
        k_enc, c = M.mlkem_encaps(ek, m)
        want = decaps_no_dk_check(dk, c)
        if t["testPassed"]:
            note = "valid dk: K'"
            if want != k_enc:
                print(f"    note  {tag}: valid dk but model does not recover K?")
        else:
            z = dk[Z_OFF:Z_OFF + 32]
            note = ("wrong H(ek) -> r' differs -> c' != c -> J(z||c)"
                    if want == M.J(z + c) else "wrong H(ek) -> K' from stored h")
        k, a, cn = c64.decaps(dk, c)
        ok = cmp_bytes(tag, f"K [{note}]", k, want)
        ok &= check(a == 0, f"{tag}: A={a}, want 0")
        ok &= check(cn, f"{tag}: canaries intact (C1)")
        if ok:
            print(f"    ok    {tag}  [{note}]")


def suite_hazmat(c64, full):
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric import mlkem
    except ImportError as e:
        check(False, f"hazmat: cryptography.hazmat mlkem unavailable ({e}); the "
                     f"independent oracle is a required leg of this suite")
        return
    n = 4 if full else 1
    print(f"\n[hazmat] interop with cryptography {cryptography.__version__}, {n} seed(s)"
          f"{'' if full else ' (--full: 4)'}")
    rnd = random.Random(0x4D4C4B454D ^ 3)
    for i in range(n):
        d = bytes(rnd.randrange(256) for _ in range(32))
        z = bytes(rnd.randrange(256) for _ in range(32))
        sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(d + z)
        their_ek = sk.public_key().public_bytes_raw()
        tag = f"hazmat seed #{i}"

        # 1. our keygen == their from_seed_bytes(d||z)
        ek, dk, cn = c64.keygen(d, z)
        ok = cmp_bytes(f"mlkem_keygen [{tag}]", "ek vs MLKEM768PrivateKey.from_seed_bytes(d||z)",
                       ek, their_ek)
        ok &= check(cn, f"mlkem_keygen [{tag}]: canaries intact (C1)")
        if not ok:
            # The rest of this seed would only cascade; use the oracle's dk
            # so the decaps leg still reports on its own merits.
            ek, dk = M.mlkem_keygen(d, z)

        # 2. their encapsulate() -> our decaps (dk on the 6502 is OURS)
        ss, ct = sk.public_key().encapsulate()          # (ss, ct) order
        k, a, cn = c64.decaps(dk, ct)
        ok2 = cmp_bytes(f"mlkem_decaps [{tag}]", "K vs hazmat encapsulate() shared secret", k, ss)
        ok2 &= check(cn, f"mlkem_decaps [{tag}]: canaries intact (C1)")

        # 3. our encaps (odd addresses) -> their decapsulate()
        m = bytes(rnd.randrange(256) for _ in range(32))
        k, c, a, status, cn = c64.encaps(ek, m, ODD, ODD + 0x4B1, ODD + 0x903)
        ok3 = check(a == 0, f"mlkem_encaps [{tag}]: A={a}, want 0")
        theirs = sk.decapsulate(c)
        ok3 &= cmp_bytes(f"mlkem_encaps [{tag}]", "our K vs hazmat decapsulate(our c)", k, theirs)
        # If their decapsulate implicitly rejected, say so — that is the
        # "our c is malformed" signature, distinct from a wrong K.
        if theirs != k and theirs == M.J(z + c):
            check(False, f"mlkem_encaps [{tag}]: hazmat implicitly REJECTED our ciphertext "
                         f"(K == J(z||c)) — c is not a valid encapsulation of m under ek")
        ok3 &= check(cn, f"mlkem_encaps [{tag}]: canaries intact (C1)")
        if ok and ok2 and ok3:
            print(f"    ok    {tag}: keygen == from_seed_bytes; their ct -> our K; our ct -> their K")


def suite_hooks(c64, full):
    print("\n[hooks] K-PKE hooks (MLKEM_TEST_HOOKS): fixed (d, m, r) vs the oracle's kpke_*")
    d, m, r = fixed_bytes("kpke d"), fixed_bytes("kpke m"), fixed_bytes("kpke r")
    want_ek, want_dk = M.kpke_keygen(d)
    want_c = M.kpke_encrypt(want_ek, m, r)

    ek, dk, cn = c64.keygen(d, bytes(32), label="mlkem_kpke_keygen")
    ok = cmp_bytes("mlkem_kpke_keygen [fixed d]", "ek_pke", ek, want_ek)
    ok &= cmp_bytes("mlkem_kpke_keygen [fixed d]", "dk_pke (1152 B)", dk, want_dk)
    ok &= check(cn, "mlkem_kpke_keygen: canaries after ek_pke / dk_pke intact (C1)")
    if ok:
        print("    ok    mlkem_kpke_keygen [fixed d]")

    _, c, _, _, cn = c64.encaps(want_ek, m, r=r, label="mlkem_kpke_encrypt")
    ok = cmp_bytes("mlkem_kpke_encrypt [fixed ek, m, r]", "c", c, want_c)
    ok &= check(cn, "mlkem_kpke_encrypt: canary after c intact (C1)")
    if ok:
        print("    ok    mlkem_kpke_encrypt [fixed ek, m, r]")
    # Localise a wrong c: c1 (u, d_u=10) is bytes 0..959, c2 (v, d_v=4) is 960..1087.
    if c != want_c:
        d1 = first_diff(c[:960], want_c[:960])
        d2 = first_diff(c[960:], want_c[960:])
        print(f"          c1 (u, compress_10): {d1 or 'ok'};  c2 (v, compress_4): {d2 or 'ok'}")

    got_m, _, cn = c64.decaps(want_dk, want_c, label="mlkem_kpke_decrypt")
    ok = cmp_bytes("mlkem_kpke_decrypt [fixed dk, c]", "m", got_m, m)
    ok &= check(cn, "mlkem_kpke_decrypt: canaries intact (C1)")
    if ok:
        print("    ok    mlkem_kpke_decrypt [fixed dk, c]")

    # Round trip entirely on the 6502 with a different m, r.
    m2, r2 = fixed_bytes("kpke m2"), fixed_bytes("kpke r2")
    _, c2, _, _, _ = c64.encaps(ek if ek == want_ek else want_ek, m2, r=r2, label="mlkem_kpke_encrypt")
    got_m2, _, _ = c64.decaps(dk if dk == want_dk else want_dk, c2, label="mlkem_kpke_decrypt")
    if cmp_bytes("K-PKE round trip on the 6502 [m2, r2]", "decrypt(encrypt(m2))", got_m2, m2):
        print("    ok    K-PKE round trip on the 6502")


def onebit_cases(full):
    """A valid (dk, c) from ACVP plus single-bit variants."""
    t = next(t for t in acvp_encapdecap()["decapsulation"] if t["reason"] == "valid decapsulation")
    dk, c = hx(t["dk"]), hx(t["c"])
    flips = [(0, 0), (CT - 1, 7)]
    if full:
        flips += [(959, 3), (960, 0), (CT // 2, 5)]
    out = []
    for byte, bit in flips:
        c2 = bytearray(c)
        c2[byte] ^= 1 << bit
        out.append((f"c ^ bit {bit} of byte {byte}", bytes(c2)))
    return t["tcId"], dk, c, hx(t["k"]), out


def suite_onebit(c64, full):
    tcid, dk, c, k_valid, cases = onebit_cases(full)
    z = dk[Z_OFF:Z_OFF + 32]
    print(f"\n[onebit] decapsulation tcId {tcid}: ciphertexts one bit away from valid (D3), "
          f"{len(cases)} case(s)")
    for name, c2 in cases:
        want = M.J(z + c2)
        assert want != k_valid
        k, a, cn = c64.decaps(dk, c2)
        tag = f"mlkem_decaps [one-bit {name}]"
        ok = cmp_bytes(tag, "K must be J(z||c')", k, want)
        if k == k_valid:
            check(False, f"{tag}: returned the VALID key K' — the re-encrypt compare "
                         f"missed a one-bit difference (early exit or partial compare)")
        ok &= check(cn, f"{tag}: canaries intact (C1)")
        if ok:
            print(f"    ok    {tag}")


def suite_timing(c64, full):
    """T1: constant-time decaps, plus cycle counts (informational)."""
    import bench_keccak as B
    t, l = c64.t, c64.l
    if any(l.address(n) is None for n in BENCH_LABELS):
        check(False, "timing: bench instrument labels missing from the test PRG; T1 not measured")
        return
    print("\n[timing] mlkem_decaps constant-time in c (T1), calibrated CIA instrument")
    overhead, st_o, _ = B.measure_stable(t, l, None)
    spin_raw, st_s, _ = B.measure_stable(t, l, "bench_spin_1000")
    if not (st_o and st_s and spin_raw - overhead == B.SPIN_EXPECTED):
        check(False, f"timing: instrument calibration off (spin net {spin_raw - overhead}, "
                     f"want {B.SPIN_EXPECTED}); not reporting ML-KEM cycles")
        return
    print(f"    calibration OK (overhead {overhead}, spin {spin_raw - overhead})")

    tcid, dk, c, _, cases = onebit_cases(False)
    inputs = [("valid c", c)] + cases
    counts, stable = {}, True
    for name, ct in inputs:
        def setup(ct=ct):
            c64.put(BUF_DK, dk)
            c64.put(BUF_CT, ct)
            c64.arm(BUF_KEY, 32)
            c64.arg("dk", BUF_DK); c64.arg("ct", BUF_CT); c64.arg("key", BUF_KEY)
        v, st, vals = B.measure_stable(t, l, "mlkem_decaps", tries=2, setup=setup)
        stable &= st
        counts[name] = v - overhead
        print(f"    {name:28} {v - overhead:>12,} cycles{'' if st else '  UNSTABLE ' + str(vals)}")
    distinct = sorted(set(counts.values()))
    line = "; ".join(f"{k}={v:,}" for k, v in counts.items())
    if check(stable, "mlkem_decaps: measurement reproducible (VICE is deterministic)") and \
       check(len(distinct) == 1, f"mlkem_decaps: constant-time in c (T1): {line}"):
        print(f"    ok    mlkem_decaps: {distinct[0]:,} cycles, identical for valid and "
              f"one-bit-modified c")

    if full:
        print("\n[timing] cycles per primitive (informational, for WP4)")
        kg = acvp_keygen()[0]
        en = acvp_encapdecap()["encapsulation"][0]

        def setup_kg():
            c64.put(BUF_SEED, hx(kg["d"])); c64.put(BUF_Z, hx(kg["z"]))
            c64.arg("seed", BUF_SEED); c64.arg("z", BUF_Z)
            c64.arg("ek", BUF_EK); c64.arg("dk", BUF_DK)

        def setup_en():
            c64.put(BUF_EK, hx(en["ek"])); c64.put(BUF_SEED, hx(en["m"]))
            c64.arg("ek", BUF_EK); c64.arg("seed", BUF_SEED)
            c64.arg("ct", BUF_CT); c64.arg("key", BUF_KEY)

        for fn, setup in (("mlkem_keygen", setup_kg), ("mlkem_encaps", setup_en)):
            v, st, vals = B.measure_stable(t, l, fn, tries=2, setup=setup)
            print(f"    {fn:28} {v - overhead:>12,} cycles{'' if st else '  UNSTABLE ' + str(vals)}")


SUITES = {
    "keygen": suite_keygen,
    "encaps": suite_encaps,
    "decaps": suite_decaps,
    "ekcheck": suite_ekcheck,
    "dkcheck": suite_dkcheck,
    "hazmat": suite_hazmat,
    "hooks": suite_hooks,
    "onebit": suite_onebit,
    "timing": suite_timing,
}


# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    full = "--full" in args
    timing = "--no-timing" not in args
    only = None
    if "--only" in args:
        only = set(args[args.index("--only") + 1].split(","))
        bad = only - set(SUITES)
        if bad:
            print(f"unknown suite(s): {sorted(bad)}; choose from {sorted(SUITES)}")
            return 2
    seed = DEFAULT_SEED
    if "--seed" in args:
        seed = int(args[args.index("--seed") + 1], 0)
    random.seed(seed)

    if not self_check_model():
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
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print("FAIL  required WP3 export(s) not in build/labels.txt:")
        for n in missing:
            print(f"      - {n}")
        print("FAILED (red: WP3 not implemented / not linked into the test PRG)")
        return 1
    # The parameter block is one struct: offsets fixed (see the ABI header).
    base = labels["mlkem_arg_ek"]
    for i, n in enumerate(ARG_BLOCK):
        if labels[n] != base + 2 * i:
            print(f"FAIL  {n} is at ${labels[n]:04X}, want mlkem_arg_ek + {2 * i} = ${base + 2 * i:04X}")
            return 1
    clash = [(n, a) for n, a in labels.items() if SCRATCH_LO <= a < SCRATCH_HI
             and not n.startswith("__")]
    if clash:
        print(f"FATAL: labels inside the harness scratch range ${SCRATCH_LO:04X}-${SCRATCH_HI:04X}: "
              f"{clash[:5]}; move the scratch")
        return 1
    if "__MAIN_LAST__" in labels and labels["__MAIN_LAST__"] > SCRATCH_LO:
        print(f"FATAL: image end ${labels['__MAIN_LAST__']:04X} overlaps the harness scratch")
        return 1

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])
    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        if wait_for_text(transport, "C64-MLKEM P", timeout=60.0, verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        c64 = C64(transport, labels)
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
