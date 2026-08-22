#!/usr/bin/env python3
"""test_keccak_ref.py — oracle self-test for tools/keccak_ref.py.

Pure Python; no VICE, no emulator, runs in seconds. This is the FIRST link in
the validation chain described in README.md:

    XKCP intermediates + NIST CAVP  ->  keccak_ref.py  ->  6502 assembly

If this file fails, the golden model is wrong and every downstream 6502
comparison is meaningless. It must stay green before any VICE test is trusted.

Covered:
  1. round constants + rho offsets vs the XKCP published tables
  2. all 240 per-step intermediate states (2 permutations x 24 rounds x 5 steps)
  3. NIST CAVP ShortMsg / VariableOut / LongMsg (LongMsg only if fetched)
  4. NIST CAVP Monte Carlo chains
  5. properties the standard corpus does NOT cover: incremental-absorb split
     invariance and multi-call squeeze continuation

Usage:  make test-ref     (or: <venv python> tools/test_keccak_ref.py)
"""

import hashlib
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keccak_ref as K

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "vectors")

FUNCS = {
    "SHA3_256":  (136, 0x06, 32),
    "SHA3_512":  (72,  0x06, 64),
    "SHAKE128":  (168, 0x1F, None),
    "SHAKE256":  (136, 0x1F, None),
}

_fails = []

# Monte Carlo chains are 1000 hash iterations each; 100 of them per function is
# minutes of pure-Python work. The default runs a prefix (still 3000 chained
# hashes per function, which is far more chaining than any ShortMsg vector);
# --full runs all 100. Same tiering rationale as the VICE suite: the default
# target has to stay fast enough that people actually run it.
MONTE_CHAINS = 3
FULL = "--full" in sys.argv
if FULL:
    MONTE_CHAINS = 100


def check(cond, label):
    if cond:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}")
        _fails.append(label)


# --- 1 + 2: XKCP published tables and intermediate states -------------------

def test_xkcp():
    print("\n[1/5] XKCP published tables and intermediate values")
    path = os.path.join(VEC, "KeccakF-1600-IntermediateValues.txt")
    txt = open(path).read()

    rc = [int(m, 16) for m in re.findall(r"RC\[\d+\]\[0\]\[0\] = ([0-9A-F]{16})", txt)]
    check(len(rc) == 24 and rc == K.RC, f"24 round constants match (LFSR-generated)")

    rho = {}
    for x, y, v in re.findall(r"RhoOffset\[(\d)\]\[(\d)\] =\s*(\d+)", txt):
        rho[int(x) + 5 * int(y)] = int(v)
    check(len(rho) == 25 and [rho[i] for i in range(25)] == K.RHO,
          "25 rho offsets match")

    blocks = re.findall(r"After (theta|rho|pi|chi|iota):\n((?:[0-9A-F ]+\n){5})", txt)
    pub = [(n, [int(w, 16) for w in b.split()]) for n, b in blocks]
    check(len(pub) == 240, f"parsed 240 intermediate states (got {len(pub)})")

    idx = 0
    mismatches = []
    A = [0] * 25
    for run in range(2):
        trace = []
        A = K.permute(A, trace=trace)
        for name, rnd, st in trace:
            pname, pst = pub[idx]
            idx += 1
            if pname != name or pst != st:
                mismatches.append(f"run{run} round{rnd} after {name}")
    check(not mismatches,
          f"all 240 per-step states match ({len(mismatches)} mismatches)")


# --- CAVP .rsp parsing ------------------------------------------------------

def parse_rsp(path):
    """Yield dicts. Len/Outputlen are in BITS. Len=0 means EMPTY message —
    the file still carries a dummy `Msg = 00`, which must NOT be hashed."""
    recs, cur, hdr = [], {}, {}
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"\[(.+?)\s*=\s*(.+?)\]", line)
        if m:
            hdr[m.group(1)] = m.group(2)
            continue
        if "=" in line:
            k, v = (s.strip() for s in line.split("=", 1))
            cur[k] = v
            if k in ("MD", "Output"):
                cur["_hdr"] = dict(hdr)
                recs.append(dict(cur))
                for kk in ("Msg", "MD", "Output", "Len", "Outputlen"):
                    cur.pop(kk, None)
    return recs


def msg_of(rec):
    if "Len" in rec:
        blen = int(rec["Len"])
        if blen == 0:
            return b""
        assert blen % 8 == 0, "byte-oriented vectors only"
        return bytes.fromhex(rec["Msg"])
    return bytes.fromhex(rec["Msg"])


# --- 3: ShortMsg / LongMsg / VariableOut ------------------------------------

def test_cavp():
    print("\n[2/5] NIST CAVP known-answer vectors")
    total = 0
    for fn in sorted(os.listdir(VEC)):
        if not fn.endswith(".rsp"):
            continue
        name = fn[:-4]
        base = next((f for f in FUNCS if name.startswith(f)), None)
        if base is None or "Monte" in name:
            continue
        rate, sfx, _ = FUNCS[base]
        recs = parse_rsp(os.path.join(VEC, fn))
        bad = 0
        for r in recs:
            msg = msg_of(r)
            if "MD" in r:
                want, outlen = r["MD"], len(bytes.fromhex(r["MD"]))
            else:
                want = r["Output"]
                outlen = (int(r["Outputlen"]) // 8 if "Outputlen" in r
                          else len(bytes.fromhex(r["Output"])))
            if K.sponge(msg, rate, sfx, outlen).hex() != want.lower():
                bad += 1
        total += len(recs)
        check(bad == 0, f"{fn}: {len(recs)} vectors, {bad} failures")
    check(total > 0, f"total CAVP vectors run: {total}")


# --- 4: Monte Carlo chains --------------------------------------------------

def test_monte_sha3():
    print("\n[3/5] NIST CAVP Monte Carlo (SHA-3)")
    for base in ("SHA3_256", "SHA3_512"):
        path = os.path.join(VEC, f"{base}Monte.rsp")
        if not os.path.exists(path):
            continue
        rate, sfx, outlen = FUNCS[base]
        txt = open(path).read()
        seed = bytes.fromhex(re.search(r"Seed = ([0-9a-f]+)", txt).group(1))
        want = re.findall(r"COUNT = \d+\nMD = ([0-9a-f]+)", txt)
        md = seed
        bad = 0
        want = want[:MONTE_CHAINS]
        for j, exp in enumerate(want):
            for _ in range(1000):
                md = K.sponge(md, rate, sfx, outlen)
            if md.hex() != exp:
                bad += 1
        check(bad == 0,
              f"{base}Monte: {len(want)} chains x 1000 iterations, {bad} failures")


def test_monte_shake():
    print("\n[4/5] NIST CAVP Monte Carlo (SHAKE)")
    for base in ("SHAKE128", "SHAKE256"):
        path = os.path.join(VEC, f"{base}Monte.rsp")
        if not os.path.exists(path):
            continue
        rate, sfx, _ = FUNCS[base]
        txt = open(path).read()
        minb = int(re.search(r"Minimum Output Length \(bits\) = (\d+)", txt).group(1)) // 8
        maxb = int(re.search(r"Maximum Output Length \(bits\) = (\d+)", txt).group(1)) // 8
        msg0 = bytes.fromhex(re.search(r"Msg = ([0-9a-f]+)", txt).group(1))
        want = re.findall(r"COUNT = \d+\nOutputlen = (\d+)\nOutput = ([0-9a-f]+)", txt)

        # SHA3VS SHAKE Monte Carlo. Determined empirically against COUNT = 0
        # and then confirmed across all 100 chains (the .rsp file is itself the
        # check on this driver — the model underneath is already pinned by the
        # 240 intermediate states and 3,192 KAT vectors above):
        #   M[i]      = leftmost 128 bits of the previous Output, right-zero-
        #               padded if the previous Output was shorter than 16 B
        #   Output[i] = SHAKE(M[i], OutputLen)
        #   OutputLen = MinOutBytes + (rightmost 16 bits of Output[i],
        #               BIG-endian, mod (MaxOutBytes - MinOutBytes + 1))
        # The reported `Outputlen` is the length of the REPORTED output — i.e.
        # the length in force when it was produced — NOT the freshly-derived
        # length that carries into the next chain. Getting that one off-by-one
        # wrong is what made the first draft of this test fail.
        rng = maxb - minb + 1
        out = msg0
        outlen = maxb
        bad = 0
        want = want[:MONTE_CHAINS]
        for j, (exp_len, exp_out) in enumerate(want):
            for _ in range(1000):
                m = (out + b"\x00" * 16)[:16]
                out = K.sponge(m, rate, sfx, outlen)
                rightmost = int.from_bytes(out[-2:], "big")
                outlen = minb + (rightmost % rng)
            if out.hex() != exp_out or len(out) * 8 != int(exp_len):
                bad += 1
        check(bad == 0,
              f"{base}Monte: {len(want)} chains x 1000 iterations, {bad} failures")


# --- 5: properties the CAVP corpus does not reach ---------------------------

def test_properties():
    print("\n[5/5] Streaming properties (NOT covered by any CAVP vector)")
    rnd = random.Random(20260822)
    ctors = {"sha3_256": K.sha3_256, "sha3_512": K.sha3_512,
             "shake_128": K.shake_128, "shake_256": K.shake_256}
    hl = {"sha3_256": lambda m, n: hashlib.sha3_256(m).digest(),
          "sha3_512": lambda m, n: hashlib.sha3_512(m).digest(),
          "shake_128": lambda m, n: hashlib.shake_128(m).digest(n),
          "shake_256": lambda m, n: hashlib.shake_256(m).digest(n)}
    outlen = {"sha3_256": 32, "sha3_512": 64, "shake_128": 512, "shake_256": 512}

    # (a) absorb split invariance: every chunking of one message agrees, and
    #     agrees with hashlib. Rate-boundary lengths are included explicitly.
    bad_split = 0
    lengths = [0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169,
               271, 272, 273, 500, 1000]
    for n in lengths:
        msg = bytes(rnd.randrange(256) for _ in range(n))
        for name, ctor in ctors.items():
            ref = hl[name](msg, outlen[name])
            for _ in range(6):
                s = ctor()
                i = 0
                while i < n:
                    j = min(n, i + rnd.randrange(1, max(2, n - i + 1)))
                    s.absorb(msg[i:j])
                    i = j
                if s.final(outlen[name]) != ref:
                    bad_split += 1
    check(bad_split == 0,
          f"absorb split invariance: {len(lengths)} lengths x 4 funcs x 6 "
          f"random chunkings, {bad_split} failures")

    # (b) multi-call squeeze continuation — what ML-KEM matrix expansion needs.
    bad_sq = 0
    for name in ("shake_128", "shake_256"):
        for n in (0, 1, 100, 1000):
            msg = bytes(rnd.randrange(256) for _ in range(n))
            ref = hl[name](msg, 2048)
            for _ in range(6):
                s = ctors[name]()
                s.absorb(msg)
                got, want_total = b"", 2048
                while len(got) < want_total:
                    k = min(want_total - len(got), rnd.randrange(1, 200))
                    got += s.squeeze(k)
                if got != ref:
                    bad_sq += 1
    check(bad_sq == 0,
          f"squeeze continuation: 2 funcs x 4 lengths x 6 random chunkings "
          f"of a 2048-byte stream, {bad_sq} failures")

    # (c) the rate-1 padding collision: suffix and final bit share one byte.
    bad_pad = 0
    for name, ctor in ctors.items():
        rate = ctor().rate
        for n in (rate - 1, rate, rate + 1):
            msg = bytes(rnd.randrange(256) for _ in range(n))
            if ctor().absorb(msg).final(outlen[name]) != hl[name](msg, outlen[name]):
                bad_pad += 1
    check(bad_pad == 0,
          f"padding at rate-1 / rate / rate+1 for all 4 functions, {bad_pad} failures")


def main():
    print("c64-mlkem oracle self-test — tools/keccak_ref.py")
    print(f"(Monte Carlo: {MONTE_CHAINS} chains/function"
          f"{'' if FULL else ' — pass --full for all 100'})")
    test_xkcp()
    test_cavp()
    test_monte_sha3()
    test_monte_shake()
    test_properties()
    print()
    if _fails:
        print(f"FAILED ({len(_fails)}):")
        for f in _fails:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
