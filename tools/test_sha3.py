#!/usr/bin/env python3
"""test_sha3.py — FIPS 202 KATs for the 6502 sponge, driven over DMA in VICE.

Checks SHA3-256, SHA3-512, SHAKE128 and SHAKE256 against NIST CAVP vectors and
against hashlib, and — more importantly — against the two things NO CAVP vector
reaches, because every published vector is one-shot:

  * incremental absorb: the same message split arbitrarily must hash the same
  * multi-call squeeze: the output stream must continue across calls

Those are the c64-mlkem-specific requirements (ML-KEM's matrix expansion
squeezes many blocks per call site), so they get property tests rather than
vectors.

Tiering: the default run is a sharp subset chosen around the rate boundaries
plus a sample, because a VICE round-trip per vector is far more expensive than
a Python one. --full runs every ShortMsg vector.

Usage:  python3 tools/test_sha3.py [--full]
Honors C64_SKIP_BUILD=1.
"""

import hashlib
import os
import random
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "mlkem.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")

MSG_BUF = 0x2000        # free RAM well above the PRG image (~$0E47)
OUT_BUF = 0x4000

FUNCS = {
    "sha3_256":  ("mlkem_sha3_256_init", 136, 32,  lambda m, n: hashlib.sha3_256(m).digest()),
    "sha3_512":  ("mlkem_sha3_512_init", 72,  64,  lambda m, n: hashlib.sha3_512(m).digest()),
    "shake128":  ("mlkem_shake128_init", 168, None, lambda m, n: hashlib.shake_128(m).digest(n)),
    "shake256":  ("mlkem_shake256_init", 136, None, lambda m, n: hashlib.shake_256(m).digest(n)),
}

_fails = []
_checks = 0


def check(cond, label):
    global _checks
    _checks += 1
    if not cond:
        _fails.append(label)
        print(f"    FAIL  {label}")
    return cond


class C64Sponge:
    """Drives the 6502 sponge with the same call sequence as keccak_ref.Sponge."""

    def __init__(self, transport, labels, fn):
        self.t, self.l = transport, labels
        self.init_label = FUNCS[fn][0]
        jsr(transport, labels[self.init_label])

    def _set_len(self, n):
        write_bytes(self.t, self.l["mlkem_sponge_len"],
                    bytes([n & 0xFF, (n >> 8) & 0xFF]))

    def absorb(self, data):
        if data:
            write_bytes(self.t, MSG_BUF, data)
        write_bytes(self.t, self.l["mlkem_zp_src"],
                    bytes([MSG_BUF & 0xFF, MSG_BUF >> 8]))
        self._set_len(len(data))
        jsr(self.t, self.l["mlkem_absorb"])
        return self

    def squeeze(self, n, dst=OUT_BUF):
        write_bytes(self.t, self.l["mlkem_zp_dst"],
                    bytes([dst & 0xFF, (dst >> 8) & 0xFF]))
        self._set_len(n)
        jsr(self.t, self.l["mlkem_squeeze"])
        return read_bytes(self.t, dst, n) if n else b""


def parse_rsp(path):
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
    blen = int(rec["Len"])
    return b"" if blen == 0 else bytes.fromhex(rec["Msg"])


# ---------------------------------------------------------------------------

def test_cavp(transport, labels, full):
    print("\n[1/3] NIST CAVP known-answer vectors")
    for fn, (init, rate, outlen, _) in FUNCS.items():
        base = {"sha3_256": "SHA3_256", "sha3_512": "SHA3_512",
                "shake128": "SHAKE128", "shake256": "SHAKE256"}[fn]
        path = os.path.join(VEC, f"{base}ShortMsg.rsp")
        recs = parse_rsp(path)
        by_len = {int(r["Len"]) // 8: r for r in recs}

        if full:
            chosen = recs
        else:
            # The rate boundaries are where padding bugs live; sample the rest.
            want = {0, 1, 2, rate - 2, rate - 1, rate, rate + 1, 2 * rate}
            chosen = [by_len[n] for n in sorted(want) if n in by_len]
            chosen += recs[::max(1, len(recs) // 8)]

        bad = 0
        seen = set()
        for r in chosen:
            key = r["Len"]
            if key in seen:
                continue
            seen.add(key)
            msg = msg_of(r)
            want_hex = (r.get("MD") or r["Output"]).lower()
            n = len(bytes.fromhex(want_hex))
            got = C64Sponge(transport, labels, fn).absorb(msg).squeeze(n)
            if got.hex() != want_hex:
                bad += 1
                if bad == 1:
                    print(f"    first bad: {fn} len={len(msg)} "
                          f"got {got.hex()[:32]}... want {want_hex[:32]}...")
        check(bad == 0, f"{base}ShortMsg: {len(seen)} vectors, {bad} failures")
        if bad == 0:
            print(f"    ok    {base}ShortMsg: {len(seen)} vectors")


def test_variable_out(transport, labels):
    print("\n[2/3] SHAKE VariableOut (a sample) + long multi-block messages")
    for fn, base in (("shake128", "SHAKE128"), ("shake256", "SHAKE256")):
        recs = parse_rsp(os.path.join(VEC, f"{base}VariableOut.rsp"))
        chosen = recs[::max(1, len(recs) // 12)]
        bad = 0
        for r in chosen:
            msg = bytes.fromhex(r["Msg"])
            n = int(r["Outputlen"]) // 8
            got = C64Sponge(transport, labels, fn).absorb(msg).squeeze(n)
            if got.hex() != r["Output"].lower():
                bad += 1
        check(bad == 0, f"{base}VariableOut: {len(chosen)} vectors, {bad} failures")
        if bad == 0:
            print(f"    ok    {base}VariableOut: {len(chosen)} vectors")

    # Messages spanning many rate blocks, absorbed in one call.
    rnd = random.Random(20260822)
    bad = 0
    for fn, (_, rate, outlen, ref) in FUNCS.items():
        for mult in (3, 7):
            n = rate * mult + 5
            msg = bytes(rnd.randrange(256) for _ in range(n))
            want_n = outlen or 64
            got = C64Sponge(transport, labels, fn).absorb(msg).squeeze(want_n)
            if got != ref(msg, want_n):
                bad += 1
    check(bad == 0, f"multi-block messages (3x and 7x rate), {bad} failures")
    if bad == 0:
        print("    ok    multi-block messages up to 7x rate")


def test_streaming(transport, labels):
    print("\n[3/3] Streaming properties (no CAVP vector covers these)")
    rnd = random.Random(7)

    # (a) incremental absorb: arbitrary chunking must not change the digest.
    bad = 0
    for fn, (_, rate, outlen, ref) in FUNCS.items():
        want_n = outlen or 64
        for n in (0, 1, rate - 1, rate, rate + 1, 2 * rate + 3):
            msg = bytes(rnd.randrange(256) for _ in range(n))
            expect = ref(msg, want_n)
            for _ in range(2):
                s = C64Sponge(transport, labels, fn)
                i = 0
                while i < n:
                    j = min(n, i + rnd.randrange(1, max(2, n - i + 1)))
                    s.absorb(msg[i:j])
                    i = j
                if n == 0:
                    s.absorb(b"")
                if s.squeeze(want_n) != expect:
                    bad += 1
    check(bad == 0, f"absorb split invariance: 4 funcs x 6 lengths x 2 chunkings, "
                    f"{bad} failures")
    if bad == 0:
        print("    ok    absorb split invariance")

    # (b) multi-call squeeze must continue the stream, not restart it.
    bad = 0
    for fn in ("shake128", "shake256"):
        rate = FUNCS[fn][1]
        ref = FUNCS[fn][3]
        for n in (0, 200):
            msg = bytes(rnd.randrange(256) for _ in range(n))
            total = 3 * rate + 17
            expect = ref(msg, total)
            for _ in range(2):
                s = C64Sponge(transport, labels, fn).absorb(msg)
                got, off = b"", 0
                while off < total:
                    k = min(total - off, rnd.randrange(1, 100))
                    got += s.squeeze(k, dst=OUT_BUF + off)
                    off += k
                if got != expect:
                    bad += 1
    check(bad == 0, f"squeeze continuation across calls, {bad} failures")
    if bad == 0:
        print("    ok    squeeze continuation across calls")


def main():
    full = "--full" in sys.argv
    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        r = subprocess.run(["make"], capture_output=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(r.stderr.decode()[-2000:])
            return 1

    labels = Labels.from_file(LABELS_PATH)
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["+reu"])

    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        if wait_for_text(transport, "C64-MLKEM P1 READY", timeout=60.0,
                         verbose=False) is None:
            print("FATAL: banner did not appear")
            mgr.release(inst)
            return 1
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        test_cavp(transport, labels, full)
        test_variable_out(transport, labels)
        test_streaming(transport, labels)
        mgr.release(inst)

    print(f"\n{_checks} checks in {time.time() - t0:.1f}s")
    if _fails:
        print(f"FAILED ({len(_fails)}):")
        for f in _fails:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
