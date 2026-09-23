#!/usr/bin/env python3
"""rig_kat.py — Known-answer tests for c64-mlkem on Ultimate 64 Elite hardware.

Runs the vetted SHA-3 and ML-KEM suites from tools/test_sha3.py and
tools/test_mlkem.py against real device output via the dispatcher rig.
Requires U64_HOST to be set and a connected U64E. Not part of `make test`.

Default depth (~5 min at 1 MHz): the test_sha3 ShortMsg subset (rate
boundaries + sample) and a VariableOut sample, 2 keyGen, 2 encaps (one on odd
addresses), 1 valid + 1 modified-ciphertext decaps, 1 rejected + 1 valid ek
check. --full: all 820 ShortMsg vectors, 25 keyGen, 25 encaps, 10 decaps,
10 ek checks. The streaming-property tests of test_sha3 are VICE-only (too
many round trips).

Usage:
    U64_HOST=10.43.23.81 python3 tools/rig_kat.py [--full] [--mhz N]
        [--only sha3,keygen,encaps,decaps,ekcheck]
Honors C64_SKIP_BUILD=1 and MLKEM_BUILD_DIR (see rig_common.py).
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_sha3 as S
import test_mlkem as T
from rig_common import build_if_needed, load_labels, Rig, RigError
from c64_test_harness import write_bytes, read_bytes

KEM_TIMEOUT = 300.0
RIG = None


class RigSponge(S.C64Sponge):
    """S.C64Sponge with each jsr() replaced by a dispatcher call; _set_len
    and the buffers are inherited unchanged."""

    def __init__(self, transport, labels, fn):
        self.t, self.l = transport, labels
        self.init_label = S.FUNCS[fn][0]
        RIG.call(self.init_label, timeout=30.0, cadence=0.02)

    def absorb(self, data):
        if data:
            write_bytes(self.t, S.MSG_BUF, data)
        write_bytes(self.t, self.l["mlkem_zp_src"],
                    bytes([S.MSG_BUF & 0xFF, S.MSG_BUF >> 8]))
        self._set_len(len(data))
        RIG.call("mlkem_absorb", timeout=30.0, cadence=0.02)
        return self

    def squeeze(self, n, dst=S.OUT_BUF):
        write_bytes(self.t, self.l["mlkem_zp_dst"],
                    bytes([dst & 0xFF, (dst >> 8) & 0xFF]))
        self._set_len(n)
        RIG.call("mlkem_squeeze", timeout=30.0, cadence=0.02)
        return read_bytes(self.t, dst, n) if n else b""


class RigC64(T.C64):
    def __init__(self, rig):
        super().__init__(rig.t, rig.l)
        self.rig = rig

    def call(self, label):
        a = self.rig.call(label, timeout=KEM_TIMEOUT, cadence=0.25)
        status = read_bytes(self.t, self.l["mlkem_status"], 1)[0]
        return (a, status)


def main():
    full = "--full" in sys.argv
    mhz = 1
    only = None
    args = sys.argv[1:]

    if "--mhz" in args:
        idx = args.index("--mhz")
        if idx + 1 < len(args):
            mhz = int(args[idx+1])
        else:
            print("Missing value for --mhz", file=sys.stderr)
            return 1

    if "--only" in args:
        idx = args.index("--only")
        if idx + 1 < len(args):
            only = args[idx+1].split(",")
        else:
            print("Missing value for --only", file=sys.stderr)
            return 1

    valid_only = {"sha3", "keygen", "encaps", "decaps", "ekcheck"}
    if only is not None:
        for name in only:
            if name not in valid_only:
                print(f"Unknown suite: {name}", file=sys.stderr)
                return 2
    if only is None:
        only = list(valid_only)

    if not T.self_check_model():
        print("FATAL: self_check_model failed")
        return 1

    build_if_needed()

    SCRATCH_LO = 0x5000
    SCRATCH_HI = 0x8000
    labels = load_labels(SCRATCH_LO, SCRATCH_HI)

    for name in T.REQUIRED_LABELS:
        if name.startswith("mlkem_kpke_"):
            continue
        if labels.address(name) is None:
            print(f"FATAL: missing required label {name}")
            return 1

    global RIG
    try:
        with Rig(labels, mhz=mhz) as rig:
            RIG = rig
            S.C64Sponge = RigSponge

            if "sha3" in only:
                t0 = time.time()
                pre_sha3 = S._checks
                S.test_cavp(rig.t, rig.l, full)
                S.test_variable_out(rig.t, rig.l)
                sha3_checks = S._checks - pre_sha3
                print(f"[sha3] {sha3_checks} checks in {time.time()-t0:.1f}s")
                if sha3_checks == 0:
                    S._fails.append("sha3 suite added zero checks")

            if "keygen" in only:
                c64 = RigC64(rig)
                t0 = time.time()
                pre_kg = T._checks
                T.suite_keygen(c64, full)
                kg_checks = T._checks - pre_kg
                print(f"[keygen] {kg_checks} checks in {time.time()-t0:.1f}s")
                if kg_checks == 0:
                    T._fails.append("keygen suite added zero checks")

            if "encaps" in only:
                c64 = RigC64(rig)
                t0 = time.time()
                pre_enc = T._checks
                T.suite_encaps(c64, full)
                enc_checks = T._checks - pre_enc
                print(f"[encaps] {enc_checks} checks in {time.time()-t0:.1f}s")
                if enc_checks == 0:
                    T._fails.append("encaps suite added zero checks")

            if "decaps" in only:
                c64 = RigC64(rig)
                t0 = time.time()
                pre_dec = T._checks
                T.suite_decaps(c64, full)
                dec_checks = T._checks - pre_dec
                print(f"[decaps] {dec_checks} checks in {time.time()-t0:.1f}s")
                if dec_checks == 0:
                    T._fails.append("decaps suite added zero checks")

            if "ekcheck" in only:
                c64 = RigC64(rig)
                t0 = time.time()
                pre_ek = T._checks
                T.suite_ekcheck(c64, full)
                ek_checks = T._checks - pre_ek
                print(f"[ekcheck] {ek_checks} checks in {time.time()-t0:.1f}s")
                if ek_checks == 0:
                    T._fails.append("ekcheck suite added zero checks")

    except RigError as e:
        print(f"RigError: {e}")
        return 1

    total_fails = S._fails + T._fails
    total_checks = S._checks + T._checks

    print(f"\nSummary: {total_checks} checks, {len(total_fails)} failures ({mhz} MHz)")
    if total_fails:
        print("FAILURES:")
        for f in total_fails:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
