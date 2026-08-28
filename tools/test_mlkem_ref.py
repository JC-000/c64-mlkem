#!/usr/bin/env python3
"""test_mlkem_ref.py — oracle self-test for tools/mlkem_ref.py.

Pure Python; no VICE, no emulator, runs in seconds. This is the FIRST link in
the P2 validation chain:

    NIST ACVP KATs + cryptography.hazmat  ->  mlkem_ref.py  ->  6502 assembly

If this file fails, the golden model is wrong and every downstream 6502
comparison is meaningless. It must stay green before any VICE test is trusted.

Covered:
  1. tables: the 128 zetas vs FIPS 203 Appendix A (transcribed), the basemul
     gammas, and the reduction constants
  2. NIST ACVP ML-KEM-768 keyGen: every (d, z) -> (ek, dk) vector
  3. NIST ACVP ML-KEM-768 encapDecap: encapsulation with m given, decapsulation
     including the modified-ciphertext (implicit rejection) cases, and both
     input-validation groups (encapsulationKeyCheck / decapsulationKeyCheck)
  4. cryptography.hazmat (independent, OpenSSL-backed): seeded keygen equality
     and bidirectional encaps/decaps interop over >= 100 random seeds
  5. internal identities: intt(ntt(f)) == f per layer, basemul vs schoolbook,
     compress/decompress bounds, byte_encode/decode round trip, CBD range,
     the c64 layout round trip, and the K-PKE round trip

The ACVP vectors are tracked in tools/vectors (see README.md there). If they
are missing, the ACVP categories SKIP LOUDLY and the run fails — a pin that
was never checked is not a pin.

Usage:  make test-ref     (or: <venv python> tools/test_mlkem_ref.py)
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mlkem_ref as M

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "vectors")

FULL = "--full" in sys.argv
HAZMAT_SEEDS = 300 if FULL else 100
RANDOM_POLYS = 200 if FULL else 40

_fails = []


def check(cond, label):
    if cond:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}")
        _fails.append(label)


def skip_loud(label):
    print(f"  SKIP  {label}")
    _fails.append("SKIPPED: " + label)


def hx(s):
    return bytes.fromhex(s)


# --- 1: tables ----------------------------------------------------------------

# FIPS 203 Appendix A, "Precomputed values for the NTT", transcribed. The
# model computes ZETAS from zeta = 17 and BitRev7; this pins that computation
# to the printed table so a wrong root or a wrong bit-reversal is caught here
# rather than by a wrong digest three layers up.
APPENDIX_A_ZETAS = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
]


def test_tables():
    print("\n[1/5] tables and constants")
    check(M.Q == 3329 and M.N == 256 and M.K == 3 and M.ETA1 == 2 and M.ETA2 == 2
          and M.DU == 10 and M.DV == 4, "ML-KEM-768 parameter set (Table 2)")
    check(M.EK_BYTES == 1184 and M.DK_BYTES == 2400 and M.CT_BYTES == 1088,
          "ek 1184 B, dk 2400 B, ct 1088 B (Table 3)")
    check(M.ZETAS == APPENDIX_A_ZETAS, "128 zetas match Appendix A")
    check(pow(17, 128, M.Q) == M.Q - 1 and pow(17, 256, M.Q) == 1,
          "zeta = 17 is a primitive 256th root of unity")
    # gamma_i = zeta^(2 BitRev7(i) + 1) — and the well-known pairing with the
    # top half of ZETAS that lets the 6502 reuse the zeta table for basemul.
    check(M.GAMMAS == [pow(17, 2 * M.bitrev7(i) + 1, M.Q) for i in range(128)]
          and all(M.GAMMAS[2 * i] == M.ZETAS[64 + i]
                  and M.GAMMAS[2 * i + 1] == M.Q - M.ZETAS[64 + i] for i in range(64)),
          "128 gammas; gamma[2i] = zetas[64+i], gamma[2i+1] = -zetas[64+i]")
    check((M.N_INV * 128) % M.Q == 1 and M.N_INV == 3303, "128^-1 mod q = 3303")


# --- 2 + 3: NIST ACVP ---------------------------------------------------------

def load_acvp(name):
    path = os.path.join(VEC, f"ML-KEM-768-{name}-FIPS203.json")
    if not os.path.exists(path):
        return None
    j = json.load(open(path))
    assert j["algorithm"] == "ML-KEM" and j["revision"] == "FIPS203"
    return j["testGroups"]


def test_acvp_keygen():
    print("\n[2/5] NIST ACVP ML-KEM-768 keyGen")
    groups = load_acvp("keyGen")
    if groups is None:
        skip_loud("tools/vectors/ML-KEM-768-keyGen-FIPS203.json missing — "
                  "run tools/fetch_vectors.sh (or make vectors)")
        return
    n, bad = 0, []
    for g in groups:
        assert g["parameterSet"] == "ML-KEM-768", g
        for t in g["tests"]:
            ek, dk = M.mlkem_keygen(hx(t["d"]), hx(t["z"]))
            n += 1
            if ek != hx(t["ek"]) or dk != hx(t["dk"]):
                bad.append(t["tcId"])
    check(n > 0 and not bad, f"{n} keyGen vectors (d, z) -> (ek, dk), {len(bad)} failures {bad}")


def test_acvp_encapdecap():
    print("\n[3/5] NIST ACVP ML-KEM-768 encapDecap")
    groups = load_acvp("encapDecap")
    if groups is None:
        skip_loud("tools/vectors/ML-KEM-768-encapDecap-FIPS203.json missing — "
                  "run tools/fetch_vectors.sh (or make vectors)")
        return
    by_fn = {}
    for g in groups:
        assert g["parameterSet"] == "ML-KEM-768", g
        by_fn.setdefault(g["function"], []).extend(g["tests"])

    # (a) encapsulation: m given, so K and c are fully determined.
    n, bad = 0, []
    for t in by_fn.get("encapsulation", []):
        k, c = M.mlkem_encaps(hx(t["ek"]), hx(t["m"]))
        n += 1
        if k != hx(t["k"]) or c != hx(t["c"]):
            bad.append(t["tcId"])
        # and the matching dk must decapsulate it to the same K
        if M.mlkem_decaps(hx(t["dk"]), c) != hx(t["k"]):
            bad.append(("decaps", t["tcId"]))
    check(n > 0 and not bad, f"{n} encapsulation vectors m -> (K, c) and decaps back, "
          f"{len(bad)} failures {bad}")

    # (b) decapsulation: valid ciphertexts and modified ones (implicit rejection).
    n_ok, n_rej, bad = 0, 0, []
    for t in by_fn.get("decapsulation", []):
        dk, c, want = hx(t["dk"]), hx(t["c"]), hx(t["k"])
        got = M.mlkem_decaps(dk, c)
        if got != want:
            bad.append(t["tcId"])
        # Classify independently of the reason string: does c re-encrypt?
        z = dk[768 * M.K + 64:]
        rejected = (got == M.J(z + c))
        if t["reason"] == "modified ciphertext":
            n_rej += 1
            if not rejected:
                bad.append(("expected implicit rejection", t["tcId"]))
        else:
            n_ok += 1
            if rejected:
                bad.append(("unexpected rejection", t["tcId"]))
    check(n_ok > 0 and n_rej > 0 and not bad,
          f"{n_ok} valid + {n_rej} modified-ciphertext decapsulation vectors "
          f"(K = J(z||c) on rejection), {len(bad)} failures {bad}")

    # (c) input validation. testPassed == false means the key must be REJECTED.
    n, bad = 0, []
    for t in by_fn.get("encapsulationKeyCheck", []):
        n += 1
        if M.ek_is_valid(hx(t["ek"])) != t["testPassed"]:
            bad.append(t["tcId"])
        if not t["testPassed"]:
            try:
                M.mlkem_encaps(hx(t["ek"]), bytes(32))
                bad.append(("no exception", t["tcId"]))
            except ValueError:
                pass
    check(n > 0 and not bad, f"{n} encapsulationKeyCheck vectors (§7.2 modulus check), "
          f"{len(bad)} failures {bad}")
    n, bad = 0, []
    for t in by_fn.get("decapsulationKeyCheck", []):
        n += 1
        if M.dk_is_valid(hx(t["dk"])) != t["testPassed"]:
            bad.append(t["tcId"])
        if not t["testPassed"]:
            try:
                M.mlkem_decaps(hx(t["dk"]), bytes(M.CT_BYTES))
                bad.append(("no exception", t["tcId"]))
            except ValueError:
                pass
    check(n > 0 and not bad, f"{n} decapsulationKeyCheck vectors (§7.3 hash check), "
          f"{len(bad)} failures {bad}")


# --- 4: cryptography.hazmat interop ----------------------------------------

def test_hazmat():
    print(f"\n[4/5] cryptography.hazmat interop ({HAZMAT_SEEDS} seeds"
          f"{'' if FULL else ' — pass --full for 300'})")
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric import mlkem
    except ImportError as e:
        skip_loud(f"cryptography.hazmat mlkem unavailable ({e}) — independent oracle NOT checked")
        return
    print(f"  (cryptography {cryptography.__version__})")
    rnd = random.Random(0x4D4C4B454D)   # fixed seed: a failure must reproduce
    bad_ek, bad_theirs, bad_ours = [], [], []
    for i in range(HAZMAT_SEEDS):
        d = bytes(rnd.randrange(256) for _ in range(32))
        z = bytes(rnd.randrange(256) for _ in range(32))
        ek, dk = M.mlkem_keygen(d, z)
        sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(d + z)   # seed is d || z
        if sk.public_key().public_bytes_raw() != ek:
            bad_ek.append(i)
            continue
        # their encapsulate -> our decaps
        ss, ct = sk.public_key().encapsulate()                 # (ss, ct) order
        if M.mlkem_decaps(dk, ct) != ss:
            bad_theirs.append(i)
        # our encaps -> their decapsulate, via a public key THEY parsed from our ek
        m = bytes(rnd.randrange(256) for _ in range(32))
        k, c = M.mlkem_encaps(ek, m)
        pk = mlkem.MLKEM768PublicKey.from_public_bytes(ek)
        if sk.decapsulate(c) != k or pk.public_bytes_raw() != ek:
            bad_ours.append(i)
    check(not bad_ek, f"{HAZMAT_SEEDS} seeded keygens: ek byte-identical to "
          f"MLKEM768PrivateKey.from_seed_bytes(d||z), {len(bad_ek)} failures {bad_ek[:5]}")
    check(not bad_theirs, f"{HAZMAT_SEEDS} hazmat encapsulate() ciphertexts decapsulated by "
          f"our mlkem_decaps, {len(bad_theirs)} failures {bad_theirs[:5]}")
    check(not bad_ours, f"{HAZMAT_SEEDS} of our ciphertexts decapsulated by hazmat, "
          f"{len(bad_ours)} failures {bad_ours[:5]}")

    # Implicit rejection agreement: flip one ciphertext byte, both sides must
    # derive the same (wrong) key — hazmat has no error path for this either.
    bad = 0
    for i in range(10):
        d = bytes(rnd.randrange(256) for _ in range(32))
        z = bytes(rnd.randrange(256) for _ in range(32))
        ek, dk = M.mlkem_keygen(d, z)
        sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(d + z)
        ss, ct = sk.public_key().encapsulate()
        ct2 = bytearray(ct)
        ct2[rnd.randrange(len(ct2))] ^= 1 << rnd.randrange(8)
        ct2 = bytes(ct2)
        ours, theirs = M.mlkem_decaps(dk, ct2), sk.decapsulate(ct2)
        if ours != theirs or ours == ss or ours != M.J(z + ct2):
            bad += 1
    check(bad == 0, f"10 bit-flipped ciphertexts: implicit-rejection key agrees with hazmat, "
          f"{bad} failures")


# --- 5: internal identities ---------------------------------------------------

def rand_poly(rnd):
    return [rnd.randrange(M.Q) for _ in range(M.N)]


def edge_polys():
    polys = [[0] * M.N, [M.Q - 1] * M.N, [1] * M.N]
    for i in (0, 1, 127, 128, 255):
        p = [0] * M.N
        p[i] = 1
        polys.append(p)
        p = [0] * M.N
        p[i] = M.Q - 1
        polys.append(p)
    return polys


def test_identities():
    print(f"\n[5/5] internal identities ({RANDOM_POLYS} random polys + edge cases)")
    rnd = random.Random(203)
    polys = edge_polys() + [rand_poly(rnd) for _ in range(RANDOM_POLYS)]

    # (a) NTT / INTT, as a whole and layer by layer.
    bad_rt, bad_layers, bad_range = 0, 0, 0
    for f in polys:
        fh = M.ntt(f)
        if M.intt(fh) != f:
            bad_rt += 1
        layers = M.ntt_layers(f)
        if layers[-1] != fh:
            bad_layers += 1
        inv = M.intt_layers(fh)
        # Undoing NTT layer l gives TWICE the state before layer l (GS
        # butterfly with the reversed zeta index, see intt_layer); the seven
        # doublings are what the final 128^-1 removes.
        prev = [f] + layers[:-1]
        for l in range(M.NTT_LAYERS):
            if M.intt_layer(layers[l], l) != [(2 * x) % M.Q for x in prev[l]]:
                bad_layers += 1
            if inv[6 - l] != [((1 << (7 - l)) * x) % M.Q for x in prev[l]]:
                bad_layers += 1
        if inv[-1] != f or M.intt_scale(inv[-2]) != f:
            bad_layers += 1
        if any(not 0 <= x < M.Q for x in fh + M.intt(fh)):
            bad_range += 1
    check(bad_rt == 0, f"intt(ntt(f)) == f for {len(polys)} polys, {bad_rt} failures")
    check(bad_layers == 0, f"per-layer: ntt_layers / intt_layer undo each of 7 layers, "
          f"{bad_layers} failures")
    check(bad_range == 0, f"all NTT/INTT outputs in [0, q), {bad_range} failures")

    # (b) basemul against the negacyclic schoolbook product.
    bad = 0
    pairs = [(polys[i], polys[j]) for i in range(0, len(polys), 3)
             for j in range(1, len(polys), 7)][:60]
    for a, b in pairs:
        if M.intt(M.basemul(M.ntt(a), M.ntt(b))) != M.poly_mul_schoolbook(a, b):
            bad += 1
    check(bad == 0, f"intt(basemul(ntt(a), ntt(b))) == schoolbook a*b mod X^256+1 "
          f"for {len(pairs)} pairs, {bad} failures")

    # (c) compress / decompress: round trip on the compressed side is exact,
    # and decompress(compress(x)) is within the FIPS 203 §4.2.1 bound
    # |x' - x| mod±q <= round(q / 2^(d+1)).
    bad_rt, bad_bound = 0, 0
    for d in (1, 4, 5, 10, 11):
        for y in range(1 << d):
            if M.compress(d, M.decompress(d, y)) != y:
                bad_rt += 1
        bound = (M.Q + (1 << d)) // (1 << (d + 1))   # round(q / 2^(d+1))
        for x in range(M.Q):
            x2 = M.decompress(d, M.compress(d, x))
            diff = (x2 - x) % M.Q
            if min(diff, M.Q - diff) > bound:
                bad_bound += 1
            if not 0 <= M.compress(d, x) < (1 << d):
                bad_bound += 1
    check(bad_rt == 0, "compress(decompress(y)) == y for d in {1,4,5,10,11}, "
          f"{bad_rt} failures")
    check(bad_bound == 0, "decompress(compress(x)) within round(q/2^(d+1)) for all x, "
          f"{bad_bound} failures")

    # (d) byte_encode / byte_decode round trip for every d in use.
    bad = 0
    for d in (1, 4, 10, 12):
        m = M.Q if d == 12 else 1 << d
        for _ in range(10):
            f = [rnd.randrange(m) for _ in range(M.N)]
            b = M.byte_encode(d, f)
            if len(b) != 32 * d or M.byte_decode(d, b) != f:
                bad += 1
        f = [m - 1] * M.N
        if M.byte_decode(d, M.byte_encode(d, f)) != f:
            bad += 1
    check(bad == 0, f"byte_decode(byte_encode(f)) == f for d in {{1,4,10,12}}, {bad} failures")
    # d = 12 decode reduces mod q (Alg. 6) — ek_is_valid is what catches it.
    b = M.byte_encode(12, [0] * M.N)
    b = bytes([0xFF, 0x0F]) + b[2:]              # coefficient 0 = 4095 = q + 766
    check(M.byte_decode(12, b)[0] == 766 and not M.ek_is_valid(b + bytes(M.EK_BYTES - len(b))),
          "byte_decode(12) reduces a field >= q mod q; ek_is_valid rejects it")

    # (e) CBD output range and bit consumption.
    bad = 0
    for eta in (2, 3):
        for _ in range(20):
            f = M.sample_cbd(eta, bytes(rnd.randrange(256) for _ in range(64 * eta)))
            if any(not (x <= eta or x >= M.Q - eta) for x in f):
                bad += 1
    check(bad == 0, f"sample_cbd coefficients in [-eta, eta] mod q, {bad} failures")

    # (f) SampleNTT: every coefficient < q; the expected stream is ~472 B, and
    # needing a 4th 168-byte block is a ~1% event per seed. rho = 7 (32-byte
    # little-endian), (i, j) = (0, 0) needs 516 B — WP2's "> 3 squeeze blocks"
    # seed. Pin that, and that a search agrees it is the first such rho.
    bad = 0
    for i in range(3):
        for j in range(3):
            if any(not 0 <= x < M.Q for x in M.sample_ntt(bytes(range(32)), i, j)):
                bad += 1
    long_rho = (7).to_bytes(32, "little")
    used = M.sample_ntt_bytes_consumed(long_rho, 0, 0)
    first = next((n for n in range(64)
                  if M.sample_ntt_bytes_consumed(n.to_bytes(32, "little"), 0, 0) > 504), None)
    check(bad == 0 and used == 516 and first == 7,
          f"sample_ntt: outputs in [0, q); rho=07 00..00 (i,j)=(0,0) consumes {used} B "
          f"(> 3 x 168), first such rho in 0..63 is {first}")

    # (g) c64 layout round trip, including a deliberately unreduced value.
    f = rand_poly(rnd)
    b = M.poly_to_c64(f)
    check(len(b) == 512 and b[:256] == bytes(x & 0xFF for x in f)
          and M.poly_from_c64(b) == f
          and M.poly_from_c64(bytes([0x01]) + bytes(255) + bytes([0x0D]) + bytes(255))[0] == 0x0D01,
          "poly_to_c64 / poly_from_c64: split-plane 256 lo + 256 hi, unreduced passes through")

    # (h) K-PKE round trip, and ML-KEM decaps of a tampered ct != K.
    bad = 0
    for _ in range(5):
        d = bytes(rnd.randrange(256) for _ in range(32))
        ek, dk = M.kpke_keygen(d)
        m = bytes(rnd.randrange(256) for _ in range(32))
        r = bytes(rnd.randrange(256) for _ in range(32))
        if M.kpke_decrypt(dk, M.kpke_encrypt(ek, m, r)) != m:
            bad += 1
    check(bad == 0, f"K-PKE decrypt(encrypt(m)) == m for 5 keys, {bad} failures")


def main():
    print("c64-mlkem oracle self-test — tools/mlkem_ref.py")
    test_tables()
    test_acvp_keygen()
    test_acvp_encapdecap()
    test_hazmat()
    test_identities()
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
