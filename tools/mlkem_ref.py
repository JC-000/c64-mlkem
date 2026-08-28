"""mlkem_ref.py — ML-KEM-768 (FIPS 203) golden model with every internal step
individually callable, mirroring the decomposition the 6502 code will use.

Pure Python: stdlib + hashlib only. Polynomials are list[int] of 256
coefficients in [0, q); polyvecs are list[poly] of length k. Bytes in, bytes
out at the FIPS boundaries. Nothing here is constant-time or fast — it is the
white-box oracle that tools/test_mlkem_ref.py pins to the NIST ACVP vectors
and to cryptography.hazmat, and which the VICE harnesses then compare the
assembly against, step by step.

Algorithm numbers below refer to FIPS 203 (final, August 2024). Two places
where ML-KEM differs from Kyber round 3 and a transcription from older code
would silently produce a wrong-but-self-consistent implementation:

  * K-PKE.KeyGen hashes G(d || k), not G(d)         (Alg. 13 line 1)
  * SampleNTT is seeded with rho || j || i for A[i][j] (Alg. 13 line 6):
    the COLUMN index byte comes first.

The 6502 in-memory polynomial layout lives in poly_to_c64 / poly_from_c64 and
nowhere else; see their docstring.
"""

import hashlib

# --- parameters (FIPS 203 Table 2, ML-KEM-768) ------------------------------

Q = 3329
N = 256
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

EK_BYTES = 384 * K + 32          # 1184
DK_BYTES = 768 * K + 96          # 2400
CT_BYTES = 32 * (DU * K + DV)    # 1088

ZETA = 17                        # primitive 256th root of unity mod q
N_INV = pow(128, -1, Q)          # 3303: the scaling at the end of INTT
                                 # (128 = n/2 — the NTT has 7 layers, Alg. 10)


def bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


# ZETAS[i] = zeta^BitRev7(i) mod q — Appendix A's table, in the order the NTT
# consumes it: layer l (len = 128 >> l) uses ZETAS[2^l .. 2^(l+1)-1], in order.
ZETAS = [pow(ZETA, bitrev7(i), Q) for i in range(128)]

# Basemul twiddles: gamma_i = zeta^(2*BitRev7(i)+1) (Alg. 11, line 4).
GAMMAS = [pow(ZETA, 2 * bitrev7(i) + 1, Q) for i in range(128)]


# --- hashes (FIPS 203 §4.1) ---------------------------------------------------

def G(x):
    """SHA3-512 -> (a, b), two 32-byte halves."""
    h = hashlib.sha3_512(x).digest()
    return h[:32], h[32:]


def H(x):
    return hashlib.sha3_256(x).digest()


def J(x):
    return hashlib.shake_256(x).digest(32)


def prf(eta, s, b):
    """PRF_eta(s, b) = SHAKE256(s || B(b), 64*eta) — s is 32 bytes, b one byte."""
    assert len(s) == 32 and 0 <= b < 256
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def xof(rho, i, j):
    """The SHAKE128 stream for A[i][j]: seed is rho || B(j) || B(i) (Alg. 13
    line 6 and Alg. 14 line 5 — j first). Returns a hashlib object; call
    .digest(n) for the first n bytes."""
    assert len(rho) == 32
    return hashlib.shake_128(rho + bytes([j, i]))


# --- polynomial arithmetic ------------------------------------------------

def poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def poly_sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def polyvec_add(a, b):
    return [poly_add(x, y) for x, y in zip(a, b)]


def polyvec_sub(a, b):
    return [poly_sub(x, y) for x, y in zip(a, b)]


def poly_mul_schoolbook(a, b):
    """Negacyclic schoolbook product a*b mod (X^256 + 1) in the ORDINARY
    domain. The independent check on basemul: intt(basemul(ntt(a), ntt(b)))
    must equal this."""
    c = [0] * N
    for i, x in enumerate(a):
        if not x:
            continue
        for j, y in enumerate(b):
            k = i + j
            if k < N:
                c[k] += x * y
            else:
                c[k - N] -= x * y
    return [v % Q for v in c]


# --- NTT (Alg. 9), INTT (Alg. 10), per-layer helpers ------------------------
#
# Layer numbering: layer 0 is the first NTT layer (len = 128), layer 6 the
# last (len = 2). The INTT walks them back in the opposite order, so
# intt_layer(f, 6) undoes ntt_layer(f, 6) — the per-layer harness on the 6502
# compares against ntt_layers()[l] / intt_layers()[l] to name the failing one.

NTT_LAYERS = 7


def ntt_layer(f, layer):
    """Apply NTT layer `layer` (0..6) to f, returning a new list. Zetas are
    consumed from ZETAS[2^layer ..] in order, one per butterfly block."""
    assert 0 <= layer < NTT_LAYERS
    f = list(f)
    length = 128 >> layer
    i = 1 << layer
    for start in range(0, N, 2 * length):
        zeta = ZETAS[i]
        i += 1
        for j in range(start, start + length):
            t = (zeta * f[j + length]) % Q
            f[j + length] = (f[j] - t) % Q
            f[j] = (f[j] + t) % Q
    return f


def intt_layer(f_hat, layer):
    """Apply the inverse of NTT layer `layer`, WITHOUT the final 1/128 scaling
    (that is intt_scale, applied once after layer 0 is undone).

    Per-layer harness note: this is Alg. 10's Gentleman-Sande butterfly with
    Alg. 10's zeta indexing (i counting DOWN from 2^(layer+1)-1), which within
    a layer is the NTT's index order reversed, and ZETAS[2^(l+1)-1-b] ==
    -ZETAS[2^l+b]^-1. So each inverse layer returns TWICE the state the NTT
    had before that layer: intt_layer(ntt_layer(f, l), l) == 2*f mod q. The
    seven doublings are exactly what intt_scale's 128^-1 removes. Compare a
    6502 layer against 2 * ntt_layers(f)[l-1], not ntt_layers(f)[l-1]."""
    assert 0 <= layer < NTT_LAYERS
    f = list(f_hat)
    length = 128 >> layer
    i = (1 << (layer + 1)) - 1
    for start in range(0, N, 2 * length):
        zeta = ZETAS[i]
        i -= 1
        for j in range(start, start + length):
            t = f[j]
            f[j] = (t + f[j + length]) % Q
            f[j + length] = (zeta * (f[j + length] - t)) % Q
    return f


def intt_scale(f):
    return [(x * N_INV) % Q for x in f]


def ntt_layers(f):
    """States after each NTT layer: list of 7 polys; [6] == ntt(f)."""
    out = []
    for l in range(NTT_LAYERS):
        f = ntt_layer(f, l)
        out.append(f)
    return out


def intt_layers(f_hat):
    """States after undoing layers 6, 5, ..., 0, then after scaling: list of 8
    polys, indexed by step; [7] == intt(f_hat). Step s (0..6) carries a factor
    2^(s+1) relative to ntt_layers(f)[5-s] (see intt_layer)."""
    out = []
    f = f_hat
    for l in reversed(range(NTT_LAYERS)):
        f = intt_layer(f, l)
        out.append(f)
    out.append(intt_scale(f))
    return out


def ntt(f):
    assert len(f) == N
    for l in range(NTT_LAYERS):
        f = ntt_layer(f, l)
    return f


def intt(f_hat):
    assert len(f_hat) == N
    f = f_hat
    for l in reversed(range(NTT_LAYERS)):
        f = intt_layer(f, l)
    return intt_scale(f)


def basecase_multiply(a0, a1, b0, b1, gamma):
    """Alg. 12: product in Z_q[X]/(X^2 - gamma)."""
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def basemul(a_hat, b_hat):
    """Alg. 11 MultiplyNTTs: pointwise in the NTT domain."""
    c = [0] * N
    for i in range(128):
        c[2 * i], c[2 * i + 1] = basecase_multiply(
            a_hat[2 * i], a_hat[2 * i + 1], b_hat[2 * i], b_hat[2 * i + 1], GAMMAS[i])
    return c


def polyvec_ntt(v):
    return [ntt(f) for f in v]


def polyvec_intt(v):
    return [intt(f) for f in v]


def polyvec_basemul_acc(a_hat, b_hat):
    """Inner product of two polyvecs in the NTT domain: sum_i a[i] o b[i]."""
    acc = [0] * N
    for f, g in zip(a_hat, b_hat):
        acc = poly_add(acc, basemul(f, g))
    return acc


# --- sampling (Alg. 7, Alg. 8) ---------------------------------------------

def sample_ntt_stream(stream):
    """Alg. 7 rejection sampling over an XOF object exposing .digest(n) for the
    first n bytes. Exposed separately so a test can drive a chosen stream."""
    a = []
    # Pull the stream in 3-byte units; hashlib SHAKE has no incremental
    # squeeze, so grow the requested prefix as needed. 168-byte blocks keep
    # the requests aligned with what the 6502 sponge squeezes.
    buf, pos, want = b"", 0, 168 * 3
    while len(a) < N:
        if pos + 3 > len(buf):
            buf = stream.digest(want)
            want += 168
        c0, c1, c2 = buf[pos], buf[pos + 1], buf[pos + 2]
        pos += 3
        d1 = c0 + 256 * (c1 & 0x0F)
        d2 = (c1 >> 4) + 16 * c2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
    return a


def sample_ntt(rho, i, j):
    """A_hat[i][j] = SampleNTT(rho || B(j) || B(i)) — row i, column j."""
    return sample_ntt_stream(xof(rho, i, j))


def sample_ntt_bytes_consumed(rho, i, j):
    """How many XOF bytes Alg. 7 consumes for this seed — lets a test pick a
    seed whose stream needs more than 3 squeeze blocks (> 504 B)."""
    stream = xof(rho, i, j)
    n, got, buf = 0, 0, b""
    while got < N:
        if n + 3 > len(buf):
            buf = stream.digest(len(buf) + 168)
        c0, c1, c2 = buf[n], buf[n + 1], buf[n + 2]
        n += 3
        if c0 + 256 * (c1 & 0x0F) < Q:
            got += 1
        if (c1 >> 4) + 16 * c2 < Q and got < N:
            got += 1
    return n


def bytes_to_bits(b):
    """Alg. 3: little-endian bit order within each byte."""
    return [(byte >> k) & 1 for byte in b for k in range(8)]


def bits_to_bytes(bits):
    """Alg. 4."""
    assert len(bits) % 8 == 0
    out = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        out[i >> 3] |= bit << (i & 7)
    return bytes(out)


def sample_cbd(eta, b):
    """Alg. 8 SamplePolyCBD_eta: b is 64*eta bytes."""
    assert len(b) == 64 * eta
    bits = bytes_to_bits(b)
    f = []
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f


# --- codecs (Alg. 5, Alg. 6, §4.2.1) ----------------------------------------

def byte_encode(d, f):
    """Alg. 5: 256 d-bit integers -> 32*d bytes. d = 12 encodes mod q."""
    m = Q if d == 12 else 1 << d
    bits = []
    for a in f:
        assert 0 <= a < m, (d, a)
        for _ in range(d):
            bits.append(a & 1)
            a >>= 1
    return bits_to_bytes(bits)


def byte_decode(d, b):
    """Alg. 6: 32*d bytes -> 256 integers, each reduced mod m (m = q for
    d = 12, 2^d otherwise). Note the reduction: an out-of-range 12-bit field
    is silently taken mod q here, exactly as the standard specifies; the ek
    modulus check in mlkem_encaps is what rejects such inputs."""
    assert len(b) == 32 * d, (d, len(b))
    m = Q if d == 12 else 1 << d
    bits = bytes_to_bits(b)
    return [sum(bits[i * d + j] << j for j in range(d)) % m for i in range(N)]


def compress(d, x):
    """Compress_d(x) = round(2^d / q * x) mod 2^d, round-half-up."""
    return (((x << d) + (Q >> 1)) // Q) & ((1 << d) - 1)


def decompress(d, y):
    """Decompress_d(y) = round(q / 2^d * y), round-half-up."""
    return ((Q * y) + (1 << (d - 1))) >> d


def poly_compress(d, f):
    return [compress(d, x) for x in f]


def poly_decompress(d, f):
    return [decompress(d, y) for y in f]


def polyvec_compress(d, v):
    return [poly_compress(d, f) for f in v]


def polyvec_decompress(d, v):
    return [poly_decompress(d, f) for f in v]


def polyvec_encode(d, v):
    return b"".join(byte_encode(d, f) for f in v)


def polyvec_decode(d, b):
    return [byte_decode(d, b[32 * d * i:32 * d * (i + 1)]) for i in range(K)]


# --- K-PKE (Alg. 13, 14, 15) --------------------------------------------------

def gen_matrix(rho):
    """A_hat[i][j] for i, j in [0, k) — the model may hold the matrix; the
    6502 must not (4.5 KB) and generates each entry on demand."""
    return [[sample_ntt(rho, i, j) for j in range(K)] for i in range(K)]


def kpke_keygen(d):
    """Alg. 13. d is 32 bytes. Returns (ek_pke, dk_pke): 1184 B and 1152 B."""
    assert len(d) == 32
    rho, sigma = G(d + bytes([K]))            # G(d || k) — ML-KEM, not Kyber
    a_hat = gen_matrix(rho)
    n = 0
    s, e = [], []
    for _ in range(K):
        s.append(sample_cbd(ETA1, prf(ETA1, sigma, n)))
        n += 1
    for _ in range(K):
        e.append(sample_cbd(ETA1, prf(ETA1, sigma, n)))
        n += 1
    s_hat = polyvec_ntt(s)
    e_hat = polyvec_ntt(e)
    t_hat = [poly_add(polyvec_basemul_acc(a_hat[i], s_hat), e_hat[i]) for i in range(K)]
    ek = polyvec_encode(12, t_hat) + rho
    dk = polyvec_encode(12, s_hat)
    return ek, dk


def kpke_encrypt(ek_pke, m, r):
    """Alg. 14. m and r are 32 bytes. Returns the 1088-byte ciphertext."""
    assert len(ek_pke) == EK_BYTES and len(m) == 32 and len(r) == 32
    n = 0
    t_hat = polyvec_decode(12, ek_pke[:384 * K])
    rho = ek_pke[384 * K:]
    a_hat = gen_matrix(rho)
    y, e1 = [], []
    for _ in range(K):
        y.append(sample_cbd(ETA1, prf(ETA1, r, n)))
        n += 1
    for _ in range(K):
        e1.append(sample_cbd(ETA2, prf(ETA2, r, n)))
        n += 1
    e2 = sample_cbd(ETA2, prf(ETA2, r, n))
    y_hat = polyvec_ntt(y)
    # u = INTT(A_hat^T o y_hat) + e1: row i of A^T is column i of A.
    u = [poly_add(intt(polyvec_basemul_acc([a_hat[j][i] for j in range(K)], y_hat)), e1[i])
         for i in range(K)]
    mu = poly_decompress(1, byte_decode(1, m))
    v = poly_add(poly_add(intt(polyvec_basemul_acc(t_hat, y_hat)), e2), mu)
    c1 = polyvec_encode(DU, polyvec_compress(DU, u))
    c2 = byte_encode(DV, poly_compress(DV, v))
    return c1 + c2


def kpke_decrypt(dk_pke, c):
    """Alg. 15. Returns the 32-byte message."""
    assert len(dk_pke) == 384 * K and len(c) == CT_BYTES
    c1, c2 = c[:32 * DU * K], c[32 * DU * K:]
    u = polyvec_decompress(DU, polyvec_decode(DU, c1))
    v = poly_decompress(DV, byte_decode(DV, c2))
    s_hat = polyvec_decode(12, dk_pke)
    w = poly_sub(v, intt(polyvec_basemul_acc(s_hat, polyvec_ntt(u))))
    return byte_encode(1, poly_compress(1, w))


# --- ML-KEM (Alg. 16, 17, 18; input checks §7.1-§7.3) ------------------------

def mlkem_keygen(d, z):
    """Alg. 16 ML-KEM.KeyGen_internal. Returns (ek, dk): 1184 B, 2400 B."""
    assert len(d) == 32 and len(z) == 32
    ek, dk_pke = kpke_keygen(d)
    dk = dk_pke + ek + H(ek) + z
    return ek, dk


def ek_is_valid(ek):
    """§7.2 encapsulation-key check: length, and every 12-bit field of t_hat
    already reduced mod q (re-encoding the decoded key reproduces it)."""
    if len(ek) != EK_BYTES:
        return False
    t = ek[:384 * K]
    return polyvec_encode(12, polyvec_decode(12, t)) == t


def dk_is_valid(dk):
    """§7.3 decapsulation-key check: length, and the stored H(ek) matches."""
    if len(dk) != DK_BYTES:
        return False
    ek = dk[384 * K:768 * K + 32]
    return H(ek) == dk[768 * K + 32:768 * K + 64]


def mlkem_encaps(ek, m):
    """Alg. 17 ML-KEM.Encaps_internal with the §7.2 input check. m is the
    32-byte randomness. Returns (K, c). Raises ValueError on an invalid ek —
    the standard says "return an error", so an exception, not a value."""
    if not ek_is_valid(ek):
        raise ValueError("ML-KEM-768 encapsulation key failed the §7.2 check")
    assert len(m) == 32
    k, r = G(m + H(ek))
    c = kpke_encrypt(ek, m, r)
    return k, c


def mlkem_decaps(dk, c):
    """Alg. 18 ML-KEM.Decaps_internal with the §7.3 input checks. Returns K;
    on a ciphertext that does not re-encrypt this is the implicit-rejection
    key J(z || c), silently. Raises ValueError on a malformed dk or a
    wrong-length c."""
    if len(c) != CT_BYTES:
        raise ValueError("ML-KEM-768 ciphertext has the wrong length")
    if not dk_is_valid(dk):
        raise ValueError("ML-KEM-768 decapsulation key failed the §7.3 check")
    dk_pke = dk[:384 * K]
    ek_pke = dk[384 * K:768 * K + 32]
    h = dk[768 * K + 32:768 * K + 64]
    z = dk[768 * K + 64:768 * K + 96]
    m_prime = kpke_decrypt(dk_pke, c)
    k_prime, r_prime = G(m_prime + h)
    k_bar = J(z + c)
    c_prime = kpke_encrypt(ek_pke, m_prime, r_prime)
    if c != c_prime:            # the 6502 does this as a full-length OR-accumulate
        return k_bar
    return k_prime


# --- 6502 memory layout -----------------------------------------------------

def poly_to_c64(f):
    """The in-memory polynomial layout the 6502 code uses: 512 bytes.

    TENTATIVE — split-plane, per the P2 brief's recommendation: 256 low bytes
    (coefficient i at offset i) followed by 256 high bytes (coefficient i's
    bits 8..11 at offset 256 + i), each plane page-aligned in BSS, so a
    coefficient is `lda lo,x` / `lda hi,x` with one index register and no
    doubling. Coefficients are the canonical representatives in [0, q).

    The NTT implementer (WP1) owns this choice and declares it once in
    src/mlkem.inc; if it changes, change it HERE and nowhere else — this
    function and poly_from_c64 are the only place the harness converts."""
    assert len(f) == N and all(0 <= x < Q for x in f)
    return bytes(x & 0xFF for x in f) + bytes(x >> 8 for x in f)


def poly_from_c64(b):
    """Inverse of poly_to_c64. Does NOT reduce: a coefficient >= q comes back
    as-is so a missing final reduction on the 6502 is visible to the test."""
    assert len(b) == 2 * N
    return [b[i] | (b[N + i] << 8) for i in range(N)]


def polyvec_to_c64(v):
    return b"".join(poly_to_c64(f) for f in v)


def polyvec_from_c64(b):
    assert len(b) == 2 * N * K
    return [poly_from_c64(b[2 * N * i:2 * N * (i + 1)]) for i in range(K)]
