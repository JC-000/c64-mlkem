"""Reference Keccak-f[1600] with per-step checkpoints, mirroring the
decomposition the 6502 code will use. Lane i = x + 5y, little-endian."""
M = (1 << 64) - 1

def rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & M if n else v

RHO = [0]*25
def _mk_rho():
    x, y = 1, 0
    for t in range(24):
        RHO[x + 5*y] = ((t+1)*(t+2)//2) % 64
        x, y = y, (2*x + 3*y) % 5
_mk_rho()

def _mk_rc():
    rc, lfsr = [], 1
    for _ in range(24):
        w = 0
        for j in range(7):
            if lfsr & 1:
                w ^= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ 0x71) & 0xFF if lfsr & 0x80 else (lfsr << 1) & 0xFF
        rc.append(w)
    return rc
RC = _mk_rc()

def theta(A):
    C = [A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20] for x in range(5)]
    D = [C[(x-1) % 5] ^ rol(C[(x+1) % 5], 1) for x in range(5)]
    return [A[x + 5*y] ^ D[x] for y in range(5) for x in range(5)]

def rho(A):
    return [rol(A[i], RHO[i]) for i in range(25)]

def pi(A):
    B = [0]*25
    for y in range(5):
        for x in range(5):
            B[y + 5*((2*x + 3*y) % 5)] = A[x + 5*y]
    return B

def rhopi(A):                      # the fused step the 6502 will implement
    return pi(rho(A))

def chi(A):
    B = list(A)
    for y in range(5):
        for x in range(5):
            B[x + 5*y] = A[x + 5*y] ^ ((~A[(x+1) % 5 + 5*y]) & A[(x+2) % 5 + 5*y] & M)
    return B

def iota(A, r):
    B = list(A); B[0] ^= RC[r]; return B

def permute(A, trace=None):
    for r in range(24):
        A = theta(A)
        if trace is not None: trace.append(("theta", r, list(A)))
        A = rho(A)
        if trace is not None: trace.append(("rho", r, list(A)))
        A = pi(A)
        if trace is not None: trace.append(("pi", r, list(A)))
        A = chi(A)
        if trace is not None: trace.append(("chi", r, list(A)))
        A = iota(A, r)
        if trace is not None: trace.append(("iota", r, list(A)))
    return A

def to_bytes(A):  return b"".join(l.to_bytes(8, "little") for l in A)
def from_bytes(b): return [int.from_bytes(b[8*i:8*i+8], "little") for i in range(25)]

def sponge(msg, rate, suffix, outlen):
    A = [0]*25
    pad = bytearray(msg) + bytes([suffix])
    while len(pad) % rate: pad.append(0)
    pad[-1] |= 0x80
    for off in range(0, len(pad), rate):
        st = bytearray(to_bytes(A))
        for i in range(rate): st[i] ^= pad[off+i]
        A = permute(from_bytes(bytes(st)))
    out = b""
    while len(out) < outlen:
        out += to_bytes(A)[:rate]
        if len(out) < outlen: A = permute(A)
    return out[:outlen]


# =============================================================================
# Streaming sponge — mirrors the API the 6502 code exposes.
#
# The one-shot `sponge()` above is convenient for vector checking, but every
# NIST CAVP vector is one-shot too, so nothing in the standard corpus
# exercises incremental absorb or multi-call squeeze. Those are exactly what
# ML-KEM needs (matrix expansion squeezes many blocks per call site), so the
# golden model implements the SAME state machine the assembly will, and the
# property tests in test_keccak_ref.py drive it the same way.
# =============================================================================

class Sponge:
    """init / absorb* / final / squeeze* — the shape of the ca65 API."""

    def __init__(self, rate, suffix):
        self.rate = rate
        self.suffix = suffix
        self.A = [0] * 25
        self.buf = bytearray()      # partial block not yet absorbed
        self.squeezing = False
        self.out = bytearray()      # unread bytes of the current squeeze block

    def _absorb_block(self, block):
        st = bytearray(to_bytes(self.A))
        for i in range(self.rate):
            st[i] ^= block[i]
        self.A = permute(from_bytes(bytes(st)))

    def absorb(self, data):
        """Incremental. Any chunking must give the same result as one call."""
        assert not self.squeezing, "absorb after squeeze"
        self.buf += data
        while len(self.buf) >= self.rate:
            self._absorb_block(self.buf[:self.rate])
            del self.buf[:self.rate]
        return self

    def _pad_and_switch(self):
        block = bytearray(self.buf) + bytes([self.suffix])
        block += b"\x00" * (self.rate - len(block))
        block[-1] |= 0x80           # when len(buf) == rate-1 this ORs into the
        self._absorb_block(block)   # suffix byte itself: 0x06|0x80 = 0x86
        self.buf = bytearray()
        self.squeezing = True
        self.out = bytearray(to_bytes(self.A)[:self.rate])

    def squeeze(self, n):
        """Repeatedly callable. Continues the stream across calls."""
        if not self.squeezing:
            self._pad_and_switch()
        res = bytearray()
        while len(res) < n:
            if not self.out:
                self.A = permute(self.A)
                self.out = bytearray(to_bytes(self.A)[:self.rate])
            take = min(n - len(res), len(self.out))
            res += self.out[:take]
            del self.out[:take]
        return bytes(res)

    def final(self, n):
        """SHA-3 fixed-length digest."""
        return self.squeeze(n)


def sha3_256():  return Sponge(136, 0x06)
def sha3_512():  return Sponge(72,  0x06)
def shake_128(): return Sponge(168, 0x1F)
def shake_256(): return Sponge(136, 0x1F)
