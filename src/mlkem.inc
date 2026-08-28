; ======================================================================
; mlkem.inc — public header for c64-mlkem.
;
; Consumers .include this file (NOT src/constants.s, which pulls in KERNAL/CIA
; equates you do not need).
;
; ZERO PAGE: this library uses §6.2's consumer-assembled model. Its ZP slots
; are NOT exported from any archive — you assemble src/zp_config.s into your
; own build and apply overrides there:
;
;     ca65 -D mlkem_zp_src=0x40 -D mlkem_zp_dst=0x42 ... src/zp_config.s
;
; Override values must be `$`-free (`0x40` or decimal) — see the warning in
; src/zp_config.s. No library rebuild is needed for a slot override under this
; model.
;
; SEGMENTS to place in your cfg (contract §4):
;     LIB_MLKEM_CODE      library code
;     LIB_MLKEM_RODATA    round constants / rho-offset tables
;     LIB_MLKEM_BSS       the 200-byte Keccak state — REQUIRES align = $100
;                         and must be the LAST segment in a file-emitting
;                         area (a mid-area bss segment makes ld65 emit a
;                         shorter image and everything after it loads at the
;                         wrong address, silently). See cfg/mlkem-example.cfg.
;
; VERSION GATE (contract §1) — .assert/lderror, never .if/.error:
;     .import LIB_MLKEM_VERSION_MAJOR, LIB_MLKEM_VERSION_MINOR
;     .assert (LIB_MLKEM_VERSION_MAJOR > 0) .or (LIB_MLKEM_VERSION_MINOR >= 1), lderror, "needs c64-mlkem v0.1+"
;
; FOOTPRINT GATE (contract §6.6):
;     .import LIB_MLKEM_RESIDENT_BYTES, LIB_MLKEM_COLD_BYTES
;     .import __MAIN_SIZE__
;     .assert LIB_MLKEM_RESIDENT_BYTES + LIB_MLKEM_COLD_BYTES <= __MAIN_SIZE__, lderror, "c64-mlkem footprint exceeds the MAIN budget"
; ======================================================================

.ifndef MLKEM_INC_INCLUDED
MLKEM_INC_INCLUDED = 1

; --- State ----------------------------------------------------------------
; 200 bytes, page-aligned, in LIB_MLKEM_BSS.
.import keccak_state

; --- Keccak-f[1600] permutation -------------------------------------------
; keccak_f1600  in-place 24-round permutation of keccak_state.
;               456,605 cycles (measured; `make bench`).
;               Clobbers A/X/Y and the mlkem_zp_tmp / mlkem_zp_len slots.
; keccak_clear  zero all 200 state bytes.
.import keccak_f1600, keccak_clear

; --- Sponge: SHA3-256 / SHA3-512 / SHAKE128 / SHAKE256 --------------------
;
; Streaming API. Absorb accepts arbitrary lengths and may be called repeatedly;
; squeeze may be called repeatedly and CONTINUES the output stream, which is
; what ML-KEM's matrix expansion needs. Padding is applied automatically on the
; first squeeze, so a SHA-3 digest is just init / absorb* / squeeze.
;
;   1. jsr one of the four init routines
;   2. per absorb:  mlkem_zp_src     <- pointer to the message chunk
;                   mlkem_sponge_len <- chunk length (16-bit, little-endian)
;                   jsr mlkem_absorb
;   3. per squeeze: mlkem_zp_dst     <- pointer to the output buffer
;                   mlkem_sponge_len <- bytes wanted (16-bit, little-endian)
;                   jsr mlkem_squeeze
;
; Both calls consume mlkem_sponge_len (it reads 0 on return) and advance the
; pointer slot they used, so absorbing a contiguous message in chunks needs the
; pointer set only once.
;
; Digest sizes: SHA3-256 -> 32 bytes, SHA3-512 -> 64. The SHAKEs are
; extendable: squeeze as many bytes as you want, in as many calls as you want.
;
; NOTE: these routines call keccak_f1600, which clobbers mlkem_zp_tmp and
; mlkem_zp_len. Do not keep live consumer state in those two slots across a
; sponge call. mlkem_zp_src and mlkem_zp_dst are preserved (advanced, not
; destroyed).
.import mlkem_sha3_256_init, mlkem_sha3_512_init
.import mlkem_shake128_init, mlkem_shake256_init
.import mlkem_absorb, mlkem_squeeze, mlkem_sponge_len

; --- P2: mod-3329 polynomial arithmetic and the NTT (FIPS 203 Alg. 9-12) ---
;
; POLYNOMIAL LAYOUT — split-plane, 512 bytes, PAGE-ALIGNED:
;     ptr + 0   .. ptr + 255   low  bytes of c[0..255]
;     ptr + 256 .. ptr + 511   high bytes of c[0..255]
; Coefficients are canonical, 0 <= c < 3329, at every call boundary (high
; byte 0..12). PAGE ALIGNMENT IS A HARD REQUIREMENT: the routines patch only
; the high byte of their plane accesses, so a pointer whose low byte is not
; $00 is silently addressed at its page base. It is also what keeps every
; indexed access input-independent in cost. Allocate polynomial buffers with
; .align 256 and assert it, the keccak_state pattern.
;
; Pointers: mlkem_zp_dst = the in-place operand and the result;
;           mlkem_zp_src = the second operand of a binary op (never written).
; Clobbers: A/X/Y, mlkem_zp_tmp, mlkem_zp_len, mlkem_zp_mul. The pointer slots
; themselves are preserved.
;
;   mlkem_poly_ntt      (dst) <- NTT(dst)                         Alg. 9
;   mlkem_poly_intt     (dst) <- NTT^-1(dst), incl. the x3303      Alg. 10
;   mlkem_poly_basemul  (dst) <- MultiplyNTTs(dst, src)            Alg. 11/12
;   mlkem_poly_add      (dst) <- dst + src mod q
;   mlkem_poly_sub      (dst) <- dst - src mod q   (wraps to +q, never negative)
;   mlkem_poly_reduce   (dst) <- dst mod q for ANY unsigned 16-bit coefficient
;                       (byte_decode_12 output, < 2q add/sub intermediates,
;                       < 6q dot-product accumulations all included)
;
; Cycle counts are in README (measured; `make test-ntt` prints them).
;
; CONSTANT TIME: none of these branches on a coefficient; every table indexed
; by secret-derived data is page-aligned. Timing depends on nothing but the
; call.
;
; INIT — the consumer's job, once at boot, both idempotent:
;   mul_tables_init     contract §8.1: fills the shared quarter-square table
;                       at LIB_SHARED_SQTAB_BASE (1 KB of RAM outside every
;                       segment; standalone default $9000 — override with
;                       `-D LIB_SHARED_SQTAB_BASE=0x<addr>`, `$`-free). In a
;                       build with -D SHARED_SQTAB_INIT this library does NOT
;                       provide it; the link's designated owner does, and the
;                       consumer calls that one.
;   mlkem_arith_init    builds the two 512 B reduction tables in
;                       LIB_MLKEM_BSS. Reads nothing else. Every routine above
;                       reads them, so a missing call is a wrong answer, not
;                       a crash.
; Mirror the library's §6.7 guard in your own link:
;   .import __<AREA>_LAST__
;   .assert __<AREA>_LAST__ <= LIB_SHARED_SQTAB_BASE, lderror, "image overruns sqtab"
.import mlkem_poly_ntt, mlkem_poly_intt, mlkem_poly_basemul
.import mlkem_poly_add, mlkem_poly_sub, mlkem_poly_reduce
.import mlkem_arith_init

; --- P2 / WP2: samplers and codecs (src/sample.s, src/codec.s) -------------
;
; POLYNOMIAL LAYOUT: split-plane, 512 bytes, page-aligned — 256 low bytes then
; 256 high bytes; coefficient i is byte i of each plane (mirrored by
; tools/mlkem_ref.py poly_to_c64 / poly_from_c64). Every routine below reads
; its polynomial / byte string at (mlkem_zp_src) and writes at (mlkem_zp_dst);
; both pointers are set by the caller before EVERY call and are not preserved.
; All of them clobber A/X/Y, mlkem_zp_tmp, mlkem_zp_len and mlkem_sponge_len.
; A routine that writes a polynomial writes all 512 bytes and nothing past.
;
; mlkem_sample_ntt        FIPS 203 Alg. 7 over the live SHAKE128 stream: the
;                         caller has run mlkem_shake128_init and absorbed
;                         rho || j || i; output A[i][j] (NTT order, [0, q)) at
;                         (mlkem_zp_dst). Squeezes 3-4 rate blocks itself.
; mlkem_sample_cbd2       Alg. 8, eta = 2: 128 PRF bytes -> polynomial in
;                         [0, q) (negative v stored as q + v). Constant time.
; mlkem_byte_encode_12    Alg. 5, d = 12: polynomial -> 384 bytes. Constant time.
; mlkem_byte_decode_12    Alg. 6, d = 12: 384 bytes -> polynomial, RAW unpack:
;                         a field >= q is written unreduced (3329..4095). The
;                         < q check on an encapsulation key is the caller's
;                         (FIPS 203 §7.2) and must be an explicit per-
;                         coefficient compare, not re-encode-and-compare.
; mlkem_compress_{1,4,10} eq. 4.7, round-half-up: [0, q) -> d-bit values,
;                         unpacked. Constant time (branch-free division by q).
; mlkem_decompress_{1,4,10} eq. 4.8: d-bit values -> [0, q). Constant time.
.import mlkem_sample_ntt, mlkem_sample_cbd2
.import mlkem_byte_encode_12, mlkem_byte_decode_12
.import mlkem_compress_1, mlkem_compress_4, mlkem_compress_10
.import mlkem_decompress_1, mlkem_decompress_4, mlkem_decompress_10

; --- P2 / WP3: K-PKE and ML-KEM-768 (src/kem.s, FIPS 203 Alg. 13-18) --------
;
; Wire formats, verbatim, at caller-supplied addresses with NO alignment
; requirement: ek 1,184 B, dk 2,400 B, c 1,088 B, K / d / z / m 32 B.
;
; PARAMETER BLOCK: six little-endian 16-bit pointers, contiguous in
; LIB_MLKEM_BSS (a 12-byte struct at mlkem_arg_ek). Set once; no call
; modifies it.
;     mlkem_arg_ek    +0    mlkem_arg_dk    +2    mlkem_arg_ct   +4
;     mlkem_arg_key   +6    mlkem_arg_seed  +8    mlkem_arg_z   +10
;
;   mlkem_keygen   seed = d, z          -> ek, dk            A = 0
;   mlkem_encaps   ek, seed = m         -> key = K, ct = c   A = status
;   mlkem_decaps   dk, ct               -> key = K           A = 0
;
; mlkem_encaps status (A, and latched in mlkem_status): 0 = ok; 1 = ek failed
; the FIPS 203 §7.2 modulus check (a 12-bit field of t_hat >= q) — nothing
; has been written. Length checks are the caller's (pointers, not lengths).
; mlkem_decaps never fails: a ciphertext that does not re-encrypt yields
; K = J(z || c) silently, in constant time (full-length compare, masked
; select). The §7.3 H(ek) check on dk is the caller's per FIPS 203; this
; library does not perform it. mlkem_keygen / mlkem_decaps also clear
; mlkem_status.
;
; Clobbers A/X/Y, every mlkem_zp_* slot, mlkem_sponge_len, keccak_state and
; all library BSS. Requires mul_tables_init + mlkem_arith_init once at boot.
; BSS: 4,632 B in this TU (eight page-aligned polynomials, 320 B chunk
; buffer, 128 B hash scratch, the block). The matrix A is never stored.
.import mlkem_keygen, mlkem_encaps, mlkem_decaps
.import mlkem_arg_ek, mlkem_arg_dk, mlkem_arg_ct
.import mlkem_arg_key, mlkem_arg_seed, mlkem_arg_z
.import mlkem_status

.endif
