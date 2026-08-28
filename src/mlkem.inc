; =============================================================================
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
; =============================================================================

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

.endif
