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
; PHASE 1 — not yet implemented. Declarations land here as they ship.
;   keccak_f1600      in-place 24-round permutation of keccak_state

; --- Sponge: SHA3-256 / SHA3-512 / SHAKE128 / SHAKE256 --------------------
; PHASE 2 — not yet implemented. Streaming API:
;   *_init / *_absorb (incremental, arbitrary length) / *_final | *_squeeze
;   SHAKE squeeze is repeatedly callable — ML-KEM's matrix expansion squeezes
;   many blocks per call site.

.endif
