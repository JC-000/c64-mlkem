.setcpu "6502"

; =============================================================================
; constants.s — hardware equates and build-time constants for c64-mlkem.
;
; Consumers do NOT include this file: it pulls in KERNAL/CIA equates they do
; not need. The consumer-facing surface is src/mlkem.inc (routine declarations)
; plus src/zp_config.s (ZP slots).
; =============================================================================

.ifndef CONSTANTS_S_INCLUDED
CONSTANTS_S_INCLUDED = 1

; ZERO PAGE IS NOT INCLUDED HERE — deliberately.
;
; c64-mlkem uses contract §6.2's consumer-assembled ZP model: NO archive TU
; defines a slot. Library TUs that need one `.importzp` it by name:
;
;     .importzp mlkem_zp_src, mlkem_zp_dst
;
; src/zp_config.s holds the .ifndef-guarded defaults + .exportzp block and is
; linked into the library's OWN standalone PRG only; a consumer assembles that
; file into their build instead, applying -D overrides there with no library
; rebuild. Including zp_config.s here would silently convert this into the
; bake-everywhere model and make every archive TU a definer — the exact thing
; §6.2 says to avoid for a new library.

; --- c64-lib-contract §8.1: shared quarter-square table placement ---------
; LIB_SHARED_SQTAB_BASE / sqtab_lo / sqtab_hi as source-level equates, so every
; TU that reads the table derives the same address at assemble time (the
; multiply self-modifies the page byte of its `abs,x` loads, which ld65 cannot
; relocate). The default and the two §8.1 asserts live in that file ONLY.
.include "sqtab_base.inc"

; --- KERNAL ---------------------------------------------------------------
chrout          = $FFD2         ; print character in A

; --- CIA1 (used by the cycle-count bench harness in src/bench.s) ----------
cia1_ta_lo      = $DC04
cia1_ta_hi      = $DC05
cia1_tb_lo      = $DC06
cia1_tb_hi      = $DC07
cia1_icr        = $DC0D
cia1_cra        = $DC0E
cia1_crb        = $DC0F

; --- VIC-II ---------------------------------------------------------------
vic_border      = $D020
vic_screen_ctrl = $D011         ; bit 4 = DEN, display enable
vic_raster      = $D012         ; raster line, low 8 bits

; --- Keccak-f[1600] parameters (FIPS 202) ---------------------------------
; State is 25 lanes x 8 bytes. Lane index i = x + 5y, lanes little-endian.
KECCAK_LANES       = 25
KECCAK_STATE_BYTES = 200
KECCAK_ROUNDS      = 24

; Sponge rates (bytes) and domain-separation suffixes.
SHA3_256_RATE   = 136
SHA3_512_RATE   = 72
SHAKE128_RATE   = 168
SHAKE256_RATE   = 136
SHA3_SUFFIX     = $06           ; FIPS 202 SHA-3   (NOT $01 — that is
SHAKE_SUFFIX    = $1F           ; FIPS 202 SHAKE    original Keccak padding)

.endif
