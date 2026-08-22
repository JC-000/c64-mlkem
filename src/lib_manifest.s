.setcpu "6502"

; =============================================================================
; c64-mlkem aggregate manifest — c64-lib-contract §5 (SPEC v0.10.6).
;
; Split from src/lib_version.s per §1 TU isolation: ld65 links whole archive
; members, so the §5 aggregates a consumer legitimately imports must not share
; a member with the deprecated bare §1 version names.
;
; §6.4 (the manifest describes the archive it ships in): this TU must be
; assembled under the same configuration as the archive it ships in AND gated
; on the same switches as the code it describes. P1 has no variant/profile
; axis and no §8.x switches, so both halves are trivially satisfied today —
; that stops being true the moment a Keccak variant target is added, and this
; comment is the reminder.
;
; §6.6 safe-direction rule: RESIDENT_BYTES and COLD_BYTES MUST each be >= the
; measured segment sum for THIS archive, rounded UP (fleet convention: the
; next 256-byte boundary). A consumer asserts declared <= budget, so a
; safe-direction value means declared-passes implies actual-passes.
;
; Refreshed from the ld65 map file at the end of every phase
; (`make check-manifest`, which FAILS if a value is below measured).
;
; P1 Phase 1 measurement — Keccak-f[1600] permutation, compact/looped form:
;   LIB_MLKEM_CODE    484 B   (theta, rho+pi, chi, iota, the round driver)
;   LIB_MLKEM_RODATA  267 B   (192 B round constants + 3 x 25 B rho/pi tables)
;   ------------------------
;   resident          751 B   -> declared 768 (next 256-B boundary)
; Against the P1 budget of ~3 KB code+rodata that is 24.4% — the sponge layer
; and its four rate/suffix wrappers land in the remaining headroom.
;
; LIB_MLKEM_BSS is 584 B (200 state + 56 alignment pad + 200 rho+pi
; destination + 120 theta scratch + 8 lane scratch). BSS is not a footprint
; equate; consumers size it from the segment itself.
; =============================================================================

; --- §5 required four ---------------------------------------------------

; Approximate code+rodata that must stay CPU-resident in any consumer.
LIB_MLKEM_RESIDENT_BYTES = 768

; Approximate code+rodata a consumer MAY overlay-page (load on demand).
; Pairs with RESIDENT_BYTES per §6.6 — COLD is reclaimable-after-init and may
; live in a different consumer budget. (HANDOFF.md omits this equate; §5
; requires it. Divergence recorded in README.md.)
LIB_MLKEM_COLD_BYTES = 0

; Total bytes of ZP slots claimed — sum of every .exportzp slot in
; src/zp_config.s:
;   $30-$31  mlkem_zp_src   2 B
;   $32-$33  mlkem_zp_dst   2 B
;   $34-$35  mlkem_zp_len   2 B
;   $36-$37  mlkem_zp_tmp   2 B
;   ----------------------------
;                           8 B
LIB_MLKEM_ZP_USAGE_BYTES = 8

; Bitmask of REU banks claimed (§3). P1 uses no REU at all — the Keccak state
; is 200 bytes of main memory and there is nothing to stage. Do not pass -reu
; to VICE for this library's tests.
LIB_MLKEM_REU_BANKS_USED = 0

; --- §8 shared primitives -----------------------------------------------
;
; Keccak is XOR/AND/NOT/rotate only — it contains no multiply, so the §8.3
; shared 8x8 multiply tables and the §8.1 quarter-square table are irrelevant
; here. Both masks are 0: this library neither owns nor consumes any shared
; primitive.
;
; This changes in P2: the NTT's modular multiplies are a candidate consumer of
; the shared 8x8 tables, at which point LIB_MLKEM_SHARED_CONSUMES gains bits
; and §8.0's ownership-state machinery becomes live for this repo.
LIB_MLKEM_SHARED_PRIMITIVES = 0
LIB_MLKEM_SHARED_CONSUMES   = 0

.export LIB_MLKEM_RESIDENT_BYTES:    abs
.export LIB_MLKEM_COLD_BYTES:        abs
.export LIB_MLKEM_ZP_USAGE_BYTES:    abs
.export LIB_MLKEM_REU_BANKS_USED:    abs
.export LIB_MLKEM_SHARED_PRIMITIVES: abs
.export LIB_MLKEM_SHARED_CONSUMES:   abs
