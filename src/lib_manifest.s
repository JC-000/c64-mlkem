.setcpu "6502"

; =============================================================================
; c64-mlkem aggregate manifest — c64-lib-contract §5 (SPEC v0.11.0).
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
; P1 measurement — Keccak-f[1600] + the FIPS 202 sponge, after the rho+pi
; optimisation pass:
;   LIB_MLKEM_CODE   1169 B   (886 permutation + 283 sponge/SHA-3/SHAKE)
;   LIB_MLKEM_RODATA  308 B   (192 B round constants, 100 B rho/pi tables,
;                              16 B copy-variant dispatch table)
;   ------------------------
;   resident         1477 B   -> declared 1536 (next 256-B boundary)
; 48.1% of the ~3 KB P1 budget. The permutation grew 402 B (the eight unrolled
; byte-rotation copy variants) to buy a 24% cycle reduction — the size-for-
; speed trade the v0.2.0 baseline was tagged to measure against.
;
; LIB_MLKEM_BSS is 594 B (200 state + 56 alignment pad + 200 rho+pi
; destination + 120 theta scratch + 8 lane scratch + 3 dispatch scratch + 7
; sponge context). BSS is not a footprint equate; consumers size it from the
; segment itself.
; =============================================================================

; --- §5 required four ---------------------------------------------------

; Approximate code+rodata that must stay CPU-resident in any consumer.
LIB_MLKEM_RESIDENT_BYTES = 1536

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
; Keccak is XOR/AND/NOT/rotate only — it contains no multiply at all, so every
; §8.x shared primitive is irrelevant here. Both masks are 0: this library
; neither owns nor consumes any of them.
;
; This changes in P2, where the NTT's modular multiplies make all three
; candidates — and they are three DIFFERENT obligations, not one:
;   §8.1  sqtab       shared quarter-square TABLE
;   §8.2  reu_mul     shared REU multiplication TABLE
;   §8.3  ct_mul_8x8  shared constant-time multiply BODY (not a table)
; Whichever P2 touches, LIB_MLKEM_SHARED_CONSUMES gains the corresponding bits
; and §8.0's ownership-state machinery becomes live for this repo.
LIB_MLKEM_SHARED_PRIMITIVES = 0
LIB_MLKEM_SHARED_CONSUMES   = 0

.export LIB_MLKEM_RESIDENT_BYTES:    abs
.export LIB_MLKEM_COLD_BYTES:        abs
.export LIB_MLKEM_ZP_USAGE_BYTES:    abs
.export LIB_MLKEM_REU_BANKS_USED:    abs
.export LIB_MLKEM_SHARED_PRIMITIVES: abs
.export LIB_MLKEM_SHARED_CONSUMES:   abs

; =============================================================================
; c64-lib-contract §8.4 catch-loop: precalc-table enumeration
; =============================================================================
;
; src/precalc_table.inc is copied BYTE-FOR-BYTE from the contract repo root
; (`cmp src/precalc_table.inc ../c64-lib-contract/precalc_table.inc`); never
; edit the local copy. §8.4 requires it to be .include'd from exactly ONE
; translation unit, and this manifest TU is that unit (the c64-x25519 shape:
; the §5 aggregates, the §8.0 masks and the §8.4 enumeration share one member,
; so a consumer importing any of them pulls in the same, deliberately
; export-only object).
;
; NO BARE `LIB_PRECALC_<name>_*` EXPORTS — ever. The macro emits the deprecated
; unprefixed triple unless LIB_NO_BARE_EXPORTS is defined. This library ships
; no bare exports of any kind (the §1 zero-consumer carve-out it was first to
; take; CLAUDE.md standing invariant: the export surface is byte-identical with
; and without `-D LIB_NO_BARE_EXPORTS=1`). Defining the switch HERE, before the
; include, keeps that true once P2 adds rows: only the `LIB_MLKEM_PRECALC_*`
; family is ever emitted, and `make check-prefix` fails the build if a bare
; form leaks. (§8.4 has no written zero-consumer carve-out of its own — §1's
; reasoning applies verbatim; see docs/contract-p2-alignment.md §5.)
.ifndef LIB_NO_BARE_EXPORTS
LIB_NO_BARE_EXPORTS = 1
.endif

.include "precalc_table.inc"

; P1 (v0.4.x): ZERO invocations — no table clears the §8.4 floor (largest is
; the 192 B round-constant sequence). docs/precalc-tables.md agrees, in both
; directions, as the intake rule requires.
;
; P2 (pending — see docs/precalc-tables.md "P2 (pending)" and
; docs/contract-p2-alignment.md §4 for the exact rows). Planned, to be
; uncommented by the WP that lands each table, in lock-step with the doc row:
;
;   LIB_PRECALC_TABLE "sqtab",      1024, PRECALC_REGION_RAM,    PRECALC_SHARED_YES, "MLKEM"
;   LIB_PRECALC_TABLE "mlkem_zetas", 256, PRECALC_REGION_RODATA, PRECALC_SHARED_NO,  "MLKEM"
;
; "sqtab" is §8.1-normative and MUST NOT be prefixed; the library prefix goes
; in the fifth argument only. The sqtab row is emitted only when
; LIB_MLKEM_SHARED_CONSUMES carries LIB_SHARED_PRIMITIVES_SQTAB (it is the
; §8.0 "consumption surface" of a deferring build too, so it is NOT gated on
; SHARED_SQTAB_INIT).
