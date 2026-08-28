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
;   $38-$3F  mlkem_zp_mul   8 B   (P2: multiply operand/product scratch)
;   ----------------------------
;                          16 B
LIB_MLKEM_ZP_USAGE_BYTES = 16

; Bitmask of REU banks claimed (§3). P1 uses no REU at all — the Keccak state
; is 200 bytes of main memory and there is nothing to stage. Do not pass -reu
; to VICE for this library's tests.
LIB_MLKEM_REU_BANKS_USED = 0

; --- §8 shared primitives -----------------------------------------------
;
; P2 (WP1): the NTT multiply reads the §8.1 quarter-square TABLE `sqtab`
; (src/ntt.s, via src/sqtab_base.inc). It takes neither §8.2 reu_mul (no REU
; in P2) nor the §8.3 ct_mul_8x8 BODY (private mlkem_-prefixed multiply; see
; docs/contract-p2-alignment.md §3), so bits $0002 / $0004 stay clear in both
; masks and no §8.3 provider obligation attaches.
;
; Bit constants: copied verbatim from §8.0, .ifndef-guarded, NEVER exported
; (an exporter reintroduces the #43 duplicate-identifier collision in every
; composed link, and only a composed link ever sees it).
.ifndef LIB_SHARED_PRIMITIVES_SQTAB
  LIB_SHARED_PRIMITIVES_SQTAB      = $0001
.endif
.ifndef LIB_SHARED_PRIMITIVES_REU_MUL
  LIB_SHARED_PRIMITIVES_REU_MUL    = $0002
.endif
.ifndef LIB_SHARED_PRIMITIVES_CT_MUL_8X8
  LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004
.endif

; Ownership mask — §8.0's required CONDITIONAL form: the bit means "owned in
; this build configuration" and the deferral switch drops it, so two libraries
; sharing the table end up with disjoint masks and the consumer's
; double-ownership assert is satisfiable. SHARED_SQTAB_INIT reaches this TU via
; CONTRACT_DEFINES (every archive member) and is in the §6.3 invalidation
; signature, which is what §6.4 needs for the manifest to describe the archive.
.ifdef SHARED_SQTAB_INIT
  _OWN_SQTAB = 0
.else
  _OWN_SQTAB = LIB_SHARED_PRIMITIVES_SQTAB
.endif
LIB_MLKEM_SHARED_PRIMITIVES = _OWN_SQTAB

; Consumes mask — set iff this build READS the primitive at all. A deferral
; switch does not clear it; only profile-gated non-consumption would, and this
; library has one member set and no profile axis, so it is unconditional.
; States: standalone $0001/$0001 (owner); c64-https composed, built with
; -D SHARED_SQTAB_INIT, $0000/$0001 (deferring consumer).
LIB_MLKEM_SHARED_CONSUMES = LIB_SHARED_PRIMITIVES_SQTAB
.assert (LIB_MLKEM_SHARED_PRIMITIVES & ~LIB_MLKEM_SHARED_CONSUMES) = 0, error, "a build cannot own a primitive it does not consume"

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
; the 192 B round-constant sequence).
;
; P2 WP1 rows — each landed in the same commit as its table and its
; docs/precalc-tables.md row (the intake rule blocks any asymmetry):
;
;   sqtab        §8.1 shared quarter-square table, 1,024 B of equate-placed
;                RAM at LIB_SHARED_SQTAB_BASE. "sqtab" is §8.1-normative and
;                MUST NOT be prefixed (the cross-adopter audit greps
;                _PRECALC_sqtab_SIZE); the library prefix is the fifth
;                argument only. Emitted whenever the consumes bit is set — it
;                is consumption surface in a deferring build too, so it is
;                NOT gated on SHARED_SQTAB_INIT.
;   mlkem_zetas  the 128 NTT twiddles in traversal order, 256 B of RODATA
;                (lo/hi planes), hot-loop-read: exactly at the floor.
;
; Not enumerated, below the 256 B floor: mlkem_sqd (27 B |d| quarter-squares).
; The R1/R2 reduction tables (1 KB of BSS, built at run time by
; mlkem_arith_init) are page-aligned and secret-indexed but are not
; PRECALCULATED data — they are computed on the target, so they are not §8.4
; tables; they are recorded in docs/precalc-tables.md for completeness.
LIB_PRECALC_TABLE "sqtab",      1024, PRECALC_REGION_RAM,    PRECALC_SHARED_YES, "MLKEM"
LIB_PRECALC_TABLE "mlkem_zetas", 256, PRECALC_REGION_RODATA, PRECALC_SHARED_NO,  "MLKEM"
