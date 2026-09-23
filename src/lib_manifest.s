.setcpu "6502"

; =============================================================================
; c64-mlkem aggregate manifest — c64-lib-contract §5 (SPEC 1.2.3).
;
; Split from src/lib_version.s per §1 TU isolation: ld65 links whole archive
; members, so the §5 aggregates a consumer legitimately imports must not share
; a member with the deprecated bare §1 version names.
;
; §6.4 (the manifest describes the archive it ships in): this TU is assembled
; under the same configuration as the archive it ships in AND gated on the
; same switches as the code it describes. Two archives, two configurations:
;
;   mlkem.a          full ML-KEM-768 incl. Keccak. Default configuration;
;                    reads the §8.1 sqtab, so the masks and the "sqtab" row
;                    are present. build/obj/mlkem_lib_manifest.o.
;   mlkem-keccak.a   FIPS 202 only. Assembled with -D MLKEM_KECCAK_ONLY=1 into
;                    build/kobj/mlkem_lib_manifest.o by the lib-keccak target
;                    ONLY: that member set never reads the table, so both
;                    masks are 0 and no §8.4 row is emitted. §6.4 forbids one
;                    manifest describing two member sets; this is the
;                    nist-curves per-variant shape. The Makefile REJECTS
;                    MLKEM_KECCAK_ONLY in CONTRACT_DEFINES at parse time
;                    (a consumer cannot honor it; it
;                    only names a member set the lib-keccak target selects).
;                    `make check-archives` pins both manifests with od65.
;
; §5 safe-direction rule: RESIDENT_BYTES and COLD_BYTES MUST each be >= the
; placed span of the segments they cover in a link of THIS archive (internal
; alignment fill charged; inter-segment gaps and leading padding not), rounded
; UP (fleet convention: the next 256-byte boundary). A consumer asserts
; declared <= budget, so a safe-direction value means declared-passes implies
; actual-passes.
;
; Refreshed from the ld65 map files at the end of every phase
; (`make check-manifest`, which links EACH archive into its own probe image,
; reads the declared values from that archive's manifest member with od65,
; and FAILS if one is below the measured placed span).
;
; P3 measurement (v0.5.1) — the shipped mlkem.a configuration, no test hooks:
;   LIB_MLKEM_CODE   6311 B   (1474 Keccak-f + 281 sponge + 84 sqtab init +
;                              1629 NTT/field + 221 samplers + 681 codecs +
;                              1941 K-PKE/ML-KEM)
;   LIB_MLKEM_RODATA  897 B   (192 Keccak RC + 407 zetas/NTT + 32 CBD +
;                              256 compress tables + 1 + 9 B align pad)
;   ------------------------
;   resident         7208 B   -> declared 7424 (next 256-B boundary)
; The standalone test PRG (-D MLKEM_TEST_HOOKS=1) measures 7381 B, +173 B of
; per-layer / K-PKE hook entry points; 7424 covers both. 93.9% of the 7,680 B
; c64-https CRYPTO_OVERLAY window (README: what is actually free in it is a
; P4 question). v0.5.0 was 6719 B (5694 + 1025), declared 6912.
;
; P1 (Keccak only, the mlkem-keccak.a configuration): 1755 code + 192 rodata
; = 1947 B -> declared 2048 (v0.3.0-v0.5.0: 1477 B, declared 1536).
;
; LIB_MLKEM_BSS is 6641 B in the full link (527 Keccak/sponge; 1042 NTT R
; tables + scratch; 4 sqtab init; 203 samplers/codecs; 4632 K-PKE incl. eight
; page-aligned polynomials; the rest is page-alignment fill). BSS is not a
; footprint equate; consumers size it from the segment itself. The wire
; buffers ek/dk/ct (1,184 + 2,400 + 1,088 B) are the CALLER's and are NOT in
; it. Keccak-only: 527 B.
; =============================================================================

; --- §5 required four ---------------------------------------------------

; Approximate code+rodata that must stay CPU-resident in any consumer.
; Per archive (§6.4): the Keccak-only member set is 1947 B measured, the full
; set 7208 B. Both are literal decimals so tools/check_manifest.py can read
; them without evaluating expressions.
.ifdef MLKEM_KECCAK_ONLY
LIB_MLKEM_RESIDENT_BYTES = 2048
.else
LIB_MLKEM_RESIDENT_BYTES = 7424
.endif

; Approximate code+rodata a consumer MAY overlay-page (load on demand).
; Pairs with RESIDENT_BYTES per §5 — COLD is reclaimable-after-init and may
; live in a different consumer budget. (HANDOFF.md omits this equate; §5
; requires it. Divergence recorded in README.md.) Still 0 in P2: the two
; init routines (mul_tables_init 84 B, mlkem_arith_init) sit in
; LIB_MLKEM_CODE — splitting them into a reclaimable init segment would save
; < 200 B and is not worth a fourth consumer segment.
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
; CONTRACT_DEFINES (every archive member) and is in the build's invalidation
; signature (`make check-staleness`), which is what §6.4 needs for the manifest to describe the archive.
.ifdef MLKEM_KECCAK_ONLY
  _OWN_SQTAB = 0                        ; mlkem-keccak.a: no multiply, no table
.elseif .defined(SHARED_SQTAB_INIT)
  _OWN_SQTAB = 0                        ; deferring: a sibling owns the table
.else
  _OWN_SQTAB = LIB_SHARED_PRIMITIVES_SQTAB
.endif
LIB_MLKEM_SHARED_PRIMITIVES = _OWN_SQTAB

; Consumes mask — set iff this build READS the primitive at all. A deferral
; switch does not clear it; only profile-gated non-consumption would, and this
; library has one member set and no profile axis, so it is unconditional.
; States: standalone $0001/$0001 (owner); c64-https composed, built with
; -D SHARED_SQTAB_INIT, $0000/$0001 (deferring consumer); mlkem-keccak.a
; $0000/$0000 (its member set contains no multiply at all).
.ifdef MLKEM_KECCAK_ONLY
LIB_MLKEM_SHARED_CONSUMES = 0
.else
LIB_MLKEM_SHARED_CONSUMES = LIB_SHARED_PRIMITIVES_SQTAB
.endif
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
; src/precalc_table.inc is a BYTE-FOR-BYTE copy of the contract's file at the
; tag pinned by CONTRACT_PRECALC_REF in the Makefile (`git -C
; ../c64-lib-contract show <ref>:precalc_table.inc`); `make check-precalc`
; verifies it. Never edit the local copy. §8.4 requires it to be .include'd
; from exactly ONE translation unit, and this manifest TU is that unit (the
; c64-x25519 shape: the §5 aggregates, the §8.0 masks and the §8.4
; enumeration share one member, so a consumer importing any of them pulls in
; the same, deliberately export-only object).
;
; NO BARE `LIB_PRECALC_<name>_*` EXPORTS — ever. The macro emits the deprecated
; unprefixed triple unless LIB_NO_BARE_EXPORTS is defined. This library ships
; no bare exports of any kind (the §1 zero-consumer carve-out it was first to
; take; CLAUDE.md standing invariant: the export surface is byte-identical with
; and without `-D LIB_NO_BARE_EXPORTS=1`). Defining the switch HERE, before the
; include, keeps that true once P2 adds rows: only the `LIB_MLKEM_PRECALC_*`
; family is ever emitted, and `make check-prefix` fails the build if a bare
; form leaks. This is §8.4's own zero-consumer carve-out for the bare
; LIB_PRECALC_* triple, which it satisfies by defining LIB_NO_BARE_EXPORTS in
; the enumerating TU, .ifndef-guarded.
.ifndef LIB_NO_BARE_EXPORTS
LIB_NO_BARE_EXPORTS = 1
.endif

.include "precalc_table.inc"

; P1 (v0.4.x): ZERO invocations — no Keccak table clears the §8.4 floor (the
; largest is the 192 B round-constant sequence). That is still the state of
; the mlkem-keccak.a manifest, so every row below is gated out of it.
;
; P2 rows — each landed in the same commit as its table and its
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
;   mlkem_rtab   the mod-q reduction tables R1[k] = 256k mod q and
;                R2[k] = 65536k mod q, 1,024 B (four 256 B planes) of
;                page-aligned LIB_MLKEM_BSS built once at boot by
;                mlkem_arith_init. Hot-loop-read (three lookups per multiply)
;                and secret-indexed, so >= 256 B AND hot-loop-read: it clears
;                the floor. Computed on the target rather than stored in the
;                image — but so is sqtab, which §8.1 makes a mandatory row, so
;                "built at init" does not exempt a table from §8.4. Region
;                RAM (it is not image bytes). Algorithm-specific (q = 3329).
;
; Not enumerated, below the 256 B floor: mlkem_sqd (27 B |d| quarter-squares,
; in the R2 page tail), the 14-entry per-block U table (same tail), the 32 B
; CBD nibble tables, the 108 B compress tables.
.ifndef MLKEM_KECCAK_ONLY
LIB_PRECALC_TABLE "sqtab",      1024, PRECALC_REGION_RAM,    PRECALC_SHARED_YES, "MLKEM"
LIB_PRECALC_TABLE "mlkem_zetas", 256, PRECALC_REGION_RODATA, PRECALC_SHARED_NO,  "MLKEM"
LIB_PRECALC_TABLE "mlkem_rtab", 1024, PRECALC_REGION_RAM,    PRECALC_SHARED_NO,  "MLKEM"
.endif
