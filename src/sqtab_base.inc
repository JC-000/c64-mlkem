; =============================================================================
; sqtab_base.inc — c64-lib-contract §8.1 placement header (canonical shape).
;
; The ONLY place the standalone default for LIB_SHARED_SQTAB_BASE lives (§6.7
; v0.10.2: two independent copies of an .ifndef default can silently disagree).
; Included from src/constants.s (every library TU that reads the table) and
; from src/main.s (the §6.7 image guard). See docs/contract-p2-alignment.md §2.
;
; The table is 1,024 B of RAM OUTSIDE every ld65 segment: sqtab_lo at base,
; sqtab_hi at base + $0200, each 512 B, (sqtab_hi[n] << 8 | sqtab_lo[n]) =
; floor(n^2 / 4) for n in 0..510. Populated by the §8.1 canonical
; `mul_tables_init` (src/sqtab.s in an owner build; a sibling's in a deferring
; build). ld65 does not know it exists, which is why main.s asserts
; __MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE.
;
; Override: `ca65 -D LIB_SHARED_SQTAB_BASE=0x<addr>` in CONTRACT_DEFINES —
; `$`-free (0xBC00, never $BC00: an unquoted `$B` is a shell positional
; parameter and the value silently becomes 0 — CLAUDE.md, SPEC §2).
;
; Never .export LIB_SHARED_SQTAB_BASE, sqtab_lo or sqtab_hi (§8.1 v0.8.5 /
; v0.9.1): two libraries exporting the same unprefixed name is a guaranteed
; duplicate-identifier failure in any composed link.
;
; Standalone default $9000 — page-aligned; clear of c64-x25519 ($7800),
; c64-ChaCha20-Poly1305 ($8000/$8400), c64-nist-curves ($9C00), c64-https
; ($B800/$BC00) and the c64-test-harness scratch ($C000-$CFFF); RAM under
; every $01 banking state (the $A000-$BFFF BASIC ROM window is NOT — a table
; written there reads back ROM bytes with the default $01, silently).
; =============================================================================

.ifndef SQTAB_BASE_INC_INCLUDED
SQTAB_BASE_INC_INCLUDED = 1

.ifndef LIB_SHARED_SQTAB_BASE
    LIB_SHARED_SQTAB_BASE = $9000
.endif
sqtab_lo = LIB_SHARED_SQTAB_BASE
sqtab_hi = LIB_SHARED_SQTAB_BASE + $0200

.assert (LIB_SHARED_SQTAB_BASE & $00ff) = 0, error, "sqtab base must be page-aligned"
.assert sqtab_hi = sqtab_lo + $0200,        error, "sqtab_hi must follow sqtab_lo by $0200"
; The multiply computes the two page bytes as >sqtab_lo + carry and then + 2
; with a carry it assumes clear; both need the 1 KB table to fit below $10000.
.assert LIB_SHARED_SQTAB_BASE <= $FC00,     error, "sqtab (1 KB) must fit below $10000"

.endif
