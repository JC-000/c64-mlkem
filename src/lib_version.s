.setcpu "6502"

; =============================================================================
; c64-mlkem library version constants — c64-lib-contract §1 (SPEC v0.11.0).
;
; TU-ISOLATION RULE (§1): this translation unit exports the four §1 version
; equates and NOTHING else. ld65 links whole archive members, so if the
; deprecated bare names below shared a member with anything a consumer
; legitimately imports (e.g. the §5 aggregates), the bare names would enter a
; two-library link uninvited and collide with a sibling library's identical
; bare exports (c64-lib-contract#43). The §5 aggregate surface lives in
; src/lib_manifest.s.
;
; Consumers gate with .assert/lderror, NOT .if/.error: an .import'ed symbol
; has no value until link, so ca65 rejects an .if guard outright with
; "Constant expression expected". .assert defers evaluation to ld65 and still
; fires before anything runs:
;
;   .import LIB_MLKEM_VERSION_MAJOR, LIB_MLKEM_VERSION_MINOR
;   .assert (LIB_MLKEM_VERSION_MAJOR > 0) .or (LIB_MLKEM_VERSION_MINOR >= 1), lderror, "this consumer needs c64-mlkem v0.1 or later"
;
; (One line — ca65 rejects backslash continuation unless `.linecont +`.)
;
; LIB_MLKEM_ABI_VERSION is a monotonic generation counter for the exported
; surface (§1, v0.7.5 semantics): starts at 1, increments on any breaking
; export change, DELIBERATELY INDEPENDENT of MAJOR. §7 permits breaking
; changes on MINOR bumps while pre-1.0, so MAJOR stays 0 and carries no
; signal; a consumer gating on MINOR would never fire for exactly the changes
; the gate exists to catch.
;
; History:
;   1  v0.1.0  initial surface (P1 scaffold; no crypto exports yet)
;   1  v0.2.0  ADDITIVE only — keccak_f1600/keccak_clear and the FIPS 202
;              sponge joined the surface; nothing was removed or renamed, so
;              the ABI generation counter does NOT move (§1: it counts
;              BREAKING export changes, not releases).
;   1  v0.3.0  rho+pi optimisation. Pure implementation change: no export
;              added, removed or renamed, and no calling convention touched,
;              so the counter again does not move.
;   2  v0.4.0  BREAKING: the four deprecated bare exports were removed under
;              the contract v0.11.0 §1 zero-consumer carve-out. A removed
;              export is exactly what this counter is for, so it moves for the
;              first time. Free in practice — the library had no consumers to
;              break, which is the whole argument for doing it now.
;   2  v0.5.0  ADDITIVE only — P2: mlkem_poly_* / mlkem_sample_* / codecs /
;              mlkem_keygen/encaps/decaps, mul_tables_init (owner builds),
;              mlkem_arith_init, the §8.0 masks moving 0/0 -> 1/1 and three
;              §8.4 LIB_MLKEM_PRECALC_* triples joined the surface; the P1
;              surface is byte-identical (od65 on both archives against the
;              v0.4.0 header). Nothing removed or renamed, no calling
;              convention touched: the counter does not move.
; =============================================================================

LIB_MLKEM_VERSION_MAJOR = 0
LIB_MLKEM_VERSION_MINOR = 5
LIB_MLKEM_VERSION_PATCH = 1
LIB_MLKEM_ABI_VERSION   = 2

; `: abs` is required, not decorative. These values fit in a byte, so ca65
; infers ZEROPAGE without the hint, while a consumer's .import defaults to
; absolute — producing "ld65: Warning: Address size mismatch" at every import
; site (§1; same defect class as the §8.4 macro exports fixed in v0.7.4).
.export LIB_MLKEM_VERSION_MAJOR: abs
.export LIB_MLKEM_VERSION_MINOR: abs
.export LIB_MLKEM_VERSION_PATCH: abs
.export LIB_MLKEM_ABI_VERSION:   abs

; NO DEPRECATED BARE EXPORTS — c64-lib-contract §1 zero-consumer carve-out
; (contract v0.11.0).
;
; §1 requires every library to ALSO export the unprefixed LIB_VERSION_MAJOR /
; _MINOR / _PATCH / LIB_ABI_VERSION, and states its own reason: so *existing*
; single-library consumers keep working unchanged. c64-mlkem had no released
; consumers when it onboarded, so those exports would have protected nobody
; while adding a fifth claimant to the exact four names that produce
; contract#43's `ld65: Error: Duplicate external identifier` in any link that
; composes two libraries.
;
; The carve-out (contract PR #125) lets such a library omit them. This one is
; therefore born in the state every other library reaches at contract v1.0, and
; never has to make the removal.
;
; A consumer imports the PREFIXED forms only:
;   .import LIB_MLKEM_VERSION_MAJOR, LIB_MLKEM_VERSION_MINOR
;   .assert (LIB_MLKEM_VERSION_MAJOR > 0) .or (LIB_MLKEM_VERSION_MINOR >= 4), lderror, "needs c64-mlkem v0.4+"
;
; Nothing here is gated on LIB_NO_BARE_EXPORTS. Passing `-D LIB_NO_BARE_EXPORTS=1`
; remains harmless and is still the right thing for a composing consumer to do
; build-wide — it simply has no effect on this library.
