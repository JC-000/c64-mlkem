.setcpu "6502"

; =============================================================================
; c64-mlkem library version constants — c64-lib-contract §1 (SPEC v0.10.6).
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
; =============================================================================

LIB_MLKEM_VERSION_MAJOR = 0
LIB_MLKEM_VERSION_MINOR = 1
LIB_MLKEM_VERSION_PATCH = 0
LIB_MLKEM_ABI_VERSION   = 1

; `: abs` is required, not decorative. These values fit in a byte, so ca65
; infers ZEROPAGE without the hint, while a consumer's .import defaults to
; absolute — producing "ld65: Warning: Address size mismatch" at every import
; site (§1; same defect class as the §8.4 macro exports fixed in v0.7.4).
.export LIB_MLKEM_VERSION_MAJOR: abs
.export LIB_MLKEM_VERSION_MINOR: abs
.export LIB_MLKEM_VERSION_PATCH: abs
.export LIB_MLKEM_ABI_VERSION:   abs

.ifndef LIB_NO_BARE_EXPORTS
; Deprecated bare forms (contract v0.7.0; removed at contract v1.0). Identical
; across every contract library, so a consumer composing two or more libraries
; suppresses them build-wide with `ca65 -D LIB_NO_BARE_EXPORTS=1` and imports
; the prefixed forms only. Aliased to the prefixed equates rather than
; restating the literals: a release bump touches the four lines above, and the
; two forms cannot drift (§1).
LIB_VERSION_MAJOR = LIB_MLKEM_VERSION_MAJOR
LIB_VERSION_MINOR = LIB_MLKEM_VERSION_MINOR
LIB_VERSION_PATCH = LIB_MLKEM_VERSION_PATCH
LIB_ABI_VERSION   = LIB_MLKEM_ABI_VERSION

.export LIB_VERSION_MAJOR: abs
.export LIB_VERSION_MINOR: abs
.export LIB_VERSION_PATCH: abs
.export LIB_ABI_VERSION:   abs
.endif
