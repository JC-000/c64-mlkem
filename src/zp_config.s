.setcpu "6502"

; =============================================================================
; zp_config.s — public zero-page slot inventory for c64-mlkem.
; c64-lib-contract §2 (SPEC v0.11.0).
;
; DELIVERY MODEL: consumer-assembled source (§6.2's recommended shape for new
; libraries). This file is NOT a member of any build/lib/*.a archive. Archive
; TUs `.importzp` these slots; the consumer assembles this file into their own
; build and applies slot overrides there. That is the only model where a
; consumer slot override requires no library rebuild at all.
;
; The library's own standalone PRG (`make`) assembles this file with the
; defaults below, so in-tree tests and the bench harness build unchanged.
;
; Overrides
; ---------
;   ca65 -D mlkem_zp_src=0x40 ...
;
; VALUES MUST BE `$`-FREE (§2, normative). Unquoted `$40` on a shell command
; line expands as positional parameter $4 followed by 0, so the slot silently
; becomes address $00 with no diagnostic at any stage. Through make it is
; worse: `$40` and `$$40` both measured to 0, `$$$$40` yields the shell PID.
; ca65 parses `0x40` natively; plain decimal also works.
;
; Naming: every slot carries the `mlkem_` prefix. Per §2's prefix registry a
; library's own `<shortname>_` is registered to it by construction; bare
; generic names (`zp_tmp1`, `zp_ptr1`) are the documented #83 cross-library
; collision failure class and MUST NOT appear here.
;
; Default addresses: $30-$37. Chosen to avoid c64-x25519's default claims
; ($14-$16, $1C, $1E-$2A, $2C-$2F, $40-$7F) because c64-https links both
; libraries. ZP *addresses* are expected to be relocated by consumers via -D;
; it is the *names* that must never collide. Picking a non-overlapping default
; just means the common composition works without any -D at all.
;
; NOT declared here: the 200-byte Keccak state. It lives in LIB_MLKEM_BSS as
; absolute, page-aligned memory — not zero page (§4 / cfg/mlkem.cfg).
; =============================================================================

.ifndef ZP_CONFIG_S_INCLUDED
ZP_CONFIG_S_INCLUDED = 1

; Source pointer — message/absorb input, (mlkem_zp_src),y indirect indexed.
.ifndef mlkem_zp_src
    mlkem_zp_src = $30
.endif

; Destination pointer — squeeze/digest output, (mlkem_zp_dst),y.
.ifndef mlkem_zp_dst
    mlkem_zp_dst = $32
.endif

; 16-bit remaining-length counter for absorb/squeeze loops.
.ifndef mlkem_zp_len
    mlkem_zp_len = $34
.endif

; General scratch pair (§2: general-purpose scratch takes <shortname>_zp_<role>).
.ifndef mlkem_zp_tmp
    mlkem_zp_tmp = $36
.endif

; When zp_config.s is transitively .include'd (e.g. via constants.s), the
; including TU must NOT re-emit these .exportzp directives — ld65 errors if one
; symbol is exported from two objects. Includers set ZP_CONFIG_NO_EXPORTS = 1
; before the include; this file compiled as its own .o does not, and so emits
; them.
.ifndef ZP_CONFIG_NO_EXPORTS
.exportzp mlkem_zp_src
.exportzp mlkem_zp_dst
.exportzp mlkem_zp_len
.exportzp mlkem_zp_tmp
.endif

.endif
