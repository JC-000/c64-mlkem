.setcpu "6502"

; =============================================================================
; state.s — the Keccak-f[1600] state buffer.
;
; 25 lanes x 8 bytes = 200 bytes. FIPS 202 lane index i = x + 5y, each lane
; stored little-endian, which is also the state's byte-serialisation order —
; so the sponge's rate-block XOR is a straight byte-wise operation over the
; first `rate` bytes with no reordering.
;
; PAGE ALIGNMENT IS LOAD-BEARING, not a performance hint. 200 bytes fits
; inside one page, so an aligned base means:
;   - `lda keccak_state,x` for x = 0..199 never crosses a page boundary
;     (no +1-cycle penalty, and the cost is input-independent);
;   - the high byte of every lane address is constant, which the fused rho+pi
;     destination-indexed copy relies on to address lanes by an 8-bit offset.
;
; The .align 256 below is deliberately paired with `align = $100` on the
; LIB_MLKEM_BSS segment in cfg/mlkem.cfg. Per contract §4, ld65 warns about a
; dropped cfg `align` ONLY when the segment contains a source-level `.align`
; to check it against — expressing alignment in the cfg alone gets a consumer
; NO diagnostic at all when they drop the attribute. The .assert then makes it
; a hard error rather than a warning.
; =============================================================================

.include "constants.s"

.export keccak_state

.segment "LIB_MLKEM_BSS"

.align 256
keccak_state:
        .res KECCAK_STATE_BYTES

.assert (keccak_state .mod 256) = 0, lderror, "keccak_state is not page-aligned: LIB_MLKEM_BSS needs align = $100 (see cfg/mlkem.cfg)"
