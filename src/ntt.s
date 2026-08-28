.setcpu "6502"

; =============================================================================
; ntt.s — mod-3329 field arithmetic and the ML-KEM NTT (FIPS 203 Alg. 9-12).
;
; POLYNOMIAL LAYOUT (declared in src/mlkem.inc, mirrored by
; tools/mlkem_ref.py poly_to_c64): split-plane, 512 B, PAGE-ALIGNED —
;     ptr + 0   .. ptr + 255   low  bytes of c[0..255]
;     ptr + 256 .. ptr + 511   high bytes of c[0..255]   (0..12)
; Every routine here reads its operand pointers from mlkem_zp_dst (in-place
; operand and result) / mlkem_zp_src (second operand, never written) and
; patches the HIGH byte of every `abs,x` / `abs,y` plane access below from
; them (self-modifying code, patched once per call, public data). The low
; address byte is never patched: it is the assembled 0 (or 1 for the odd
; coefficient of a basemul pair). A buffer that is not page-aligned is
; therefore silently addressed at its page base — the alignment is a hard
; ABI requirement, not a hint, and it is also what makes every indexed access
; input-independent in cost (no page crossing for any x).
;
; VALUE REPRESENTATION: canonical [0, q) at every routine boundary and inside
; every layer. No Montgomery domain, no lazy ranges: each butterfly output is
; conditionally subtracted, so mlkem_poly_ntt needs no final pass and every
; per-layer hook boundary is canonical by construction.
;
; THE MULTIPLY (the design decision this file turns on). a*b mod q with
; a, b < q, both 12-bit. Write a = a1*256 + a0 (a1 <= 13) and split:
;
;     a*b = a0*b  +  256*a1*b
;
; a0*b is an 8x12 product formed from two inline §8.1 quarter-square partials
; (a0*b0 and a0*b1, via sqtab_lo/hi, t(x+y) - t(|x-y|)); it is < 2^20 so its
; three bytes P0, P1, P2 (P2 <= 12) reduce as
;     P0 + R1[P1] + R2[P2]          R1[k] = 256k mod q, R2[k] = 65536k mod q
; with R1/R2 page-aligned lookup tables in LIB_MLKEM_BSS built once by
; mlkem_arith_init. The 256*a1*b term is the E input of the shared core:
;   - NTT / INTT / scaling (b public, fixed per butterfly block): E = U[a1]
;     where U[k] = k*(256b mod q) mod q, 14 entries built once per block
;     (fq_setblk). Two partials per butterfly.
;   - general secret x secret (basemul): E = R1[lo(a1*b0)] + R2[hi(a1*b0) +
;     a1*b1] from one more partial and a 14x14 product read off sqtab with a
;     27-byte |d| table. Three partials plus the small one.
; The sum V = P0 + R1[P1] + R2[P2] + E < 256 + 4q folds once more through R1
; on its high byte (W = V0 + R1[V1] < 256 + q) and one masked conditional
; subtract gives [0, q).
;
; Cost, measured by `make test-ntt` (see README): the NTT butterfly is
; ~490 cycles, of which the block-table multiply is ~330; a general multiply
; ~450. Cheaper alternatives considered and rejected are in HANDOFF-P2 /
; docs/contract-p2-alignment.md §3 (the §8.3 body: ~4 partials + 2 re-bakes
; per butterfly through jsr) and the report.
;
; CONSTANT TIME. The coefficient is the secret; zeta and the loop indices are
; public. No instruction below branches on a coefficient: the conditional
; subtract / add of q is a carry-derived mask, |x - y| is a sign-mask flip,
; and the sqtab page select is a carry added into the patched address byte.
; Every table indexed by a secret-derived byte is page-aligned and read with
; a base low byte of 0 (sqtab: §8.1 assert; R1/R2/U: .align 256 + .assert
; below; the 27-byte |d| table lives in the R2 page tail). The
; per-block U build and the R-table init branch on public data only.
; tools/test_ntt.py's S5 check pins the cycle count equal across all-zero /
; all q-1 / random / impulse inputs.
;
; §8.1: this TU reads sqtab_lo/hi at LIB_SHARED_SQTAB_BASE (src/sqtab_base.inc
; via constants.s) and never exports the names. It does NOT take the §8.3
; canonical body — the private multiply is mlkem_-prefixed and shaped for a
; 12x12 product (docs/contract-p2-alignment.md §3).
; =============================================================================

.include "constants.s"

.importzp mlkem_zp_src, mlkem_zp_dst, mlkem_zp_len, mlkem_zp_tmp, mlkem_zp_mul

.export mlkem_arith_init
.export mlkem_poly_ntt, mlkem_poly_intt, mlkem_poly_basemul
.export mlkem_poly_add, mlkem_poly_sub, mlkem_poly_reduce

; Per-layer entry points for the differential harness (tools/test_ntt.py).
; Gated so the shipped archive's export surface stays minimal (§6.5).
.ifdef MLKEM_TEST_HOOKS
.export mlkem_ntt_layer, mlkem_intt_layer, mlkem_ntt_layer_num
.endif

; --- zero-page aliases -------------------------------------------------------
; mlkem_zp_mul (8 B): multiply operands and product bytes, hot.
fq_a_lo = mlkem_zp_mul + 0      ; a (secret operand)
fq_a_hi = mlkem_zp_mul + 1
fq_b_lo = mlkem_zp_mul + 2      ; b (zeta, or second secret operand)
fq_b_hi = mlkem_zp_mul + 3
fq_p0   = mlkem_zp_mul + 4      ; product bytes / 16-bit accumulator
fq_p1   = mlkem_zp_mul + 5
fq_p2   = mlkem_zp_mul + 6
fq_px   = mlkem_zp_mul + 7      ; partial scratch / mask
fq_r_lo = mlkem_zp_tmp + 0      ; multiply result
fq_r_hi = mlkem_zp_tmp + 1
fq_e_lo = mlkem_zp_len + 0      ; the 256*a1*b term (E), < 2q
fq_e_hi = mlkem_zp_len + 1

; The conditional subtract exploits q = $0D01: the low byte of q is 1, so the
; low-byte step is "subtract the carry".
.assert MLKEM_Q_LO = 1, error, "the masked conditional subtract assumes q & $FF = 1"

; =============================================================================
.segment "LIB_MLKEM_RODATA"

; Zetas (256 B, split-plane, generated) and the reduction equates.
.include "mlkem_tables.inc"

; t(|k - 13|) for k = 0..26: the quarter-square of a signed difference in
; [-13, 13], so the 14x14 product a1*b1 needs no sign handling. (a1 = a >> 8
; reaches 13: q - 1 = 3328 = $0D00.) Computed by the assembler, not typed.
; It is secret-indexed, so it is READ from fq_sqd inside a page-aligned BSS
; page (mlkem_arith_init copies it there); this rodata image is the source.
mlkem_sqd_src:
.repeat 27, k
        .byte ((k - 13) * (k - 13)) / 4
.endrepeat

; SMC site lists: the address of every plane-access instruction, grouped by
; which pointer/plane patches its high address byte. Maintained by hand next
; to the code; nt_patch_dst / nt_patch_src walk them.
nt_dst_lo_sites:
        .addr nt_s01, nt_s03, nt_s05, nt_s07, nt_s09
        .addr it_s01, it_s02, it_s05, it_s06, it_s09, it_s11
        .addr sc_s01, sc_s03
        .addr ad_s01, ad_s05
        .addr sb_s02, sb_s05
        .addr rd_s02, rd_s03
        .addr bm_s01, bm_s05, bm_s09, bm_s10, bm_s17, bm_s19
nt_dst_lo_end:
nt_dst_hi_sites:
        .addr nt_s02, nt_s04, nt_s06, nt_s08, nt_s10
        .addr it_s03, it_s04, it_s07, it_s08, it_s10, it_s12
        .addr sc_s02, sc_s04
        .addr ad_s03, ad_s06
        .addr sb_s04, sb_s06
        .addr rd_s01, rd_s04
        .addr bm_s02, bm_s06, bm_s11, bm_s12, bm_s18, bm_s20
nt_dst_hi_end:
nt_src_lo_sites:
        .addr ad_s02, sb_s01, bm_s03, bm_s07, bm_s13, bm_s14
nt_src_lo_end:
nt_src_hi_sites:
        .addr ad_s04, sb_s03, bm_s04, bm_s08, bm_s15, bm_s16
nt_src_hi_end:

NT_DST_LO_N = (nt_dst_lo_end - nt_dst_lo_sites) / 2
NT_DST_HI_N = (nt_dst_hi_end - nt_dst_hi_sites) / 2
NT_SRC_LO_N = (nt_src_lo_end - nt_src_lo_sites) / 2
NT_SRC_HI_N = (nt_src_hi_end - nt_src_hi_sites) / 2

; =============================================================================
.segment "LIB_MLKEM_BSS"

; Page-aligned tables FIRST (ld65 aligns the whole fragment; odd bytes last).
.align 256
mlkem_r1_lo:    .res 256        ; R1[k] = 256k mod q
mlkem_r1_hi:    .res 256
mlkem_r2_lo:    .res 256        ; R2[k] = 65536k mod q, k <= 181 ever indexed
mlkem_r2_hi:    .res 256
.assert (mlkem_r1_lo .mod 256) = 0, lderror, "mlkem_r1_lo is not page-aligned: LIB_MLKEM_BSS needs align = $100"

; Per-block table U[k] = k * (256b mod q) mod q, k = 0..13, in the unused
; tail of the R2 pages (R2 is only ever indexed up to 181).
fq_u_lo = mlkem_r2_lo + 240
fq_u_hi = mlkem_r2_hi + 240
; The 27-byte |d| quarter-square table, likewise in the free tail (182..239).
fq_sqd  = mlkem_r2_lo + 200
.assert (fq_sqd .mod 256) <= 256 - 27, error, "fq_sqd straddles a page"

nt_len:         .res 1          ; butterfly distance for the current layer
nt_cnt:         .res 1          ; butterflies left in the block
nt_blocks:      .res 1          ; blocks in the current layer
nt_bcnt:        .res 1          ; blocks left
nt_zidx:        .res 1          ; zeta index of the next block
nt_savex:       .res 1          ; X/Y across the multiply (which clobbers both)
nt_savey:       .res 1
bm_r00:         .res 2          ; basemul: x0*y0, x1*y1, (x0+x1)(y0+y1)
bm_r11:         .res 2
bm_m:           .res 2
.ifdef MLKEM_TEST_HOOKS
mlkem_ntt_layer_num: .res 1     ; hook input: layer 0..6
.endif

; =============================================================================
.segment "LIB_MLKEM_CODE"

; -----------------------------------------------------------------------------
; SQPART x, y, olo, ohi — 8x8 -> 16 quarter-square partial x*y over the §8.1
; sqtab: t(x+y) - t(|x-y|). x, y, olo, ohi are zero-page bytes; olo/ohi double
; as scratch. Clobbers A, X, Y. Constant-time: the page bit of x+y goes into
; the patched high address byte (never a branch); |x-y| is (d ^ m) - m with m
; the borrow mask. 76 cycles.
; -----------------------------------------------------------------------------
.macro SQPART xa, ya, olo, ohi
        .local lsite, hsite
        lda xa
        clc
        adc ya                   ; A = (x+y) & $FF, C = page bit
        tax
        lda #>sqtab_lo
        adc #0
        sta lsite+2             ; patch `lda sqtab_lo,x` page
        adc #(>sqtab_hi - >sqtab_lo)    ; C is clear here (base <= $FC00)
        sta hsite+2             ; patch `lda sqtab_hi,x` page
        lda xa
        sec
        sbc ya                   ; d = x - y, C = 1 iff x >= y
        sta olo
        lda #0
        sbc #0                  ; m = $FF iff x < y
        sta ohi
        eor olo
        sec
        sbc ohi                 ; |d| = (d ^ m) - m
        tay
lsite:  lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta olo
hsite:  lda sqtab_hi,x
        sbc sqtab_hi,y
        sta ohi
.endmacro

; -----------------------------------------------------------------------------
; CSUBQ lo, hi, olo, ohi, msk — (lo:hi) < 2q  ->  (olo:ohi) = value mod q.
; Masked, never branched: C = (v < q) from a 16-bit compare, m = C ? 0 : 13,
; then v - [v >= q] - 256*m with the borrow chain intact. 36 cycles.
; -----------------------------------------------------------------------------
.macro CSUBQ lo, hi, olo, ohi, msk
        lda #<(MLKEM_Q - 1)
        cmp lo
        lda #>(MLKEM_Q - 1)
        sbc hi                  ; C = (q-1 >= v) = (v < q)
        lda #0
        sbc #0                  ; A = (v < q) ? $00 : $FF ; C preserved
        and #MLKEM_Q_HI
        sta msk
        lda lo
        sbc #0                  ; lo - [v >= q]
        sta olo
        lda hi
        sbc msk
        sta ohi
.endmacro

; -----------------------------------------------------------------------------
; MODSUB alo, ahi, blo, bhi — fq_p0:fq_p1 = (a - b) mod q for a, b < q.
; Computes ~(b - a - 1) = a - b so the carry out is exactly "a < b", then adds
; q under that mask. Uses fq_px. 52 cycles.
; -----------------------------------------------------------------------------
.macro MODSUB alo, ahi, blo, bhi
        lda blo
        clc
        sbc alo                 ; b - a - 1
        eor #$FF                ; = a - b (low)
        sta fq_p0
        lda bhi
        sbc ahi
        eor #$FF                ; = a - b (high); C = 1 iff a < b
        sta fq_p1
        lda #0
        sbc #0
        eor #$FF
        and #MLKEM_Q_HI         ; 13 iff a < b
        sta fq_px
        lda fq_p0
        adc #0                  ; + [a < b]   (q & $FF = 1)
        sta fq_p0
        lda fq_p1
        adc fq_px
        sta fq_p1
.endmacro

; =============================================================================
; fq_csubq_p — fq_p0:fq_p1 (< 2q) reduced in place. For the cold paths.
; =============================================================================
fq_csubq_p:
        CSUBQ fq_p0, fq_p1, fq_p0, fq_p1, fq_px
        rts

; =============================================================================
; mlkem_fq_mul — general a*b mod q, a and b < q, both secret.
;   in:  fq_a, fq_b      out: fq_r      clobbers: A X Y, fq_p*, fq_e
; =============================================================================
mlkem_fq_mul:
        ; q0 = a1 * b0 (<= 3060), into fq_e
        SQPART fq_a_hi, fq_b_lo, fq_e_lo, fq_e_hi
        ; a1 * b1 (<= 169) straight off the table: sum index <= 26, no page
        ; crossing; the signed difference indexes the |d| table.
        lda fq_a_hi
        clc
        adc fq_b_hi
        tax
        lda fq_a_hi
        sec
        sbc fq_b_hi
        clc
        adc #13
        tay
        lda sqtab_lo,x
        sec
        sbc fq_sqd,y            ; A = a1*b1
        clc
        adc fq_e_hi             ; + hi(q0) <= 12 + 169 = 181, no carry
        tax
        ; E = R1[lo(q0)] + R2[hi(q0) + a1*b1]  (< 2q): the 256*a1*b term
        ldy fq_e_lo
        lda mlkem_r1_lo,y
        clc
        adc mlkem_r2_lo,x
        sta fq_e_lo
        lda mlkem_r1_hi,y
        adc mlkem_r2_hi,x
        sta fq_e_hi
        jmp fq_mul_core

; =============================================================================
; fq_mul_blk — a*b mod q where b is the block constant set by mlkem_fq_setblk.
;   in:  fq_a, fq_b (unchanged since setblk), U table   out: fq_r
; =============================================================================
fq_mul_blk:
        ldx fq_a_hi
        lda fq_u_lo,x
        sta fq_e_lo
        lda fq_u_hi,x
        sta fq_e_hi
        ; fall through

; =============================================================================
; fq_mul_core — fq_r = (a0*b + E) mod q, E < 2q in fq_e.
; =============================================================================
fq_mul_core:
        SQPART fq_a_lo, fq_b_lo, fq_p0, fq_p1           ; p00 = a0*b0
        SQPART fq_a_lo, fq_b_hi, fq_px, fq_p2           ; p01 = a0*b1 (<= 3060)
        lda fq_p1
        clc
        adc fq_px
        sta fq_p1                                       ; P1
        lda fq_p2
        adc #0
        sta fq_p2                                       ; P2 <= 12
        ; V = P0 + R1[P1] + R2[P2] + E   (< 256 + 4q, high byte <= 53)
        ldx fq_p1
        lda mlkem_r1_lo,x
        clc
        adc fq_p0
        sta fq_p0
        lda mlkem_r1_hi,x
        adc #0
        sta fq_p1
        ldx fq_p2
        lda mlkem_r2_lo,x
        clc
        adc fq_p0
        sta fq_p0
        lda mlkem_r2_hi,x
        adc fq_p1
        sta fq_p1
        lda fq_e_lo
        clc
        adc fq_p0
        sta fq_p0
        lda fq_e_hi
        adc fq_p1
        tax                                             ; V1
        ; W = V0 + R1[V1]  (< 256 + q)
        lda mlkem_r1_lo,x
        clc
        adc fq_p0
        sta fq_p0
        lda mlkem_r1_hi,x
        adc #0
        sta fq_p1
        CSUBQ fq_p0, fq_p1, fq_r_lo, fq_r_hi, fq_px
        rts

; =============================================================================
; mlkem_fq_setblk — prepare the block constant b (in fq_b, public):
;   U[k] = k * (256b mod q) mod q for k = 0..13.
; Public data throughout; the loop's timing depends on b only.
; Clobbers A X, fq_p*, fq_e. Preserves fq_b (the multiply reads it).
; =============================================================================
fq_setblk:
        ldx fq_b_lo
        lda mlkem_r1_lo,x
        sta fq_p0
        lda mlkem_r1_hi,x
        sta fq_p1
        ldx fq_b_hi
        lda mlkem_r2_lo,x
        clc
        adc fq_p0
        sta fq_p0
        lda mlkem_r2_hi,x
        adc fq_p1
        sta fq_p1
        jsr fq_csubq_p                  ; w = 256b mod q in fq_p0:fq_p1
        lda #0
        sta fq_u_lo
        sta fq_u_hi
        sta fq_e_lo
        sta fq_e_hi
        ldx #1
fqsb_loop:
        lda fq_e_lo
        clc
        adc fq_p0
        sta fq_e_lo
        lda fq_e_hi
        adc fq_p1
        sta fq_e_hi
        ; conditional subtract of q on PUBLIC data (k * w, both public), so a
        ; branch is fine here: the path depends on zeta only, never on a
        ; coefficient. Do not copy this shape into anything secret.
        lda fq_e_lo
        sec
        sbc #<MLKEM_Q
        tay
        lda fq_e_hi
        sbc #>MLKEM_Q
        bcc :+
        sta fq_e_hi
        sty fq_e_lo
:       lda fq_e_lo
        sta fq_u_lo,x
        lda fq_e_hi
        sta fq_u_hi,x
        inx
        cpx #14
        bne fqsb_loop
        rts

; =============================================================================
; nt_patch_dst / nt_patch_src — patch the plane-access sites from the pointer.
; High byte only (see the header). ~40 cycles per site.
; =============================================================================
nt_patch_dst:
        lda mlkem_zp_dst+1
        sta fq_a_lo
        lda #<nt_dst_lo_sites
        sta fq_r_lo
        lda #>nt_dst_lo_sites
        sta fq_r_hi
        ldx #NT_DST_LO_N
        jsr nt_patch
        inc fq_a_lo                     ; high plane = +$100
        lda #<nt_dst_hi_sites
        sta fq_r_lo
        lda #>nt_dst_hi_sites
        sta fq_r_hi
        ldx #NT_DST_HI_N
        jmp nt_patch

nt_patch_src:
        lda mlkem_zp_src+1
        sta fq_a_lo
        lda #<nt_src_lo_sites
        sta fq_r_lo
        lda #>nt_src_lo_sites
        sta fq_r_hi
        ldx #NT_SRC_LO_N
        jsr nt_patch
        inc fq_a_lo
        lda #<nt_src_hi_sites
        sta fq_r_lo
        lda #>nt_src_hi_sites
        sta fq_r_hi
        ldx #NT_SRC_HI_N
        ; fall through

; list pointer in fq_r, X = entries, byte in fq_a_lo -> site+2
nt_patch:
ntp_loop:
        ldy #0
        lda (fq_r_lo),y
        sta fq_p0
        iny
        lda (fq_r_lo),y
        sta fq_p1
        ldy #2
        lda fq_a_lo
        sta (fq_p0),y
        lda fq_r_lo
        clc
        adc #2
        sta fq_r_lo
        bcc :+
        inc fq_r_hi
:       dex
        bne ntp_loop
        rts

; =============================================================================
; nt_fetch_zeta — b = zetas[nt_zidx], build its block table.
; =============================================================================
nt_fetch_zeta:
        ldy nt_zidx
        lda mlkem_zetas_lo,y
        sta fq_b_lo
        lda mlkem_zetas_hi,y
        sta fq_b_hi
        jmp fq_setblk

; =============================================================================
; ntt_layer_run — one forward layer (Alg. 9, one value of len) in place.
;   nt_len = len, nt_blocks = 256 / (2 len), nt_zidx = first zeta index.
;   Butterfly (X = j, Y = j + len):  t = zeta * f[Y]
;                                    f[Y] = f[X] - t ;  f[X] = f[X] + t
; =============================================================================
ntt_layer_run:
        lda nt_blocks
        sta nt_bcnt
        ldx #0
ntl_block:
        stx nt_savex
        jsr nt_fetch_zeta
        inc nt_zidx
        ldx nt_savex
        txa
        clc
        adc nt_len
        tay                             ; Y = j + len
        lda nt_len
        sta nt_cnt
ntl_bf:
        ; a = f[Y]
nt_s01: lda $FF00,y
        sta fq_a_lo
nt_s02: lda $FF00,y
        sta fq_a_hi
        stx nt_savex
        sty nt_savey
        jsr fq_mul_blk                  ; t -> fq_r
        ldx nt_savex
        ldy nt_savey
        ; d = f[X] - t (mod q) -> fq_px:fq_p2, via ~(t - f[X] - 1); C = f[X] < t
        lda fq_r_lo
        clc
nt_s03: sbc $FF00,x
        eor #$FF
        sta fq_px
        lda fq_r_hi
nt_s04: sbc $FF00,x
        eor #$FF
        sta fq_p2
        lda #0
        sbc #0
        eor #$FF
        and #MLKEM_Q_HI
        sta fq_e_hi                     ; 13 iff f[X] < t (E is dead here)
        lda fq_px
        adc #0
        sta fq_px
        lda fq_p2
        adc fq_e_hi
        sta fq_p2
        ; s = f[X] + t (mod q) -> f[X]
        lda fq_r_lo
        clc
nt_s05: adc $FF00,x
        sta fq_p0
        lda fq_r_hi
nt_s06: adc $FF00,x
        sta fq_p1
        lda #<(MLKEM_Q - 1)
        cmp fq_p0
        lda #>(MLKEM_Q - 1)
        sbc fq_p1
        lda #0
        sbc #0
        and #MLKEM_Q_HI
        sta fq_e_lo
        lda fq_p0
        sbc #0
nt_s07: sta $FF00,x
        lda fq_p1
        sbc fq_e_lo
nt_s08: sta $FF00,x
        ; f[Y] = d
        lda fq_px
nt_s09: sta $FF00,y
        lda fq_p2
nt_s10: sta $FF00,y
        inx
        iny
        dec nt_cnt
        beq :+
        jmp ntl_bf
:       tya                             ; next block starts at j + 2 len
        tax
        dec nt_bcnt
        beq :+
        jmp ntl_block
:       rts

; =============================================================================
; intt_layer_run — one inverse layer (Alg. 10, one value of len) in place,
; WITHOUT the 128^-1 scaling.
;   nt_len = len, nt_blocks = 256 / (2 len), nt_zidx = first zeta index
;   (counting DOWN, one per block).
;   Butterfly (X = j, Y = j + len):  t = f[X]
;                                    f[X] = t + f[Y] ;  f[Y] = zeta * (f[Y] - t)
; =============================================================================
intt_layer_run:
        lda nt_blocks
        sta nt_bcnt
        ldx #0
itl_block:
        stx nt_savex
        jsr nt_fetch_zeta
        dec nt_zidx
        ldx nt_savex
        txa
        clc
        adc nt_len
        tay
        lda nt_len
        sta nt_cnt
itl_bf:
        ; a = f[Y] - f[X] (mod q), via ~(f[X] - f[Y] - 1); C = f[Y] < f[X]
it_s01: lda $FF00,x
        clc
it_s02: sbc $FF00,y
        eor #$FF
        sta fq_a_lo
it_s03: lda $FF00,x
it_s04: sbc $FF00,y
        eor #$FF
        sta fq_a_hi
        lda #0
        sbc #0
        eor #$FF
        and #MLKEM_Q_HI
        sta fq_e_hi
        lda fq_a_lo
        adc #0
        sta fq_a_lo
        lda fq_a_hi
        adc fq_e_hi
        sta fq_a_hi
        ; s = f[X] + f[Y] (mod q) -> f[X]
it_s05: lda $FF00,x
        clc
it_s06: adc $FF00,y
        sta fq_p0
it_s07: lda $FF00,x
it_s08: adc $FF00,y
        sta fq_p1
        lda #<(MLKEM_Q - 1)
        cmp fq_p0
        lda #>(MLKEM_Q - 1)
        sbc fq_p1
        lda #0
        sbc #0
        and #MLKEM_Q_HI
        sta fq_e_lo
        lda fq_p0
        sbc #0
it_s09: sta $FF00,x
        lda fq_p1
        sbc fq_e_lo
it_s10: sta $FF00,x
        ; f[Y] = zeta * a
        stx nt_savex
        sty nt_savey
        jsr fq_mul_blk
        ldx nt_savex
        ldy nt_savey
        lda fq_r_lo
it_s11: sta $FF00,y
        lda fq_r_hi
it_s12: sta $FF00,y
        inx
        iny
        dec nt_cnt
        beq :+
        jmp itl_bf
:       tya
        tax
        dec nt_bcnt
        beq :+
        jmp itl_block
:       rts

; =============================================================================
; mlkem_poly_ntt — (dst) <- NTT(dst), FIPS 203 Alg. 9. Canonical output.
; =============================================================================
mlkem_poly_ntt:
        jsr nt_patch_dst
        lda #128
        sta nt_len
        lda #1
        sta nt_blocks
        sta nt_zidx
@layer:
        jsr ntt_layer_run
        ; next layer: len /= 2, blocks *= 2 (= the zeta index we are now at)
        lda nt_zidx
        sta nt_blocks
        lsr nt_len
        lda nt_len
        cmp #1
        bne @layer
        rts

; =============================================================================
; mlkem_poly_intt — (dst) <- NTT^-1(dst), FIPS 203 Alg. 10 including the
; final 128^-1 = 3303 scaling. Canonical output.
; =============================================================================
mlkem_poly_intt:
        jsr nt_patch_dst
        lda #2
        sta nt_len
        lda #64
        sta nt_blocks
        lda #127
        sta nt_zidx
pi_layer:
        jsr intt_layer_run
        lsr nt_blocks
        asl nt_len                      ; 2 .. 128, then 0: done
        bne pi_layer
        ; scale every coefficient by 128^-1 (a public block constant)
        lda #<MLKEM_N_INV
        sta fq_b_lo
        lda #>MLKEM_N_INV
        sta fq_b_hi
        jsr fq_setblk
        ldx #0
pi_scale:
sc_s01: lda $FF00,x
        sta fq_a_lo
sc_s02: lda $FF00,x
        sta fq_a_hi
        stx nt_savex
        jsr fq_mul_blk
        ldx nt_savex
        lda fq_r_lo
sc_s03: sta $FF00,x
        lda fq_r_hi
sc_s04: sta $FF00,x
        inx
        bne pi_scale
        rts

; =============================================================================
; mlkem_poly_basemul — (dst) <- MultiplyNTTs(dst, src), FIPS 203 Alg. 11/12.
; Pair p = (2p, 2p+1), gamma_p = zetas[64 + p/2] for even p, q - that for odd
; (the generator asserts this identity), so the zeta table's top half serves
; and the odd pairs subtract. Karatsuba over the pair:
;     c0 = x0 y0 +/- zeta * (x1 y1)
;     c1 = (x0 + x1)(y0 + y1) - x0 y0 - x1 y1
; four general multiplies per pair instead of five. Every product is reduced
; to [0, q) before it is combined (S4: no unreduced 24-bit accumulation).
; The parity branch is on the public index.
; =============================================================================
mlkem_poly_basemul:
        jsr nt_patch_dst
        jsr nt_patch_src
        ldx #0
bm_pair:
        stx nt_savex
        ; r00 = x0 * y0
bm_s01: lda $FF00,x
        sta fq_a_lo
bm_s02: lda $FF00,x
        sta fq_a_hi
bm_s03: lda $FF00,x
        sta fq_b_lo
bm_s04: lda $FF00,x
        sta fq_b_hi
        jsr mlkem_fq_mul
        lda fq_r_lo
        sta bm_r00
        lda fq_r_hi
        sta bm_r00+1
        ldx nt_savex
        ; r11 = x1 * y1
bm_s05: lda $FF01,x
        sta fq_a_lo
bm_s06: lda $FF01,x
        sta fq_a_hi
bm_s07: lda $FF01,x
        sta fq_b_lo
bm_s08: lda $FF01,x
        sta fq_b_hi
        jsr mlkem_fq_mul
        lda fq_r_lo
        sta bm_r11
        lda fq_r_hi
        sta bm_r11+1
        ldx nt_savex
        ; m = (x0 + x1)(y0 + y1), both sums reduced first
bm_s09: lda $FF00,x
        clc
bm_s10: adc $FF01,x
        sta fq_p0
bm_s11: lda $FF00,x
bm_s12: adc $FF01,x
        sta fq_p1
        jsr fq_csubq_p
        lda fq_p0
        sta fq_a_lo
        lda fq_p1
        sta fq_a_hi
bm_s13: lda $FF00,x
        clc
bm_s14: adc $FF01,x
        sta fq_p0
bm_s15: lda $FF00,x
bm_s16: adc $FF01,x
        sta fq_p1
        jsr fq_csubq_p
        lda fq_p0
        sta fq_b_lo
        lda fq_p1
        sta fq_b_hi
        jsr mlkem_fq_mul
        lda fq_r_lo
        sta bm_m
        lda fq_r_hi
        sta bm_m+1
        ldx nt_savex
        ; g = zeta * r11, zeta = zetas[64 + X/4]
        txa
        lsr
        lsr
        ora #64
        tay
        lda mlkem_zetas_lo,y
        sta fq_b_lo
        lda mlkem_zetas_hi,y
        sta fq_b_hi
        lda bm_r11
        sta fq_a_lo
        lda bm_r11+1
        sta fq_a_hi
        jsr mlkem_fq_mul                ; g -> fq_r
        ldx nt_savex
        ; c0 = r00 + g (even pair) or r00 - g (odd pair)
        txa
        and #2
        bne bm_odd
        lda bm_r00
        clc
        adc fq_r_lo
        sta fq_p0
        lda bm_r00+1
        adc fq_r_hi
        sta fq_p1
        jsr fq_csubq_p
        jmp bm_c0
bm_odd:
        MODSUB bm_r00, bm_r00+1, fq_r_lo, fq_r_hi
bm_c0:
        lda fq_p0
bm_s17: sta $FF00,x
        lda fq_p1
bm_s18: sta $FF00,x
        ; c1 = m - r00 - r11
        MODSUB bm_m, bm_m+1, bm_r00, bm_r00+1
        lda fq_p0
        sta bm_m
        lda fq_p1
        sta bm_m+1
        MODSUB bm_m, bm_m+1, bm_r11, bm_r11+1
        lda fq_p0
bm_s19: sta $FF01,x
        lda fq_p1
bm_s20: sta $FF01,x
        inx
        inx
        beq :+
        jmp bm_pair
:       rts

; =============================================================================
; mlkem_poly_add — (dst) <- dst + src mod q.   256 iterations: inx/bne, never
; a bpl count-down (P1's keccak_clear bug shape).
; =============================================================================
mlkem_poly_add:
        jsr nt_patch_dst
        jsr nt_patch_src
        ldx #0
pa_loop:
ad_s01: lda $FF00,x
        clc
ad_s02: adc $FF00,x
        sta fq_p0
ad_s03: lda $FF00,x
ad_s04: adc $FF00,x
        sta fq_p1
        jsr fq_csubq_p
        lda fq_p0
ad_s05: sta $FF00,x
        lda fq_p1
ad_s06: sta $FF00,x
        inx
        bne pa_loop
        rts

; =============================================================================
; mlkem_poly_sub — (dst) <- dst - src mod q, wrapping to dst - src + q (S3).
; =============================================================================
mlkem_poly_sub:
        jsr nt_patch_dst
        jsr nt_patch_src
        ldx #0
ps_loop:
        ; ~(src - dst - 1) = dst - src; C = dst < src
sb_s01: lda $FF00,x
        clc
sb_s02: sbc $FF00,x
        eor #$FF
        sta fq_p0
sb_s03: lda $FF00,x
sb_s04: sbc $FF00,x
        eor #$FF
        sta fq_p1
        lda #0
        sbc #0
        eor #$FF
        and #MLKEM_Q_HI
        sta fq_px
        lda fq_p0
        adc #0
sb_s05: sta $FF00,x
        lda fq_p1
        adc fq_px
sb_s06: sta $FF00,x
        inx
        bne ps_loop
        rts

; =============================================================================
; mlkem_poly_reduce — (dst) <- dst mod q for any unsigned 16-bit input (S2):
; v mod q = (v_lo + R1[v_hi]) mod q, the sum < 256 + q.
; =============================================================================
mlkem_poly_reduce:
        jsr nt_patch_dst
        ldx #0
pr_loop:
rd_s01: lda $FF00,x
        tay
        lda mlkem_r1_lo,y
        clc
rd_s02: adc $FF00,x
        sta fq_p0
        lda mlkem_r1_hi,y
        adc #0
        sta fq_p1
        jsr fq_csubq_p
        lda fq_p0
rd_s03: sta $FF00,x
        lda fq_p1
rd_s04: sta $FF00,x
        inx
        bne pr_loop
        rts

; =============================================================================
; mlkem_arith_init — build R1 / R2 in LIB_MLKEM_BSS. Idempotent; call once at
; boot, after nothing in particular (it does not read sqtab). Public data.
;   R1[k] = 256k mod q      (step 256)
;   R2[k] = 65536k mod q    (step 2^16 mod q = MLKEM_MONT_R)
; =============================================================================
mlkem_arith_init:
        lda #0
        sta fq_p0
        sta fq_p1
        tax
@r1:
        lda fq_p0
        sta mlkem_r1_lo,x
        lda fq_p1
        sta mlkem_r1_hi,x
        inc fq_p1                       ; += 256
        jsr fq_csubq_p
        inx
        bne @r1
        lda #0
        sta fq_p0
        sta fq_p1
@r2:
        lda fq_p0
        sta mlkem_r2_lo,x
        lda fq_p1
        sta mlkem_r2_hi,x
        lda fq_p0
        clc
        adc #<MLKEM_MONT_R
        sta fq_p0
        lda fq_p1
        adc #>MLKEM_MONT_R
        sta fq_p1
        jsr fq_csubq_p
        inx
        bne @r2
        ; the |d| table into its page-aligned home
        ldx #26
@sqd:
        lda mlkem_sqd_src,x
        sta fq_sqd,x
        dex
        bpl @sqd                        ; 27 entries: bit 7 of 26 is clear
        rts

; =============================================================================
; Test hooks: one layer at a time, for the differential harness.
;   mlkem_ntt_layer:  L = 0 is len 128 (zeta 1) ... L = 6 is len 2.
;   mlkem_intt_layer: L = 0 is len 2 (zetas 127..64) ... L = 6 is len 128
;                     (zeta 1), EXCLUDING the final 3303 scaling.
; =============================================================================
.ifdef MLKEM_TEST_HOOKS
mlkem_ntt_layer:
        jsr nt_patch_dst
        ldx mlkem_ntt_layer_num
        lda #128
        sta nt_len
        lda #1
        sta nt_blocks
@shift:
        cpx #0
        beq @go
        lsr nt_len
        asl nt_blocks
        dex
        jmp @shift
@go:
        lda nt_blocks
        sta nt_zidx
        jmp ntt_layer_run

mlkem_intt_layer:
        jsr nt_patch_dst
        ldx mlkem_ntt_layer_num
        lda #2
        sta nt_len
        lda #64
        sta nt_blocks
        lda #128
        sta nt_zidx
@shift:
        cpx #0
        beq @go
        asl nt_len
        lsr nt_blocks
        lsr nt_zidx
        dex
        jmp @shift
@go:
        dec nt_zidx                     ; (128 >> L) - 1
        jmp intt_layer_run
.endif
