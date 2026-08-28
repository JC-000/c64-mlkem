.setcpu "6502"

; =============================================================================
; codec.s — ML-KEM codecs: ByteEncode12 / ByteDecode12 (FIPS 203 Alg. 5/6,
; d = 12) and Compress_d / Decompress_d (§4.2.1 eq. 4.7 / 4.8) for d = 1, 4, 10.
;
; Polynomial layout and calling convention: see src/sample.s (split-plane 512 B;
; input at (mlkem_zp_src), output at (mlkem_zp_dst); clobbers A/X/Y,
; mlkem_zp_tmp, mlkem_zp_len). Every routine writes all 512 output bytes (the
; high plane of a compressed poly is written as zero, never left stale) and
; nothing past them.
;
; CONSTANT TIME. Compress runs on secret polynomials in K-PKE.Encrypt (u, v),
; Decompress_1 on the secret message m, ByteEncode12 on the secret key. None
; of them contains a data-dependent branch: the only branches are the fixed-
; count loops, every carry is folded with `adc #0`, and every table indexed
; by a data byte is asserted not to straddle a page (an `abs,x` page cross is
; +1 cycle). ByteDecode12 and the other Decompress_d take public data but use
; the same shape anyway.
;
; --- Compress_d: y = floor((2^d * x + q/2) / q) mod 2^d ---------------------
;
; The division by q = 3329 is done as ESTIMATE + BRANCH-FREE CORRECTIONS,
; with no multiply and 108 bytes of tables in total:
;
;   v   = (x << d) + 1664                      (24-bit; x < q, so v < 2^22)
;   y_e = T_hi_d[x >> 8] + T_lo[(x & 255) >> 2]
;         where T_hi_d[h] = floor(h * 256 * 2^d / q)  (14 entries per d)
;         and   T_lo[m]   = floor(m * 4 * 1024 / q)   (64 entries, d = 10 only;
;                                                      d = 1, 4 index entry 0 = 0)
;   repeat K_d times:  y += (v >= q * (y_e + 1 + n)),  n = 0, 1, ...
;
; Both table terms are floors of a split of x * 2^d / q, so y_e never exceeds
; the true quotient, and the deficit is bounded by the two dropped fractions,
; the two dropped low bits of x (d = 10: 3 * 1024/q) and the +1664/q rounding
; term: < 2 + 0.93 + 0.5, so K = 3 corrections suffice for d = 10, and
; K = 2 for d = 4 (no T_lo: 255 * 16/q = 1.23) and d = 1 (y_e = 0, y <= 2).
; Verified exhaustively for every x in [0, q) and every d before this was
; written; the bound is tight (the third correction fires for d = 10). The
; corrections are a fixed-count loop of 24-bit compare / carry-add, so the
; cost is identical for every input.
;
; The multiply by q inside the correction uses q = 13 * 256 + 1:
;   q * y1 = ((13 * y1) << 8) + y1,  13 * y1 = ((3 * y1) << 2) + y1.
;
; --- Decompress_d: x = floor((q * y + 2^(d-1)) / 2^d) --------------------------
;
; Same q-multiply, then a right shift by d done as a byte select (d = 10 drops
; a whole byte first) plus a short fixed-count bit shift. Output is < q for
; every d-bit input by construction (max is round(q - q/2^d) < q).
;
; The three d-specific entry points each load a 7-byte parameter block into
; BSS and share one generic body, so there is exactly one implementation of
; the arithmetic to get right.
; =============================================================================

.include "constants.s"

.importzp mlkem_zp_src, mlkem_zp_dst, mlkem_zp_tmp, mlkem_zp_len

.export mlkem_byte_encode_12, mlkem_byte_decode_12
.export mlkem_compress_1, mlkem_compress_4, mlkem_compress_10
.export mlkem_decompress_1, mlkem_decompress_4, mlkem_decompress_10

MLKEM_Q         = 3329
MLKEM_Q_LO      = $01
MLKEM_Q_HI      = $0D
MLKEM_Q_HALF    = 1664          ; (q - 1) / 2: the round-half-up offset
PAIRS_12        = 128           ; ByteEncode12 handles two coefficients per 3 bytes

; =============================================================================
.segment "LIB_MLKEM_RODATA"

; Compress parameter blocks, 7 bytes each:
;   +0 bit shifts applied to v after the byte placement
;   +1 byte placement: 0 -> v = [lo, hi, 0]; 1 -> v = [0, lo, hi] (a << 8)
;   +2 T_lo index mask (63 for d = 10, 0 otherwise -> entry 0 = 0)
;   +3 T_hi table base (14 entries per d)
;   +4 K, number of corrections
;   +5 / +6 output mask (2^d - 1), lo / hi
cp_params:
        .byte 1, 0,  0,  0, 2, $01, $00     ; d = 1
        .byte 4, 0,  0, 14, 2, $0F, $00     ; d = 4
        .byte 2, 1, 63, 28, 3, $FF, $03     ; d = 10  (<< 8 then << 2)

; Decompress parameter blocks, 4 bytes each:
;   +0 bit shifts, +1 byte select (1 -> drop the low byte first),
;   +2 / +3 rounding constant 2^(d-1), lo / hi
dc_params:
        .byte 1, 0, $01, $00                ; d = 1
        .byte 4, 0, $08, $00                ; d = 4
        .byte 2, 1, $00, $02                ; d = 10

; T_hi_d[h] = floor(h * 256 * 2^d / q), h = 0..13 (x < q => x >> 8 <= 13).
; All three d share one lo-byte table and one hi-byte table, indexed by
; 14 * d_index + h. Computed by the assembler from the definition.
cp_thi_lo:
.repeat 14, h
        .byte <((h * 256 * 2) / MLKEM_Q)
.endrepeat
.repeat 14, h
        .byte <((h * 256 * 16) / MLKEM_Q)
.endrepeat
.repeat 14, h
        .byte <((h * 256 * 1024) / MLKEM_Q)
.endrepeat
cp_thi_hi:
.repeat 14, h
        .byte >((h * 256 * 2) / MLKEM_Q)
.endrepeat
.repeat 14, h
        .byte >((h * 256 * 16) / MLKEM_Q)
.endrepeat
.repeat 14, h
        .byte >((h * 256 * 1024) / MLKEM_Q)
.endrepeat

; T_lo[m] = floor(m * 4 * 1024 / q), m = 0..63 (d = 10; max 77 fits a byte).
cp_tlo:
.repeat 64, m
        .byte <((m * 4 * 1024) / MLKEM_Q)
.endrepeat

; Secret-indexed tables must not straddle a page (see the header).
.assert >cp_thi_lo = >(cp_thi_lo + 41), lderror, "cp_thi_lo straddles a page: compress cost would depend on secret data"
.assert >cp_thi_hi = >(cp_thi_hi + 41), lderror, "cp_thi_hi straddles a page: compress cost would depend on secret data"
.assert >cp_tlo = >(cp_tlo + 63), lderror, "cp_tlo straddles a page: compress cost would depend on secret data"

; =============================================================================
.segment "LIB_MLKEM_BSS"

; parameter block (compress: 7 bytes; decompress reuses the first 4)
cp_shift:       .res 1
cp_pre:         .res 1
cp_lomask:      .res 1
cp_hibase:      .res 1
cp_k:           .res 1
cp_mask_lo:     .res 1
cp_mask_hi:     .res 1

cp_xlo:         .res 1              ; the coefficient being processed
cp_xhi:         .res 1
cp_v:           .res 3              ; 24-bit numerator
cp_y:           .res 2              ; quotient estimate / result
mk_in:          .res 2              ; mul13 input  (y + 1 or y)
mk_p:           .res 2              ; mul13 output (13 * input)
cp_w:           .res 3              ; running q * (y_e + 1 + n)
cd_k:           .res 1              ; encode/decode pair index
cd_a:           .res 2              ; coefficient a (lo, hi)
cd_b:           .res 2              ; coefficient b (lo, hi)
cd_t:           .res 1

; =============================================================================
.segment "LIB_MLKEM_CODE"

; -----------------------------------------------------------------------------
; hi_planes — mlkem_zp_tmp = mlkem_zp_src + 256, mlkem_zp_len = mlkem_zp_dst + 256
; -----------------------------------------------------------------------------
.proc hi_planes
        lda mlkem_zp_src+0
        sta mlkem_zp_tmp+0
        lda mlkem_zp_src+1
        clc
        adc #1
        sta mlkem_zp_tmp+1
        lda mlkem_zp_dst+0
        sta mlkem_zp_len+0
        lda mlkem_zp_dst+1
        clc
        adc #1
        sta mlkem_zp_len+1
        rts
.endproc

; -----------------------------------------------------------------------------
; mul13 — mk_p = 13 * mk_in (16-bit; input <= 1101, so no overflow)
;   13 * a = ((2a + a) << 2) + a
; -----------------------------------------------------------------------------
.proc mul13
        lda mk_in+0
        asl
        sta mk_p+0
        lda mk_in+1
        rol
        sta mk_p+1                  ; 2a
        lda mk_p+0
        clc
        adc mk_in+0
        sta mk_p+0
        lda mk_p+1
        adc mk_in+1
        sta mk_p+1                  ; 3a
        asl mk_p+0
        rol mk_p+1
        asl mk_p+0
        rol mk_p+1                  ; 12a
        lda mk_p+0
        clc
        adc mk_in+0
        sta mk_p+0
        lda mk_p+1
        adc mk_in+1
        sta mk_p+1                  ; 13a
        rts
.endproc

; =============================================================================
; Compress_d entry points: X = parameter block offset.
; =============================================================================
.proc mlkem_compress_1
        ldx #0
        jmp compress_common
.endproc

.proc mlkem_compress_4
        ldx #7
        jmp compress_common
.endproc

.proc mlkem_compress_10
        ldx #14
        jmp compress_common
.endproc

.proc compress_common
        ldy #0
:       lda cp_params,x
        sta cp_shift,y
        inx
        iny
        cpy #7
        bne :-
        jsr hi_planes

        ldy #0                      ; coefficient index
coef:
        ; --- v = x placed per cp_pre, then << cp_shift, then + 1664 --------
        ldx cp_pre
        lda #0
        sta cp_v+0
        sta cp_v+2
        lda (mlkem_zp_src),y
        sta cp_xlo
        sta cp_v+0,x
        lda (mlkem_zp_tmp),y
        sta cp_xhi
        sta cp_v+1,x
        ldx cp_shift
:       asl cp_v+0
        rol cp_v+1
        rol cp_v+2
        dex
        bne :-
        lda cp_v+0
        clc
        adc #<MLKEM_Q_HALF
        sta cp_v+0
        lda cp_v+1
        adc #>MLKEM_Q_HALF
        sta cp_v+1
        lda cp_v+2
        adc #0
        sta cp_v+2

        ; --- y_e = T_lo[(xlo >> 2) & lomask] + T_hi[hibase + xhi] ----------
        lda cp_xlo
        lsr
        lsr
        and cp_lomask
        tax
        lda cp_tlo,x
        sta cp_y+0
        lda cp_xhi
        clc
        adc cp_hibase
        tax
        lda cp_thi_lo,x
        clc
        adc cp_y+0
        sta cp_y+0
        lda cp_thi_hi,x
        adc #0
        sta cp_y+1

        ; --- w = q * (y_e + 1) = ((13 * y1) << 8) + y1 ----------------------
        lda cp_y+0
        clc
        adc #1
        sta mk_in+0
        lda cp_y+1
        adc #0
        sta mk_in+1
        jsr mul13
        lda mk_in+0
        sta cp_w+0
        lda mk_in+1
        clc
        adc mk_p+0
        sta cp_w+1
        lda mk_p+1
        adc #0
        sta cp_w+2

        ; --- K times: y += (v >= w); w += q  (branch-free) -----------------
        ldx cp_k
corr:
        sec
        lda cp_v+0
        sbc cp_w+0
        lda cp_v+1
        sbc cp_w+1
        lda cp_v+2
        sbc cp_w+2                  ; C = (v >= w)
        lda cp_y+0
        adc #0
        sta cp_y+0
        lda cp_y+1
        adc #0
        sta cp_y+1
        lda cp_w+0
        clc
        adc #MLKEM_Q_LO
        sta cp_w+0
        lda cp_w+1
        adc #MLKEM_Q_HI
        sta cp_w+1
        lda cp_w+2
        adc #0
        sta cp_w+2
        dex
        bne corr

        ; --- store y mod 2^d --------------------------------------------------
        lda cp_y+0
        and cp_mask_lo
        sta (mlkem_zp_dst),y
        lda cp_y+1
        and cp_mask_hi
        sta (mlkem_zp_len),y
        iny
        beq done                    ; body is longer than a branch reaches
        jmp coef
done:
        rts
.endproc

; =============================================================================
; Decompress_d entry points: X = parameter block offset.
; =============================================================================
.proc mlkem_decompress_1
        ldx #0
        jmp decompress_common
.endproc

.proc mlkem_decompress_4
        ldx #4
        jmp decompress_common
.endproc

.proc mlkem_decompress_10
        ldx #8
        jmp decompress_common
.endproc

.proc decompress_common
        ldy #0
:       lda dc_params,x
        sta cp_shift,y              ; cp_shift, cp_pre (= byte select), cp_lomask/cp_hibase (= round lo/hi)
        inx
        iny
        cpy #4
        bne :-
        jsr hi_planes

        ldy #0
coef:
        lda (mlkem_zp_src),y
        sta mk_in+0
        lda (mlkem_zp_tmp),y
        sta mk_in+1
        jsr mul13                   ; mk_p = 13 * y

        ; v = y + round + (13 * y) << 8 ; y + round < 2^16, so no carry out
        lda mk_in+0
        clc
        adc cp_lomask               ; round lo
        sta cp_v+0
        lda mk_in+1
        adc cp_hibase               ; round hi
        clc
        adc mk_p+0
        sta cp_v+1
        lda mk_p+1
        adc #0
        sta cp_v+2

        ; r = v[sel .. sel+1] >> shift
        ldx cp_pre
        lda cp_v+0,x
        sta cp_y+0
        lda cp_v+1,x
        sta cp_y+1
        ldx cp_shift
:       lsr cp_y+1
        ror cp_y+0
        dex
        bne :-

        lda cp_y+0
        sta (mlkem_zp_dst),y
        lda cp_y+1
        sta (mlkem_zp_len),y
        iny
        bne coef
        rts
.endproc

; =============================================================================
; mlkem_byte_encode_12 — polynomial at (src) -> 384 bytes at (dst).
;   Pair (a, b) -> [a.lo, a.hi | b.lo << 4, b.lo >> 4 | b.hi << 4]
; Coefficients are 12-bit values (< q on the encrypt path; raw fields up to
; 4095 round-trip through decode/encode, which the tests pin).
; =============================================================================
.proc mlkem_byte_encode_12
        jsr hi_planes               ; tmp = src hi plane (len unused)
        lda #0
        sta cd_k
pair:
        lda cd_k
        asl
        tay                         ; Y = 2k
        lda (mlkem_zp_src),y
        sta cd_a+0
        lda (mlkem_zp_tmp),y
        sta cd_a+1
        iny
        lda (mlkem_zp_src),y
        sta cd_b+0
        lda (mlkem_zp_tmp),y
        sta cd_b+1

        ldy #0
        lda cd_a+0
        sta (mlkem_zp_dst),y
        iny
        lda cd_b+0
        asl
        asl
        asl
        asl
        sta cd_t
        lda cd_a+1
        and #$0F
        ora cd_t
        sta (mlkem_zp_dst),y
        iny
        lda cd_b+1
        asl
        asl
        asl
        asl
        sta cd_t
        lda cd_b+0
        lsr
        lsr
        lsr
        lsr
        ora cd_t
        sta (mlkem_zp_dst),y

        ; dst += 3 (branch-free carry)
        lda mlkem_zp_dst+0
        clc
        adc #3
        sta mlkem_zp_dst+0
        lda mlkem_zp_dst+1
        adc #0
        sta mlkem_zp_dst+1

        inc cd_k
        lda cd_k
        cmp #PAIRS_12               ; cmp, not bpl: 128 has bit 7 set
        bne pair
        rts
.endproc

; =============================================================================
; mlkem_byte_decode_12 — 384 bytes at (src) -> polynomial at (dst).
;   [c0, c1, c2] -> a = c0 | (c1 & $0F) << 8,  b = c1 >> 4 | c2 << 4
; RAW unpack: a 12-bit field >= q is written as-is, unreduced (pinned
; behaviour, see tools/test_sampler.py; the < q check on an ek is the
; caller's, per FIPS 203 §7.2).
; =============================================================================
.proc mlkem_byte_decode_12
        jsr hi_planes               ; len = dst hi plane (tmp unused)
        lda #0
        sta cd_k
triple:
        ldy #0
        lda (mlkem_zp_src),y
        sta cd_a+0
        iny
        lda (mlkem_zp_src),y
        sta cd_t
        and #$0F
        sta cd_a+1
        lda cd_t
        lsr
        lsr
        lsr
        lsr
        sta cd_b+0
        iny
        lda (mlkem_zp_src),y
        sta cd_t
        asl
        asl
        asl
        asl
        ora cd_b+0
        sta cd_b+0
        lda cd_t
        lsr
        lsr
        lsr
        lsr
        sta cd_b+1

        lda cd_k
        asl
        tay                         ; Y = 2k
        lda cd_a+0
        sta (mlkem_zp_dst),y
        lda cd_a+1
        sta (mlkem_zp_len),y
        iny
        lda cd_b+0
        sta (mlkem_zp_dst),y
        lda cd_b+1
        sta (mlkem_zp_len),y

        lda mlkem_zp_src+0
        clc
        adc #3
        sta mlkem_zp_src+0
        lda mlkem_zp_src+1
        adc #0
        sta mlkem_zp_src+1

        inc cd_k
        lda cd_k
        cmp #PAIRS_12
        bne triple
        rts
.endproc
