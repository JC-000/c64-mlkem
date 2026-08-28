.setcpu "6502"

; =============================================================================
; sample.s — ML-KEM samplers (FIPS 203 Alg. 7 SampleNTT, Alg. 8 SamplePolyCBD
; with eta = 2).
;
; POLYNOMIAL LAYOUT (declared once in src/mlkem.inc, mirrored by
; tools/mlkem_ref.py poly_to_c64): split-plane, 512 bytes — 256 low bytes then
; 256 high bytes, page-aligned. Coefficient i is (base),i / (base+256),i, so a
; routine walks both planes with ONE index register and two ZP pointers that
; differ only in their high byte.
;
; CALLING CONVENTION (the P1 sponge's): input at (mlkem_zp_src), output at
; (mlkem_zp_dst); both are set by the caller before every call and are NOT
; preserved. Clobbers A/X/Y, mlkem_zp_tmp, mlkem_zp_len, mlkem_sponge_len.
;
; mlkem_sample_ntt
;   Rejection sampling over the LIVE SHAKE128 stream. The caller has already
;   run mlkem_shake128_init and absorbed rho || j || i; this routine's only
;   input is the sponge state. It squeezes one 168-byte rate block at a time
;   into a private buffer and consumes it in 3-byte units, so the stream
;   position carries across blocks exactly as in the model (3 blocks usually,
;   4 sometimes — the block count is data-dependent by construction, and rho
;   is public, so that is the one legitimately data-dependent loop in P2).
;   Stops at exactly 256 accepted coefficients even when the last triple's d2
;   would also be accepted.
;
; mlkem_sample_cbd2
;   128 PRF bytes -> polynomial. Each byte yields two coefficients: the low
;   nibble is coefficient 2k, the high nibble 2k+1; within a nibble
;   x = b0 + b1, y = b2 + b3 (FIPS 203 Alg. 8's little-endian bit order),
;   value (x - y) mod q. A 16-entry nibble table gives lo/hi bytes directly,
;   with negatives already stored as q + v. The input is SECRET (s, e, r): no
;   branch depends on it, and the two 16-byte tables are asserted not to
;   straddle a page so `abs,x` costs the same for every nibble.
; =============================================================================

.include "constants.s"

.importzp mlkem_zp_src, mlkem_zp_dst, mlkem_zp_tmp
.import mlkem_squeeze, mlkem_sponge_len

.export mlkem_sample_ntt, mlkem_sample_cbd2

MLKEM_Q_HI      = 13            ; q = 3329 = $0D01: hi byte 13, lo byte 1
MLKEM_Q         = 3329
CBD_BYTES       = 128           ; 64 * eta

.segment "LIB_MLKEM_RODATA"

; Nibble -> (x - y) mod q, split into lo / hi byte. Computed by the assembler
; from the FIPS 203 definition, never typed.
mlkem_cbd2_lo:
.repeat 16, n
        .byte <((((n & 1) + ((n >> 1) & 1)) - (((n >> 2) & 1) + ((n >> 3) & 1)) + MLKEM_Q) .mod MLKEM_Q)
.endrepeat
mlkem_cbd2_hi:
.repeat 16, n
        .byte >((((n & 1) + ((n >> 1) & 1)) - (((n >> 2) & 1) + ((n >> 3) & 1)) + MLKEM_Q) .mod MLKEM_Q)
.endrepeat
; Both tables are indexed by a secret nibble; a page straddle would make the
; lookup cost depend on its value. 32 bytes total, one check covers both.
.assert >mlkem_cbd2_lo = >(mlkem_cbd2_hi + 15), lderror, "mlkem_cbd2 tables straddle a page: lookup cost would depend on secret data"

.segment "LIB_MLKEM_BSS"

sn_buf:         .res SHAKE128_RATE  ; one squeezed rate block
sn_out:         .res 2              ; caller's output pointer, saved across squeezes
sn_j:           .res 1              ; accepted-coefficient count (mod 256)
sn_lo:          .res 1              ; low byte of the candidate under test
cbd_k:          .res 1              ; input byte index
cbd_byte:       .res 1

.segment "LIB_MLKEM_CODE"

; =============================================================================
; mlkem_sample_ntt — A[i][j] from the seeded SHAKE128 state to (mlkem_zp_dst).
; =============================================================================
.proc mlkem_sample_ntt
        lda mlkem_zp_dst+0
        sta sn_out+0
        lda mlkem_zp_dst+1
        sta sn_out+1
        lda #0
        sta sn_j

refill:
        ; --- squeeze the next 168-byte block into sn_buf --------------------
        lda #<sn_buf
        sta mlkem_zp_dst+0
        lda #>sn_buf
        sta mlkem_zp_dst+1
        lda #SHAKE128_RATE
        sta mlkem_sponge_len+0
        lda #0
        sta mlkem_sponge_len+1
        jsr mlkem_squeeze           ; clobbers zp_tmp / zp_len, advances zp_dst

        ; --- output pointers: dst = lo plane, tmp = hi plane ----------------
        lda sn_out+0
        sta mlkem_zp_dst+0
        sta mlkem_zp_tmp+0
        lda sn_out+1
        sta mlkem_zp_dst+1
        clc
        adc #1
        sta mlkem_zp_tmp+1

        ldx #0                      ; byte offset into sn_buf, steps of 3
        ldy sn_j                    ; Y = j, the next coefficient index
triple:
        ; d1 = c0 | (c1 & $0F) << 8
        lda sn_buf+0,x
        sta sn_lo
        lda sn_buf+1,x
        and #$0F
        jsr try_accept
        beq done                    ; Y wrapped: 256 coefficients written

        ; d2 = (c1 >> 4) | c2 << 4
        lda sn_buf+1,x
        lsr
        lsr
        lsr
        lsr
        sta sn_lo
        lda sn_buf+2,x
        asl
        asl
        asl
        asl
        ora sn_lo
        sta sn_lo
        lda sn_buf+2,x
        lsr
        lsr
        lsr
        lsr
        jsr try_accept
        beq done

        inx
        inx
        inx
        cpx #SHAKE128_RATE
        bne triple
        sty sn_j
        jmp refill
done:
        rts
.endproc

; try_accept — candidate d = (A << 8) | sn_lo, Y = j.
; If d < q: store it as coefficient j, j += 1. Returns Z set iff Y wrapped to
; 0, i.e. exactly 256 coefficients have now been accepted; Z clear otherwise
; (including every rejection).
;   d < 3329 = $0D01  <=>  hi < 13, or hi == 13 and lo == 0 (d = 3328 = q-1).
.proc try_accept
        cmp #MLKEM_Q_HI
        bcc accept                  ; hi < 13
        bne reject                  ; hi > 13
        lda sn_lo
        bne reject                  ; hi == 13, lo != 0: d >= q
        lda #MLKEM_Q_HI
accept:
        sta (mlkem_zp_tmp),y        ; hi plane
        lda sn_lo
        sta (mlkem_zp_dst),y        ; lo plane
        iny                         ; Z <- (j == 256)
        rts
reject:
        lda #1                      ; Z clear
        rts
.endproc

; =============================================================================
; mlkem_sample_cbd2 — 128 bytes at (mlkem_zp_src) -> polynomial at (mlkem_zp_dst)
; =============================================================================
.proc mlkem_sample_cbd2
        lda mlkem_zp_dst+0
        sta mlkem_zp_tmp+0
        lda mlkem_zp_dst+1
        clc
        adc #1
        sta mlkem_zp_tmp+1          ; hi plane

        lda #0
        sta cbd_k
loop:
        ldy cbd_k
        lda (mlkem_zp_src),y
        sta cbd_byte
        tya
        asl
        tay                         ; Y = 2k (k <= 127, no wrap)

        lda cbd_byte
        and #$0F
        tax
        lda mlkem_cbd2_lo,x
        sta (mlkem_zp_dst),y
        lda mlkem_cbd2_hi,x
        sta (mlkem_zp_tmp),y
        iny

        lda cbd_byte
        lsr
        lsr
        lsr
        lsr
        tax
        lda mlkem_cbd2_lo,x
        sta (mlkem_zp_dst),y
        lda mlkem_cbd2_hi,x
        sta (mlkem_zp_tmp),y

        inc cbd_k
        lda cbd_k
        cmp #CBD_BYTES              ; cmp, not bpl: 128 has bit 7 set
        bne loop
        rts
.endproc
