.setcpu "6502"

; =============================================================================
; kem.s — K-PKE (FIPS 203 Alg. 13-15) and ML-KEM-768 KeyGen / Encaps / Decaps
; (Alg. 16-18) as a looped, table-driven glue layer over WP1 (src/ntt.s), WP2
; (src/sample.s, src/codec.s) and the P1 sponge (src/sponge.s).
;
; PARAMETER BLOCK (tools/test_mlkem.py documents it; offsets are fixed and
; asserted below): six little-endian 16-bit pointers in LIB_MLKEM_BSS,
; contiguous from mlkem_arg_ek. A call reads them and never writes them.
;
;     mlkem_arg_ek    +0   ek  1,184 B          (hooks: ek_pke, same size)
;     mlkem_arg_dk    +2   dk  2,400 B          (hooks: dk_pke, 1,152 B)
;     mlkem_arg_ct    +4   c   1,088 B
;     mlkem_arg_key   +6   K      32 B          (kpke_decrypt: m)
;     mlkem_arg_seed  +8   d (keygen) / m (encaps, kpke_encrypt)
;     mlkem_arg_z    +10   z (keygen) / r (kpke_encrypt)
;
;     mlkem_keygen   in seed=d, z      out ek, dk        A = 0
;     mlkem_encaps   in ek, seed=m     out key, ct       A = status (also in
;                    mlkem_status): 0 ok; 1 = ek failed the §7.2 modulus
;                    check, in which case NOTHING has been written.
;     mlkem_decaps   in dk, ct         out key           A = 0; implicit
;                    rejection yields J(z || c) silently. No §7.3 H(ek) check
;                    (the caller's, per FIPS 203).
;
; No alignment requirement on any wire buffer: every byte-string access is
; (zp),y with a 16-bit pointer. Polynomials live in page-aligned BSS below.
;
; MEMORY PLAN — eight polynomials (4,096 B), never the matrix:
;     kem_pva[3]  s_hat (keygen) / y_hat (encrypt) / u_hat (decrypt)
;     kem_pvb[3]  e_hat -> t_hat (keygen) / t_hat (encrypt) / s_hat (decrypt)
;     kem_pt      one sampled A[i][j], then the basemul product; also e / mu
;     kem_pacc    the running dot-product accumulator (u_i, v, s^T u)
; Each A[i][j] is expanded from SHAKE128 into kem_pt and consumed at once.
;
; POINTER TABLE: kem_ptrs is a 14-entry table of 16-bit pointers; the first
; six ARE the parameter block. Every routine that walks a byte string takes
; a table index in X plus a constant offset (ld_src / ld_dst / ptr_calc), so
; "ek + 1152" is one 9-byte macro and there is exactly one pointer-arithmetic
; routine to get right. Internal entries: RHO, PSEED (PRF seed), M, IN
; (running input stream), RUN (running output stream), EKP (ek_pke for
; encrypt), MOUT (decrypt's m), OUT (encrypt's c).
;
; BYTE ENCODE / DECODE for d = 1, 4, 10 is one bit-serial packer and one
; bit-serial unpacker (enc_poly / dec_poly, d in a variable) on top of WP2's
; unpacked Compress_d / Decompress_d — ~110 B each instead of six specialised
; routines, at ~26 cycles per bit, which is < 2% of any primitive. WP2's
; ByteEncode12 / ByteDecode12 are used for the 12-bit key fields.
;
; CONSTANT TIME. The only data-dependent control flow is (a) SampleNTT's
; rejection loop on public rho, (b) mlkem_encaps's public §7.2 check, and (c)
; the public kp_cmp mode flag. The decaps re-encryption compares all 1,088
; bytes with an accumulate-OR (cmp_len) and selects K with a mask: no branch
; on the result, and no early exit anywhere in the compare (T1 in the tests).
; In compare mode the re-encrypted ciphertext never touches the caller's c:
; each encoded chunk lands in kem_buf and is OR-compared from there.
;
; HASH INPUTS, per FIPS 203: G(d || k) with k = 3 as one byte; PRF(sigma, N)
; with N incrementing across s (0-2) then e (3-5); PRF(r, N) across y (0-2),
; e1 (3-5), e2 (6); XOF seed rho || j || i (j FIRST); H(ek); (K, r) = G(m ||
; H(ek)); K_bar = J(z || c). Squeezing G's 64 bytes as two 32-byte calls is
; the P1 sponge's documented streaming property.
; =============================================================================

.include "constants.s"

.importzp mlkem_zp_src, mlkem_zp_dst, mlkem_zp_tmp, mlkem_zp_len

.import mlkem_sha3_256_init, mlkem_sha3_512_init
.import mlkem_shake128_init, mlkem_shake256_init
.import mlkem_absorb, mlkem_squeeze, mlkem_sponge_len
.import mlkem_poly_ntt, mlkem_poly_intt, mlkem_poly_basemul
.import mlkem_poly_add, mlkem_poly_sub
.import mlkem_sample_ntt, mlkem_sample_cbd2
.import mlkem_byte_encode_12, mlkem_byte_decode_12
.import mlkem_compress_1, mlkem_compress_4, mlkem_compress_10
.import mlkem_decompress_1, mlkem_decompress_4, mlkem_decompress_10

.export mlkem_keygen, mlkem_encaps, mlkem_decaps
.export mlkem_arg_ek, mlkem_arg_dk, mlkem_arg_ct
.export mlkem_arg_key, mlkem_arg_seed, mlkem_arg_z
.export mlkem_status

.ifdef MLKEM_TEST_HOOKS
.export mlkem_kpke_keygen, mlkem_kpke_encrypt, mlkem_kpke_decrypt
.endif

; --- ML-KEM-768 wire layout ----------------------------------------------------
KEM_K           = 3
EK_T_BYTES      = 384 * KEM_K       ; 1152: t_hat, then rho
EK_BYTES        = EK_T_BYTES + 32   ; 1184
DK_EK_OFF       = EK_T_BYTES        ; 1152: ek inside dk
DK_RHO_OFF      = DK_EK_OFF + EK_T_BYTES ; 2304
DK_H_OFF        = DK_EK_OFF + EK_BYTES   ; 2336: H(ek)
DK_Z_OFF        = DK_H_OFF + 32          ; 2368: z
CT_BYTES        = 32 * (10 * KEM_K + 4)  ; 1088
CBD_BYTES       = 128                    ; 64 * eta, eta = 2
MLKEM_Q_HI      = 13
MLKEM_Q_LO      = 1

; --- pointer-table indices ------------------------------------------------------
IDX_EK    = 0
IDX_DK    = 2
IDX_CT    = 4
IDX_KEY   = 6
IDX_SEED  = 8
IDX_Z     = 10
IDX_RHO   = 12
IDX_PSEED = 14
IDX_M     = 16
IDX_IN    = 18
IDX_RUN   = 20
IDX_EKP   = 22
IDX_MOUT  = 24
IDX_OUT   = 26

; =============================================================================
.segment "LIB_MLKEM_RODATA"

k_byte:         .byte KEM_K         ; the "|| k" byte of G(d || k)

; =============================================================================
.segment "LIB_MLKEM_BSS"

; Page-aligned polynomials FIRST (ld65 aligns the whole fragment; odd bytes
; declared before an .align would still land after it AND push it a page).
.align 256
kem_pva:        .res 3 * 512
kem_pvb:        .res 3 * 512
kem_pt:         .res 512
kem_pacc:       .res 512
.assert (kem_pva .mod 256) = 0, lderror, "kem_pva is not page-aligned: LIB_MLKEM_BSS needs align = $100"

kem_buf:        .res 320            ; PRF output (128) / one encoded chunk in compare mode (320)
kem_hb:         .res 4 * 32         ; hash scratch: 4 x 32 B (see each primitive)

; The parameter block. Contiguous, offsets asserted.
kem_ptrs:
mlkem_arg_ek:   .res 2
mlkem_arg_dk:   .res 2
mlkem_arg_ct:   .res 2
mlkem_arg_key:  .res 2
mlkem_arg_seed: .res 2
mlkem_arg_z:    .res 2
                .res 2 * 8          ; internal entries IDX_RHO .. IDX_OUT
.assert mlkem_arg_dk - mlkem_arg_ek = 2, error, "parameter block offset"
.assert mlkem_arg_ct - mlkem_arg_ek = 4, error, "parameter block offset"
.assert mlkem_arg_key - mlkem_arg_ek = 6, error, "parameter block offset"
.assert mlkem_arg_seed - mlkem_arg_ek = 8, error, "parameter block offset"
.assert mlkem_arg_z - mlkem_arg_ek = 10, error, "parameter block offset"

mlkem_status:   .res 1
kp_nonce:       .res 1              ; PRF counter N
kp_i:           .res 1              ; row / vector index
kp_j:           .res 1              ; column index
kp_base:        .res 1              ; vec_each: polyvec base page
kp_pi:          .res 1              ; vec_each: page of element i
kp_acc:         .res 1              ; mat_row: page of the accumulator
kp_t:           .res 1              ; mat_row: 0 = A[i][j], 1 = A[j][i]
kp_cmp:         .res 1              ; enc_poly: 1 = compare against (RUN) instead of writing
cmp_acc:        .res 1              ; accumulate-OR of the ciphertext compare
enc_d:          .res 1              ; bits per coefficient for enc_poly / dec_poly
enc_len:        .res 2              ; 32 * enc_d
shift_back:     .res 1
nbits:          .res 1
bacc:           .res 1
c_lo:           .res 1
c_hi:           .res 1
save_y:         .res 1
kem_ij:         .res 2              ; XOF suffix: j, i

; =============================================================================
; Macros — every one expands to a constant-argument call into one routine.
; =============================================================================

; zp_src / zp_dst <- kem_ptrs[idx] + off
.macro SRC idx, off
        ldx #idx
        lda #<(off)
        ldy #>(off)
        jsr ld_src
.endmacro
.macro DST idx, off
        ldx #idx
        lda #<(off)
        ldy #>(off)
        jsr ld_dst
.endmacro

; zp_src / zp_dst <- absolute address
.macro SRCI addr
        lda #<(addr)
        sta mlkem_zp_src+0
        lda #>(addr)
        sta mlkem_zp_src+1
.endmacro
.macro DSTI addr
        lda #<(addr)
        sta mlkem_zp_dst+0
        lda #>(addr)
        sta mlkem_zp_dst+1
.endmacro

; kem_ptrs[dst] <- kem_ptrs[src] + off
.macro PTRSET dst, src, off
        ldx #src
        lda #<(off)
        ldy #>(off)
        jsr ptr_calc
        ldx #dst
        jsr ptr_store
.endmacro
; kem_ptrs[dst] <- absolute address
.macro PTRSETI dst, addr
        lda #<(addr)
        sta kem_ptrs+dst
        lda #>(addr)
        sta kem_ptrs+dst+1
.endmacro
; kem_ptrs[idx] += len
.macro PADD idx, len
        ldx #idx
        lda #<(len)
        ldy #>(len)
        jsr ptr_add
.endmacro

.macro ABSORB len
        lda #<(len)
        ldy #>(len)
        jsr absorb_len
.endmacro
.macro SQUEEZE len
        lda #<(len)
        ldy #>(len)
        jsr squeeze_len
.endmacro

; for i in 0..2: kp_pi = base + 2i; jsr routine
.macro VEC base, routine
        lda #base
        ldx #<(routine)
        ldy #>(routine)
        jsr vec_each
.endmacro

; =============================================================================
.segment "LIB_MLKEM_CODE"

; --- pointer helpers ----------------------------------------------------------

; ptr_calc: A/Y (lo/hi) <- kem_ptrs[X] + A:Y
.proc ptr_calc
        clc
        adc kem_ptrs+0,x
        pha
        tya
        adc kem_ptrs+1,x
        tay
        pla
        rts
.endproc

.proc ld_src
        jsr ptr_calc
        sta mlkem_zp_src+0
        sty mlkem_zp_src+1
        rts
.endproc

.proc ld_dst
        jsr ptr_calc
        sta mlkem_zp_dst+0
        sty mlkem_zp_dst+1
        rts
.endproc

; ptr_store: kem_ptrs[X] <- A:Y
.proc ptr_store
        sta kem_ptrs+0,x
        tya
        sta kem_ptrs+1,x
        rts
.endproc

; ptr_add: kem_ptrs[X] += A:Y
.proc ptr_add
        clc
        adc kem_ptrs+0,x
        sta kem_ptrs+0,x
        tya
        adc kem_ptrs+1,x
        sta kem_ptrs+1,x
        rts
.endproc

; set_dst / set_src / set_both: pointer <- page A, offset 0 (a polynomial)
.proc set_both
        jsr set_src
.endproc                            ; falls through
.proc set_dst
        sta mlkem_zp_dst+1
        lda #0
        sta mlkem_zp_dst+0
        rts
.endproc

.proc set_src
        sta mlkem_zp_src+1
        pha
        lda #0
        sta mlkem_zp_src+0
        pla
        rts
.endproc

; --- sponge helpers -------------------------------------------------------------

.proc absorb_len
        sta mlkem_sponge_len+0
        sty mlkem_sponge_len+1
        jmp mlkem_absorb
.endproc

.proc squeeze_len
        sta mlkem_sponge_len+0
        sty mlkem_sponge_len+1
        jmp mlkem_squeeze
.endproc

; copy32: 32 bytes (zp_src) -> (zp_dst)
.proc copy32
        ldy #31
:       lda (mlkem_zp_src),y
        sta (mlkem_zp_dst),y
        dey
        bpl :-
        rts
.endproc

; zero_poly: polynomial at page A <- 0
.proc zero_poly
        jsr set_dst
        ldy #0
        tya
:       sta (mlkem_zp_dst),y
        iny
        bne :-
        inc mlkem_zp_dst+1
:       sta (mlkem_zp_dst),y
        iny
        bne :-
        rts
.endproc

; --- vec_each: for i in 0..2 { kp_pi = base + 2i; jsr routine } ----------------
.proc vec_each
        sta kp_base
        stx call+1
        sty call+2
        lda #0
        sta kp_i
loop:
        lda kp_i
        asl
        adc kp_base                 ; carry clear after asl of a small value
        sta kp_pi
call:   jsr $FFFF                   ; patched (public data)
        inc kp_i
        lda kp_i
        cmp #KEM_K
        bne loop
        rts
.endproc

; --- prf_cbd: polynomial at page A <- CBD2(PRF(PSEED, N)); N += 1 -----------------
.proc prf_cbd
        pha
        jsr mlkem_shake256_init
        SRC IDX_PSEED, 0
        ABSORB 32
        SRCI kp_nonce
        ABSORB 1
        inc kp_nonce
        DSTI kem_buf
        SQUEEZE CBD_BYTES
        SRCI kem_buf
        pla
        jsr set_dst
        jmp mlkem_sample_cbd2
.endproc

; --- gen_a: kem_pt <- A[i][j] = SampleNTT(rho || j || i), A = i, X = j -----------
.proc gen_a
        sta kem_ij+1
        stx kem_ij+0
        jsr mlkem_shake128_init
        SRC IDX_RHO, 0
        ABSORB 32
        SRCI kem_ij
        ABSORB 2
        DSTI kem_pt
        jmp mlkem_sample_ntt
.endproc

; --- mat_row: poly[kp_acc] += sum_j A[i][j] o pva[j]  (kp_t = 1: A[j][i]) --------
.proc mat_row
        lda #0
        sta kp_j
loop:
        lda kp_t
        bne transposed
        lda kp_i
        ldx kp_j
        jmp go
transposed:
        lda kp_j
        ldx kp_i
go:     jsr gen_a                   ; kem_pt = A entry
        lda kp_j
        asl
        adc #>kem_pva
        jsr set_src
        lda #>kem_pt
        jsr set_dst
        jsr mlkem_poly_basemul      ; kem_pt = A o pva[j]
        lda #>kem_pt
        jsr set_src
        lda kp_acc
        jsr set_dst
        jsr mlkem_poly_add
        inc kp_j
        lda kp_j
        cmp #KEM_K
        bne loop
        rts
.endproc

; --- dot_ab: kem_pacc <- INTT(sum_j pva[j] o pvb[j]); pva is consumed --------------
.proc dot_ab
        lda #>kem_pacc
        jsr zero_poly
        lda #0
        sta kp_j
loop:
        lda kp_j
        asl
        adc #>kem_pvb
        jsr set_src
        lda kp_j
        asl
        adc #>kem_pva
        jsr set_dst
        jsr mlkem_poly_basemul      ; pva[j] = pva[j] o pvb[j]
        lda kp_j
        asl
        adc #>kem_pva
        jsr set_src
        lda #>kem_pacc
        jsr set_dst
        jsr mlkem_poly_add
        inc kp_j
        lda kp_j
        cmp #KEM_K
        bne loop
        lda #>kem_pacc
        jsr set_dst
        jmp mlkem_poly_intt
.endproc

; --- pacc_add_pt: kem_pacc += kem_pt -------------------------------------------
.proc pacc_add_pt
        lda #>kem_pt
        jsr set_src
        lda #>kem_pacc
        jsr set_dst
        jmp mlkem_poly_add
.endproc

; --- set_len: enc_len <- 32 * enc_d ----------------------------------------------
.proc set_len
        lda #0
        sta enc_len+1
        lda enc_d
        asl
        asl
        asl
        asl
        asl
        rol enc_len+1
        sta enc_len+0
        rts
.endproc

; --- cmp_len: cmp_acc |= (zp_src)[k] ^ (zp_dst)[k] for k < enc_len ---------------
; Full length, every byte, no early exit; consumes enc_len.
.proc cmp_len
        ldx enc_len+1
        lda enc_len+0
        beq :+
        inx
:       ldy #0
loop:
        lda (mlkem_zp_src),y
        eor (mlkem_zp_dst),y
        ora cmp_acc
        sta cmp_acc
        iny
        bne :+
        inc mlkem_zp_src+1
        inc mlkem_zp_dst+1
:       dec enc_len+0
        bne loop
        dex
        bne loop
        rts
.endproc

; =============================================================================
; enc_poly — ByteEncode_d of the polynomial at page A (d = enc_d, values
; already < 2^d from Compress_d) to (RUN), which advances by 32 d. In compare
; mode (kp_cmp = 1) the bytes go to kem_buf and are OR-compared against (RUN)
; instead. Bit-serial: coefficient bits LSB first, bytes filled LSB first
; (FIPS 203 Alg. 5 / BitsToBytes).
; =============================================================================
.proc enc_poly
        jsr set_src
        lda mlkem_zp_src+1
        clc
        adc #1
        sta mlkem_zp_tmp+1          ; hi plane
        lda #0
        sta mlkem_zp_tmp+0
        lda kp_cmp
        beq direct
        DSTI kem_buf
        jmp go
direct: DST IDX_RUN, 0
go:
        lda #8
        sta nbits
        ldy #0
coef:
        lda (mlkem_zp_src),y
        sta c_lo
        lda (mlkem_zp_tmp),y
        sta c_hi
        ldx enc_d
bitloop:
        lsr c_hi
        ror c_lo                    ; carry = next bit of the coefficient
        ror bacc                    ; enters at bit 7, reaches bit 0 after 8
        dec nbits
        bne nostore
        sty save_y
        ldy #0
        lda bacc
        sta (mlkem_zp_dst),y
        inc mlkem_zp_dst+0
        bne :+
        inc mlkem_zp_dst+1
:       ldy save_y
        lda #8
        sta nbits
nostore:
        dex
        bne bitloop
        iny
        bne coef

        jsr set_len
        DST IDX_RUN, 0              ; chunk start, for the compare
        lda enc_len+0
        ldy enc_len+1
        ldx #IDX_RUN
        jsr ptr_add
        lda kp_cmp
        beq done
        SRCI kem_buf
        jsr cmp_len
done:   rts
.endproc

; =============================================================================
; dec_poly — ByteDecode_d from (IN) (advances by 32 d) to the polynomial at
; page A: each coefficient is its d bits, unreduced (Alg. 6 with m = 2^d).
; =============================================================================
.proc dec_poly
        jsr set_dst
        lda mlkem_zp_dst+1
        clc
        adc #1
        sta mlkem_zp_len+1          ; hi plane
        lda #0
        sta mlkem_zp_len+0
        sta nbits                   ; no bits buffered yet
        SRC IDX_IN, 0
        jsr set_len
        lda enc_len+0
        ldy enc_len+1
        ldx #IDX_IN
        jsr ptr_add
        lda #16
        sec
        sbc enc_d
        sta shift_back
        ldy #0
coef:
        ldx enc_d
bitloop:
        lda nbits
        bne have
        sty save_y
        ldy #0
        lda (mlkem_zp_src),y
        sta bacc
        inc mlkem_zp_src+0
        bne :+
        inc mlkem_zp_src+1
:       ldy save_y
        lda #8
        sta nbits
have:
        dec nbits
        lsr bacc                    ; carry = next input bit
        ror c_hi
        ror c_lo                    ; bits enter at the top ...
        dex
        bne bitloop
        ldx shift_back
:       lsr c_hi                    ; ... and are shifted down by 16 - d
        ror c_lo
        dex
        bne :-
        lda c_lo
        sta (mlkem_zp_dst),y
        lda c_hi
        sta (mlkem_zp_len),y
        iny
        bne coef
        rts
.endproc

; =============================================================================
; vec_each element routines (kp_pi = page of element i)
; =============================================================================

; pv[i] <- NTT(CBD2(PRF(PSEED, N++)))
.proc el_sample
        lda kp_pi
        jsr prf_cbd
        lda kp_pi
        jsr set_dst
        jmp mlkem_poly_ntt
.endproc

; (RUN) <- ByteEncode12(pv[i]); RUN += 384
.proc el_enc12
        lda kp_pi
        jsr set_src
        DST IDX_RUN, 0
        jsr mlkem_byte_encode_12
        PADD IDX_RUN, 384
        rts
.endproc

; pv[i] <- ByteDecode12((IN)); IN += 384
.proc el_dec12
        SRC IDX_IN, 0
        lda kp_pi
        jsr set_dst
        jsr mlkem_byte_decode_12
        PADD IDX_IN, 384
        rts
.endproc

; pv[i] <- NTT(Decompress10(ByteDecode10((IN)))); IN += 320
.proc el_dec10
        lda #10
        sta enc_d
        lda kp_pi
        jsr dec_poly
        lda kp_pi
        jsr set_both
        jsr mlkem_decompress_10
        lda kp_pi
        jsr set_dst
        jmp mlkem_poly_ntt
.endproc

; keygen row: t_hat[i] (= e_hat[i] on entry) += sum_j A[i][j] o s_hat[j]
.proc el_trow
        lda kp_pi
        sta kp_acc
        jmp mat_row
.endproc

; encrypt: u_i = INTT(sum_j A[j][i] o y_hat[j]) + e1_i -> Compress10 -> (RUN)
.proc el_u
        lda #>kem_pacc
        jsr zero_poly
        lda #>kem_pacc
        sta kp_acc
        jsr mat_row
        lda #>kem_pacc
        jsr set_dst
        jsr mlkem_poly_intt
        lda #>kem_pt
        jsr prf_cbd                 ; e1_i, nonce 3 + i
        jsr pacc_add_pt
        lda #>kem_pacc
        jsr set_both
        jsr mlkem_compress_10
        lda #10
        sta enc_d
        lda #>kem_pacc
        jmp enc_poly
.endproc

; =============================================================================
; K-PKE.KeyGen (Alg. 13): SEED = d; ek_pke -> (EK), dk_pke -> (DK).
; Leaves t_hat in kem_pvb and rho in kem_hb[0..32) for mlkem_keygen.
; =============================================================================
.proc kpke_keygen
        jsr mlkem_sha3_512_init
        SRC IDX_SEED, 0
        ABSORB 32
        SRCI k_byte
        ABSORB 1
        DSTI kem_hb
        SQUEEZE 64                  ; hb0 = rho, hb1 = sigma
        PTRSETI IDX_RHO, kem_hb
        PTRSETI IDX_PSEED, kem_hb + 32
        lda #0
        sta kp_nonce
        sta kp_t
        VEC >kem_pva, el_sample     ; s_hat, N = 0..2
        VEC >kem_pvb, el_sample     ; e_hat, N = 3..5
        VEC >kem_pvb, el_trow       ; t_hat = A o s_hat + e_hat
        PTRSET IDX_RUN, IDX_EK, 0
        VEC >kem_pvb, el_enc12      ; ek = ByteEncode12(t_hat) ...
        SRCI kem_hb
        DST IDX_EK, EK_T_BYTES
        jsr copy32                  ;      || rho
        PTRSET IDX_RUN, IDX_DK, 0
        VEC >kem_pva, el_enc12      ; dk_pke = ByteEncode12(s_hat)
        lda #0
        rts
.endproc

; =============================================================================
; K-PKE.Encrypt (Alg. 14): EKP = ek_pke, M = m, PSEED = r, OUT = c.
; kp_cmp = 1: compare against (OUT) instead of writing (decaps).
; encrypt_body: entered by mlkem_encaps with t_hat already in kem_pvb.
; =============================================================================
.proc kpke_encrypt
        PTRSET IDX_IN, IDX_EKP, 0
        VEC >kem_pvb, el_dec12      ; t_hat
.endproc                            ; falls through
.proc encrypt_body
        PTRSET IDX_RHO, IDX_EKP, EK_T_BYTES
        lda #0
        sta kp_nonce
        VEC >kem_pva, el_sample     ; y_hat, N = 0..2
        PTRSET IDX_RUN, IDX_OUT, 0
        lda #1
        sta kp_t                    ; A^T
        VEC 0, el_u                 ; c1: u_0, u_1, u_2 (e1 N = 3..5)
        jsr dot_ab                  ; pacc = INTT(t_hat . y_hat), pva consumed
        lda #>kem_pt
        jsr prf_cbd                 ; e2, N = 6
        jsr pacc_add_pt
        PTRSET IDX_IN, IDX_M, 0
        lda #1
        sta enc_d
        lda #>kem_pt
        jsr dec_poly                ; ByteDecode1(m)
        lda #>kem_pt
        jsr set_both
        jsr mlkem_decompress_1      ; mu
        jsr pacc_add_pt             ; v = t.y + e2 + mu
        lda #>kem_pacc
        jsr set_both
        jsr mlkem_compress_4
        lda #4
        sta enc_d
        lda #>kem_pacc
        jmp enc_poly                ; c2
.endproc

; =============================================================================
; K-PKE.Decrypt (Alg. 15): DK = dk_pke, CT = c; m -> (MOUT).
; =============================================================================
.proc kpke_decrypt
        PTRSET IDX_IN, IDX_CT, 0
        VEC >kem_pva, el_dec10      ; u_hat
        lda #4
        sta enc_d
        lda #>kem_pt
        jsr dec_poly
        lda #>kem_pt
        jsr set_both
        jsr mlkem_decompress_4      ; v in kem_pt
        PTRSET IDX_IN, IDX_DK, 0
        VEC >kem_pvb, el_dec12      ; s_hat
        jsr dot_ab                  ; pacc = INTT(s_hat . u_hat)
        lda #>kem_pacc
        jsr set_src
        lda #>kem_pt
        jsr set_dst
        jsr mlkem_poly_sub          ; w = v - s^T u
        lda #>kem_pt
        jsr set_both
        jsr mlkem_compress_1
        PTRSET IDX_RUN, IDX_MOUT, 0
        lda #0
        sta kp_cmp
        lda #1
        sta enc_d
        lda #>kem_pt
        jmp enc_poly                ; m = ByteEncode1(Compress1(w))
.endproc

; =============================================================================
; check_t — §7.2 modulus check on the decoded t_hat in kem_pvb.
; Returns A = 0 if every coefficient < q, A = 1 otherwise. Public data; exits
; early on the first offender.
; =============================================================================
.proc check_t
        lda #>kem_pvb
        jsr set_src
        lda #>kem_pvb + 1
        sta mlkem_zp_tmp+1
        lda #0
        sta mlkem_zp_tmp+0
        sta kp_i
poly:
        ldy #0
coef:
        lda (mlkem_zp_tmp),y        ; high byte, 0..15
        cmp #MLKEM_Q_HI
        bcc next
        bne bad
        lda (mlkem_zp_src),y        ; hi = 13: only 3328 = $0D00 is < q
        bne bad
next:   iny
        bne coef
        inc mlkem_zp_src+1
        inc mlkem_zp_src+1
        inc mlkem_zp_tmp+1
        inc mlkem_zp_tmp+1
        inc kp_i
        lda kp_i
        cmp #KEM_K
        bne poly
        lda #0
        rts
bad:    lda #1
        rts
.endproc

; =============================================================================
; PUBLIC: ML-KEM-768 KeyGen (Alg. 16). SEED = d, Z = z -> (EK), (DK).
; =============================================================================
.proc mlkem_keygen
        jsr kpke_keygen             ; (EK) = ek, (DK)[0..1152) = dk_pke
        PTRSET IDX_RUN, IDX_DK, DK_EK_OFF
        VEC >kem_pvb, el_enc12      ; dk[1152..) = ek (t_hat re-encoded ...
        SRCI kem_hb
        DST IDX_DK, DK_RHO_OFF
        jsr copy32                  ;               ... then rho)
        jsr mlkem_sha3_256_init
        SRC IDX_EK, 0
        ABSORB EK_BYTES
        DST IDX_DK, DK_H_OFF
        SQUEEZE 32                  ; H(ek)
        SRC IDX_Z, 0
        DST IDX_DK, DK_Z_OFF
        jsr copy32                  ; z
        lda #0
        sta mlkem_status
        rts
.endproc

; =============================================================================
; PUBLIC: ML-KEM-768 Encaps (Alg. 17 + §7.2 check). EK = ek, SEED = m ->
; (KEY) = K, (CT) = c. A = status: 0 ok, 1 = ek rejected (nothing written).
; =============================================================================
.proc mlkem_encaps
        PTRSET IDX_IN, IDX_EK, 0
        VEC >kem_pvb, el_dec12      ; t_hat (raw fields)
        jsr check_t
        sta mlkem_status
        beq ok
        rts                         ; A = 1: rejected, nothing written
ok:
        jsr mlkem_sha3_256_init
        SRC IDX_EK, 0
        ABSORB EK_BYTES
        DSTI kem_hb
        SQUEEZE 32                  ; hb0 = H(ek)
        jsr mlkem_sha3_512_init
        SRC IDX_SEED, 0
        ABSORB 32                   ; m
        SRCI kem_hb
        ABSORB 32                   ; || H(ek)
        DST IDX_KEY, 0
        SQUEEZE 32                  ; K
        DSTI kem_hb + 32
        SQUEEZE 32                  ; hb1 = r
        PTRSET IDX_EKP, IDX_EK, 0
        PTRSET IDX_M, IDX_SEED, 0
        PTRSETI IDX_PSEED, kem_hb + 32
        PTRSET IDX_OUT, IDX_CT, 0
        lda #0
        sta kp_cmp
        jsr encrypt_body
        lda mlkem_status            ; 0
        rts
.endproc

; =============================================================================
; PUBLIC: ML-KEM-768 Decaps (Alg. 18, no §7.3 check). DK = dk, CT = c ->
; (KEY) = K, or J(z || c) when c does not re-encrypt. A = 0 always.
; =============================================================================
.proc mlkem_decaps
        PTRSETI IDX_MOUT, kem_hb
        jsr kpke_decrypt            ; hb0 = m'
        jsr mlkem_sha3_512_init
        SRCI kem_hb
        ABSORB 32                   ; m'
        SRC IDX_DK, DK_H_OFF
        ABSORB 32                   ; || h
        DSTI kem_hb + 64
        SQUEEZE 32                  ; hb2 = K'
        DSTI kem_hb + 32
        SQUEEZE 32                  ; hb1 = r'
        jsr mlkem_shake256_init
        SRC IDX_DK, DK_Z_OFF
        ABSORB 32                   ; z
        SRC IDX_CT, 0
        ABSORB CT_BYTES             ; || c
        DSTI kem_hb + 96
        SQUEEZE 32                  ; hb3 = K_bar = J(z || c)
        PTRSET IDX_EKP, IDX_DK, DK_EK_OFF
        PTRSETI IDX_M, kem_hb
        PTRSETI IDX_PSEED, kem_hb + 32
        PTRSET IDX_OUT, IDX_CT, 0
        lda #1
        sta kp_cmp
        lda #0
        sta cmp_acc
        jsr kpke_encrypt            ; cmp_acc = OR over c ^ c'

        ; mask = $FF iff cmp_acc = 0 (c = c'), branch-free:
        ; (x | -x) has bit 7 set iff x != 0; shift it into carry; 0 - borrow.
        lda cmp_acc
        sta c_lo
        lda #0
        sec
        sbc c_lo
        ora c_lo
        asl
        lda #0
        sbc #0
        sta c_hi                    ; mask
        DST IDX_KEY, 0
        ldy #31
:       lda kem_hb + 64,y           ; K'
        eor kem_hb + 96,y           ; ^ K_bar
        and c_hi
        eor kem_hb + 96,y           ; K_bar ^ (mask & (K' ^ K_bar))
        sta (mlkem_zp_dst),y
        dey
        bpl :-
        lda #0
        sta mlkem_status
        rts
.endproc

; =============================================================================
; Test hooks (MLKEM_TEST_HOOKS): the K-PKE primitives on the same block.
; =============================================================================
.ifdef MLKEM_TEST_HOOKS

.proc mlkem_kpke_keygen
        jmp kpke_keygen             ; SEED = d -> (EK), (DK) = dk_pke
.endproc

.proc mlkem_kpke_encrypt            ; EK = ek_pke, SEED = m, Z = r -> (CT)
        PTRSET IDX_EKP, IDX_EK, 0
        PTRSET IDX_M, IDX_SEED, 0
        PTRSET IDX_PSEED, IDX_Z, 0
        PTRSET IDX_OUT, IDX_CT, 0
        lda #0
        sta kp_cmp
        jsr kpke_encrypt
        lda #0
        rts
.endproc

.proc mlkem_kpke_decrypt            ; DK = dk_pke, CT = c -> (KEY) = m
        PTRSET IDX_MOUT, IDX_KEY, 0
        jsr kpke_decrypt
        lda #0
        rts
.endproc

.endif
