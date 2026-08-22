.setcpu "6502"

; =============================================================================
; sponge.s — FIPS 202 sponge: SHA3-256, SHA3-512, SHAKE128, SHAKE256.
;
; One generic sponge parameterised by (rate, domain suffix); the four public
; functions are three-instruction wrappers that select the pair. Compact by
; construction — the whole layer is one absorb loop, one pad, one squeeze loop.
;
; NO SEPARATE ABSORB BUFFER. Incoming bytes are XORed straight into the state
; at `sponge_pos`, and a permutation fires when pos reaches the rate. A
; buffered design would cost another 168 bytes of BSS and an extra copy per
; block for nothing.
;
; STREAMING, as the P1 brief requires:
;   - absorb takes arbitrary lengths and may be called repeatedly; any
;     chunking of the same message gives the same result.
;   - squeeze may be called repeatedly and CONTINUES the output stream across
;     calls — ML-KEM's matrix expansion squeezes many blocks per call site.
;   - squeeze applies the padding automatically on its first call, so SHA-3
;     usage is simply init / absorb* / squeeze. This mirrors the reference
;     model's Sponge class exactly, which is what lets the differential tests
;     drive both with identical call sequences.
;
; CALLING CONVENTION
;   absorb:   pointer   -> mlkem_zp_src (ZP, for (zp),y)
;             length    -> mlkem_sponge_len (16-bit, little-endian)
;             then jsr mlkem_absorb
;   squeeze:  pointer   -> mlkem_zp_dst
;             length    -> mlkem_sponge_len
;             then jsr mlkem_squeeze
;   Both consume mlkem_sponge_len (it reads 0 on return).
;
; ZERO PAGE: this layer uses only mlkem_zp_src / mlkem_zp_dst. keccak_f1600
; clobbers mlkem_zp_tmp and mlkem_zp_len, so nothing here may hold live state
; in those two across a permutation — which is why the length counter and the
; sponge context live in BSS rather than in zero page.
; =============================================================================

.include "constants.s"

.importzp mlkem_zp_src, mlkem_zp_dst
.import keccak_state, keccak_f1600, keccak_clear

.export mlkem_sha3_256_init, mlkem_sha3_512_init
.export mlkem_shake128_init, mlkem_shake256_init
.export mlkem_absorb, mlkem_squeeze, mlkem_sponge_len

.ifdef MLKEM_TEST_HOOKS
.export sponge_pos, sponge_rate, sponge_suffix, sponge_squeezing
.endif

.segment "LIB_MLKEM_BSS"

sponge_rate:        .res 1      ; 136 / 72 / 168
sponge_suffix:      .res 1      ; $06 SHA-3, $1F SHAKE
sponge_pos:         .res 1      ; byte offset within the current rate block
sponge_squeezing:   .res 1      ; 0 = absorbing, 1 = padded and squeezing
sponge_n:           .res 1      ; bytes handled this chunk
mlkem_sponge_len:   .res 2      ; caller-supplied length, consumed in place

.segment "LIB_MLKEM_CODE"

; =============================================================================
; Public init entry points. A = rate, X = domain suffix.
;
; The suffixes are FIPS 202's, NOT original Keccak's $01 — a library that
; confuses the two produces plausible-looking digests that match nothing.
; =============================================================================
.proc mlkem_sha3_256_init
        lda #SHA3_256_RATE
        ldx #SHA3_SUFFIX
        jmp sponge_init
.endproc

.proc mlkem_sha3_512_init
        lda #SHA3_512_RATE
        ldx #SHA3_SUFFIX
        jmp sponge_init
.endproc

.proc mlkem_shake128_init
        lda #SHAKE128_RATE
        ldx #SHAKE_SUFFIX
        jmp sponge_init
.endproc

.proc mlkem_shake256_init
        lda #SHAKE256_RATE
        ldx #SHAKE_SUFFIX
        jmp sponge_init
.endproc

.proc sponge_init
        sta sponge_rate
        stx sponge_suffix
        lda #0
        sta sponge_pos
        sta sponge_squeezing
        jmp keccak_clear            ; tail call; keccak_clear rts's for us
.endproc

; =============================================================================
; mlkem_absorb — XOR mlkem_sponge_len bytes at (mlkem_zp_src) into the state.
; =============================================================================
.proc mlkem_absorb
outer:
        lda mlkem_sponge_len+0
        ora mlkem_sponge_len+1
        bne :+
        rts
:
        jsr chunk_size              ; sponge_n = min(len, rate - pos)

        ; --- XOR sponge_n bytes: Y indexes the source, X the state ---------
        ldy #0
        ldx sponge_pos
xor_loop:
        cpy sponge_n
        beq xor_done
        lda (mlkem_zp_src),y
        eor keccak_state,x
        sta keccak_state,x
        iny
        inx
        bne xor_loop                ; pos+n <= rate <= 168, so X cannot wrap
xor_done:

        ; --- advance the source pointer by sponge_n -------------------------
        lda mlkem_zp_src+0
        clc
        adc sponge_n
        sta mlkem_zp_src+0
        bcc :+
        inc mlkem_zp_src+1
:
        jsr advance                 ; len -= n, pos += n, permute if block full
        jmp outer
.endproc

; =============================================================================
; mlkem_squeeze — write mlkem_sponge_len bytes to (mlkem_zp_dst).
;
; Pads and permutes on the first call. Continues the output stream on every
; later call, so squeezing 2 x 100 bytes equals squeezing 200 in one go.
; =============================================================================
.proc mlkem_squeeze
        lda sponge_squeezing
        bne outer
        jsr sponge_pad
outer:
        lda mlkem_sponge_len+0
        ora mlkem_sponge_len+1
        bne :+
        rts
:
        ; A fresh block is needed only once the previous one is exhausted.
        lda sponge_pos
        cmp sponge_rate
        bne have_room
        jsr keccak_f1600
        lda #0
        sta sponge_pos
have_room:
        jsr chunk_size

        ldy #0
        ldx sponge_pos
copy_loop:
        cpy sponge_n
        beq copy_done
        lda keccak_state,x
        sta (mlkem_zp_dst),y
        iny
        inx
        bne copy_loop
copy_done:

        lda mlkem_zp_dst+0
        clc
        adc sponge_n
        sta mlkem_zp_dst+0
        bcc :+
        inc mlkem_zp_dst+1
:
        ; len -= n, pos += n. Unlike absorb this must NOT permute on a full
        ; block — the next call does that, so a squeeze ending exactly on a
        ; block boundary does not burn a permutation it might never need.
        jsr shrink
        jmp outer
.endproc

; =============================================================================
; sponge_pad — apply the FIPS 202 pad10*1 with the domain suffix, permute.
;
; When pos == rate-1 the suffix and the final $80 bit land in the SAME byte.
; Two separate EORs at that index give exactly the byte one combined EOR of
; ($06|$80) = $86 would, so no special case is needed — this is the padding
; edge that the CAVP rate-1 vectors exercise.
; =============================================================================
.proc sponge_pad
        ldx sponge_pos
        lda keccak_state,x
        eor sponge_suffix
        sta keccak_state,x

        ldx sponge_rate
        dex
        lda keccak_state,x
        eor #$80
        sta keccak_state,x

        jsr keccak_f1600
        lda #0
        sta sponge_pos
        lda #1
        sta sponge_squeezing
        rts
.endproc

; =============================================================================
; chunk_size — sponge_n = min(mlkem_sponge_len, rate - pos), always >= 1.
; =============================================================================
.proc chunk_size
        lda sponge_rate
        sec
        sbc sponge_pos
        sta sponge_n                ; avail; >= 1 because pos < rate always
        lda mlkem_sponge_len+1
        bne done                    ; len >= 256 > avail, so n = avail
        lda mlkem_sponge_len+0
        cmp sponge_n
        bcs done                    ; len >= avail, so n = avail
        sta sponge_n                ; else n = len
done:
        rts
.endproc

; =============================================================================
; shrink  — mlkem_sponge_len -= sponge_n, sponge_pos += sponge_n
; advance — the same, then permute and reset pos if the block is now full
; =============================================================================
.proc shrink
        lda mlkem_sponge_len+0
        sec
        sbc sponge_n
        sta mlkem_sponge_len+0
        bcs :+
        dec mlkem_sponge_len+1
:
        lda sponge_pos
        clc
        adc sponge_n
        sta sponge_pos
        rts
.endproc

.proc advance
        jsr shrink
        lda sponge_pos
        cmp sponge_rate
        bne done
        jsr keccak_f1600
        lda #0
        sta sponge_pos
done:
        rts
.endproc
