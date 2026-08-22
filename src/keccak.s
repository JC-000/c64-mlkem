.setcpu "6502"

; =============================================================================
; keccak.s — Keccak-f[1600] permutation (FIPS 202), compact/looped form.
;
; State: 25 lanes x 8 bytes = 200 B at `keccak_state`, page-aligned (src/state.s).
; Lane index i = x + 5y; lane i occupies bytes 8i..8i+7, little-endian. That is
; also the sponge's byte-serialisation order, so a rate-block XOR is a straight
; byte-wise operation with no reordering.
;
; DATAFLOW — chosen to avoid a 200-byte copy per round:
;
;     theta   state -> state   (in place)
;     rho+pi  state -> B       (fused; pi is a permutation, so it needs a
;                               separate destination anyway)
;     chi     B     -> state   (separate src/dst also removes chi's usual
;                               need to save two lanes per row)
;     iota    state[0..7] ^= RC[round]
;
; A naive implementation would copy B back to the state after rho+pi and then
; run chi in place; letting chi consume B and write the state instead makes
; that copy (~2,000 cycles/round, ~48k over 24 rounds) disappear entirely.
;
; Page alignment: `keccak_state` and `keccak_B` are both page-aligned and 200 B
; long, so every `abs,X` access below stays inside one page — no +1-cycle page
; -cross penalty, and the cost does not depend on which lane is touched.
;
; SIZE/SPEED: this is the compact form the P1 brief asks for first. The round
; constants are a 192-byte table rather than being generated on the fly (which
; would save ~150 B); unrolling and the RC-generator trade-off are deliberately
; left as MEASURED decisions, not defaults. See README.
; =============================================================================

.include "constants.s"

.importzp mlkem_zp_tmp, mlkem_zp_len

.export keccak_f1600
.export keccak_clear

; Per-step entry points for the differential test harness. They are gated so
; the shipped archive's export surface stays minimal and stable — contract
; §6.5 makes exported symbols contract surface, and these are test scaffolding,
; not library API. The archive is never built with this define.
.ifdef MLKEM_TEST_HOOKS
.export keccak_theta, keccak_rhopi, keccak_chi, keccak_iota
.export keccak_B
; kc_round is a zero-page equate, so it needs .exportzp, not .export. The
; harness writes it before calling keccak_iota standalone, to select which
; round constant is applied.
.exportzp kc_round
.endif

.import keccak_state

; --- zero-page aliases (within the 8 bytes declared in zp_config.s) ---------
kc_count   = mlkem_zp_tmp + 0      ; byte counter inside a lane
kc_lane    = mlkem_zp_tmp + 1      ; source lane index 0..24
kc_rowbase = mlkem_zp_len + 0      ; chi row base: 0, 40, 80, 120, 160
kc_round   = mlkem_zp_len + 1      ; round counter 0..23

.segment "LIB_MLKEM_RODATA"

.include "keccak_tables.inc"

.segment "LIB_MLKEM_BSS"

.align 256
keccak_B:       .res 200           ; rho+pi destination; page-aligned
keccak_C:       .res 40            ; theta column parities
keccak_rot:     .res 40            ; ROTL64(C[x], 1)
keccak_D:       .res 40            ; theta D[x]
keccak_tmp:     .res 8             ; one lane of scratch

.segment "LIB_MLKEM_CODE"

; =============================================================================
; keccak_clear — zero the 200-byte state.
; =============================================================================
.proc keccak_clear
        ; Counting DOWN with bpl would be wrong here: X starts at 199 ($C7),
        ; whose bit 7 is already set, so the very first bpl falls through and
        ; only one byte gets cleared. 200 > 128, so this counts up instead.
        lda #0
        ldx #0
:       sta keccak_state,x
        inx
        cpx #200
        bne :-
        rts
.endproc

; =============================================================================
; theta
;   C[x]   = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
;   D[x]   = C[x-1] ^ ROTL64(C[x+1], 1)
;   A[x,y] ^= D[x]
;
; Byte offsets: lane (x,y) is at 40y + 8x, so a column's five lanes sit exactly
; 40 bytes apart — which is why the C loop below is one flat 40-iteration pass
; rather than a nested one.
; =============================================================================
.proc keccak_theta
        ; --- C[k] = XOR of the five rows, k = 0..39 ------------------------
        ldx #0
c_loop:
        lda keccak_state+0,x
        eor keccak_state+40,x
        eor keccak_state+80,x
        eor keccak_state+120,x
        eor keccak_state+160,x
        sta keccak_C,x
        inx
        cpx #40
        bne c_loop

        ; --- rot[x] = ROTL64(C[x], 1), five lanes --------------------------
        ; 64-bit rotate-left-by-1 on a little-endian lane: seed the carry with
        ; bit 63 (top bit of byte 7), then rol bytes 0..7 in ascending order.
        ldx #0
rot_loop:
        lda keccak_C+7,x
        asl a                       ; C = old bit 63
        .repeat 8, i
        lda keccak_C+i,x
        rol a                       ; lda does not disturb the carry
        sta keccak_rot+i,x
        .endrepeat
        txa
        clc
        adc #8
        tax
        cpx #40
        bne rot_loop

        ; --- D[k] = C[(k+32) mod 40] ^ rot[(k+8) mod 40], k = 0..39 --------
        ; For k = 8*col + j, (k+32) mod 40 selects column (col+4) mod 5 and
        ; (k+8) mod 40 selects column (col+1) mod 5 — both at the same byte j.
        ldx #0
d_loop:
        txa
        clc
        adc #32
        cmp #40
        bcc :+
        sbc #40
:       tay
        lda keccak_C,y
        sta kc_count                ; stash C[(k+32) mod 40]
        txa
        clc
        adc #8
        cmp #40
        bcc :+
        sbc #40
:       tay
        lda keccak_rot,y
        eor kc_count
        sta keccak_D,x
        inx
        cpx #40
        bne d_loop

        ; --- A[i] ^= D[i mod 40] for all 200 bytes --------------------------
        ; Unrolled over the five rows so the D index is just X, with no
        ; separate wrapping counter.
        ldx #0
apply:
        lda keccak_D,x
        eor keccak_state+0,x
        sta keccak_state+0,x
        lda keccak_D,x
        eor keccak_state+40,x
        sta keccak_state+40,x
        lda keccak_D,x
        eor keccak_state+80,x
        sta keccak_state+80,x
        lda keccak_D,x
        eor keccak_state+120,x
        sta keccak_state+120,x
        lda keccak_D,x
        eor keccak_state+160,x
        sta keccak_state+160,x
        inx
        cpx #40
        bne apply
        rts
.endproc

; =============================================================================
; rho + pi, fused:  B[pi_dst[i]] = ROTL64(A[i], rho[i])
;
; rho[i] splits as 8*byte + bit. The whole-byte part is free — it is just a
; byte permutation applied while copying the lane into scratch. Only the 0..7
; residual bits need real shifting.
; =============================================================================
.proc keccak_rhopi
        lda #0
        sta kc_lane
lane_loop:
        ; --- copy lane into keccak_tmp, applying the whole-byte rotation ---
        ldy kc_lane
        lda keccak_rho_byte,y
        tay                         ; Y = destination index inside tmp
        lda kc_lane
        asl a
        asl a
        asl a
        tax                         ; X = 8 * lane = source byte offset
        lda #8
        sta kc_count
byte_loop:
        lda keccak_state,x
        sta keccak_tmp,y
        inx
        iny
        tya
        and #7                      ; tmp index wraps within the lane
        tay
        dec kc_count
        bne byte_loop

        ; --- residual bit rotation, 0..7 times ------------------------------
        ldy kc_lane
        ldx keccak_rho_bit,y
        beq no_bits
bit_loop:
        lda keccak_tmp+7
        asl a                       ; C = bit 63
        rol keccak_tmp+0
        rol keccak_tmp+1
        rol keccak_tmp+2
        rol keccak_tmp+3
        rol keccak_tmp+4
        rol keccak_tmp+5
        rol keccak_tmp+6
        rol keccak_tmp+7
        dex
        bne bit_loop
no_bits:

        ; --- store into B at the pi destination -----------------------------
        ldy kc_lane
        ldx keccak_pi_dst,y
        .repeat 8, i
        lda keccak_tmp+i
        sta keccak_B+i,x
        .endrepeat

        inc kc_lane
        lda kc_lane
        cmp #25
        beq :+
        jmp lane_loop               ; the lane body exceeds a branch's 8-bit
:       rts                         ; displacement, so this cannot be a bne
.endproc

; =============================================================================
; chi:  A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
;
; Reads B, writes the state. Within one row the three lane displacements are
; compile-time constants, so X carries only (row base + byte index) and the
; five columns unroll with fixed offsets — no per-column index arithmetic.
; =============================================================================
.proc keccak_chi
        lda #0
        sta kc_rowbase
row_loop:
        ldx kc_rowbase
        ldy #8
byte_loop:
        ; x = 0: dst +0,  ~src +8,  & +16
        lda keccak_B+8,x
        eor #$FF
        and keccak_B+16,x
        eor keccak_B+0,x
        sta keccak_state+0,x
        ; x = 1: dst +8,  ~src +16, & +24
        lda keccak_B+16,x
        eor #$FF
        and keccak_B+24,x
        eor keccak_B+8,x
        sta keccak_state+8,x
        ; x = 2: dst +16, ~src +24, & +32
        lda keccak_B+24,x
        eor #$FF
        and keccak_B+32,x
        eor keccak_B+16,x
        sta keccak_state+16,x
        ; x = 3: dst +24, ~src +32, & +0
        lda keccak_B+32,x
        eor #$FF
        and keccak_B+0,x
        eor keccak_B+24,x
        sta keccak_state+24,x
        ; x = 4: dst +32, ~src +0,  & +8
        lda keccak_B+0,x
        eor #$FF
        and keccak_B+8,x
        eor keccak_B+32,x
        sta keccak_state+32,x
        inx
        dey
        bne byte_loop

        lda kc_rowbase
        clc
        adc #40
        sta kc_rowbase
        cmp #200
        bne row_loop
        rts
.endproc

; =============================================================================
; iota:  A[0,0] ^= RC[round]
; =============================================================================
.proc keccak_iota
        lda kc_round
        asl a
        asl a
        asl a                       ; 8 * round
        tax
        ldy #0
:       lda keccak_state,y
        eor keccak_rc,x
        sta keccak_state,y
        inx
        iny
        cpy #8
        bne :-
        rts
.endproc

; =============================================================================
; keccak_f1600 — the full 24-round permutation, in place on keccak_state.
; Clobbers A, X, Y and the library's four ZP scratch slots.
; =============================================================================
.proc keccak_f1600
        lda #0
        sta kc_round
round_loop:
        jsr keccak_theta
        jsr keccak_rhopi
        jsr keccak_chi
        jsr keccak_iota
        inc kc_round
        lda kc_round
        cmp #24
        bne round_loop
        rts
.endproc
