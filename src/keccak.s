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
kc_count   = mlkem_zp_tmp + 0      ; iota: RC pointer lo (P1 used it as the rotation pass counter)
kc_lane    = mlkem_zp_tmp + 1      ; iota: RC pointer hi (P1 used it as the lane counter)
kc_rowbase = mlkem_zp_len + 0      ; chi row base: 0, 40, 80, 120, 160
kc_round   = mlkem_zp_len + 1      ; round counter 0..23

.segment "LIB_MLKEM_RODATA"

.include "keccak_tables.inc"

.assert (keccak_rc .mod 8) = 0, lderror, "keccak_rc is not 8-aligned: an iota entry would straddle a page"

.segment "LIB_MLKEM_BSS"

; Order matters here. ld65 aligns an object's ENTIRE segment fragment to the
; largest alignment requested inside it, so any variable declared BEFORE the
; `.align 256` below still lands after that alignment — and then pushes
; keccak_B to the next page, costing ~253 bytes of padding. The aligned
; buffers come first; the odd bytes go at the end where they are free.
.align 256
keccak_B:       .res 200           ; rho+pi destination; page-aligned
; theta's column parities with a one-lane mirror on each side:
;     [C4'] [C0 C1 C2 C3 C4] [C0']
; so that C[col-1] and C[col+1] are fixed displacements from C[col] for every
; column, no mod-40 wrap. 56 B, which is exactly the tail of keccak_B's page:
; every theta access stays inside that page, so none pays a crossing cycle.
keccak_Cx:      .res 56
keccak_C        = keccak_Cx + 8
.assert >keccak_B = >(keccak_Cx + 55), lderror, "keccak_Cx leaves keccak_B's page: theta cost would move with the layout"
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
;
; D is never stored. After C is mirrored (C[-1] = C[4], C[5] = C[0]) the
; column loop walks X = 8*col and, per byte, rotates C[col+1] left by one
; (the rol carry chain runs down the lane; eor/tay/sta leave C alone), XORs
; C[col-1], parks the D byte in Y and applies it to the five rows straight
; away. That fuses P1's three passes (rot 535 + D 2,000 + apply 2,880
; cycles/round) into one of ~2,700 (P3 lever 3; measured in README).
; =============================================================================
.proc keccak_theta
        ; --- C[k] = XOR of the five rows, k = 0..39 ------------------------
        ; Four bytes per iteration, X = 36, 32, .. 0 (bpl exits on $FC): the
        ; loop overhead is 11 cycles per 4 bytes instead of 7 per byte.
        ldx #36
c_loop:
        .repeat 4, i
        lda keccak_state+0+i,x
        eor keccak_state+40+i,x
        eor keccak_state+80+i,x
        eor keccak_state+120+i,x
        eor keccak_state+160+i,x
        sta keccak_C+i,x
        .endrepeat
        dex
        dex
        dex
        dex
        bpl c_loop

        ; --- mirror: C[-1] = C[4], C[5] = C[0] ------------------------------
        ldx #7
:       lda keccak_C+32,x
        sta keccak_C-8,x
        lda keccak_C+0,x
        sta keccak_C+40,x
        dex
        bpl :-

        ; --- per column: D = C[col-1] ^ ROTL64(C[col+1], 1); A[col,*] ^= D --
        ldx #0
col_loop:
        lda keccak_C+8+7,x
        asl a                       ; C = bit 63 of C[col+1]
        .repeat 8, i
        lda keccak_C+8+i,x
        rol a                       ; carry chains from the previous byte
        eor keccak_C-8+i,x          ; A = D[col] byte i
        tay
        eor keccak_state+0+i,x
        sta keccak_state+0+i,x
        tya
        eor keccak_state+40+i,x
        sta keccak_state+40+i,x
        tya
        eor keccak_state+80+i,x
        sta keccak_state+80+i,x
        tya
        eor keccak_state+120+i,x
        sta keccak_state+120+i,x
        tya
        eor keccak_state+160+i,x
        sta keccak_state+160+i,x
        .endrepeat
        txa
        clc
        adc #8
        tax
        cpx #40
        beq :+
        jmp col_loop                ; body exceeds a branch displacement
:       rts
.endproc

; =============================================================================
; rho + pi, fused:  B[pi_dst[i]] = ROTL64(A[i], rho[i])
;
; Three things make this the fast form rather than the obvious one:
;
;  1. THE BYTE ROTATION IS FREE. rho[i] splits as 8*byte + bit; the whole-byte
;     part is applied while copying the lane, by choosing which destination
;     byte each source byte lands in. No shifting at all.
;
;  2. THE COPY GOES STRAIGHT TO THE DESTINATION. The lane is written directly
;     into keccak_B at its pi destination and rotated IN PLACE there, so there
;     is no scratch lane and no second 8-byte store pass.
;
;  3. IT ROTATES THE SHORT WAY ROUND. ROTL64(v, 8s+b) with b > 4 equals a
;     byte-rotation of s+1 followed by a rotate RIGHT of 8-b, since
;     8s+b == 8(s+1)-(8-b). Taking whichever direction is shorter caps the bit
;     passes at 4 instead of 7 and cuts the per-round total from 88 to 52.
;     The decomposition is verified for all 25 lanes in tools/test_keccak_ref.py.
;
; And one from P3 (levers 4 and 5b): THE LANE LOOP IS A GENERATED SCRIPT.
; P1 walked a lane counter through four 25-entry tables and a jump vector,
; ~80 cycles of bookkeeping per lane. The 25 lanes are now straight-line
; KECCAK_LANE expansions (src/keccak_tables.inc, from the validated model):
; every parameter is an immediate, the copy variant is a plain `jsr`, and
; the bit rotation is a `jsr` straight to the entry for that lane's pass
; count in an unrolled pass ladder (rot_left4 falls into rot_left3 ... into
; the rts), so there is no dispatch and no pass counter. No table is read,
; so nothing here can straddle a page. 7 or 10 bytes per lane.
;
; Register discipline through one lane:
;     Y = 8 * source lane                      (copy only)
;     X = destination byte offset in keccak_B  (held across copy AND rotate)
; =============================================================================
.macro KECCAK_LANE lane, dst, s, sc
        ldy #8 * lane
        ldx #dst
        jsr .ident(.sprintf("copy_s%d", s))
    .if (sc & $7F) > 0
        .if sc & $80
        jsr .ident(.sprintf("rot_right%d", sc & $7F))
        .else
        jsr .ident(.sprintf("rot_left%d", sc & $7F))
        .endif
    .endif
.endmacro

.proc keccak_rhopi
        KECCAK_RHOPI_SCRIPT
        rts
.endproc

; --- the rotation pass ladders, in place at keccak_B + X -------------------
; rot_leftN / rot_rightN rotate the lane by N bits (N = 1..4): each entry is
; one pass that falls through into the next-lower entry and finally the rts.
.macro ROT_LEFT_PASS
        lda keccak_B+7,x
        asl a                       ; C = bit 63
        rol keccak_B+0,x
        rol keccak_B+1,x
        rol keccak_B+2,x
        rol keccak_B+3,x
        rol keccak_B+4,x
        rol keccak_B+5,x
        rol keccak_B+6,x
        rol keccak_B+7,x
.endmacro
.macro ROT_RIGHT_PASS
        lda keccak_B+0,x
        lsr a                       ; C = bit 0
        ror keccak_B+7,x
        ror keccak_B+6,x
        ror keccak_B+5,x
        ror keccak_B+4,x
        ror keccak_B+3,x
        ror keccak_B+2,x
        ror keccak_B+1,x
        ror keccak_B+0,x
.endmacro

rot_left4:  ROT_LEFT_PASS
rot_left3:  ROT_LEFT_PASS
rot_left2:  ROT_LEFT_PASS
rot_left1:  ROT_LEFT_PASS
        rts
rot_right4: ROT_RIGHT_PASS
rot_right3: ROT_RIGHT_PASS
rot_right2: ROT_RIGHT_PASS
rot_right1: ROT_RIGHT_PASS
        rts

; --- the eight byte-rotation copy variants ---------------------------------
; Each writes all 8 source bytes to their rotated destination positions:
;     keccak_B[dst + ((j + s) & 7)] = keccak_state[8*lane + j]
; Straight-line lda abs,Y / sta abs,X pairs — no index arithmetic at all.
.macro COPY_VARIANT s
    .repeat 8, j
        lda keccak_state+j,y
        sta keccak_B+((j+s) & 7),x
    .endrepeat
        rts
.endmacro

copy_s0: COPY_VARIANT 0
copy_s1: COPY_VARIANT 1
copy_s2: COPY_VARIANT 2
copy_s3: COPY_VARIANT 3
copy_s4: COPY_VARIANT 4
copy_s5: COPY_VARIANT 5
copy_s6: COPY_VARIANT 6
copy_s7: COPY_VARIANT 7

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
;
; The entry is read through a zero-page pointer rather than `abs,x`: an
; (zp),y read only pays the page-cross cycle when the 8-byte entry itself
; straddles a page, which the 8-alignment of keccak_rc rules out. That makes
; the permutation's cycle count independent of where rodata lands (P1's
; headline moved by 115-251 cycles between links before this). kc_count /
; kc_lane are free during iota and are consecutive, so they serve as the
; pointer without widening the library's ZP surface.
; =============================================================================
kc_rcptr   = kc_count               ; 2 bytes: kc_count, kc_lane
.assert kc_lane = kc_count + 1, error, "kc_rcptr needs kc_count and kc_lane consecutive"
.proc keccak_iota
        lda kc_round
        asl a
        asl a
        asl a                       ; 8 * round (< 256)
        clc
        adc #<keccak_rc
        sta kc_rcptr+0
        lda #>keccak_rc
        adc #0
        sta kc_rcptr+1
        ldy #7
:       lda keccak_state,y
        eor (kc_rcptr),y
        sta keccak_state,y
        dey
        bpl :-
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
