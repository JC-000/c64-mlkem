.setcpu "6502"

; =============================================================================
; bench.s — cycle-exact benchmark harness.
;
; SHIPS IN NO ARCHIVE. This is the library author's measurement instrument,
; not library surface. Keeping it out of build/lib/*.a also makes this TU the
; natural home for an image guard (the linked image must end below the region)
; when a future phase places an equate-reserved region.
;
; bench_cycles_start / bench_cycles_stop configure CIA1 Timer A + Timer B as a
; chained free-running 32-bit down-counter from $FFFFFFFF:
;   TA counts phi2 (system clock) cycles; TB counts TA underflows.
; Result lands in `bench_cycles` as a little-endian u32.
;
; Why not the jiffy clock: the KERNAL IRQ is what advances it, so a timed body
; that runs with IRQs masked reports 0 jif. A jiffy is also ~17,045 NTSC
; cycles — far too coarse for a single Keccak-f[1600] permutation (estimated
; 150k-350k cycles). A single 16-bit timer would overflow, hence the chain.
;
; CAVEAT (inherited from the c64-x25519 original): this replaces the KERNAL's
; CIA1 TA setup, so the jiffy IRQ rate is wrong afterwards until KERNAL
; re-init. Fine for a run-once bench harness; not a drop-in for long-running
; host programs.
;
; CALIBRATION: the TB tick is asserted to be exactly 65,536 TA cycles. That is
; an arithmetic claim about CIA underflow/reload behaviour, not a measured
; one — `make bench` calibrates it against a routine of known cycle cost
; before any Keccak number is reported. Do not trust the raw u32 until that
; calibration passes.
;
; Single-shot; not nestable. Preserves the caller's I-flag.
; =============================================================================

.include "constants.s"

.export bench_cycles_start, bench_cycles_stop, bench_cycles
.export bench_spin_1000
.export vic_blank, vic_unblank, bench_sync_frame

.segment "CODE"

; --- bench_cycles_start ---------------------------------------------------
; Configure CIA1 TA+TB as a chained 32-bit down-counter starting at
; $FFFFFFFF. Saves the caller's P (incl. I flag) and leaves IRQs masked while
; the counter runs; bench_cycles_stop's plp restores it.
.proc bench_cycles_start
        php                         ; save caller's P (incl. I flag)
        pla
        sta bench_cycles_saved_p
        sei                         ; mask IRQs while we reconfigure CIA1

        ; Stop both timers so a write to TA/TB hi loads the latch without
        ; racing a force-load.
        lda #$00
        sta cia1_cra                ; CRA = 0 -> TA stopped
        sta cia1_crb                ; CRB = 0 -> TB stopped

        ; Mask CIA1 TA/TB underflow IRQ sources. ICR write with bit 7 = 0
        ; means "clear the named sources"; bits 0,1 name TA and TB underflow.
        lda #$7f
        sta cia1_icr
        lda cia1_icr                ; read clears latched IRQs

        ; TA latch = $FFFF (writing hi to a stopped timer loads the counter).
        lda #$ff
        sta cia1_ta_lo
        sta cia1_ta_hi

        ; TB latch = $FFFF
        sta cia1_tb_lo
        sta cia1_tb_hi

        ; Start TB first, in "count TA underflows" mode.
        ; CRB = %01010001: bit0 start, bit3 continuous, bit4 force-load,
        ;                  bits5-6 = 10 -> count TA underflows.
        lda #$51
        sta cia1_crb

        ; Start TA counting phi2.
        ; CRA = %00010001: bit0 start, bit3 continuous, bit4 force-load,
        ;                  bits5-6 = 00 -> count phi2.
        lda #$11
        sta cia1_cra
        rts
.endproc

; --- bench_cycles_stop ----------------------------------------------------
; Stop both timers, compute the 32-bit elapsed count into bench_cycles,
; restore the caller's P.
.proc bench_cycles_stop
        ; Stop both timers => atomic snapshot, no read-while-running hazard.
        lda #$00
        sta cia1_cra
        sta cia1_crb

        ; low 16 bits = $FFFF - TA
        sec
        lda #$ff
        sbc cia1_ta_lo
        sta bench_cycles+0
        lda #$ff
        sbc cia1_ta_hi
        sta bench_cycles+1

        ; high 16 bits = $FFFF - TB
        sec
        lda #$ff
        sbc cia1_tb_lo
        sta bench_cycles+2
        lda #$ff
        sbc cia1_tb_hi
        sta bench_cycles+3

        lda bench_cycles_saved_p
        pha
        plp                         ; restore caller's I flag
        rts
.endproc

; --- vic_blank / vic_unblank ---------------------------------------------
; The VIC-II steals CPU cycles on badlines (~40-43 cycles each, 25 per frame
; in text mode). A measurement window shorter than a frame therefore contains
; a VARYING number of badlines depending on where in the frame it starts, and
; repeated runs of the same code disagree — measured here as 1293 / 1310 /
; 1396 / 1439 cycles for one identical 1,293-cycle routine.
;
; Clearing DEN (bit 4 of $D011) blanks the display and stops badline DMA
; outright, which makes the count reproducible to the cycle and is also ~6%
; faster. Blank across any window whose result is meant to be exact.
.proc vic_blank
        lda vic_screen_ctrl
        and #$EF                    ; DEN = 0: display off, no badline DMA
        sta vic_screen_ctrl
        rts
.endproc

.proc vic_unblank
        lda vic_screen_ctrl
        ora #$10                    ; DEN = 1
        sta vic_screen_ctrl
        rts
.endproc

; --- bench_sync_frame -----------------------------------------------------
; Wait for a full raster frame to elapse, twice.
;
; Why this is REQUIRED after vic_blank and not merely tidy: the VIC-II samples
; DEN only at raster line $30. Clearing it later in a frame leaves badline DMA
; running for the REST of that frame, so a short measurement window taken right
; after vic_blank may still be stolen from — and whether it is depends purely
; on where in the frame the blank happened. That is not a stable property of
; the code being measured, and it is exactly what made an earlier version of
; this harness report 1293 / 1310 / 1396 / 1439 cycles for one identical
; routine depending on what ran before it.
;
; Waiting also aligns the window start to a known raster position, so the
; measurement is reproducible rather than merely usually-right.
.proc bench_sync_frame
        ldx #2
frame:
:       lda vic_raster              ; leave line 0
        beq :-
:       lda vic_raster              ; and come back to it
        bne :-
        dex
        bne frame
        rts
.endproc

; --- bench_spin_1000 ------------------------------------------------------
; Calibration target of known cost. A `dex` / `bne` pair is 2 + 3 = 5 cycles
; per iteration while branching, 2 + 2 = 4 on the final non-taken branch.
; Entered with X = 0 => 256 iterations:
;     ldx #0        2
;     255 x (dex+bne taken)   255 * 5 = 1275
;     1   x (dex+bne not taken)         4
;     rts                              6
;   total = 1287 cycles, plus 6 for the caller's jsr.
; `make bench` asserts the measured value against this before trusting any
; Keccak number.
.proc bench_spin_1000
        ldx #$00
:       dex
        bne :-
        rts
.endproc

.segment "BSS"

bench_cycles_saved_p:   .res 1
bench_cycles:           .res 4
