.setcpu "6502"

; =============================================================================
; main.s — standalone test-harness driver for c64-mlkem.
;
; SHIPS IN NO ARCHIVE (contract §6.1: never put a driver object into an
; archive). Consumers supply their own entry point; this file exists so
; `make` produces a PRG that the c64-test-harness can load into VICE and
; drive over the binary monitor.
;
; Runtime shape: print a banner, then park in an infinite loop. The harness
; syncs on the banner with wait_for_text(), then DMAs inputs in, `jsr`s a
; routine by its label address, and DMAs results out. Nothing here needs to
; do any work itself.
;
; This TU deliberately emits into the bare CODE/BSS segments rather than
; LIB_MLKEM_*: §4's prefix rule binds *library* sources, and the point of the
; rule is that a consumer's own CODE must not collide with library bytes.
; Driver code IS the consumer here.
; =============================================================================

.include "constants.s"

.import keccak_state
.import bench_cycles_start, bench_cycles_stop, bench_cycles, bench_spin_1000

.export start

; --- PRG load address ($0801) ---------------------------------------------
.segment "LOADADDR"
        .addr   *+2

; --- BASIC stub: 10 SYS 2061 ----------------------------------------------
; 12 bytes, $0801-$080C, so execution starts at $080D = 2061.
.segment "BASICSTUB"
basic_stub:
        .word   next_line           ; pointer to next BASIC line
        .word   2026                ; line number
        .byte   $9E                 ; SYS token
        .byte   "2061", $00         ; argument + end-of-line
next_line:
        .word   $0000               ; end of BASIC program

; --- Entry point ($080D) --------------------------------------------------
.segment "CODE"

start:
        ; Reference the imports so ld65 pulls the objects into the link even
        ; while nothing calls them yet. Costs 6 bytes and keeps `make` an
        ; honest check that every TU assembles, links and lands somewhere.
        lda     #<keccak_state
        lda     #<bench_cycles

        ldx     #$00
:       lda     banner,x
        beq     idle
        jsr     chrout
        inx
        bne     :-

idle:
        jmp     idle                ; park for the harness

banner:
        .byte   "C64-MLKEM P1 READY", $0D, $00

.segment "BSS"
; (driver scratch, if any, lands here)
