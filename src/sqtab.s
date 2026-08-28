.setcpu "6502"

; =============================================================================
; sqtab.s — c64-lib-contract §8.1 shared quarter-square table: the init.
;
; OWNER build (standalone default, SHARED_SQTAB_INIT undefined): this TU
; provides the canonical `mul_tables_init` — the one unprefixed export this
; library has, permitted because it is the §8.1 canonical name (on
; check-prefix's allow-list for exactly that reason). No historical
; `sqtab_init` alias exists here and none may be invented (a second unprefixed
; export with no clause behind it).
;
; DEFERRING build (`-D SHARED_SQTAB_INIT` in CONTRACT_DEFINES): a sibling or
; the consumer's own module owns the table. The canonical entry is IMPORTED and
; the body below is gated out entirely (§6.4 half two). NEVER an exported stub:
; two same-named inits in one composed link is the duplicate-identifier failure
; the switch exists to remove (§8.1 v0.9.0, import-never-stub).
;
; The library's own routines never call this. Boot-time init is the consumer's
; job (§8.0 deferring-consumer row); the standalone PRG's src/main.s calls it
; once at start. Idempotent: table bytes only, no other state.
;
; Table: sqtab_lo/hi[n] = floor(n^2 / 4), n = 0..511 (511 is unused by any
; consumer; filling it costs nothing and keeps the loop a clean page pair).
; Built by the recurrence t(n+1) = t(n) + floor((n+1)/2), all public data, so
; the page-select branch below is not a timing concern.
; =============================================================================

.include "constants.s"

.ifndef SHARED_SQTAB_INIT

.export mul_tables_init

.segment "LIB_MLKEM_BSS"
sq_acc:     .res 2              ; t(n), 16-bit (t(511) = 65,280 fits)
sq_inc:     .res 1              ; floor((n+1)/2), <= 255
sq_page:    .res 1              ; 0 for n < 256, 1 after

.segment "LIB_MLKEM_CODE"

.proc mul_tables_init
        lda #0
        sta sq_acc
        sta sq_acc+1
        sta sq_inc
        sta sq_page
        tax                             ; n & $FF
@loop:
        lda sq_page
        bne @page1
        lda sq_acc
        sta sqtab_lo,x
        lda sq_acc+1
        sta sqtab_hi,x
        jmp @advance
@page1:
        lda sq_acc
        sta sqtab_lo+256,x
        lda sq_acc+1
        sta sqtab_hi+256,x
@advance:
        ; t(n+1) = t(n) + floor((n+1)/2); the increment grows by one after
        ; every EVEN n (floor((n+2)/2) - floor((n+1)/2) = 1 iff n even).
        clc
        lda sq_acc
        adc sq_inc
        sta sq_acc
        bcc :+
        inc sq_acc+1
:       txa
        and #1
        bne :+
        inc sq_inc
:       inx
        bne @loop
        inc sq_page
        lda sq_page
        cmp #2
        bne @loop
        rts
.endproc

.else

; Deferring build: the provider's canonical entry, by import only.
.import mul_tables_init

.endif
