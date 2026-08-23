# CLAUDE.md — working notes for agents in this repo

Read `HANDOFF.md` first; it is the authoritative P1 brief. This file records
the conventions that are easy to get wrong.

## Scope discipline

**P1 is Keccak only.** No NTT, no ML-KEM arithmetic, no samplers — that is P2,
gated on P1's measured cycle count and starting from its own handoff. No
changes to `c64-https` (consumer wiring is Phase 4, consumer-side). No ML-DSA
ever. No REU anywhere in P1.

## The four numbers P1 owed — all in hand as of v0.3.0

1. **Keccak-f[1600] = 456,605 cycles** (19,025/round). Was 600,771 before the
   rho+pi pass; `v0.2.0` preserves that baseline.
2. **1,477 B resident** (1,169 code + 308 rodata), 594 B BSS. 48.1% of the
   ~3 KB budget.
3. **820 NIST CAVP ShortMsg vectors** across the four functions, plus 199
   per-step differential checks and the streaming properties. All pass.
4. **Five SPEC divergences**, tabulated in README.

**The headline is bad news and must not be softened:** the measurement is
1.3x the TOP of the roadmap's 150k–350k estimate band. Keccak alone is
25–27M cycles for keygen+decaps against a 40–70M total budget. Any planning
figure derived from the old estimate is void.

## Toolchain traps

- The ca65 define flag is **`-D name[=value]`**. `--asm-define` is `cl65`'s
  spelling and `ca65` rejects it outright.
- **Never put `$` in a `-D` value.** Unquoted `$40` becomes `0` silently at
  every stage. Through make it is worse: `$40` and `$$40` both yield 0,
  `$$$$40` yields the shell PID. Use `0x40` or decimal.
- `.assert ..., lderror` for anything involving an `.import`ed symbol —
  **never** `.if`/`.error`. An imported symbol has no value until link, so ca65
  rejects an `.if` guard with `Constant expression expected` and the guard
  never assembles at all.
- ca65 rejects backslash line-continuation unless `.linecont +`. Keep asserts
  on one line.
- Version exports need `: abs`. Without it ca65 infers zeropage (the values fit
  in a byte) and every consumer `.import` warns `Address size mismatch`.
- **bss-type segments stay last** in a file-emitting area. Mid-area, ld65 emits
  a shorter image and everything after the hole loads at the wrong address —
  measured at 9,154 bytes of displacement, silent.
- **ld65 aligns an object's ENTIRE segment fragment** to the largest alignment
  requested anywhere inside it. A variable declared *before* an `.align 256`
  therefore still lands after that alignment AND pushes the aligned buffer to
  the next page. Cost 253 B of BSS here before it was spotted. Put aligned
  buffers first, odd bytes last.
- **`jmp (abs)` fetches the high byte from the same page as the low one.** A
  vector whose low byte is `$FF` reads garbage. `kc_jmp` carries a link-time
  assert against exactly that.
- **Branch displacement is 8-bit.** Both `keccak_rhopi`'s lane loop and any
  other long body need `beq :+ / jmp target` instead of a plain `bne`.

## Contract obligations that bind file layout

Contract is **v0.11.0**; `git -C ../c64-lib-contract fetch --tags` before
checking, the local tags go stale. Prefix `<X>` = `MLKEM`, shortname `mlkem`.

- `src/lib_version.s` exports the four §1 version equates and **nothing else** —
  ld65 links whole archive members, so a manifest equate sharing that member
  drags the deprecated bare names into a two-library link and collides.
- `src/lib_manifest.s` carries the §5 aggregates. Footprint equates are
  **safe-direction**: ≥ measured, rounded UP to the next 256-byte boundary.
  Refresh them from the map file (`make check-manifest`) at the end of every
  phase.
- Zero page uses the §6.2 **consumer-assembled** model. `zp_config.s` is in NO
  archive; library TUs `.importzp`. Do not `.include "zp_config.s"` from
  `constants.s` — that silently converts the repo to the bake-everywhere model
  and makes every archive TU a slot definer.
- Slot names carry the `mlkem_` prefix. Bare `zp_tmp1`/`zp_ptr1` are the
  documented cross-library collision failure class.
- Library sources never use bare `CODE`/`RODATA`/`DATA`/`BSS`. Driver TUs
  (`main.s`, `bench.s`) do, deliberately — they are the consumer in the
  standalone build and ship in no archive.
- The `lib` / `lib-*` make-target namespace is **reserved for targets that
  produce archives**. Checks take `check-*`.

## Validation

`tools/keccak_ref.py` is the golden model and is pinned to the standards by
`make test-ref` (240 XKCP per-step states, 3,192 CAVP vectors, Monte Carlo
chains, streaming properties). **If `make test-ref` is red, every 6502
comparison downstream is meaningless — fix it first.**

The model implements the same *streaming* state machine as the assembly, on
purpose: no NIST vector exercises incremental absorb or multi-call squeeze, and
those are exactly what ML-KEM needs.

When adding 6502 step functions, keep them individually callable behind
`MLKEM_TEST_HOOKS` so the per-step differential harness can reach them. The
shipped archive never defines that switch, so the export surface — which §6.5
makes contract surface — stays minimal and stable. `make` and `make lib` build
from two separate object trees (`build/tobj` and `build/obj`) precisely so the
two configurations cannot leak into each other; §6.4 requires it.

That harness is not decoration. It caught `keccak_clear` clearing exactly one
byte (counting down from 199 with `bpl`, whose bit 7 is already set) on the
first run, and it is what made the rho+pi rewrite safe to attempt — a wrong
step names its round and its step mapping instead of producing a wrong digest.

`src/keccak_tables.inc` is GENERATED (`make tables`). Never hand-edit it: the
round constants, pi destinations and rho decomposition all come from the
validated model, so a transcription slip is impossible by construction.

## Tests

- `test_*.py` = runnable-by-CI logic tests; `rig_*.py` = needs real hardware.
  P1 is all VICE, so everything is `test_*.py`.
- Honor `C64_SKIP_BUILD=1`.
- Read addresses from `build/labels.txt` via the harness `Labels` class; never
  hardcode.
- Never invoke `x64sc` directly — always through `c64-test-harness`.
- Use the venv interpreter at
  `/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3`.
- Keep the default suite fast; put exhaustive runs behind a flag. VICE
  round-trips dominate, so a vector count that is trivial in Python is not
  trivial under the emulator.

## Benchmarking

`src/bench.s` chains CIA1 Timer A + B into a 32-bit φ2 cycle counter. The jiffy
clock is useless here: it is advanced by the KERNAL IRQ, so a body that runs
with IRQs masked reports 0, and a jiffy is ~17,045 cycles anyway.

`make bench` calibrates against `bench_spin_1000` (1,293 cycles including its
`jsr`) and **refuses to print a Keccak number if calibration is off**. Do not
weaken that gate — it is what turns "TB ticks every 65,536 TA cycles" from an
arithmetic claim about CIA underflow into a measured one.

**Two traps that produced plausible-but-wrong numbers here.** Both are fixed;
both will come back if the harness is rewritten:

1. **DEN is sampled once per frame.** The VIC-II checks display-enable only at
   raster line `$30`, so `vic_blank` mid-frame leaves badline DMA running for
   the rest of that frame. Whether a short window gets stolen from then depends
   on *what ran before*, not on the code being measured — one identical
   1,293-cycle routine measured 1293 / 1310 / 1396 / 1439. `bench_sync_frame`
   waits two full frames after blanking, which also aligns the window start to
   a known raster position. Blanking alone is NOT sufficient.
2. **The first sample differs from the steady state.** Discard a warm-up
   measurement.

VICE is cycle-deterministic, so a repeated run must reproduce exactly; a
varying count means the measurement is wrong, not the emulator. Useful
independent check: the sponge overhead measures exactly 3,850 cycles/block both
before and after the rho+pi work, code the optimisation never touched.
