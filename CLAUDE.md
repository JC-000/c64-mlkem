# CLAUDE.md — working notes for agents in this repo

Read `HANDOFF.md` first; it is the authoritative P1 brief. This file records
the conventions that are easy to get wrong.

## Scope discipline

**P1 is Keccak only.** No NTT, no ML-KEM arithmetic, no samplers — that is P2,
gated on P1's measured cycle count and starting from its own handoff. No
changes to `c64-https` (consumer wiring is Phase 4, consumer-side). No ML-DSA
ever. No REU anywhere in P1.

## The four numbers P1 owes

1. measured cycles per Keccak-f[1600] permutation
2. code+rodata+bss bytes per the ld65 map file
3. KAT pass counts per function
4. SPEC divergences and surprises

They feed a 40–70M-cycle keygen+decaps budget (Keccak's share estimated at
9–21M over ~55–60 permutations), and they decide whether P2 proceeds as
planned. Report them prominently.

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

## Contract obligations that bind file layout

Contract is **v0.10.6**; `git -C ../c64-lib-contract fetch --tags` before
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
makes contract surface — stays minimal and stable.

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
with IRQs masked reports 0, and a jiffy is ~17,045 cycles anyway. **Calibrate
against `bench_spin_1000` (1,287 cycles) before trusting any Keccak number** —
the "TB tick = 65,536 cycles" relationship is an arithmetic claim about CIA
underflow behaviour, not yet a measured one. VICE is cycle-deterministic, so a
repeated run must reproduce exactly; a varying count means the measurement is
wrong, not the emulator.
