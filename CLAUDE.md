# CLAUDE.md — working notes for agents in this repo

Read `HANDOFF.md` (P1, Keccak) and `HANDOFF-P2.md` (P2, ML-KEM-768) first;
they are the authoritative briefs. For current state, open items and how the
user wants work run, read the latest SESSION HANDOFF at the end of
`HANDOFF-P3.md`. This file records the conventions that are easy to get wrong.

## Scope discipline

P1 and P2 are both complete (v0.5.0); the P3 Lane A optimisation pass is
landed (v0.5.1, implementation-only, ABI 2), and validated on the U64E
(`make rig`). No changes to `c64-https` (consumer
wiring is Phase 4, consumer-side — including re-planning its overlay, see
below). No ML-DSA ever. No REU anywhere.

## The numbers — as of v0.5.1 (P3 pass)

1. **Keccak-f[1600] = 339,688 cycles** (14,154/round), **link-invariant**
   since v0.5.1 (P1: 456,605, and it moved with the rodata layout; 600,771
   at `v0.2.0`, which preserves that baseline). Six P3 commits, one lever
   each, numbers in their messages.
2. **KeyGen 21,801,702 · Encaps 24,880,455 · Decaps 29,597,879 cycles.**
   keygen+decaps = **51,399,581**, of which **29.9M (58%) is 88 Keccak
   permutations** and 17.4M is NTT/INTT/basemul (578,948 / 618,146 / 307,993
   per call). Inside the 40–70M budget, just under the midpoint. About 50 s
   of CPU per TLS handshake for the PQ half alone. (v0.5.0: 61,928,289 =
   26,835,087 + 35,093,202.)
3. **7,208 B resident** shipped (6,311 code + 897 rodata; 7,381 with test
   hooks), declared 7424; contiguous CODE+RODATA is 7,231 B with this link's
   23 B alignment gap (≤ 63 B while RODATA directly follows CODE at
   `align = $40`; §5 gives only `(-previous_end) mod alignment`, and a
   consumer that reorders or aligns more coarsely can pay more). **93.9% of
   the 7,680 B `CRYPTO_OVERLAY` window, no split needed** — but only ~2.5 KB
   of that window is actually free in c64-https' default UCI cfg, so the
   consumer must re-plan its overlay (P4; fit is explicitly deferred per
   HANDOFF-P3). Keccak-only member set: 1,947 B, declared 2048.
   **BSS 6,641 B**, excluding the caller's ek/dk/ct (4,672 B).
4. **Every ACVP vector** (25 keyGen, 25 encaps, 10 decaps incl. modified
   ciphertexts, 10 + 10 key checks), hazmat interop both ways, 820 CAVP +
   199 per-step Keccak checks; **48/48 mutants killed** (WP1 15, WP2 13,
   WP3 18, P1 2 — 45 at v0.5.1; the three hardware-validation adversary
   mutants were added on `hw/rig-validation`). All constant-time claims are
   measured cycle pins, not assertions.
5. **Fourteen SPEC/brief divergences** (P1 1–6, P2 7–14), tabulated in README.

**The headline must not be softened:** Keccak is now inside the roadmap's
150–350k band (3% under its top) only after a 26% cut, and it is still 58%
of every ML-KEM operation. The non-Keccak 15–45M estimate came in at 21.5M;
the total survives the 40–70M budget because that band was wide.

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
  vector whose low byte is `$FF` reads garbage. P1's `kc_jmp` carried a
  link-time assert against exactly that; since v0.5.1 rho+pi has no vector
  (the lane loop is a generated straight-line script), but the trap applies
  to any `jmp (abs)` added later.
- **Branch displacement is 8-bit.** `keccak_theta`'s column loop and any
  other long body need `beq :+ / jmp target` instead of a plain `bne`.
- **A taken branch across a page edge costs a cycle, and the code's page
  offset is the consumer's.** Rodata placement no longer moves the Keccak
  count (v0.5.1), but a loop whose `bne` lands on a page edge in some link
  still adds one cycle per iteration — chi measured 4,191 and 4,230 per
  round in two P3 links, code untouched. Bound it (≤ 1,200/permutation
  here); do not chase it.
- **`wp2-rodata-align-reverted` is layout-tuned and re-picked after every
  code-size change.** The three bare compress tables are one 148 B span
  whose page phase takes one of four values; one always fits, so no pad
  makes the straddle deterministic. When the gate reports it survived after
  a size change, re-pick the pad (0/64/128/192) from the mutant's
  `labels.txt` — `tools/mutants/README.md` has the procedure. It moved
  three times in P3.
- **A whole-tree diff between an edit and a checkout is not a mutant
  patch.** The diff captures every uncommitted change in the tree, and the
  checkout then discards the lever you were working on (it happened once in
  P3; the saved copy was the only reason it cost nothing). Build patches
  with `diff -u` against a scratch copy, as `tools/mutants/README.md` says.
- **A page-straddle `.assert` needs a backing align, or it is a coin toss.**
  `src/codec.s` asserts three secret-indexed tables do not cross a page; the
  assert only *fails* when the layout happens to straddle, so a green link
  proves nothing about the next link. The tables carry `.align 64` — which
  brings the next trap.
- **ld65 silently drops a source `.align` the cfg does not permit.** A
  segment's cfg entry needs `align = $40` (or larger) for a `.align 64` in
  the source to take effect; without it ld65 warns (only if a source-level
  align exists to check against) and proceeds. `LIB_MLKEM_RODATA` therefore
  **requires `align = $40`** in every consumer cfg, and the `lderror` asserts
  are what turn the dropped align into a failed link. The reverted-align
  mutant pins that.
- **Any harness scratch address is a claim about the image size.** `test_sha3`
  hardcoded `MSG_BUF = $2000` as "well above the PRG image" when the image
  ended at ~$0E47; after WP3 `LIB_MLKEM_RODATA` spanned `$1FC0–$23C0`, the
  test wrote its message over the Keccak round constants and every vector
  failed, including the empty message. Scratch now sits above `$5000` and
  every VICE test checks `__MAIN_LAST__` from the labels file against its
  scratch range at startup. Do the same in any new test.
- **One ML-KEM call is tens of millions of cycles.** The harness's default
  `jsr` timeout is 5 s; keygen is ~30 s emulated. `bench_keccak.JSR_TIMEOUT`
  is 900 s and `test_mlkem.py` sets its own. A timeout here is a measurement
  failure, not a result.

## Contract obligations that bind file layout

Contract is **SPEC 1.2.3** (main branch, untagged; latest tag v1.2.2) — read
the SPEC version line, not the tag, and `git -C ../c64-lib-contract fetch
--tags` first (`check-precalc` reads the pinned tag from local objects).
`docs/contract-p2-alignment.md` is the historical record of P2's adoption and
has the exact §8.1 / §8.0 shapes it took. Prefix `<X>` = `MLKEM`, shortname
`mlkem`.

- **Every archive export is under `mlkem_` / `LIB_MLKEM_` / `keccak_`**, or is
  one of the exact §8 canonical names (`mul_tables_init`, `ct_mul_8x8`, …).
  `make check-prefix` (in `make test`) enforces it on the extracted archive
  members. `poly_`, `mul_`, `ct_`, `sha_` are other libraries' prefixes.
- `src/precalc_table.inc` is a byte-for-byte copy of the contract's file at
  the tag `CONTRACT_PRECALC_REF` pins in the Makefile (v1.2.2; it moves
  deliberately when adopting a new contract tag) — never edit it; refresh with
  `git -C ../c64-lib-contract show v1.2.2:precalc_table.inc >
  src/precalc_table.inc`. `make check-precalc` (in `make test`) fails if the
  copy differs from that ref. It is `.include`d from
  `src/lib_manifest.s` and nowhere else, and that TU defines
  `LIB_NO_BARE_EXPORTS` first so no bare `LIB_PRECALC_*` form is ever emitted.

- `src/lib_version.s` exports the four §1 version equates and **nothing else** —
  ld65 links whole archive members, so anything sharing that member enters a
  consumer's link uninvited.
- **No deprecated bare `LIB_VERSION_*` exports, and no unprefixed archive member
  basenames.** They are zero-consumer carve-outs (the bare version-export one
  is §1's) that this library was first to take; re-adding either would put it
  back on a migration path it deliberately skipped. The export surface is
  byte-identical with and without `-D LIB_NO_BARE_EXPORTS=1`.
- `LIB_MLKEM_ABI_VERSION` moves only on a **breaking** export change. It went
  1 → 2 at v0.4.0 for the bare-export removal; it did NOT move for v0.2.0
  (additive) or v0.3.0 (implementation-only).
- `src/lib_manifest.s` carries the §5 aggregates. Footprint equates are
  **safe-direction**: ≥ measured, rounded UP to the next 256-byte boundary.
  The basis is the **placed span** of the segments they cover (internal
  alignment fill charged, inter-segment gaps and leading padding not), not a
  sum of object sizes. `make check-manifest` measures it on probe links of
  both archives, reading the declared values from each archive's manifest
  member with `od65`. Refresh at the end of every phase.
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
  produce archives**. Checks take `check-*`. There is deliberately **no
  `lib-kem`**: `mlkem.a` is the ML-KEM archive (HANDOFF-P2's `mlkem-kem.a`
  would be a byte-identical second name; README divergence 7).
- **`mlkem-keccak.a` has its own manifest object** (`build/kobj`, assembled
  with `-D MLKEM_KECCAK_ONLY=1`): masks 0/0, no §8.4 rows, `RESIDENT_BYTES`
  2048 (measured 1947). §6.4 forbids one manifest describing two member sets.
  `MLKEM_KECCAK_ONLY` in `CONTRACT_DEFINES` is **rejected at parse time** —
  no target can honor it build-wide. `check-archives` pins both manifests'
  values with `od65`; `check-staleness` pins that alternating `lib` /
  `lib-keccak` on a warm tree rebuilds nothing and overwrites neither.
- **`sqtab` lives outside every segment** at `LIB_SHARED_SQTAB_BASE`
  (`src/sqtab_base.inc`, the only place the default `$9000` lives; shipped
  next to `mlkem.inc`). The multiply bakes the page byte into its `abs,x`
  sites, so the base is in the build's invalidation signature (see the
  "Build-configuration invalidation" section; `make check-staleness`).
  `src/main.s` carries an image guard (the link fails if the image reaches the
  sqtab window), kept as repo-local hygiene, and `make check-sqtab-guard`
  proves it fires. Never `.export` `sqtab_lo/hi` or the base; never invent a
  `sqtab_init` alias.
- **§8.4 rows for tables built at init.** `mlkem_rtab` (the 1 KB R1/R2
  reduction tables, BSS, built by `mlkem_arith_init`) IS enumerated — `sqtab`
  is built at init too and §8.1 makes its row mandatory. Region RAM. Add a
  row and a `LIB_PRECALC_TABLE` invocation in the same commit as any new
  table ≥ 256 B that is hot-loop-read or page-aligned.

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

## Build-configuration invalidation

`CONTRACT_DEFINES` / `CONTRACT_ZP_DEFINES` must invalidate what they
reconfigure. Without that, a warm tree answers "Nothing to be done", exits 0
and ships the previously-configured artifact — the chacha#86 shape. This repo
had the bug; `make check-staleness` is the regression guard.

Two things about the fix that will look like over-engineering and are not:

- **The check runs at PARSE time, not from a recipe.** By the time a recipe
  runs, make has already stat'd its targets. Deleting the PRG from a recipe
  leaves make convinced it still exists, so the link is skipped and the build
  produces *no output file at all*. Measured.
- **It deletes stale objects rather than depending on a stamp file.** macOS
  ships **GNU Make 3.81**, whose mtime comparison has 1-second granularity, so
  a stamp rewritten in the same second as the objects it should invalidate
  compares as not-newer and nothing rebuilds. Also measured.

`check-staleness` asserts **both** legs — changed knob flips the artifact, and
unchanged knob rebuilds nothing — on three knobs: the ZP slot, the sqtab base,
and the Keccak-only manifest. Leg 1 alone passes on a guard that has degraded
to an unconditional rebuild.

Header edits are the same bug class along a different axis. Every ca65
recipe writes `--create-full-dep` to a `.d` file next to its object, and the
Makefile `-include`s those files. There are no hand-listed header
prerequisites, and no rule builds a `.d`, so make never restarts. The guard's
`rm -rf` of the object trees takes the `.d` files with it. The `deps1`
build-scheme tag in `CONFIG_SIG` wipes, once, any tree built before the `.d`
files existed. `.DELETE_ON_ERROR:` removes an object whose `.d` failed to
write, so it cannot survive without one. `make check-deps`
(make resolves every include) and `make check-deps-rebuild` (incremental ==
clean, and a second make runs nothing) are the regression guards.

## Tests

- `test_*.py` = runnable-by-CI logic tests; `rig_*.py` = needs real hardware.
  The rigs (`make rig` / `rig-full` / `rig-turbo`, never in `make test`) run
  the same KATs and the cycle counts on the U64E through `tools/rig_common.py`,
  which parks a mailbox dispatcher on `idle` because the Ultimate has no
  `jsr()`. **Host reads of C64 RAM steal CPU cycles on the U64E** (fw 3.15):
  about 10 cycles + ~1.15 cycles per byte for each `read_bytes`, so a 5 ms
  poll loop added +1.5k–2.2k to a Keccak x8, differently every run.
  Non-memory REST calls (config, info) steal nothing (adversarial review,
  2026-09-22). Never poll inside a measurement window — `quiet_s` exists
  for that; rig_bench's poll probe reports the effect but does not gate on it.
  The rigs were proven on the U64E (fw 3.15, 1 MHz) against two mutants from
  the gate: `wp3-cmp-mismatch-timing` (rig_bench T1: tampered decaps +2 /
  +2,172 cycles over valid) and `wp3-cmp-acc-reset` (rig_kat onebit: the
  valid key K' returned for a one-bit c1 tamper).
- Honor `C64_SKIP_BUILD=1`.
- Read addresses from `build/labels.txt` via the harness `Labels` class; never
  hardcode.
- Never invoke `x64sc` directly — always through `c64-test-harness`.
- **Device I/O routing — the single funnel.** Every byte a tool sends to or
  reads from a C64 goes through the harness helpers `write_bytes` /
  `read_bytes` / `jsr` / `wait_for_text`, never a raw `transport.write_memory`,
  `socket`, `requests`, or hand-rolled `machine:writemem`/`/v1/` REST call.
  That funnel is the ONE place that owns chunking (`memory.py` splits at 84 B,
  below the Ultimate's 128 B POST-leak boundary) and, on real hardware, `/Temp`
  cleanup — so a bypass can wedge the shared C64U (fw 1.1.0; ~15 body-carrying
  REST POSTs fill `/Temp` and only a physical power-cycle recovers it). Fetch
  the transport with `transport = inst.transport` and pass it INTO those
  helpers; do not call methods on it. `make check-harness-routing` (in `make
  test`, `tools/check_harness_routing.sh`) fails the build the moment a tool
  adds a bypass. A deliberate, reviewed exception widens that guard's regex in
  the same commit.
- Use the venv interpreter at
  `/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3`.
- Keep the default suite fast; put exhaustive runs behind a flag. VICE
  round-trips dominate, so a vector count that is trivial in Python is not
  trivial under the emulator. `make test` (default depth) is ~90 s of VICE;
  `make test-mlkem-full` alone is ~150 calls of 10–40M cycles.
- **Parallel VICE suites on one machine are fine** — `c64-test-harness` 0.12.4
  allocates monitor ports 6511–6531 via a cross-process `PortLock` through
  `ViceInstanceManager`, and `run_parallel` caps at 10 instances by default
  (`max_workers`); past ~10 instances machine-wide the port allocator raises
  `RuntimeError` ("No free ports"), which looks like a test failure. Never run
  two `make` invocations in one build tree (they overwrite the same `build/`
  outputs), and real hardware (the U64E) stays serialised through the harness
  device queue.
- Read-only for implementers: `tools/test_*.py`, `tools/mlkem_ref.py`,
  `tools/mutants/`. The red author owns them; disputes go to the supervisor.

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

`make bench-kem` measures KeyGen/Encaps/Decaps on ACVP `tcId 1` inputs and
**checks the outputs against the model** before printing a number — a cycle
count for a call that computed the wrong thing is worthless. The Keccak share
is a permutation *count* from the model times the permutation cost measured
in the same link, never a subtraction. `test_mlkem.py --full` prints the same
keygen/encaps counts and must agree to the cycle.
