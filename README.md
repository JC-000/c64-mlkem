# c64-mlkem

ML-KEM (FIPS 203) for the Commodore 64, in ca65 assembly.

Part of the [JC-000](https://github.com/JC-000) 6502 crypto library ecosystem
and conformant to [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
**v0.11.0**. Precalculated-table enumeration per §8.0:
[`docs/precalc-tables.md`](docs/precalc-tables.md) — nothing in this library
clears the §8.0 floor.

The eventual product is **ML-KEM-768**, providing the post-quantum half of the
hybrid `X25519MLKEM768` (0x11EC) key exchange for
[c64-https](https://github.com/JC-000/c64-https)' TLS 1.3 client.

---

## Status: Phase 1 complete (v0.3.0)

The work is phased. **Phase 1 is Keccak only** — the SHA-3 family that ML-KEM
is built on:

| Phase | Scope | State |
|---|---|---|
| **P1** | Keccak-f[1600], SHA3-256/512, SHAKE128/256, KAT-verified in VICE, contract-packaged | **complete** — all four functions verified against 820 NIST CAVP vectors, measured, optimised, packaged |
| P2 | NTT / mod-3329 arithmetic, samplers, keygen/encaps/decaps vs NIST ACVP | not started — gated on P1's numbers |
| P4 | c64-https consumer wiring | consumer-side, not this repo |

P1 was the gating unknown: **no 6502 Keccak implementation existed anywhere**
to calibrate against, so the roadmap's wall-clock model rested on an estimate
band of 150k–350k cycles per permutation. That estimate has now been replaced
by a measurement, and **it did not survive** — see below.

### Release history

| Tag | Keccak-f[1600] | Resident | What it is |
|---|---:|---:|---|
| [`v0.2.0`](https://github.com/JC-000/c64-mlkem/releases/tag/v0.2.0) | 600,771 | 1,034 B | Functional baseline. Correct and complete, deliberately unoptimised — kept as the historical reference point. |
| [`v0.3.0`](https://github.com/JC-000/c64-mlkem/releases/tag/v0.3.0) | **456,605** | 1,477 B | rho+pi optimised: −24.0% cycles for +402 B. |

### Measured cycles per Keccak-f[1600]

> ## 456,605 cycles
>
> 19,025 cycles/round · 446 ms at 1.023 MHz · display blanked.

**24.0% faster than the v0.2.0 baseline** (600,771 cycles), all of it from
`rho+pi`. The unoptimised form is preserved at tag
[`v0.2.0`](https://github.com/JC-000/c64-mlkem/releases/tag/v0.2.0) as the
reference point.

The count is exact and repeatable within a build, and shifts by a few tens of
cycles between builds: `iota` does 192 `lda keccak_rc,x` reads per permutation
and how many cross a page depends on where ld65 placed the round-constant
table. Page-aligning it would make the headline figure build-invariant.

**Still 1.3x the top of the roadmap's 150,000–350,000 estimate band.** At
~55–60 permutations for ML-KEM-768 keygen+decaps that is **25–27M cycles of
Keccak alone**, against a total budget of 40–70M for the whole operation —
down from 33–36M at v0.2.0, but the original estimate does not survive contact
with a measurement either way.

Measured with CIA1 Timer A+B chained as a 32-bit phi2 counter (`src/bench.s`).
Single and 8x-amortised measurements agree to 0.0 cycles.

### Where the cycles go

| Step | v0.2.0 | **v0.3.0** | x24 | share |
|---|---:|---:|---:|---:|
| theta | 6,859 | 6,859 | 164,616 | 36.1% |
| **rho+pi** | 13,764 | **7,757** | 186,168 | 40.8% |
| chi | 4,191 | 4,195 | 100,680 | 22.1% |
| iota | 208 | 208 | 4,992 | 1.1% |
| **total** | 25,022 | **19,019** | 456,456 | |

`rho+pi` went from 55.0% of the permutation to 40.8%, a **43.6% cut**, from
three changes — for 402 bytes of code:

1. **The copy goes straight to its destination.** The lane is written directly
   into `keccak_B` at its pi destination and rotated in place there. No scratch
   lane, no second store pass.
2. **The byte rotation is free.** `rho[i]` splits as `8*byte + bit`; the whole
   -byte part is just *which destination byte each source byte lands in*. The
   eight possibilities are unrolled as eight straight-line copy routines
   reached through a jump table, which deletes the per-byte index bookkeeping
   (`tya`/`and #7`/`tay`) that dominated the old version.
3. **It rotates the short way round.** `ROTL64(v, 8s+b)` with `b > 4` equals a
   byte-rotation of `s+1` then a rotate *right* of `8-b`, since
   `8s+b == 8(s+1)-(8-b)`. Taking the shorter direction caps the bit passes at
   4 instead of 7 and cuts the per-round total from 88 to 52.

Still on the table: **theta** is now the second cost at 36.1% (its `D` step
does per-byte mod-40 index arithmetic that could be unrolled per column), and
**page-aligning the RC table** would remove the build-to-build variation.

### What the sponge costs

Absorbing one full 136-byte rate block takes **460,455 cycles**, of which
456,605 is the permutation — so the whole sponge layer (XOR-into-state,
padding, block bookkeeping) is **3,850 cycles, 0.8%**. Sponge-level
optimisation would be wasted effort; the permutation is the entire cost. That
the figure is *exactly* 3,850 both before and after the rho+pi work — code the
optimisation never touched — is a useful independent check on the instrument.

Roughly **3,385 cycles per byte hashed**.

### Measuring this correctly is harder than it looks

Two traps, both of which produced plausible-but-wrong numbers here first:

* **`DEN` is sampled once per frame.** The VIC-II checks the display-enable bit
  only at raster line `$30`, so blanking the screen mid-frame leaves badline
  DMA running for the rest of it. A short window taken right after `vic_blank`
  may or may not be stolen from, depending on what ran before — one identical
  1,293-cycle routine measured 1293 / 1310 / 1396 / 1439. `bench_sync_frame`
  waits two full frames after blanking, which also aligns the window start to a
  known raster position.
* **Discard a warm-up sample.** The first measurement after the machine has
  been doing something else can differ from the steady state.

`make bench` calibrates against a routine of known cost (1,293 cycles) and
**refuses to print a Keccak number if that calibration is off**.

### Footprint

| Segment | bytes |
|---|---:|
| `LIB_MLKEM_CODE` | 1,169 |
| `LIB_MLKEM_RODATA` | 308 |
| **resident total** | **1,477** |
| `LIB_MLKEM_BSS` | 594 |

**1,477 B of the ~3 KB P1 budget — 48.1%** (886 B permutation + 283 B sponge).
The permutation grew 402 B to buy the 24% speedup. (The full ML-KEM image must fit a
7,680-byte window in c64-https.) `make check-manifest` re-measures from the map
file and **fails** if a declared footprint equate has fallen below measured.

---

## How correctness is established

A from-scratch permutation on a 6502 fails in ways a digest comparison cannot
localise — a wrong digest tells you nothing about *which* of five step mappings
in *which* of 24 rounds broke. So validation runs at two levels.

```
   XKCP published intermediates  +  NIST CAVP vectors
                    |
                    v
        tools/keccak_ref.py   (golden model, mirrors the 6502 decomposition)
                    |
                    v
             ca65 implementation
```

**Level 1 — the golden model is pinned to the standards.**
`make test-ref` (pure Python, ~6 s, no emulator) checks `tools/keccak_ref.py`
against:

- **240 per-step intermediate states** from XKCP's
  `KeccakF-1600-IntermediateValues.txt` — two full permutations x 24 rounds x
  the state after each of θ, ρ, π, χ, ι. Plus the 24 published round constants
  and 25 ρ offsets.
- **3,192 NIST CAVP known-answer vectors** (ShortMsg, VariableOut; LongMsg
  adds ~200 more after `make vectors`).
- **CAVP Monte Carlo chains** — 1,000 chained iterations per chain, which
  reach state transitions no single-shot vector does.
- **Streaming properties that no CAVP vector covers** (see below).

**Level 2 — the assembly is differentially tested against the model.**
The 6502 step functions are individually callable behind a `MLKEM_TEST_HOOKS`
define, so the VICE harness can `jsr` one step, DMA the 200-byte state out, and
compare against the model's checkpoint for that exact round and step. A
mismatch names the round and the step.

Because ρ and π are **fused** into one destination-indexed copy in the
assembly, `After rho` has no counterpart to compare against; the fused step is
checked against `After pi`. That leaves **192 of the 240** published
checkpoints directly usable, and the ρ offset table is validated separately
against the published `RhoOffset` list.

### What the standard vectors do not reach

Every NIST CAVP vector is one-shot, so the standard corpus never exercises:

1. **Incremental absorb** — the streaming API is a c64-mlkem requirement, not
   a FIPS 202 one. Covered by split-invariance property tests: the same
   message, chunked arbitrarily, must produce an identical digest.
2. **Multi-call squeeze** — `VariableOut` varies the length but in one call.
   ML-KEM's matrix expansion squeezes many blocks per call site. Covered by a
   squeeze-continuation property test over a 2,048-byte stream.
3. **6502 memory-layout bugs** — page-boundary-spanning inputs and buffer
   alignment, which no algorithm-level vector will ever probe.

`tools/keccak_ref.py` therefore implements the **same streaming state machine**
the assembly does, not just a one-shot function, so these properties are
testable at both levels.

---

## Build and test

Requires the cc65 suite (`ca65`/`ld65`/`ar65`) and, for the VICE tests,
`x64sc` plus the `c64-test-harness` package.

```sh
make                  # standalone test PRG -> build/mlkem.prg (+ labels, map)
make test             # full suite
make test-ref         # oracle self-test only (pure Python, no VICE)
make test-vice        # per-step differential trace under VICE
make test-sha3        # FIPS 202 KATs (make test-sha3-full for all 820)
make bench            # cycle-exact Keccak-f[1600] measurement
make tables           # regenerate src/keccak_tables.inc from the model
make test-ref -- --full   # all 100 Monte Carlo chains rather than 3
make check-manifest   # measured segment sizes vs the §5 footprint equates
make check-archives   # assert no driver object leaked into an archive
make vectors          # fetch the CAVP LongMsg sets (~4.8 MB, not tracked)
```

Tests use the shared venv interpreter, since the system `python3` lacks the
harness:

```sh
/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3 tools/test_keccak_ref.py
```

`C64_SKIP_BUILD=1` makes a test reuse the existing binary instead of rebuilding.

**No REU.** P1 uses none — the Keccak state is 200 bytes of main memory and
there is nothing to stage. Do **not** pass `-reu` to VICE for this library's
tests; the c64-https default carries it and it should not be cargo-culted here.

---

## Using it from a consumer

```sh
make lib              # build/lib/mlkem.a          — every exported symbol
make lib-keccak       # build/lib/mlkem-keccak.a   — narrowed Keccak-only set
```

Link the archive directly. Never do `ar65` member surgery: an archive whose
member set a consumer has edited is outside every manifest claim it ships
(contract §6.1).

Each archive ships alongside `mlkem.inc` (the public header),
`zp_config.s`, and `cfg/mlkem-example.cfg`.

**Segments** to place in your cfg — `LIB_MLKEM_CODE`, `LIB_MLKEM_RODATA`,
`LIB_MLKEM_BSS`. `LIB_MLKEM_BSS` **requires `align = $100`** and must be the
last segment in a file-emitting area; `cfg/mlkem-example.cfg` states what
breaks if either is dropped, and `src/state.s` carries a hard `.assert` so an
alignment mistake fails the link rather than corrupting at runtime.

**Zero page** uses contract §6.2's *consumer-assembled* model — the shape the
spec recommends for new libraries. No archive TU defines a slot; you assemble
`src/zp_config.s` into your own build and override there, with **no library
rebuild**:

```sh
ca65 -D mlkem_zp_src=0x40 -D mlkem_zp_dst=0x42 src/zp_config.s
```

Override values must be `$`-free (`0x40` or decimal). An unquoted `$40` is
eaten by the shell and silently becomes address `$00`; through make, `$40` and
`$$40` both yield 0 and `$$$$40` yields the shell PID — none of them diagnosed
at any stage.

---

## Divergences from the P1 handoff brief

Per contract §6.1, where SPEC and the handoff disagree, **SPEC wins**; the
differences are recorded here.

| # | Handoff says | SPEC v0.11.0 / reality | Resolution |
|---|---|---|---|
| 1 | pin contract "v0.10.3 as of 2026-08-15" | the tag named in the brief was already superseded when it was written, and the local clone's tags were stale again until `git fetch --tags` | pinned **v0.11.0**; was v0.10.6 through c64-mlkem v0.3.0 |
| 2 | three manifest equates (`RESIDENT_BYTES`, `ZP_USAGE_BYTES`, `REU_BANKS_USED`) | §5 requires a **fourth**, `LIB_MLKEM_COLD_BYTES`, and §6.6 imports it as a pair with `RESIDENT_BYTES` | all four exported |
| 3 | consumers relocate ZP slots "via `--asm-define`" | §2 makes **`-D`** normative. `--asm-define` is `cl65`'s spelling; `ca65 --asm-define` fails with `Unknown option` | docs use `-D` |
| 4 | archive under `build/lib/` (basename unstated) | §6.1 canonicalises `<shortname>.a` | `build/lib/mlkem.a`, `mlkem-keccak.a` |
| 5 | — | §2's ZP prefix registry and §10 adopters table did not list this library | **resolved** — `mlkem_` registered and the adopters row landed in contract [v0.10.7](https://github.com/JC-000/c64-lib-contract/releases/tag/v0.10.7) ([PR #123](https://github.com/JC-000/c64-lib-contract/pull/123)) |
| 6 | brief is silent on the deprecated bare `LIB_VERSION_*` exports; §1 made them a `MUST` | contract **v0.11.0** carves out libraries with no released consumers ([PR #125](https://github.com/JC-000/c64-lib-contract/pull/125)) | this library exports **only** the prefixed forms as of v0.4.0 |

---

## License

MIT — see [LICENSE](LICENSE).
