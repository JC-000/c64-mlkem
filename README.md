# c64-mlkem

ML-KEM (FIPS 203) for the Commodore 64, in ca65 assembly.

Part of the [JC-000](https://github.com/JC-000) 6502 crypto library ecosystem
and conformant to [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
**v0.10.6**.

The eventual product is **ML-KEM-768**, providing the post-quantum half of the
hybrid `X25519MLKEM768` (0x11EC) key exchange for
[c64-https](https://github.com/JC-000/c64-https)' TLS 1.3 client.

---

## Status: Phase 1, scaffold complete

The work is phased. **Phase 1 is Keccak only** — the SHA-3 family that ML-KEM
is built on:

| Phase | Scope | State |
|---|---|---|
| **P1** | Keccak-f[1600], SHA3-256/512, SHAKE128/256, KAT-verified in VICE, contract-packaged | **in progress** — permutation done, verified and measured; sponge layer next |
| P2 | NTT / mod-3329 arithmetic, samplers, keygen/encaps/decaps vs NIST ACVP | not started |
| P4 | c64-https consumer wiring | consumer-side, not this repo |

P1 is the gating unknown: **no 6502 Keccak implementation exists anywhere** to
calibrate against. Its measured cost replaces an estimate band of 150k–350k
cycles per permutation that the whole PQC roadmap's wall-clock model rests on.

### Measured cycles per Keccak-f[1600]

> ## 600,746 cycles
>
> 25,031 cycles/round · 587 ms at 1.023 MHz · compact/looped form, display blanked.

**This is 1.7x the top of the roadmap's 150,000–350,000 estimate band.** At
~55–60 permutations for ML-KEM-768 keygen+decaps that is **33–36M cycles of
Keccak alone**, against a total budget of 40–70M for the whole operation. The
estimate the roadmap was built on does not survive contact with a measurement;
see *Where the cycles go* below for what can be recovered.

How it is measured: CIA1 Timer A+B chained as a 32-bit phi2 counter
(`src/bench.s`). The instrument is calibrated before every report against a
routine of known cost (`bench_spin_1000`, 1,293 cycles including its `jsr`) and
`make bench` **refuses to print a Keccak number if that calibration is off**.
Single and 8x-amortised measurements agree to 0.0 cycles.

The display must be blanked for the count to be exact. With it enabled the
VIC-II steals a varying number of badline cycles depending on where in the
frame the window falls — measured here as 1293 / 1310 / 1396 / 1439 for one
identical routine. `vic_blank` is not a 6% speed trick; it is what makes the
measurement reproducible at all.

### Where the cycles go

| Step | cycles/round | x24 | share |
|---|---:|---:|---:|
| theta | 6,859 | 164,616 | 27.4% |
| **rho+pi** | **13,764** | **330,336** | **55.0%** |
| chi | 4,191 | 100,584 | 16.7% |
| iota | 208 | 4,992 | 0.8% |

rho+pi dominates, and it is the step with the most headroom left in it. The
current form rotates each lane bit-by-bit with `rol` on memory (6 cycles a
byte, up to 7 passes over 8 bytes) and recomputes a wrapping tmp index per
byte. Two changes are available without touching the other steps:

1. **Rotate the short way round.** `ROTL64(v, 8s+b)` equals a byte-shift of
   `s+1` followed by `ROTR64` of `8-b`, so no lane ever needs more than 4 bit
   -shift passes instead of 7.
2. **Unroll per rotation amount.** The byte-rotate index arithmetic
   (`tya`/`and #7`/`tay`, 6 cycles per byte) is loop bookkeeping that
   disappears entirely if the eight possible byte-rotations are unrolled with
   constant offsets.

Both are size-for-speed trades against the ~2.3 KB of budget still unspent.

### Footprint

| Segment | bytes |
|---|---:|
| `LIB_MLKEM_CODE` | 484 |
| `LIB_MLKEM_RODATA` | 267 |
| **resident total** | **751** |
| `LIB_MLKEM_BSS` | 584 |

**751 B of the ~3 KB P1 budget — 24.4%.** (The full ML-KEM image must fit a
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

| # | Handoff says | SPEC v0.10.6 / reality | Resolution |
|---|---|---|---|
| 1 | pin contract "v0.10.3 as of 2026-08-15" | newest release is **v0.10.6**, whose SPEC.md self-declares `Version: 0.10.6 (2026-08-15)`. The local clone's tags were stale until `git fetch --tags`. | pinned v0.10.6 |
| 2 | three manifest equates (`RESIDENT_BYTES`, `ZP_USAGE_BYTES`, `REU_BANKS_USED`) | §5 requires a **fourth**, `LIB_MLKEM_COLD_BYTES`, and §6.6 imports it as a pair with `RESIDENT_BYTES` | all four exported |
| 3 | consumers relocate ZP slots "via `--asm-define`" | §2 makes **`-D`** normative. `--asm-define` is `cl65`'s spelling; `ca65 --asm-define` fails with `Unknown option` | docs use `-D` |
| 4 | archive under `build/lib/` (basename unstated) | §6.1 canonicalises `<shortname>.a` | `build/lib/mlkem.a`, `mlkem-keccak.a` |
| 5 | — | §2's ZP prefix registry and §10 adopters table do not yet list this library | upstream PRs to c64-lib-contract pending |

---

## License

MIT — see [LICENSE](LICENSE).
