# c64-mlkem

ML-KEM (FIPS 203) for the Commodore 64, in ca65 assembly.

Part of the [JC-000](https://github.com/JC-000) 6502 crypto library ecosystem
and conformant to [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
**v0.13.0 (head)**. Precalculated-table enumeration per §8.0/§8.4:
[`docs/precalc-tables.md`](docs/precalc-tables.md) — three P2 tables
(`sqtab`, `mlkem_zetas`, `mlkem_rtab`) clear the floor; no Keccak table does.

The eventual product is **ML-KEM-768**, providing the post-quantum half of the
hybrid `X25519MLKEM768` (0x11EC) key exchange for
[c64-https](https://github.com/JC-000/c64-https)' TLS 1.3 client.

---

## Status: Phase 2 complete (v0.5.0)

The work is phased. **Phase 1 was Keccak only** — the SHA-3 family ML-KEM is
built on; **Phase 2 is everything else** in FIPS 203:

| Phase | Scope | State |
|---|---|---|
| **P1** | Keccak-f[1600], SHA3-256/512, SHAKE128/256, KAT-verified in VICE, contract-packaged | **complete** — all four functions verified against 820 NIST CAVP vectors, measured, optimised, packaged |
| **P2** | mod-3329 arithmetic and NTT, samplers, codecs, K-PKE, ML-KEM-768 KeyGen/Encaps/Decaps vs three oracles in VICE, measured, packaged | **complete** — every ACVP vector, hazmat interop both ways, 45/45 mutants killed; measured at 61.9M cycles keygen+decaps |
| P4 | c64-https consumer wiring | consumer-side, not this repo |

P1 was the gating unknown: **no 6502 Keccak implementation existed anywhere**
to calibrate against, so the roadmap's wall-clock model rested on an estimate
band of 150k–350k cycles per permutation. That estimate has now been replaced
by a measurement, and **it did not survive** — see below.

### Release history

| Tag | Keccak-f[1600] | keygen + decaps | Resident | What it is |
|---|---:|---:|---:|---|
| [`v0.2.0`](https://github.com/JC-000/c64-mlkem/releases/tag/v0.2.0) | 600,771 | — | 1,034 B | Functional baseline. Correct and complete, deliberately unoptimised — kept as the historical reference point. |
| [`v0.3.0`](https://github.com/JC-000/c64-mlkem/releases/tag/v0.3.0) | **456,605** | — | 1,477 B | rho+pi optimised: −24.0% cycles for +402 B. |
| [`v0.4.0`](https://github.com/JC-000/c64-mlkem/releases/tag/v0.4.0) | 456,605 | — | 1,477 B | Contract v0.11.0: bare version exports dropped (ABI 2), prefixed member basenames, §6.3 staleness guard. |
| **v0.5.0** | 456,720 ¹ | **61,928,289** | **6,719 B** | **ML-KEM-768 complete.** KeyGen 26.8M, Encaps 30.2M, Decaps 35.1M cycles; 87.5% of the 7,680 B window; ABI unchanged (additive). |

¹ Same code as v0.3.0; the RC table moved with the P2 rodata and 115 cycles of
page-crossing moved with it (README, "Measured cycles per Keccak-f[1600]").

---

## Phase 2: ML-KEM-768 — measured

> ## keygen + decaps = 61,928,289 cycles
>
> KeyGen **26,835,087** · Encaps **30,221,505** · Decaps **35,093,202**
> · 60.6 s for keygen+decaps at 1.023 MHz · display blanked.

**That is inside the roadmap's 40–70M keygen+decaps budget, in its upper
half, and it is not going to get much better: 65% of it is Keccak.** The
TLS client calls KeyGen once and Decaps once per handshake, so the
post-quantum half of `X25519MLKEM768` costs the C64 **about a minute** of
CPU per connection before X25519, the certificate chain and the record layer
are counted. The 15–45M "non-Keccak" estimate the budget was built on is
replaced by a measurement of **21.7M** (keygen+decaps, everything that is not
a Keccak permutation) — inside that band, so the budget survives; but the
band's *bottom* assumed a Keccak that does not exist on this CPU.

Cycle counts are exact, reproduce to the cycle across runs (VICE is
deterministic; `make bench-kem` measures each twice and refuses to report a
number that did not), and are taken on ACVP `tcId 1` inputs — the same inputs
`make test-mlkem-full` reports, so the two must agree. Instrument: the P1 CIA
counter with the same calibration refusal.

### Where the cycles go

The Keccak share is not measured by subtraction — there is nothing to
subtract against. It is the permutation *count* for the exact input (from the
model; SampleNTT's block count depends on the public ρ) times the permutation
cost measured in the same link. The arithmetic share likewise: operation
counts × the measured NTT / INTT / basemul cost. "Rest" is samplers, codecs,
K-PKE glue and the sponge's own per-block bookkeeping (3,850 cycles per block).

| Primitive | cycles | Keccak-f × | = cycles | share | NTT / INTT / basemul | = cycles | share | rest |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| KeyGen | 26,835,087 | 43 | 19,638,960 | 73.2% | 6 / 0 / 9 | 6,246,663 | 23.3% | 949,464 |
| Encaps | 30,221,505 | 44 | 20,095,680 | 66.5% | 3 / 4 / 12 | 8,094,284 | 26.8% | 2,031,541 |
| Decaps | 35,093,202 | 45 | 20,552,400 | 58.6% | 6 / 5 / 15 | 11,420,641 | 32.5% | 3,120,161 |
| **keygen + decaps** | **61,928,289** | **88** | **40,191,360** | **64.9%** | | **17,667,304** | **28.5%** | 4,069,625 |

Per primitive, one call (`make bench-kem`; the NTT numbers were first
measured by `make test-ntt` and reproduce exactly):

| Routine | cycles | note |
|---|---:|---|
| `keccak_f1600` | 456,720 | 19,030 / round. P1's 456,605 plus 115 cycles of RC-table page crossings that moved with the rodata layout |
| `mlkem_poly_ntt` | 579,016 | 896 butterflies + 127 per-block tables, ~560 per butterfly all-in |
| `mlkem_poly_intt` | 665,120 | NTT shape + 256 scalings by 3303 |
| `mlkem_poly_basemul` | 308,063 | 128 pairs × 4 general (secret × secret) multiplies |
| one NTT butterfly multiply | ~330 | 2 quarter-square partials on `sqtab` + 14-entry per-block `U` table + table reduction |
| one general multiply | ~440 | 3 partials + the 27-entry `|d|` table |

Decaps is not "encaps plus a decrypt": K-PKE.Decrypt is 3 NTT + 3 basemul +
1 INTT (≈ 3.3M) and the re-encryption is a full Encrypt (≈ 8.1M of
arithmetic, 28 permutations). The implicit-rejection compare is 1,088 bytes
of accumulate-OR and costs the same whether or not it matches — `make
test-mlkem` pins the decaps cycle count identical for a valid ciphertext and
for ciphertexts one bit off at each end.

**What would move the number.** Keccak is 65% and the permutation is already
where P1 left it; `theta` (36% of a permutation) is the only untried step.
On the arithmetic side the multiply is the lever: ~48,000 multiplies per
keygen+decaps at 330–440 cycles. The §8.3 canonical `ct_mul_8x8` body was
rejected for exactly this reason (`docs/contract-p2-alignment.md` §3: ~4
partials + 2 SMC re-bakes through `jsr` per 12×12 product, ≈ 5–8M more).
A Montgomery-domain representation would remove the table reductions
(~130 of the 330) at the cost of a range analysis this canonical-`[0, q)`
design deliberately avoids.

### Footprint

Measured from the shipped `mlkem.a` linked into a probe image
(`build/mlkem-lib.map`; no test hooks). The test PRG is 173 B larger.

| Segment | bytes | of which |
|---|---:|---|
| `LIB_MLKEM_CODE` | 5,694 | Keccak 888 · sponge 281 · sqtab init 84 · NTT/field 1,598 · samplers 221 · codecs 681 · K-PKE/ML-KEM 1,941 |
| `LIB_MLKEM_RODATA` | 1,025 | Keccak 308 · zetas + NTT constants 407 · CBD 32 · compress tables 256 (incl. 21 B `align = $40` pad) · 1 |
| **resident total** | **6,719** | declared `LIB_MLKEM_RESIDENT_BYTES = 6912` (next 256-B boundary; also covers the 6,892 B test build) |
| `LIB_MLKEM_BSS` | 6,641 | see below |

Per work package, code + rodata:

| | bytes | share |
|---|---:|---:|
| P1 Keccak + sponge | 1,477 | 22.0% |
| WP1 field arithmetic + NTT (incl. `sqtab` init) | 2,089 | 31.1% |
| WP2 samplers + codecs | 1,190 | 17.7% |
| WP3 K-PKE + ML-KEM | 1,942 | 28.9% |
| alignment pad | 21 | 0.3% |

**6,719 B of the 7,680 B `CRYPTO_OVERLAY` window — 87.5%, 961 B headroom.
No image split was needed** (HANDOFF-P2 decision 1's fallback). Looped,
table-driven code throughout; the only unrolling is P1's eight rotation copy
variants.

**But the window is nominal.** The 7,680 B figure is the *size* of
c64-https' `CRYPTO_OVERLAY` slot. In the current UCI cfg the slot is not
empty: `TLS_DEFRAME_CODE`, `CERT_BUF_BSS` (2 KB), `VIEWER_CODE`,
`X509_NAME_CODE` and `HTTPS_TARGET_RODATA` ride it, and the cfg's own comment
puts the free space at **~2.5 KB in every default UCI profile**
(`docs/contract-p2-alignment.md` §2.6). This library fits the window it was
told to fit; it does not fit what is currently free in it, by ~4.2 KB. **The
consumer will have to re-plan its overlay** — a P4, consumer-side decision,
and one the user should have in front of them before this fit verdict is read
as final.

**BSS: 6,641 B**, none of it the caller's key material. It is eight
page-aligned polynomials (4,096 B: the two polyvecs, one sampled `A[i][j]`
consumed at once — the matrix is never stored — and the accumulator), the
1,024 B `R1`/`R2` reduction tables, the 200 B Keccak state plus 394 B of
sponge/rho-pi scratch, 320 B of chunk buffer, 128 B of hash scratch and the
small stuff, plus ~300 B of page-alignment fill. **The wire buffers are the
caller's and are NOT counted**: `ek` 1,184 B, `dk` 2,400 B, `c` 1,088 B — a
consumer that holds all three needs 4,672 B more, and they need no alignment.
The 1,024 B `sqtab` at `LIB_SHARED_SQTAB_BASE` is outside every segment
(default `$9000` standalone; c64-https already owns one at `$BC00`).

### How correctness is established, P2

Three oracles, each for a different reason (`HANDOFF-P2.md`); all run by
`make test-ref` (Python) before any 6502 comparison, then against the 6502 in
VICE by `make test-ntt`, `test-sampler`, `test-mlkem`.

| Oracle | What it proves | 6502 result |
|---|---|---|
| **NIST ACVP** (`ML-KEM-768-keyGen` / `encapDecap`, `internalProjection.json`) | byte-exact KeyGen and Encaps determinism (hazmat cannot fix `m`), the §7.2 modulus check, and implicit rejection — a broken re-encrypt yields a *wrong K silently*, and only the modified-ciphertext vectors catch it | **25 keyGen, 25 encaps, 10 decaps (modified ct), 10 + 10 key checks — all pass** (`make test-mlkem-full`) |
| **`cryptography.hazmat` 48.0.0 / OpenSSL 3.6.2** | interop with code we did not write: `from_seed_bytes(d‖z)` equals our `ek`; their `encapsulate()` ciphertexts decapsulate to their `ss` on the 6502; ours decapsulate in OpenSSL | pass, both directions (4 seeds in VICE; 100 seeds / 300 with `--full` against the model) |
| **`tools/mlkem_ref.py`** (ours, white-box) | localisation: every NTT layer, sampler, codec and K-PKE step is individually callable behind `MLKEM_TEST_HOOKS`, so a failure names its layer instead of a wrong digest | `test-ntt` (per layer, edge polys, CT cycle pin), `test-sampler` (incl. a 4-block SampleNTT seed and a `byte_decode_12` field ≥ q), `test-mlkem` K-PKE hooks |

The full VICE run is **383 checks** across the three suites plus P1's 199
per-step Keccak checks and 820 CAVP vectors. Constant-time properties are
*measured*, not asserted: the NTT's cycle count is pinned identical across
all-zero / all-(q−1) / random / impulse inputs, every codec across four
inputs, and decaps across valid and bit-flipped ciphertexts.

**Mutation gate.** Each work package's tests were written *first, by a
different agent, from FIPS 203 and the oracle* — red against stubs before the
implementer saw them — and then had to go red again against deliberate
faults applied to the green tree (`tools/mutants/*.patch`, `tools/mutate.py`):
**45 mutants — WP1 15, WP2 13, WP3 17 — all killed, each by the test the
manifest names.** They include the brief's required set (a wrong ζ, an
off-by-one reduction bound, a skipped and an early-exit rejection compare, a
CBD sampler one byte short, a `bpl` on a count ≥ 128 — P1's real
`keccak_clear` bug — a swapped `du`/`dv`, a missing final reduction) and, on
the WP2 side, the RODATA `align = $40` reverted (the page-straddle assert
must then fail the link). The gates found zero test-suite defects in WP1/WP3
and one weak vector in WP2, fixed before merge.

### P2 divergences and obligations

Where SPEC and `HANDOFF-P2.md` disagree, SPEC wins (§6.1); where the
implementation chose a behaviour FIPS 203 leaves to the caller, it is pinned
here and in `src/mlkem.inc`.

| # | Brief / spec says | What shipped | Why |
|---|---|---|---|
| 7 | HANDOFF-P2 WP4: "`mlkem-kem.a` alongside the existing archives" | **no `lib-kem` target.** `mlkem.a` *is* the ML-KEM archive | K-PKE/ML-KEM cannot be separated from the sponge it hashes with; a third archive would be a byte-identical second name for `mlkem.a`. `docs/contract-p2-alignment.md` does not call for it. |
| 8 | §4: `LIB_MLKEM_RODATA` had no alignment requirement | **`align = $40` is now REQUIRED** on `LIB_MLKEM_RODATA` | `src/codec.s` places three secret-indexed tables (42/42/64 B) at 64 B boundaries so no `abs,x` read crosses a page (cost would depend on the secret). ld65 silently drops a source `.align` the cfg does not permit; the sources carry `lderror` asserts, so a cfg that omits it **fails the link**. Mutant `wp2-rodata-align-reverted` pins that. |
| 9 | §8.1: consumer-chosen `LIB_SHARED_SQTAB_BASE` | standalone default **`$9000`**; `sqtab_base.inc` shipped next to `mlkem.inc`; consumer mirrors the §6.7 guard | Page-aligned, clear of every sibling default (`$7800`, `$8000/$8400`, `$9C00`, `$B800/$BC00`) and of the test harness's `$C000–$CFFF`; RAM under every `$01` state. The multiply bakes the page byte into its `abs,x` sites, so a stale object is a wrong address — `make check-staleness` covers the knob and `make check-sqtab-guard` proves the guard fires. |
| 10 | FIPS 203 §7.2: `ByteDecode12` output "must be < q" | **`mlkem_byte_decode_12` is a raw pass-through**: a field ≥ q is stored unreduced (3329..4095) | The modulus check on an encapsulation key is the caller's per §7.2, and this makes it *possible*: a decoder that reduced mod q would hide the violation. `mlkem_encaps` performs the explicit per-coefficient `< q` compare over all 768 fields (public data; may exit early) and returns `A = 1` with nothing written. ACVP `encapsulationKeyCheck` 10/10. |
| 11 | FIPS 203 §7.3: decaps input check `H(ek) == dk[2336..2368]` | **not performed** by `mlkem_decaps` | §7.3 assigns it to the caller (the C64 API takes pointers, not lengths, either). A dk with a wrong `H(ek)` field is processed mechanically by Alg. 18 with the *stored* h; the result is pinned to a model that mirrors that (test D2), so the behaviour is deterministic and documented. ACVP `decapsulationKeyCheck` 10/10 against that model. |
| 12 | §8.4: enumerate tables ≥ 256 B that are hot-loop-read | `mlkem_rtab` (1 KB of BSS **built at init**) *is* enumerated | WP1 read "precalculated" as "in the image" and filed no row; WP4 reversed it on the `sqtab` precedent — `sqtab` is also built at init by `mul_tables_init` and §8.1 makes *its* row mandatory. Region `RAM`, like `sqtab`. |
| 13 | §6.4: one manifest per member set | `mlkem-keccak.a` ships its **own manifest object** (`-D MLKEM_KECCAK_ONLY=1`, `build/kobj`): masks `0/0`, no §8.4 rows, `RESIDENT_BYTES = 1536` | Its member set never reads `sqtab`. `MLKEM_KECCAK_ONLY` in `CONTRACT_DEFINES` is **rejected at parse time** (§6.3 rejection branch — no target can honor it build-wide). `check-archives` pins both manifests with `od65`; `check-staleness` pins that alternating `lib` / `lib-keccak` on a warm tree rebuilds nothing and overwrites neither. |
| 14 | §8.3 canonical `ct_mul_8x8` | **not taken**; private `mlkem_`-prefixed 12×12 multiply on `sqtab` directly; bit `$0004` clear in both masks | `docs/contract-p2-alignment.md` §3: the canonical 8×8 body costs ~4 partials + 2 re-bakes per product through `jsr`, ≈ 5–8M cycles per keygen+decaps more than the inline 6+6 split. CT obligations are met privately: every secret-indexed table is page-aligned and the cycle count is pinned input-independent. |

Contract alignment for P2 — the v0.11.0 → v0.13.0 clause diff, the exact
§8.1 / §8.0 / §6.7 shapes and the items that need the user (a §8.4
zero-consumer carve-out for bare `LIB_PRECALC_*`, the `-D` quoting wording in
§8.1, the overlay free-space question, the `mlkem-keccak.a` manifest knob) —
is in [`docs/contract-p2-alignment.md`](docs/contract-p2-alignment.md); the
adopters-row and intake-PR drafts are in `docs/upstream/` and have **not**
been pushed.

---

## Phase 1: Keccak — measured

### Measured cycles per Keccak-f[1600]

> ## 456,605 cycles
>
> 19,025 cycles/round · 446 ms at 1.023 MHz · display blanked.

(456,720 in the v0.5.0 link — same code; see the note on the RC table below.
`make bench` reports whatever the current link measures.)

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

### Footprint (P1, the `mlkem-keccak.a` member set)

| Segment | bytes |
|---|---:|
| `LIB_MLKEM_CODE` | 1,169 |
| `LIB_MLKEM_RODATA` | 308 |
| **resident total** | **1,477** |
| `LIB_MLKEM_BSS` | 594 |

**1,477 B of the ~3 KB P1 budget — 48.1%** (886 B permutation + 283 B sponge).
The permutation grew 402 B to buy the 24% speedup. `make check-manifest`
re-measures both member sets from the map files and **fails** if a declared
footprint equate has fallen below measured.

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
make test             # full suite: oracles, every VICE suite, every contract check
make test-ref         # oracle self-tests only (pure Python, no VICE): Keccak + ML-KEM
make test-vice        # per-step Keccak differential trace under VICE
make test-sha3        # FIPS 202 KATs (make test-sha3-full for all 820)
make test-ntt         # mod-3329 arithmetic and NTT, per layer (-full: the sweep)
make test-sampler     # SampleNTT, CBD, ByteEncode/Decode12, Compress/Decompress
make test-mlkem       # K-PKE + ML-KEM-768 vs ACVP, hazmat, CT decaps (-full: every vector)
make test-mutants     # the 45-patch mutation gate (tools/mutants/manifest.json)
make bench            # cycle-exact Keccak-f[1600] measurement
make bench-kem        # KeyGen / Encaps / Decaps + NTT cycles, Keccak share separated
make bench-sampler    # WP2 sampler/codec cycles + constant-time check
make tables           # regenerate src/keccak_tables.inc + src/mlkem_tables.inc
make check-manifest   # measured segment sizes vs the §5 footprint equates, both archives
make check-archives   # no driver object in any archive; per-archive manifest values
make check-staleness  # §6.3 both legs on three knobs
make check-sqtab-guard  # §6.7: the image guard fires on a deliberate overrun
make check-prefix     # every archive export under mlkem_ / LIB_MLKEM_ / keccak_
make vectors          # fetch the CAVP LongMsg sets (~4.8 MB, not tracked)
```

**VICE suites cannot run concurrently** — two harness instances collide on
the monitor port. `make test` runs them one at a time; do not run a second
`make test-*` or `bench*` in parallel on the same machine.

Tests use the shared venv interpreter, since the system `python3` lacks the
harness:

```sh
/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3 tools/test_keccak_ref.py
```

`C64_SKIP_BUILD=1` makes a test reuse the existing binary instead of rebuilding.

**No REU.** Neither phase uses one — the Keccak state is 200 bytes of main
memory and the matrix `A` is never stored. Do **not** pass `-reu` to VICE for
this library's tests; the c64-https default carries it and it should not be
cargo-culted here.

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
`zp_config.s`, `sqtab_base.inc` (the §8.1 placement header) and
`cfg/mlkem-example.cfg`. `mlkem.a` links on its own: `make check-manifest`
proves it by linking the archive into a probe image.

**Segments** to place in your cfg — `LIB_MLKEM_CODE`, `LIB_MLKEM_RODATA`,
`LIB_MLKEM_BSS`. `LIB_MLKEM_RODATA` **requires `align = $40`** (P2);
`LIB_MLKEM_BSS` **requires `align = $100`** and must be the last segment in a
file-emitting area; `cfg/mlkem-example.cfg` states what breaks if any is
dropped, and the sources carry hard `.assert`s so an alignment mistake fails
the link rather than corrupting at runtime.

**Boot-time init, once, both idempotent:** `mul_tables_init` fills the 1 KB
§8.1 `sqtab` at `LIB_SHARED_SQTAB_BASE` (this library provides it unless you
build with `-D SHARED_SQTAB_INIT`, in which case your designated owner does
and this library imports it — never both); `mlkem_arith_init` builds the
mod-q tables in `LIB_MLKEM_BSS`. Mirror the §6.7 guard in your own link
(`cfg/mlkem-example.cfg` shows the three lines).

**Calling ML-KEM-768:** six 16-bit pointers in the parameter block at
`mlkem_arg_ek` (`ek`, `dk`, `ct`, `key`, `seed`, `z`), set once; then
`jsr mlkem_keygen` / `mlkem_encaps` / `mlkem_decaps`. Wire formats verbatim,
no alignment requirement. `mlkem_encaps` returns `A = 1` (and `mlkem_status`)
for an `ek` that fails the §7.2 modulus check, writing nothing.
`mlkem_decaps` never fails. Full contract in `src/mlkem.inc`.

**Zero page** uses contract §6.2's *consumer-assembled* model — the shape the
spec recommends for new libraries. No archive TU defines a slot; you assemble
`src/zp_config.s` into your own build and override there, with **no library
rebuild**:

```sh
ca65 -D mlkem_zp_src=0x40 -D mlkem_zp_dst=0x42 -D mlkem_zp_mul=0x48 src/zp_config.s
```

Five slots, 16 bytes: `mlkem_zp_src/dst/len/tmp` (2 B each, P1) and
`mlkem_zp_mul` (8 B, the multiply's operand/product scratch, P2).

Override values must be `$`-free (`0x40` or decimal). An unquoted `$40` is
eaten by the shell and silently becomes address `$00`; through make, `$40` and
`$$40` both yield 0 and `$$$$40` yields the shell PID — none of them diagnosed
at any stage.

---

## Divergences from the P1 handoff brief

Per contract §6.1, where SPEC and the handoff disagree, **SPEC wins**; the
differences are recorded here. (P2's rows 7–14 are in the Phase 2 section.)

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
