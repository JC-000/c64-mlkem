# Precalculated tables — c64-mlkem

Filed per [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
§8.0 catch loop / `adopters.md` intake step 6.

## P1: no Keccak table clears the §8.0 floor

The floor is **≥ 256 B AND** at least one of: REU-resident, hot-loop-read, or
page-aligned for fetch alignment. The FIPS 202 half of the library has **no
table meeting it**, so the `mlkem-keccak.a` manifest emits **no
`LIB_PRECALC_*` exports** and invokes the `LIB_PRECALC_TABLE` macro zero
times. (Per the intake rule, a `LIB_PRECALC_*` export without a row here — or
a row without the export — blocks merge; both are absent, consistently.) The
P2 rows are in the next section.

The complete `LIB_MLKEM_RODATA` inventory, 192 B in total (308 B up to
v0.5.0: P3 turned the five rho+pi lookup tables into immediates in a
generated straight-line lane script, see below):

| Table | Size | Region | Source | Classification | Why it is below the floor |
|---|---:|---|---|---|---|
| `keccak_rc` | 192 B | RODATA | `src/keccak_tables.inc` | algorithm-specific | Hot-loop-read (once per round, 24 rounds), but **192 B < 256 B**. It is the FIPS 202 round-constant sequence — fixed by the standard, identical in any Keccak implementation, and derivable from a 7-bit LFSR in ~150 B of code if the space is ever wanted back. |

## Classification rationale

It is **algorithm-specific, not potentially shareable**: the FIPS 202 round
constants. (Up to v0.5.0 five more tables — `keccak_pi_dst`,
`keccak_rot_byte`, `keccak_rot_cnt`, `keccak_rot_dir`, 25 B each, and the
16 B `copy_vec` jump table — encoded the ρ offsets, the π permutation and
the copy dispatch; they were likewise algorithm-specific and below the
floor.) Nothing here is a general numeric aid (no
multiply tables, no quarter-squares), so there is no cross-library sharing
story to have — which is also why `mlkem-keccak.a`'s `LIB_MLKEM_SHARED_PRIMITIVES`
and `LIB_MLKEM_SHARED_CONSUMES` are both `0`: Keccak is XOR/AND/NOT/rotate only
and contains no multiply at all.

Since v0.5.1 the ρ/π data is not a table at all: `tools/gen_tables.py`
emits the 25 lanes as `KECCAK_LANE lane, dst, s, sc` macro invocations
(`KECCAK_RHOPI_SCRIPT` in `src/keccak_tables.inc`), and `src/keccak.s`
expands each into `ldy #`/`ldx #`/`jsr copy_sN`/`jsr rot_{left,right}N`.
The decomposition `ROTL64(v, 8s+b)` = byte-rotate then a bit-rotate in
whichever direction is shorter (capping the passes at 4 instead of 7) is
still verified for all 25 lanes by `tools/test_keccak_ref.py`; the bytes
now live in `LIB_MLKEM_CODE` (225 B of script) rather than in rodata, and
nothing in the permutation reads a table at run time.

Everything here is generated from the validated reference model by
`tools/gen_tables.py` (`make tables`), never hand-written.

## P2 (rows landed: WP1 two, WP4 one)

Phase 2 (ML-KEM-768) makes this library a **§8.1 `sqtab` consumer** —
decision 2 of `HANDOFF-P2.md`, shape in `docs/contract-p2-alignment.md` §2.
§8.2 (`reu_mul`) is not taken (no REU in P2) and §8.3 (`ct_mul_8x8`) is
deliberately not taken (private `mlkem_`-prefixed multiply; reasoning in
`docs/contract-p2-alignment.md` §3). The first two rows below **shipped with
WP1** and the third with WP4, each in the same commit as its bytes and its
`LIB_PRECALC_TABLE` invocation in `src/lib_manifest.s`, never ahead of or
behind it. `src/precalc_table.inc` is byte-for-byte the contract root copy.

The rows are emitted by the `mlkem.a` manifest only. `mlkem-keccak.a` ships
its own manifest object (assembled with `-D MLKEM_KECCAK_ONLY=1`, contract
§6.4 — one manifest per member set) with zero rows and both §8.0 masks `0`,
because that member set contains no multiply; `make check-archives` pins
both with `od65` on the extracted member.

Only the prefixed `LIB_MLKEM_PRECALC_<name>_{SIZE,REGION,SHARED}` family will
be emitted: the manifest TU defines `LIB_NO_BARE_EXPORTS` before the include,
so this library's export surface stays byte-identical with and without the
consumer's build-wide define (`make check-prefix` enforces it).

### Rows that ship

| Table | Size | Region | Source | Classification | Rationale |
|---|---:|---|---|---|---|
| `sqtab` | 1,024 B | RAM — equate-placed at `LIB_SHARED_SQTAB_BASE` (standalone default `$9000`), in no segment, outside the 7,680 B window | `src/sqtab_base.inc` (placement), `src/sqtab.s` (`mul_tables_init`, owner builds only) | **potentially shareable — §8.1 canonical, `PRECALC_SHARED_YES`** | The 8×8 quarter-square table `floor(n²/4)`, n ∈ 0..510, lo/hi planes 512 B each, `hi = lo + $0200`. Bit-identical across every §8.1 adopter; c64-https owns one copy and every linked library defers to it. The name `"sqtab"`, size 1024 and region RAM are normative; only placement is consumer-chosen. Emitted whenever `LIB_MLKEM_SHARED_CONSUMES` carries bit `$0001` — a deferring build still reads it, so the row is consumption surface, not ownership surface. |
| `mlkem_zetas` | 256 B | RODATA (`LIB_MLKEM_RODATA`) | `src/mlkem_tables.inc` (generated by `make tables` from `mlkem_ref.ZETAS`) | **algorithm-specific, `PRECALC_SHARED_NO`** | The 128 NTT twiddles ζ^BitRev7(i), 16-bit each, in the NTT's traversal order — exactly at the 256 B floor and hot-loop-read (once per butterfly group, 7 layers × 128 butterflies per NTT). q = 3329 and ζ = 17 are FIPS 203's; ML-DSA's NTT (q = 8380417) and every other sibling would not converge on these bytes, so there is no sharing story. Whether stored interleaved or as lo/hi planes it is one logical table and one row. |
| `mlkem_rtab` | 1,024 B | RAM — `LIB_MLKEM_BSS`, page-aligned (`.align 256` + `lderror` assert) | `src/ntt.s` (`mlkem_r1_lo/hi`, `mlkem_r2_lo/hi`), **built on the target** by `mlkem_arith_init` once at boot | **algorithm-specific, `PRECALC_SHARED_NO`** | The mod-q reduction aid: `R1[k] = 256k mod q`, `R2[k] = 65536k mod q`, four 256 B planes. Read three times per multiply (P0 + R1[P1] + R2[P2], then R1 again on the fold) — hot-loop-read — and indexed by secret-derived bytes, hence page-aligned (contract-p2-alignment §3.3). ≥ 256 B and hot-loop-read: **clears the floor**. WP1 filed it as "not precalculated data, no row"; WP4 reversed that: `sqtab` is likewise computed on the target by `mul_tables_init`, and §8.1 makes *its* row mandatory, so "built at init" does not exempt a table from §8.4. Region `RAM`, like `sqtab` — the bytes are not in the image. q-specific: no sibling can share it. The 27 B `|d|` quarter-square table and the 14-entry per-block `U` table live in the unused tail of the R2 pages and are below the floor on their own. |

### Candidates resolved by WP1 — no rows

| Candidate | Outcome |
|---|---|
| `mlkem_zetas_basemul` | **Not tabulated (0 B).** `mlkem_poly_basemul` reads `mlkem_zetas[64 + p/2]` and subtracts for odd pairs; the generator asserts the identity. The gamma planes are still emitted by `make tables` behind `MLKEM_TABLES_GAMMAS`, which no TU defines. |
| mod-3329 reduction aid | **Enumerated after all** — see `mlkem_rtab` above (WP4 reversed WP1's "computed on the target, so not §8.4 data" reading on the `sqtab` precedent). |
| `mlkem_sqd` | 27 B (quarter-squares of a signed difference in [-13, 13]), built by `mlkem_arith_init` into the unused tail of the R2 pages. Below the floor. |

### Candidates resolved by WP2 — no rows

| Candidate | Outcome |
|---|---|
| CBD_η=2 byte → coefficient-pair lookup (256/512 B) | **Not tabulated.** `src/sample.s` uses two 16-entry nibble tables (32 B, asserted not to straddle a page). Below the floor. |
| Compress_d division tables | 108 B in `src/codec.s` (`T_hi_d`, `T_lo`), `.align 64` so no secret-indexed read crosses a page. Below the floor. |

### Below the floor in P2 — no rows

Decompress_4 lookup (32 B), the Compress/Barrett constants (≤ 8 B), any
bit-reversal table (128 B — and FIPS 203's in-place NTT needs none), and
the P1 round-constant table above. A Decompress_10 lookup (2,048 B) would
clear the floor but must not be built: it is a quarter of P2's code+rodata
budget for one multiply-and-shift.
