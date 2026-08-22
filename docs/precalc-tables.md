# Precalculated tables — c64-mlkem

Filed per [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
§8.0 catch loop / `adopters.md` intake step 6.

## No tables clear the §8.0 floor

The floor is **≥ 256 B AND** at least one of: REU-resident, hot-loop-read, or
page-aligned for fetch alignment. c64-mlkem has **no table meeting it**, so
this library emits **no `LIB_PRECALC_*` exports** and invokes the
`LIB_PRECALC_TABLE` macro zero times. (Per the intake rule, a `LIB_PRECALC_*`
export without a row here — or a row without the export — blocks merge; both
are absent, consistently.)

The complete `LIB_MLKEM_RODATA` inventory, 308 B in total:

| Table | Size | Region | Source | Classification | Why it is below the floor |
|---|---:|---|---|---|---|
| `keccak_rc` | 192 B | RODATA | `src/keccak_tables.inc` | algorithm-specific | Hot-loop-read (once per round, 24 rounds), but **192 B < 256 B**. It is the FIPS 202 round-constant sequence — fixed by the standard, identical in any Keccak implementation, and derivable from a 7-bit LFSR in ~150 B of code if the space is ever wanted back. |
| `keccak_pi_dst` | 25 B | RODATA | `src/keccak_tables.inc` | algorithm-specific | 25 B. Destination byte offset per source lane for the fused rho+pi step. |
| `keccak_rot_byte` | 25 B | RODATA | `src/keccak_tables.inc` | algorithm-specific | 25 B. Whole-byte component of the rho rotation. |
| `keccak_rot_cnt` | 25 B | RODATA | `src/keccak_tables.inc` | algorithm-specific | 25 B. Residual bit-rotation count, 0..4. |
| `keccak_rot_dir` | 25 B | RODATA | `src/keccak_tables.inc` | algorithm-specific | 25 B. Rotation direction; see note below. |
| `copy_vec` | 16 B | RODATA | `src/keccak.s` | algorithm-specific | 16 B. Jump table selecting one of eight unrolled byte-rotation copy routines. |

## Classification rationale

All six are **algorithm-specific, not potentially shareable**. They encode
FIPS 202's ρ offsets, π permutation and round constants, plus this
implementation's own dispatch. Nothing here is a general numeric aid (no
multiply tables, no quarter-squares), so there is no cross-library sharing
story to have — which is also why `LIB_MLKEM_SHARED_PRIMITIVES` and
`LIB_MLKEM_SHARED_CONSUMES` are both `0`: Keccak is XOR/AND/NOT/rotate only and
contains no multiply at all.

`keccak_rot_byte` / `keccak_rot_cnt` / `keccak_rot_dir` are one logical table
split into three parallel arrays so each is reachable with a single `lda
table,y`. They encode the decomposition `ROTL64(v, 8s+b)` = byte-rotate then a
bit-rotate in whichever direction is shorter, which caps the bit passes at 4
instead of 7. Even summed (75 B) they stay well below the floor.

All are generated from the validated reference model by `tools/gen_tables.py`
(`make tables`), never hand-written.

## This changes in P2

ML-KEM's NTT needs twiddle factors and mod-3329 reduction aids, and its modular
multiplies make this library a candidate **consumer** of a §8.x shared
primitive. Which one is an open question, and they are three distinct
obligations rather than one:

| Clause | Primitive | Kind |
|---|---|---|
| §8.1 | `sqtab` | shared quarter-square **table** |
| §8.2 | `reu_mul` | shared REU multiplication **table** |
| §8.3 | `ct_mul_8x8` | shared constant-time multiply **body** — not a table |

Expect this file and both §8 masks to gain real content when Phase 2 lands.
