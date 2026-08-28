# tools/mutants — the mutation gate

HANDOFF-P2: *"A surviving mutant is a test-suite defect and blocks the
merge."* This directory holds the deliberate faults, one unified-diff patch
each, and `manifest.json` which names them and the test command that must go
red for each. `tools/mutate.py` drives it (`make test-mutants`):

    copy tree -> build/mutants/<name>/  ->  patch -p1  ->  make  ->  run test
    PASS  = the test FAILED (mutant killed)
    FAIL  = the test passed (mutant survived), or the patch is missing / does
            not apply / does not build

Patches are written by the **red-test author** against the green
implementation, never by the implementer — the point is to prove the suite
notices, not that the code is right. A patch that no longer applies after a
refactor is a stale gate and is reported as a failure, not skipped.

## Status: patches PENDING

The WP1 implementation does not exist yet, so every `patch` in the manifest
is `null` and `mutate.py` reports `missing-patch` for all of them (exit 1).
Once the implementation lands the red author converts each row below into a
real `.patch` against the actual source lines. The fault descriptions are
precise enough that the conversion is mechanical.

## Required WP1 mutants (HANDOFF-P2 minimum set, plus adversarial extras)

| name | fault (what the patch does) | which check must catch it |
|---|---|---|
| `ntt-wrong-zeta` | In the generated zeta table (`src/mlkem_tables.inc` or wherever `make tables` puts it) replace the entry for index 77 with the value of index 76. One entry, in the middle of the last NTT layer. | `mlkem_poly_ntt` whole transform (random, all q-1: the four coefficients under zeta 77 differ); `mlkem_ntt_layer` trace names L=6; `mlkem_intt_layer` trace names L=0. |
| `reduce-bound-off-by-one` | In `mlkem_poly_reduce` change the conditional-subtract threshold from `>= q` to `> q` (or bias the Barrett quotient by one), so an input of exactly `k*q` is returned as `q` rather than 0. | `mlkem_poly_reduce[k*q boundaries + extremes]` and `[all q]`, reported NON-CANONICAL (S1). |
| `ntt-missing-final-reduce` | Delete the canonicalising pass (the `>= q` subtract) at the end of `mlkem_poly_ntt` / its last layer so outputs sit in `[q, 2q)` for some coefficients. | `mlkem_poly_ntt[all q-1]` / random cases flag NON-CANONICAL. Note `intt(ntt(f)) == f` alone would NOT catch this — hence S1. |
| `butterfly-swapped-operand` | In the Cooley-Tukey butterfly swap the operands of the subtraction: `f[j+len] = t - f[j]` instead of `f[j] - t`. | `mlkem_ntt_layer` L=0 on `impulse[255]=q-1` and `all q-1`; every non-trivial whole-NTT case. |
| `loop-bpl-256` | In a 256-iteration coefficient loop that counts X/Y down (reduce, add or sub), replace the `bne`/`beq :+ / jmp` exit with `bpl` — P1's real `keccak_clear` bug. The loop then stops at 127 (or after one iteration from 255). | `mlkem_poly_reduce[all 0xFFFF]`, `mlkem_poly_add[all q-1, all q-1]`: first diff at coeff 128 or 0. |
| `basemul-accumulator-24bit` | In `mlkem_poly_basemul` skip the reduction of `a1*b1` before multiplying by gamma, and drop the carry into the fourth accumulator byte. | `mlkem_poly_basemul[all q-1 x all q-1 (S4 accumulator width)]`. |
| `basemul-zeta-sign` | Drop the negation of gamma for the odd pair (`2i+1`), i.e. use `+zeta` for both halves. | `mlkem_poly_basemul` odd impulse pairs (`impulse[3] x impulse[3]`, `impulse[255] x impulse[255]`), random cases. |
| `sub-no-wrap` | In `mlkem_poly_sub` remove the `+q` correction on borrow. | `mlkem_poly_sub[zero, all q-1 (S3 wrap)]` NON-CANONICAL. |
| `intt-scale-wrong` | Change the 128^-1 constant 3303 to 3302 (if a Montgomery-folded constant is used, perturb that constant by one). | `mlkem_poly_intt` whole transform, `intt(ntt(f)) == f`; per-layer trace passes through L=5 and names L=6 / the full function. |
| `ntt-data-dependent-branch` | Add `lda hi,x : ora lo,x : beq skip` around the butterfly multiply so a zero coefficient bypasses it. Functionally correct. | timing section: `mlkem_poly_ntt` constant-time check (S5) — `all-zero` measures fewer cycles than `random`. |

The `bpl` mutant and the missing-final-reduce mutant are the two that a naive
"compare modulo q at the end" suite lets through; they are why `test_ntt.py`
compares **canonical values** and includes **all-0xFFFF / all-(q-1)** inputs.

## Required WP2 mutants (samplers and codecs)

Same manifest, `"test": "make test-sampler"`. `expect` is a substring the
failure output must contain, so the kill is *localised*, not incidental.

| name | fault | kill / expected failure |
|---|---|---|
| `wp2-cbd-short` | `mlkem_sample_cbd2`: loop consumes 127 of the 128 PRF bytes (last two coefficients never written) | `tools/test_sampler.py --only cbd` → `mlkem_sample_cbd2 [all-0xFF]: index 254` |
| `wp2-compress-floor` | `mlkem_compress_10`: drop the +q/2 (round-half-up) term so compress computes floor(2^d*x/q) | `tools/test_sampler.py --only compress` → `mlkem_compress_10 [boundaries 0..]` |
| `wp2-compress-floor-4` | `mlkem_compress_4`: same as wp2-compress-floor for d=4 (a separate routine or table row) | `tools/test_sampler.py --only compress` → `mlkem_compress_4 [boundaries 0..]` |
| `wp2-decompress-shift` | `mlkem_decompress_10`: rounding constant one bit short: add 2^(d-2) instead of 2^(d-1) before the >> d | `tools/test_sampler.py --only decompress` → `mlkem_decompress_10 [exhaustive` |
| `wp2-decompress-shift-1` | `mlkem_decompress_1`: decompress_1 returns floor(q/2)=1664 for y=1 instead of round(q/2)=1665 | `tools/test_sampler.py --only decompress` → `mlkem_decompress_1 [exhaustive 0..]: index 1: got 1664 want 1665` |
| `wp2-sample-ntt-accept-q` | `mlkem_sample_ntt`: rejection test uses d <= q instead of d < q (a candidate equal to 3329 is accepted) | `tools/test_sampler.py --only sample_ntt` → `stream carries a d == q` |
| `wp2-sample-ntt-d2-after-full` | `mlkem_sample_ntt`: drop the j < 256 guard on d2 so a valid d2 is stored after the 256th coefficient | `tools/test_sampler.py --only sample_ntt` → `wrote past the 512-byte output buffer` |
| `wp2-encode-nibble-swap` | `mlkem_byte_encode_12`: middle byte packed as (a1 & 0xF) | (a0 >> 8) << 4 instead of (a0 >> 8) | (a1 & 0xF) << 4 | `tools/test_sampler.py --only encode` → `mlkem_byte_encode_12 [nibble-asymmetric 0x0A5 / 0x5A0]: byte index 1` |

## Writing a patch

From a clean green tree:

    cp -r src build/mutants/scratch && $EDITOR build/mutants/scratch/ntt.s
    diff -u src/ntt.s build/mutants/scratch/ntt.s \
        | sed 's#^--- src/#--- a/src/#; s#^+++ build/mutants/scratch/#+++ b/src/#' \
        > tools/mutants/<name>.patch

or simply edit in place, `git diff > tools/mutants/<name>.patch`, `git checkout src`.
Then set `"patch": "<name>.patch"` in `manifest.json` and run
`make test-mutants` (or `tools/mutate.py --only <name>`).

Rules: one fault per patch; the mutant must **build** (a mutant that fails to
assemble tests nothing); never touch `tools/test_*.py` or `tools/*_ref.py`
from a patch.
