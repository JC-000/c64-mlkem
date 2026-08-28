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

## Required WP1 mutants (NTT and field arithmetic) — gate run, all 15 KILLED

`"test": "make test-ntt"`. Patches are written against `src/ntt.s` /
`src/mlkem_tables.inc` as merged in a9cc7f5. Two faults from the red-phase
list cannot exist in that implementation's structure and were replaced by the
nearest fault of the same class (marked *replaced*); five adversarial extras
came from reading the green source. `expect` is a substring of the failure
line, so every kill below is localised to the function, case and coefficient
it names.

| name | fault (what the patch does) | localising failure line |
|---|---|---|
| `ntt-wrong-zeta` | `mlkem_tables.inc`: zetas[77] := zetas[76], both planes. One entry, block 13 of the last NTT layer | `mlkem_ntt_layer L=6 (len=2) [all q-1]: first diff at coeff 52` (also INTT `L=0`, basemul pair 26 — every consumer of zeta 77, nothing else) |
| `reduce-bound-off-by-one` | `mlkem_poly_reduce` gets a private conditional subtract whose threshold is `q` instead of `q-1`, so `v == k*q` comes back as `q`. The shared `CSUBQ` also feeds `arith_init`/add/basemul, so the fault is scoped to reduce; the +258 B pad keeps `LIB_MLKEM_RODATA` on the same page offset | `mlkem_poly_reduce[k*q boundaries + extremes]: first diff at coeff 10: got 3329 want 0 (NON-CANONICAL)` — the only 3 failures in the run |
| `ntt-missing-final-reduce` | *replaced*: every butterfly canonicalises in place and there is no final pass. Nearest fault of the class: the high-byte half of the masked subtract on `f[X]+t` is dropped (`sbc fq_e_lo` → `sbc #0`), leaving sums ≥ q non-canonical | `mlkem_ntt_layer L=0 (len=128) [all q-1]: first diff at coeff 0: got 4927 want 1599 (NON-CANONICAL)`; the S5 timing check trips too (the over-wide values change the multiply's page select) |
| `butterfly-swapped-operand` | CT butterfly computes `f[Y] = t - f[X]` instead of `f[X] - t` (same size; SMC labels move with the `abs,x` instructions) | `mlkem_ntt_layer L=0 (len=128) [all q-1]: first diff at coeff 128: got 1601 want 1728` |
| `loop-bpl-256` | `mlkem_poly_add` counts X down from 255 with `dex`/`bpl`: bit 7 of 254 is set, so the loop runs exactly once — P1's `keccak_clear` shape | `mlkem_poly_add[all q-1, all q-1]: first diff at coeff 0: got 3328 want 3327` (`zero, zero` passes, as it must) |
| `basemul-accumulator-24bit` | *replaced*: every product is reduced before it is combined, so no 24-bit accumulator exists. Nearest fault of the class "operand exceeds the multiply's width assumption": the `(x0+x1)` sum feeding the Karatsuba middle product is not reduced (`jsr fq_csubq_p` → 3 `nop`), so `a1` reaches 26 and the 14×14 `|d|` table is over-run | `mlkem_poly_basemul[all q-1 x all q-1  (S4 accumulator width)]: first diff at coeff 1: got 2297 want 2` |
| `basemul-zeta-sign` | the parity test `and #2` → `and #0`: every pair takes the even (+γ) path | `mlkem_poly_basemul[impulse[3]=q-1 x impulse[3]=q-1]: first diff at coeff 2: got 17 want 3312` |
| `sub-no-wrap` | `mlkem_poly_sub`: the +q high-byte correction on borrow is masked out (`and #MLKEM_Q_HI` → `and #0`) | `mlkem_poly_sub[zero, all q-1  (S3 wrap)]: first diff at coeff 0: got 62209 want 1 (NON-CANONICAL)` |
| `intt-scale-wrong` | the 128⁻¹ block constant is 3302, not 3303 | `mlkem_poly_intt[all q-1]: first diff at coeff 0: got 127 want 3328`; the per-layer INTT trace passes all 7 layers, so the scaling is what is named |
| `ntt-data-dependent-branch` | the masked conditional subtract on `f[X]+t` becomes a `bcc`-guarded store. Functionally identical; one cycle per butterfly depends on the coefficient. Same size (29 B + `nop`) | `mlkem_poly_ntt: constant-time in its input (S5): all-zero=575,432, all q-1=578,552, random=579,048` — the ONLY failure in the run; INTT and basemul still measure constant |
| `ntt-a1-range-12` | *extra*: the block table `U[k]` stops at k = 12 (`cpx #14` → `cpx #13`), restoring the a1 ≤ 12 assumption the implementer caught themselves; `a = q-1 = $0D00` is the only coefficient that reaches `U[13]` | `mlkem_poly_ntt[all q-1]: first diff at coeff 0: got 3166 want 2913` (`all-zero`, impulse=1 and `all 2048` pass) |
| `sqpart-sign-mask` | *extra*: `SQPART`'s `|x-y| = (d ^ m) - m` loses the `- m` (`sbc ohi` → `sbc #0`): off by one whenever x < y in an 8×8 partial | `mlkem_poly_ntt[all-zero]: first diff at coeff 0: got 3128 want 0` |
| `rtable-one-entry` | *extra*: `mlkem_arith_init` leaves one wrong entry in the BSS reduction table, `R1[13] = 3327` (`dec mlkem_r1_lo+13` after the build; +258 B pad) | `mlkem_poly_reduce[k*q boundaries + extremes]: first diff at coeff 2: got 254 want 3328` (`q-1 = $0D00` reads `R1[13]` directly) |
| `smc-site-missing` | *extra*: one SMC site dropped from `nt_dst_lo_sites` (`ad_s05`, add's low-plane store, listed as `ad_s01` twice), so add stores its low bytes to `$FF00,x` | `mlkem_poly_add[all q-1, all q-1]: first diff at coeff 0: got 3072 want 3327` — the stale low byte |
| `basemul-karatsuba` | *extra*: recombination `c1 = m - r00 - r00` instead of `m - r00 - r11` | `mlkem_poly_basemul[impulse[0]=q-1 x impulse[0]=q-1]: first diff at coeff 1: got 3328 want 0` — the four preceding cases have `r00 == r11` and pass, which is exactly why the impulse pairs exist |

Three WP1-specific tooling facts, learned the measured way:

- **`.res` padding goes after the `rts`, not before it.** A mutant that
  grows the code pads to exactly +258 B (2 B slack + one page) so
  `LIB_MLKEM_RODATA` (align $40) lands on the same page offset and no
  page-straddle assert changes state. The first `rtable-one-entry` patch put
  the `.res 255` *inside* `mlkem_arith_init`, ahead of the `|d|` copy loop; the
  6502 fell through 255 BRKs at boot and the kill was "banner did not
  appear" — a non-local kill, correctly refused by the gate.
- **`expect` must match the case name byte-for-byte, double spaces
  included.** `test_ntt.py` names two cases `all q-1 x all q-1  (S4 …)` and
  `zero, all q-1  (S3 wrap)`; the single-space `expect` was reported as
  non-local while the log plainly showed the case. Copy the substring from a
  log, never from memory.
- **No red-phase test defect surfaced.** Every mutant was killed by the case
  designed for it on the first real run; the two non-local reports above were
  manifest typos and the BRK fall-through.

## Required WP2 mutants (samplers and codecs) — gate run, all 13 KILLED

Same manifest, `"test": "make test-sampler"`. `expect` is a substring the
failure output must contain, so the kill is *localised*, not incidental.
Patches are written against `src/sample.s` / `src/codec.s` as merged in
54eeb17. Two faults from the red-phase list could not exist in that
implementation's structure and were replaced by the nearest fault of the same
class (marked *replaced*); four adversarial extras came from reading the
green source.

| name | fault | localising failure line |
|---|---|---|
| `wp2-cbd-short` | `mlkem_sample_cbd2`: `cmp #CBD_BYTES-1`, 127 of 128 PRF bytes consumed | `mlkem_sample_cbd2 [all-0xFF]: index 254` |
| `wp2-compress-floor` | `compress_common`: the +1664 round-half-up term dropped (floor for every d) | `mlkem_compress_10 [boundaries 0..]` (d=1 and d=4 fail too) |
| `wp2-compress-floor-4` | *replaced*: there is one shared body with per-d parameter rows, so the d=4 row runs one correction short (K=1 for 2) — floors some d=4 quotients only | `mlkem_compress_4 [boundaries 0..]: index 8: got 3 want 4` |
| `wp2-decompress-shift` | `dc_params` d=10 rounding constant $0200 -> $0100 (2^(d-2)) | `mlkem_decompress_10 [exhaustive 0..]: index 2: got 6 want 7` |
| `wp2-decompress-shift-1` | `dc_params` d=1 rounding constant 1 -> 0 | `mlkem_decompress_1 [exhaustive 0..]: index 1: got 1664 want 1665` |
| `wp2-sample-ntt-accept-q` | `try_accept`: hi==13 accepts lo<=1, i.e. d<=q | `mlkem_sample_ntt [stream carries a d == q ...]: index 146: got 3329 want 27` |
| `wp2-sample-ntt-d2-after-full` | *replaced*: the j==256 stop between d1 and d2 dropped. Y is 8-bit, so the extra store wraps to index 0 (never past the buffer) and sampling runs on | `mlkem_sample_ntt [256th coeff is d1, d2 < q must be dropped ...]: index 0` |
| `wp2-encode-nibble-swap` | middle byte packed as `(b.lo & $0F) \| a.hi << 4` | `mlkem_byte_encode_12 [nibble-asymmetric 0x3A5 / 0x5AC]: byte index 1` |
| `wp2-cbd-nibble-order` | *extra*: high nibble taken for coefficient 2k, low for 2k+1 | `mlkem_sample_cbd2 [0x03 (x=2,y=0 -> +2 in even coeffs)]: index 0: got 0 want 2` |
| `wp2-sample-ntt-block-short` | *extra*: block consumed as 55 triples (`cpx #SHAKE128_RATE-3`), the last triple of every 168 B block skipped | `mlkem_sample_ntt [needs 4 blocks (510 B > 504) ...]: index 83` |
| `wp2-decode-reduces-mod-q` | *extra*: Alg. 6 literal `mod q` on a decoded field — violates the raw pass-through pin WP3's explicit `< q` ek check relies on | `mlkem_byte_decode_12 [all fields 0xFFF (>= q, raw)]: index 0: got 766 want 4095` |
| `wp2-compress-stale-hi` | *extra*: high plane of the compressed poly never written (same-size `nop` replacement) | `mlkem_compress_1 [boundaries 0..]: index 0: got 60928 want 0` |
| `wp2-rodata-align-reverted` | *extra*, `"expect_build_fail": true`: all three `.align 64` before the compress tables removed (the WP1 merge fix reverted) | build fails at LINK: `straddles a page: compress cost would depend on secret data` |

### Alignment mutants and `expect_build_fail`

A page-straddle `.assert ..., lderror` is a *layout-conditional* guard: it
fires only when the table actually crosses a page. Dropping a single
`.align 64` is therefore not deterministically killable — probed against
a9cc7f5: removing the one before `cp_thi_lo` tripped the assert, removing
the one before `cp_thi_hi` or `cp_tlo` built and passed (those tables landed
inside a page by luck). The gate mutates the whole fix instead, and the
manifest row carries `"expect_build_fail": true`: `mutate.py` then counts a
FAILED build whose output contains `expect` as the kill, a build that fails
for another reason as `non-local-kill`, and a build that succeeds as
`survived`. Without that flag a failed build is always reported as a stale
patch.


Two layout facts bit while writing these and will bite again: the
secret-indexed tables carry page-straddle `.assert`s, so a patch that
changes code size by even 8 bytes can move `LIB_MLKEM_RODATA` onto a page
edge and fail the LINK (the slack in the green tree is +36 / -8 bytes) —
prefer same-size replacements (`nop`), and widen a `bne` loop to
`beq :+ / jmp` when a mutant's extra bytes push it out of range. (Since
a9cc7f5 the three compress tables are `.align 64`, so only the 32-byte CBD
tables in `sample.s` still move with code size.)

One red-phase defect surfaced: the original `nibble-asymmetric 0x0A5 / 0x5A0`
encode vector was *symmetric under the nibble swap* (both swapped nibbles
were 0) and could not localise `wp2-encode-nibble-swap`; the mutant was
still killed by `all q-1`, but the vector is now `0x3A5 / 0x5AC`.

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

## Required WP3 mutants (K-PKE and ML-KEM-768)

Same manifest, `"test": "make test-mlkem"`. `kill` is the narrowest
`tools/test_mlkem.py --only` invocation that must go red (each suite is
tens of millions of cycles per call, so the gate need not run the lot);
`expect` is the substring the failure output must contain, so the kill is
localised to the primitive and vector it names. The ABI these rely on —
the `mlkem_arg_*` parameter block, `A`/`mlkem_status` = 1 on an ek rejected
by the §7.2 modulus check, no §7.3 check in `mlkem_decaps` — is documented at
the top of `tools/test_mlkem.py`.

| name | fault | kill / expected failure |
|---|---|---|
| `wp3-skip-rejection-compare` | `mlkem_decaps`: the c == c' result is ignored; K' is always returned | `--only decaps,onebit` → `mlkem_decaps [decapsulation tcId 88 modified ciphertext]: K (implicit rejection J(z\|\|c)) differs at byte 0` |
| `wp3-early-exit-compare` | `mlkem_decaps`: the 1,088-byte compare returns at the first mismatch instead of OR-accumulating the full length. Functionally correct. | `--only timing,onebit` → `mlkem_decaps: constant-time in c (T1)` — the valid c and the byte-0-flipped c measure different cycle counts |
| `wp3-swap-du-dv` | K-PKE.Encrypt compresses u with d=4 and v with d=10 | `--only encaps,hooks` → `mlkem_encaps [encapsulation tcId 26]: c differs at byte 0`; the hook test also prints which of c1/c2 differs |
| `wp3-prf-nonce-stuck` | the PRF nonce N is not incremented between polynomials | `--only keygen,hooks` → `mlkem_keygen [keyGen tcId 26]: ek differs at byte` |
| `wp3-g-missing-k` | `(rho, sigma) = G(d)` — the k byte is not absorbed | `--only keygen,hooks` → `mlkem_keygen [keyGen tcId 26]: ek differs at byte` (byte 0: rho changes, so every t_hat coefficient does) |
| `wp3-h-ek-wrong-length` | dk's H(ek) field hashes 1,152 B of ek instead of 1,184 | `--only keygen` → `mlkem_keygen [keyGen tcId 26]: dk differs at byte 2336` (ek and dk_pke fields are still exact, so the offset names the field) |
| `wp3-ek-check-missing` | `mlkem_encaps` never rejects (the per-coefficient `< q` compare is gone). Invisible to a re-encode-and-compare check because `byte_decode_12` passes ≥ q fields through raw | `--only ekcheck` → `accepted an ek with a coefficient >= q` (the message names `t_hat[i][j]`) |
| `wp3-m-not-hashed` | `(K, r) = G(H(m) ‖ H(ek))` — Kyber round 3, not FIPS 203 Alg. 17 | `--only encaps` → `mlkem_encaps [encapsulation tcId 26]: c differs at byte` and `K differs at byte 0` |

Two of these are worth calling out. `wp3-early-exit-compare` produces the
right K on every vector, including the one-bit cases — only the cycle count
distinguishes it, which is why `test_mlkem.py` keeps `bench_keccak.py`'s
calibration refusal rather than skipping the timing leg when the instrument
is off. `wp3-ek-check-missing` is the direct consequence of WP2's raw
`byte_decode_12` pin: an implementer who reaches for the spec's
re-encode-and-compare shape gets a check that can never fire.
