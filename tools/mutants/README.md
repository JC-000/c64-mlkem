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

## P1 mutants (Keccak and sponge) — gate run, both KILLED

P1 shipped without a mutation gate; these two came from the hardware
validation's adversarial review (`hw/rig-validation`) and were written
against its head. They are the gate's only faults below ML-KEM.

| name | fault | suite | localising failure line |
|---|---|---|---|
| `p1-keccak-rc23-bit0` | `keccak_tables.inc` (generated; patched as a hand edit would be): RC[23] low byte `$08` → `$09`. One bit of the last round's iota | `make test-vice` | `all-zero input round 23 after iota: lane 0 (x=0,y=0): got f1258f7940e1dde6 want f1258f7940e1dde7` — rounds 0–22 and every other step pass; `test_sha3` and every KEM suite go red as well |
| `p1-sponge-len-hi-ignored` | `sponge.s` chunk size: `lda mlkem_sponge_len+1 / bne done` loses the `bne` (2 `nop`), so a remaining length ≥ 256 is chunked by its low byte alone. Any length ≥ 256 is thereby worn down to a nonzero multiple of 256, where the chunk is n = 0 and absorb never advances — a **livelock** | `make test-sha3` | `c64_test_harness.transport.TimeoutError: No stopped event within 5.0s`, raised from `jsr(self.t, self.l["mlkem_absorb"])` after `SHA3_256ShortMsg` and `SHA3_512ShortMsg` pass |

**A livelocking mutant is killed by the suite's timeout, not the gate's.**
`mutate.py` puts no timeout on the test command; it relies on the harness
`jsr()` timeout (5 s default in `test_sha3`), whose `TimeoutError` escapes
`main()` inside the `ViceInstanceManager` block, so VICE is torn down and
the test exits nonzero. Measured: 7 s from patch to kill including the
build, no `x64sc` left running. A future livelock mutant needs its suite's
timeout to be the short one — under a suite with a 900 s `JSR_TIMEOUT`
(`test_mlkem`, `bench_*`) the same fault costs 15 minutes per call.

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
| `wp2-rodata-align-reverted` | *extra*, `"expect_build_fail": true`: all three `.align 64` before the compress tables removed (the WP1 merge fix reverted), plus a **layout-tuned** `.res 128` pad (P3: the +31 B of lever 1 moved `LIB_MLKEM_RODATA` from `$1FC0` to `$2000` and the bare tables happened to fit; see below) | build fails at LINK: `straddles a page: compress cost would depend on secret data` |

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


**The pad is tuned to the link, and must be re-tuned when the code size
moves.** The three bare tables are one contiguous 148 B span whose page
offset takes one of four values 64 B apart (the segment start is the code
end rounded up to `$40`); one of the four always fits inside a page, so no
pad makes the straddle deterministic across layouts. P3's lever 1 (+31 B)
moved the span from a straddling phase to a fitting one and the mutant
survived; the pad (re-picked after every lever since) shifts it back to a straddling phase for the
current link. Whenever `make test-mutants` reports this one as survived
after a code-size change, re-pick the pad (0 / 64 / 128 / 192) from
`build/mutants/wp2-rodata-align-reverted/build/labels.txt` — it is the
gate's layout dependence, not a suite gap.

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

## Required WP3 mutants (K-PKE and ML-KEM-768) — gate run, all 18 KILLED

Same manifest. Patches are written against `src/kem.s` as merged in 0996feb.
Every `test` is `make test-mlkem MLKEM_ARGS="--only <suite>"` — the
narrowest `tools/test_mlkem.py` suite that localises the fault — because a
WP3 call is 10-40M cycles; the whole WP3 gate is ~2 minutes under warp.
`expect` is a byte-exact substring of the failure line. The ABI these rely
on — the `mlkem_arg_*` parameter block, `A`/`mlkem_status` = 1 on an ek
rejected by the §7.2 modulus check, no §7.3 check in `mlkem_decaps` — is
documented at the top of `tools/test_mlkem.py`. Nine adversarial extras came
from reading the green source (the mask select, the compare accumulator,
the pointer table, the nonce counter, the A^T index, `check_t`).

| name | fault (what the patch does) | suite | localising failure line |
|---|---|---|---|
| `wp3-skip-rejection-compare` | the select mask is forced to `$FF` (`lda #$FF / nop / nop` for `lda #0 / sbc #0`): K' always | decaps | `mlkem_decaps [decapsulation tcId 88 modified ciphertext]: K (implicit rejection J(z\|\|c)) differs at byte 0 (got AA want 2C)`; tcId 86 (valid) passes |
| `wp3-early-exit-compare` | `cmp_len`: `bne exit` after the OR-accumulate, so the compare stops at the first mismatching byte. Functionally correct; +258 B pad | timing | `mlkem_decaps: constant-time in c (T1): valid c=35,103,218; c ^ bit 0 of byte 0=35,066,003; c ^ bit 7 of byte 1087=35,066,003` — the ONLY failure; both tampered inputs exit 37,215 cycles early (the first chunk's remaining 319 bytes plus the later chunks' bytes after their first difference) |
| `wp3-swap-du-dv` | `el_u` compresses u with d=4 and `encrypt_body` compresses v with d=10 (both `jsr` + `enc_d` swapped) | encaps | `mlkem_encaps [encapsulation tcId 26]: c differs at byte 0 (got 94 want 03)` |
| `wp3-prf-nonce-stuck` | `prf_cbd`: `inc kp_nonce` → 3 `nop` | keygen | `mlkem_keygen [keyGen tcId 26]: ek differs at byte 0`, and `dk differs at byte 384 (got 38 want E7)` — dk_pke[0] (s_0, N=0) is still right, s_1 is the first wrong poly |
| `wp3-g-missing-k` | `kpke_keygen`: the `jsr absorb_len` for the k byte becomes 3 `nop` — `G(d)`, not `G(d ‖ k)` | keygen | `mlkem_keygen [keyGen tcId 26]: ek differs at byte 0 (got CB want 28)` — rho changes, so everything does |
| `wp3-h-ek-wrong-length` | `mlkem_keygen`: `ABSORB EK_BYTES` → `ABSORB EK_T_BYTES` (H over 1,152 B) | keygen | `mlkem_keygen [keyGen tcId 26]: dk differs at byte 2336 (got 8E want 81)` — ek and dk_pke exact, so the offset names the H(ek) field |
| `wp3-ek-check-missing` | `mlkem_encaps`: `jsr check_t` → `lda #0 / nop` | ekcheck | `mlkem_encaps [encapsulationKeyCheck tcId 137 noisy linear system values too large]: accepted an ek with a coefficient >= q (t_hat[0][0] = 3330 >= q) (A=0 mlkem_status=0, want 1)`, then the E2 "must be untouched" checks |
| `wp3-m-not-hashed` | `mlkem_encaps` hashes m with SHA3-256 into `kem_hb+32` and absorbs that into G — Kyber round 3; +258 B pad | encaps | `mlkem_encaps [encapsulation tcId 26]: K differs at byte 0 (got 3A want 79)` and `c differs at byte 0` |
| `wp3-mask-inverted` | *extra*: `eor #$FF` after the borrow trick — valid c selects K̄, tampered c selects K'; +258 B pad | decaps | `mlkem_decaps [decapsulation tcId 86 valid decapsulation]: K differs at byte 0 (got D3 want 34)` and tcId 88 `(got AA want 2C)` — both directions wrong |
| `wp3-mask-partial` | *extra*: `sbc #0` → `sbc #1`: mask `$FE`, bit 0 of every K byte from K̄ even when c = c' | decaps | `mlkem_decaps [decapsulation tcId 86 valid decapsulation]: K differs at byte 0 (got 35 want 34)` — one bit |
| `wp3-key-select-short` | *extra*: the select loop starts at `ldy #30`; K[31] is never written | decaps | `mlkem_decaps [decapsulation tcId 86 valid decapsulation]: K differs at byte 31 (got EE want 3A)` — `EE` is the harness prefill |
| `wp3-cmp-acc-reset` | *extra*: `enc_poly` zeroes `cmp_acc` before each chunk's `cmp_len`, so only the last chunk (c2) decides; +258 B pad | onebit | `mlkem_decaps [one-bit c ^ bit 0 of byte 0]: returned the VALID key K' — the re-encrypt compare missed a one-bit difference (early exit or partial compare)`; the byte-1087 flip (in c2) still rejects, as it must |
| `wp3-z-ptr-off-by-one` | *extra*: `SRC IDX_DK, DK_Z_OFF + 1` — J over `z[1..32] ‖ dk[2400]` | decaps | `mlkem_decaps [decapsulation tcId 88 modified ciphertext]: K (implicit rejection J(z\|\|c)) differs at byte 0 (got A0 want 2C)`; valid decapsulation passes, which is why the modified-ct vectors are not optional |
| `wp3-e1-nonce-reused` | *extra*: `dec kp_nonce` after each e1_i in `el_u`: e1_0 = e1_1 = e1_2 (N=3), e2 at N=4; +258 B pad | encaps | `mlkem_encaps [encapsulation tcId 26]: c differs at byte 322 (got CA want DA)` — u_0 (bytes 0..319) is exact, u_1 is the first poly with the reused nonce |
| `wp3-matrix-not-transposed` | *extra*: `encrypt_body` sets `kp_t = 0` — A instead of A^T for u | encaps | `mlkem_encaps [encapsulation tcId 26]: c differs at byte 0 (got AC want 03)` |
| `wp3-check-t-high-byte-only` | *extra*: `check_t` drops the low-byte test for hi = 13 (4 `nop`), accepting 3328..3583 | ekcheck | `... tcId 137 ...: accepted an ek with a coefficient >= q (t_hat[0][0] = 3330 >= q)` — 3330 = `$0D02` is exactly the value only the low-byte leg rejects |
| `wp3-cmp-mismatch-timing` | *extra*, from the hardware validation's adversarial review (`ct-leak3`): `cmp_len` still ORs every byte of the full length, but a mismatching byte runs `sta cmp_acc / bne next` and a matching one `beq same / nop / bit $00` — the leak is the *count* of differing bytes: +1 cycle each from the path, +2 as linked, because the mismatch path's `bne next` ($1BFE → $1C01) also crosses a page. Either way T1 fails, so the kill does not depend on that page edge. The equal path costs exactly the green `ora`+`sta`, so a valid c measures the green count; `.res 6` before the proc and `.res 246` after the `rts` make it +256 B, so every later byte keeps its page offset (checked against the clean `labels.txt`: every label after `cmp_len` moves by exactly $100, none before it moves) | timing | `mlkem_decaps: constant-time in c (T1): valid c=29,597,879; c ^ bit 0 of byte 0=29,597,881; c ^ bit 7 of byte 1087=29,600,051` — the ONLY failure; valid equals the green count to the cycle, which is what makes it the subtle one. The byte-0 flip leaves m' intact, so c' differs from c in that one byte (+2); the byte-1087 flip changes m', so c' differs from c almost everywhere (+2,172 = 1,086 bytes × 2) |
| `wp3-v-compress-10` | *extra*: v compressed and packed with d = 10 (u correct) | encaps | `mlkem_encaps [encapsulation tcId 26]: c differs at byte 960 (got 69 want F6)` — c1 exact, c2 is where it first differs; the C1 canary after c also trips because c2 grew to 320 B |

What the run taught:

- **The first `wp3-mask-inverted` was functionally equivalent and survived.**
  `lda #0 / adc #$FF` after the `asl` gives `$FF` iff carry clear — exactly
  what `lda #0 / sbc #0` gives. The gate reported it as a survivor, the
  survivor was a wrong patch (not a test gap), and the inversion is now an
  explicit `eor #$FF`. A survivor must be read before it is blamed on the
  suite, but it must be read.
- **GNU Make 3.81's 1-second mtime granularity reached the mutation
  scratch too.** Verifying "every patch builds" by patch → `make` → `git
  checkout src/kem.s` in a loop left `build/tobj/kem.o` built from the LAST
  mutant (the checkout landed in the same second as the object), and the
  next `make test-mlkem` on the clean tree failed with `wp3-z-ptr-off-by-one`'s
  exact signature. `touch src/kem.s; make` fixed it. `mutate.py` is immune —
  it copies a fresh tree per mutant — but never trust an in-tree build made
  in the same second as a source restore.
- **No red-phase test defect surfaced**: every mutant was killed by the
  suite and vector designed for it, with the first differing byte naming the
  field (2336 = H(ek), 384 = s_1, 322 = u_1, 960 = c2, 31 = the last K byte).
