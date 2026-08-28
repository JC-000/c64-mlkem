# c64-mlkem — P2 handoff brief (ML-KEM-768 on top of P1's Keccak)

Written 2026-08-28 by the P2 supervising session. Self-contained for an agent
starting cold in this repo. `HANDOFF.md` is the P1 brief and stays
authoritative for everything Keccak; `CLAUDE.md` records the conventions that
are easy to get wrong — read both first. Where this brief and
`../c64-lib-contract/SPEC.md` disagree, SPEC wins; record the divergence in
README.

## Mission

> **P2: ML-KEM-768 (FIPS 203) KeyGen / Encaps / Decaps in ca65, verified
> against three independent oracles in VICE, measured, and packaged as a
> c64-lib-contract-conformant archive.**

The consumer is `../c64-https`, TLS 1.3 hybrid group `X25519MLKEM768`
(0x11EC). The client side *calls* KeyGen and Decaps only — but Decaps contains
K-PKE.Encrypt for the re-encapsulation check, so all three primitives exist
regardless. Consumer wiring is P4, consumer-side, not this repo.

P1 measured Keccak-f[1600] at **456,605 cycles** — 1.3× the top of the
150k–350k estimate band, putting Keccak alone at 25–27M of the roadmap's
40–70M keygen+decaps budget. P2 repeats P1's job for everything else:
**replace the 15–45M non-Keccak estimate with a measurement** and report it
without softening.

## Decisions already made (do not re-litigate)

1. **One overlay image.** Target the whole library — Keccak + P2 — inside the
   c64-https `CRYPTO_OVERLAY` slot: **7,680 B ($1E00) code+rodata**. P1 uses
   1,477 B, so P2's code+rodata budget is **≤ ~6,200 B**. If measured over,
   the fallback is a split into per-operation images (the c64-nist-curves
   P-384 precedent) — a measured decision at WP4, not a design default.
   Looped/table-driven code first; unroll only what measurement justifies.
2. **Multiply consumes §8.1 `sqtab`.** The 1 KB quarter-square table lives
   *outside* the window at a consumer-chosen `LIB_SHARED_SQTAB_BASE`
   (`.ifndef`-guarded default for standalone builds; pick one clear of
   c64-x25519's `$7800`). Set `LIB_SHARED_PRIMITIVES_SQTAB` in
   `LIB_MLKEM_SHARED_CONSUMES`, honour the `SHARED_SQTAB_INIT` switch, and
   follow §8.1's import-never-stub rule. Whether the *body* should be the
   §8.3 canonical `ct_mul_8x8` (59 B, byte-identical, `Y=b`, SMC-baked `a`)
   or a private mod-3329-shaped multiply is the NTT implementer's call, made
   with the contract-alignment lane — a private body is fine as long as it
   carries no secret-dependent branch and every table it indexes with a
   secret byte is page-aligned (`abs,x` is cycle-stable only then).
3. **Budgets.** Cycles: 40–70M for keygen+decaps total, Keccak included.
   BSS: no ceiling was given — **measure and report it**; `dk` alone is
   2,400 B, so this number is not derivable by the consumer. Never store the
   matrix `A` (4.5 KB): generate each entry from SHAKE128 and consume it.
4. **Git.** Commit locally per work package on `main` via merge from the
   WP worktree. **No push, no tag** until the user says so.
5. **Contract alignment runs as its own lane, in parallel** (WP5), against
   `../c64-lib-contract` at its current head (changelog says v0.13.0; local
   tags stop at v0.11.0 — read the SPEC version line, not the tag).

## Standing invariants (every agent, every file)

- **Every P2 symbol is under `mlkem_`.** `mlkem_poly_ntt`, never `poly_ntt`.
  `poly_` (chacha), `mul_` (x25519), `ct_` (chacha), `sha_` (nist-curves) are
  registered to other libraries and c64-https links several of them. ZP slots
  are `mlkem_zp_*` only, added to `src/zp_config.s` with `.ifndef` guard +
  `.exportzp`, never hardcoded elsewhere. If a symbol *must* land outside
  `mlkem_`, its prefix is registered upstream **in the same PR** that
  introduces it.
- No bare `LIB_VERSION_*` exports, no unprefixed archive member basenames
  (both v0.11.0 carve-outs this library was first to take).
- `src/lib_version.s` exports the four §1 equates and nothing else.
  `LIB_MLKEM_ABI_VERSION` (now 2) moves only on a breaking export change.
- Library TUs use `LIB_MLKEM_CODE` / `_RODATA` / `_BSS` only; bss-type
  segments last; aligned buffers first within a TU (ld65 aligns the whole
  fragment). Driver TUs (`main.s`, `bench.s`) are the consumer and ship in no
  archive.
- Toolchain traps from CLAUDE.md apply verbatim: `-D` never carries `$`;
  `.assert …, lderror` for anything imported; no backslash continuation;
  `: abs` on exported equates; 8-bit branch range; `jmp (abs)` page-wrap.
- Every generated table (zetas, Barrett/Montgomery constants, CBD lookup)
  comes from the validated model via `make tables`, never hand-typed.
- Test hooks stay behind `MLKEM_TEST_HOOKS`; the shipped archive never
  defines it; `build/tobj` and `build/obj` never mix.
- **No REU. No ML-DSA. No changes to c64-https.**
- Constant time: no branch on secret data (s, e, r, m, K, z, the decaps
  compare result); the decaps ciphertext compare is a full-length
  accumulate-OR, never early-exit; rejection sampling of `A` from public ρ
  is the one legitimately data-dependent loop.

## Parameters (FIPS 203, ML-KEM-768)

q=3329, n=256, k=3, η1=η2=2, du=10, dv=4. Sizes: ek 1,184 B, dk 2,400 B,
ct 1,088 B, K 32 B, seeds d,z,m 32 B each. Hash roles: G=SHA3-512,
H=SHA3-256, J=SHAKE256(·,32), PRF_η=SHAKE256(s‖b, 64η), XOF=SHAKE128(ρ‖j‖i).
P1's streaming `mlkem_absorb` / multi-call `mlkem_squeeze` are what SampleNTT
needs; this is the first real exercise of that path.

## The three oracles — and what each is for

| Oracle | Nature | Proves |
|---|---|---|
| **`cryptography.hazmat.primitives.asymmetric.mlkem`** (venv: cryptography 48.0.0 / OpenSSL 3.6.2) | independent, black-box | `MLKEM768PrivateKey.from_seed_bytes(d‖z)` is deterministic: our ek from the same seed must match byte-for-byte. Our decaps must recover the secret from *their* `encapsulate()` ciphertext; their `decapsulate()` must recover it from ours. Interop with code we did not write — the only defence against a shared misreading of the spec. Note `encapsulate()` returns `(ss, ct)` and cannot take `m`. |
| **NIST ACVP KATs** (`usnistgov/ACVP-Server`, `gen-val/json-files/ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`, `internalProjection.json`) | fixed vectors incl. `m`, plus the decaps-only vectors with modified ciphertexts | Encaps determinism (hazmat can't) and the implicit-rejection path, where a broken re-encrypt yields a *wrong K silently* rather than an error. Fetch on demand like the LongMsg sets if large; track if small. |
| **`tools/mlkem_ref.py`** (ours) | white-box, per-step | Localisation: every internal step individually callable so a failing NTT names its layer, like P1's per-round trace. **Pinned to the other two by `make test-ref` before any 6502 comparison is meaningful.** |

### `tools/mlkem_ref.py` API (WP0 delivers this; red-test authors code to it)

Pure Python, stdlib + `hashlib` only (hazmat is used by the *pin test*, not
the model). Polynomials are `list[int]` of 256 coefficients in `[0, q)`;
polyvecs are `list[poly]` of length k. Bytes in, bytes out at the FIPS
boundaries.

```
Q, N, K, ETA1, ETA2, DU, DV
ZETAS            # 128 entries, bit-reversed order, as FIPS 203 Appendix A
ntt(f) -> f_hat ; intt(f_hat) -> f ; basemul(a_hat, b_hat) -> c_hat
poly_add(a, b) ; poly_sub(a, b) ; polyvec_* likewise
sample_ntt(rho: bytes, i: int, j: int) -> poly           # A[i][j], XOF stream
sample_cbd(eta: int, b: bytes) -> poly                    # b is 64*eta bytes
prf(eta, s: bytes, b: int) -> bytes ; G(x) -> (rho, sigma) ; H(x) ; J(x)
byte_encode(d, f) -> bytes ; byte_decode(d, b) -> poly
compress(d, x) -> int ; decompress(d, y) -> int   (and poly-wise variants)
kpke_keygen(d) -> (ek_pke, dk_pke)
kpke_encrypt(ek_pke, m, r) -> c ; kpke_decrypt(dk_pke, c) -> m
mlkem_keygen(d, z) -> (ek, dk)
mlkem_encaps(ek, m) -> (K, c) ; mlkem_decaps(dk, c) -> K
poly_to_c64(f) -> bytes ; poly_from_c64(b) -> poly       # the 6502 memory layout
```

The 6502 in-memory polynomial layout is the NTT implementer's choice,
declared once in `src/mlkem.inc` and mirrored by `poly_to_c64` /
`poly_from_c64`. Recommended: **split-plane** — 256 low bytes then 256 high
bytes, each page-aligned — so a coefficient is `lda lo,x` / `lda hi,x` with
one index register and no doubling. Whatever is chosen, `mlkem_ref.py` is the
only place the harness converts.

## Work packages and the red/green protocol

```
WP0  oracle ─────────────────────────────────────────────── must be green first
     ├── WP1 red: NTT/basemul tests ─► WP1 green: implement ─► mutation gate
     └── WP2 red: sampler/codec tests ─► WP2 green: implement ─► mutation gate
WP3  red: K-PKE + ML-KEM KATs + hazmat interop in VICE ─► green ─► mutation gate
WP4  bench, footprint vs 7,680 B, BSS, manifest, archives, README numbers
WP5  contract alignment — runs alongside all of the above
```

**Red first, by a different agent, from the spec.** For each of WP1–WP3 an
adversarial test author receives FIPS 203, the oracle, and the export list
below — *not* the implementation — and writes the harness. It must be red
against stubs before the implementer sees it. The implementer turns it green
and may not edit the tests; disputes go to the supervisor.

**Mutation gate before merge.** The same adversarial agent then applies
deliberate faults to a copy of the green tree (`tools/mutants/*.patch`,
driven by `tools/mutate.py`, working in `build/mutants/`) and the suite must
go red for every one. Required mutants at minimum: one wrong zeta; an
off-by-one in the reduction bound; a skipped or early-exit implicit-rejection
compare; a CBD sampler one byte short; a `bpl` on a count ≥ 128 (P1's real
`keccak_clear` bug); a swapped `du`/`dv`; a missing final reduction leaving a
coefficient ≥ q. **A surviving mutant is a test-suite defect and blocks the
merge.**

### WP0 — oracle (one agent)
`tools/mlkem_ref.py` per the API above; `tools/test_mlkem_ref.py` pins it to
ACVP (all keyGen and encapDecap vectors, including the decaps-only modified-ct
cases) and to hazmat (seeded keygen equality; bidirectional interop over ≥ 100
random seeds); `tools/fetch_vectors.sh` extended; `make test-ref` runs it.
Generated-table hooks: `tools/gen_tables.py` learns to emit
`src/mlkem_tables.inc` (zetas in the NTT's traversal order, reduction
constants) from the model.

### WP1 — field arithmetic and NTT (red author + implementer, worktree)
Exports: `mlkem_poly_ntt`, `mlkem_poly_intt`, `mlkem_poly_basemul`,
`mlkem_poly_add`, `mlkem_poly_sub`, `mlkem_poly_reduce` (to `[0,q)`),
`mlkem_poly_tomont` if a Montgomery domain is used, plus the §8.1 sqtab
plumbing. Per-layer hooks under `MLKEM_TEST_HOOKS` so the harness can run one
NTT layer and compare. Tests: every layer against the model on random and
edge polys (all-zero, all q−1, single-coefficient impulses), basemul against
schoolbook-in-model, `intt(ntt(f)) == f`, and a cycle count per NTT reported
even at this stage.

### WP2 — samplers and codecs (red author + implementer, worktree)
Exports: `mlkem_sample_ntt` (rejection over a live SHAKE128 stream — pass the
sponge, not a buffer), `mlkem_sample_cbd2`, `mlkem_byte_encode_12` /
`_decode_12`, `mlkem_compress_{1,4,10}` / `_decompress_{1,4,10}` (or
generic-d with the constants tabled — implementer's call, measured). Tests:
per function against the model, including a SampleNTT seed whose stream
needs > 3 squeeze blocks and a `byte_decode_12` input with a coefficient ≥ q
(FIPS 203 says the modulus check is the caller's job for ek — the test pins
whatever behaviour is declared).

### WP3 — K-PKE and ML-KEM (red author + implementer, after WP1+WP2 merge)
Exports: `mlkem_keygen(d, z) -> ek, dk`, `mlkem_encaps(ek, m) -> K, c`,
`mlkem_decaps(dk, c) -> K`, with the K-PKE internals as hooks. Buffers in
`LIB_MLKEM_BSS`, caller-supplied pointers via the existing `mlkem_zp_src/dst`
convention. Tests in VICE: every ACVP vector (behind `--full`; a curated
subset by default — one VICE round-trip per vector, and keygen is
~30M cycles ≈ 30 s emulated per vector, so budget the suite), hazmat interop
in both directions, and the modified-ciphertext decaps vectors.

### WP4 — measurement and packaging (supervisor + one agent)
Cycles per KeyGen / Encaps / Decaps and per NTT with the calibrated CIA
instrument (`bench.s`, keep the calibration refusal). Code+rodata vs 7,680 B;
BSS total; `make check-manifest`; `mlkem-kem.a` alongside the existing
archives; `check-archives`, `check-staleness` extended; README release row and
a "Where the cycles go" table in P1's style. ABI bump only if an export
broke. Version to **v0.5.0**.

### WP5 — contract alignment (one agent, parallel, owns the upstream side)
Against `../c64-lib-contract` head (not the stale tags):
- Diff SPEC v0.11.0 → current for any clause that newly binds this repo.
- §8.1 consumption shape for `sqtab` (header, `.assert`s, `SHARED_SQTAB_INIT`,
  import-never-stub) and the §8.0 `SHARED_CONSUMES` mask construction;
  recommendation on §8.3 body reuse for the NTT implementer.
- §8.0/§8.4: `docs/precalc-tables.md` rows + `LIB_PRECALC_TABLE` macro
  (`src/precalc_table.inc` copied verbatim from the contract root) for every
  P2 table at or above the 256 B floor — the 128-zeta table is exactly 256 B
  and hot-loop-read, so it is *in*.
- A `make check-prefix` that fails on any exported symbol not under `mlkem_`
  / `LIB_MLKEM_` / `keccak_` (P1's registered names).
- Draft the adopters-row update and the intake PR text for
  `c64-lib-contract`; split registry rows from any normative ask (the #123
  lesson). **Do not push or open PRs** — leave them in `docs/upstream/` for
  the user.

## Test conventions (unchanged from P1)

`test_*.py` = CI logic tests; `rig_*.py` = hardware. Honour
`C64_SKIP_BUILD=1`. Addresses from `build/labels.txt` via `Labels`, never
hardcoded. VICE only through `c64-test-harness`. Interpreter:
`/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3`. Default
suite fast, exhaustive behind `--full`. VICE is cycle-deterministic: a
varying count means the measurement is wrong.

## Reporting back

The summary the user needs at the end of P2: (1) cycles per KeyGen, Encaps,
Decaps, with the Keccak share separated out; (2) code+rodata vs the 7,680 B
window and whether a split was needed; (3) BSS bytes; (4) KAT and interop
pass counts per oracle; (5) mutation-gate results; (6) SPEC divergences and
surprises. Bad news is reported as bad news.
