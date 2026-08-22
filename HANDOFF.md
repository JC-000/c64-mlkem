# c64-mlkem — P1 handoff brief (Keccak / SHA-3 / SHAKE)

Written 2026-08-22 by the c64-https planning session. This brief is
self-contained: it assumes you are a fresh agent starting in this empty
directory with no prior context.

## Mission

Create **c64-mlkem**, a new 6502 crypto library repo (ca65/ld65, Commodore 64)
in the JC-000 sibling-library ecosystem. Its eventual product is **ML-KEM-768**
(FIPS 203) for the c64-https TLS 1.3 client's hybrid `X25519MLKEM768` key
exchange. The work is phased; **this brief covers Phase 1 only**:

> **P1: Keccak-f[1600] + SHA3-256 + SHA3-512 + SHAKE128 + SHAKE256,
> KAT-verified in VICE, packaged as a c64-lib-contract-conformant archive.**

Phase 2 (NTT/mod-3329 arithmetic, samplers, keygen/encaps/decaps vs NIST ACVP
KATs) builds on P1 in this same repo, but do NOT start it — P1 is the gating
unknown (no 6502 Keccak exists anywhere to calibrate against) and its measured
results feed the wall-clock model for the rest of the roadmap.

## Why this exists (one paragraph of context)

c64-https (../c64-https) does real TLS 1.3 to real internet servers from a
C64. The PQC roadmap adds the hybrid group X25519MLKEM768 (0x11EC). A
feasibility analysis (2026-08-22, in the c64-https session plans) concluded
ML-KEM-768 keygen+decaps is ~40-70M cycles — cheaper than the X25519 it rides
alongside — so the blockers are code, not wall-clock. The single largest
unknown in that estimate is the cost of one Keccak-f[1600] permutation on a
6502, estimated at 150k-350k cycles. P1 exists to build the primitive and
**replace that estimate with a measurement**.

## Deliverables (acceptance criteria)

1. **A git repo** in this directory (you `git init`; model the layout on
   ../c64-x25519 — Makefile, src/, cfg/, test/ or tools/, README.md,
   CLAUDE.md, VERSION).
2. **Keccak-f[1600] permutation** in ca65 assembly, operating on a 200-byte
   state. Implement the **looped** (compact) form first — the c64-https
   consumer wants the whole eventual ML-KEM image inside a 7,680 B window, so
   the P1 code budget is **≤ ~3 KB code+rodata**; unrolling is a later,
   measured decision, not a default.
3. **Sponge layer**: SHA3-256, SHA3-512, SHAKE128, SHAKE256 with a
   **streaming API** — `*_init` / `*_absorb` (arbitrary-length, incremental) /
   `*_final`-or-`*_squeeze` (SHAKE squeeze must be callable repeatedly:
   ML-KEM's matrix expansion squeezes many blocks per call site). Rates:
   SHA3-256/SHAKE128 r=136/168, SHA3-512 r=72, SHAKE256 r=136; domain
   suffixes 0x06 (SHA3) / 0x1F (SHAKE).
4. **FIPS 202 KATs passing in VICE**, driven from Python over the
   c64-test-harness DMA interface (pattern below). Minimum vector set: empty
   input, short (<rate), exactly-rate, multi-block, and incremental-absorb
   split tests for each of the four functions, checked against Python's
   `hashlib.sha3_256/sha3_512/shake_128/shake_256`.
5. **A cycle benchmark**: measured cycles for one Keccak-f[1600] permutation
   (VICE is cycle-deterministic; a repeated run must reproduce exactly).
   Report the number prominently in the README — it calibrates the project
   wall-clock model (estimate band to beat/confirm: 150k-350k).
6. **Contract packaging** (see next section): `make lib-keccak` producing a
   narrowed archive in `build/lib/`.

## c64-lib-contract obligations

The contract spec lives at ../c64-lib-contract (SPEC.md; **pin the newest
GitHub release tag — v0.10.3 as of 2026-08-15** — tags are now current with
SPEC). Your two adopter templates are ../c64-x25519 and ../c64-nist-curves;
read one of their Makefiles + src/zp_config.s before writing your own.
Requirements that bind P1:

- **Segment names** (§4): `LIB_MLKEM_CODE`, `LIB_MLKEM_RODATA`,
  `LIB_MLKEM_BSS` (the consumer's cfg places them by name). If you split
  hot/cold or init-only code, use `LIB_MLKEM_HOT_CODE` / `_COLD_CODE` /
  `_INIT_CODE` per the x25519 v0.8.0 precedent.
- **`src/lib_version.s`**: exported absolute equates
  `LIB_MLKEM_VERSION_{MAJOR,MINOR,PATCH}` + `LIB_MLKEM_ABI_VERSION`
  (export `:abs` so consumer link-time `.assert`s see them without warnings).
- **`src/zp_config.s`**: every zero-page slot `.ifndef`-guarded AND
  `.exportzp`-ed, so the consumer can relocate slots via `--asm-define`.
  **No hardcoded ZP anywhere else.** Keep ZP usage minimal (a few pointer
  pairs); Keccak state itself is absolute memory, not ZP. Prefix canonical
  slot names (`mlkem_zp_*`) — the §6.5 lesson: bare aliases without
  `.ifndef` guards broke consumers.
- **Manifest equates** (§1/§5, gated exports under
  `ca65 -D LIB_NO_BARE_EXPORTS=1` supported): `LIB_MLKEM_RESIDENT_BYTES`,
  `LIB_MLKEM_ZP_USAGE_BYTES`, `LIB_MLKEM_REU_BANKS_USED = 0` (P1 uses no
  REU), `LIB_MLKEM_SHARED_PRIMITIVES = 0` / `LIB_MLKEM_SHARED_CONSUMES = 0`
  for now (Keccak has no multiplies, so the §8 shared mul-table machinery is
  irrelevant until P2 — where NTT muls may consume the shared 8×8 tables).
- **Archive targets** (§6.1): `make lib-keccak` builds `build/lib/` archives
  from a variant object list — the consumer never does member surgery. Never
  put a `main.o`/driver object into an archive.
- Follow ../c64-lib-contract SPEC for anything this summary elides; where
  SPEC and this brief disagree, SPEC wins — note the divergence in your
  README.

## Implementation guidance (6502 specifics)

- **State layout**: 25 lanes × 8 bytes = 200 B, page-aligned in
  `LIB_MLKEM_BSS`. 64-bit lane ops on a 6502 are byte loops; ρ (rotations by
  0..63) decomposes into byte-shuffles (multiples of 8 are free — pure byte
  permutation) plus a 0-7 bit rotate. Consider combining ρ+π via a
  destination-indexed copy with a 25-entry offset/rotate table in rodata.
- θ needs 5 column-parity lanes (40 B scratch) and rotate-by-1; χ is
  in-place-per-plane with 2 lanes of scratch; ι XORs a 24-entry × 8-byte RC
  table (192 B rodata — or generate on the fly to save ~150 B; measure).
- Straight-line byte code beats clever loops on 6502 more often than not, but
  the 3 KB budget rules — prefer table-driven loops, measure, and record the
  size/speed tradeoff you chose in the README.
- No SEI/banking concerns in this repo: the consumer decides placement
  (c64-https plans to run it from under-KERNAL RAM at $E000; that discipline
  is consumer-side). Your test cfg can place code anywhere convenient.

## Test conventions (ecosystem rules — do not improvise)

- **Harness**: the `c64-test-harness` package (../c64-test-harness). Use the
  shared venv interpreter
  `/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3`
  (system python3 lacks the harness). If the venv lacks it:
  `pip install -e ../c64-test-harness` into that venv. Never run `x64sc`
  directly from tests — always go through the harness.
- **Test pattern**: DMA-driven KATs, modeled on
  ../c64-https/tools/test_x25519.py — build a PRG with the routine + a small
  call stub, launch VICE via the harness, DMA inputs in, `jsr`, DMA the
  digest out, compare in Python against `hashlib`. Read labels from the
  build's labels/map file rather than hardcoding addresses.
- **Naming boundary** (ecosystem-wide, enforced in c64-https by a guard
  test): `test_*.py` = runnable-by-CI logic tests; `rig_*.py` = scripts
  needing real hardware. P1 needs no hardware — everything is VICE.
- **`C64_SKIP_BUILD=1`** convention: test scripts run the build themselves
  unless this env var says to reuse the existing binary. Honor it.
- No REU needed for P1 (don't pass `-reu`; there is nothing to fetch). Note
  this in the README so nobody cargo-cults the c64-https `-reu` default here.

## Explicit non-goals for P1

- **No NTT / ML-KEM code** (P2 — separate handoff after P1's benchmark).
- **No changes to c64-https**, no consumer wiring
  (`tools/integration/build_mlkem.sh`, cfg segments, `USE_MLKEM_HYBRID` are
  Phase 4, consumer-side).
- **No REU claims** and no REU-cached anything.
- **No ML-DSA / Dilithium** — out of scope for the whole roadmap.
- Don't create a GitHub repo or push unless the user asks; local `git init`
  + clean commits are enough for P1.

## Reporting back

When P1 is done, the summary the user needs is: (1) measured cycles per
Keccak-f[1600] permutation, (2) code+rodata+bss byte sizes per the map file,
(3) KAT pass counts per function, (4) any SPEC divergences or surprises.
Those four numbers decide whether P2 proceeds on the current plan (they feed
a 40-70M-cycle total budget for keygen+decaps, of which the Keccak share was
estimated at 9-21M over ~55-60 permutations).
