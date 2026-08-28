# c64-lib-contract alignment for Phase 2 (WP5)

Written 2026-08-28 against `../c64-lib-contract` at head `c771935`
(SPEC version line: **0.13.0, 2026-08-27**). The newest tag is `v0.11.0`;
the changelog runs to 0.13.0. Content was read from the SPEC, not inferred
from tags. `HANDOFF-P2.md` decision 2 and the WP5 section are the brief.

Everything here is documentation and build plumbing. The ML-KEM arithmetic —
including the multiply body §3 recommends — belongs to the NTT implementer.

## 1. SPEC v0.11.0 → v0.13.0: what newly or differently binds this repo

`git diff v0.11.0..HEAD -- SPEC.md` touches exactly four regions: the
version line, §6.3 (one new paragraph block), §8.2 (two new paragraphs), and
§13.x / §12 (network backend ABI and changelog). No other clause changed.
§1, §2, §4, §5, §6.1–6.2, §6.4–6.7, §8.0, §8.1, §8.3, §8.4 are textually
identical to v0.11.0, so the v0.4.0 conformance record in
`adopters.md` stands for them.

| Release | Clause | What changed | Verdict for c64-mlkem |
|---|---|---|---|
| 0.11.1 | §6.3 "Which consequence the rule carries" | A knob the target *cannot* honor MUST be rejected at parse time; one it *can* honor MUST invalidate whatever it reconfigures. Unchanged knobs MUST NOT rebuild; the pinning check MUST assert the artifact flipped. Explicitly names a stale `LIB_SHARED_SQTAB_BASE` as "a wrong address for the §8.1 window". Changelog: "`c64-mlkem` is unassessed against this paragraph." | **Binds — already satisfied.** Commit `79b80e1` implements the invalidation branch (parse-time signature compare, object deletion — not a stamp prerequisite, because GNU Make 3.81's 1-second mtime granularity defeats one) and `make check-staleness` pins both legs. This repo has no member-set axis (`LIB_SRCS` is unconditional), so the rejection branch is n/a — the same shape as c64-x25519. The adopters row still says "unassessed"; the draft in `docs/upstream/01-adopters-row.md` corrects it. **P2 note:** once `LIB_SHARED_SQTAB_BASE` rides `CONTRACT_DEFINES`, it is covered by the same signature automatically (the signature is the flattened `CA65FLAGS|CONTRACT_DEFINES|CONTRACT_ZP_DEFINES` string). `check-staleness` should gain a second knob leg using it — that is a WP4 item, listed in §6 below. |
| 0.12.0 | §13.0 `NET_BACKEND_FAMILIES : absolute`; `net_families.inc` canonical copy | Network backends only. | Does not bind (no §13 domain). |
| 0.12.0 | §13.2 error-code allocation table, advisory codes | Network backends only. | Does not bind. |
| 0.12.0 / 0.12.1 | §13.3 `net_caps.inc`, MTU derivation | Network backends / their consumers only. | Does not bind. |
| 0.13.0 | §13.4 TOD start + verify, `$01 NET_ERR_TIMEBASE_STOPPED` | Network backends only. | Does not bind. |
| 0.13.0 | §8.2 "DMA completion is confirmed … before the next REU register access" + measured failure record | Every REU execute must be followed by a `$DF00` bit-6 confirm and a bracketed post-execute settle (≥ 49 cy at 48 MHz on U64E fw 3.15; open at 64 MHz), on fetch and table-build paths. | **Does not bind: no REU in P2** (HANDOFF-P2 standing invariant; `LIB_MLKEM_REU_BANKS_USED = 0`). Recorded because it is the reason NOT to reach for §8.2 `reu_mul` as the NTT multiply: an adopter taking it today inherits an obligation whose 64 MHz floor is unbracketed and whose canonical fix (c64-x25519#115) is unpublished. |
| 0.13.0 | §13.2 `$8D UCI_ERR_OPEN_REFUSED` | Network. | Does not bind. |
| — | §8.1 sqtab (unchanged text) | Consumer-chosen base, `.ifndef` header, two asserts, `mul_tables_init` canonical init (idempotent), `SHARED_SQTAB_INIT` deferral, import-never-stub, `sqtab_lo/hi` and `LIB_SHARED_SQTAB_BASE` never exported, mandatory `LIB_PRECALC_TABLE "sqtab"` row. | **Binds in P2 once the multiply exists** (decision 2). Shape in §2. |
| — | §8.0 masks (unchanged) | Conditional `LIB_MLKEM_SHARED_PRIMITIVES` / `_CONSUMES`, subset assert, bit constants copied verbatim and `.ifndef`-guarded, never exported. | **Binds in P2** — masks go from `0`/`0` to the forms in §2.5. `LIB_MLKEM_ABI_VERSION` does not move (additive). |
| — | §8.3 ct_mul_8x8 (unchanged) | Byte-identical 59 B body, five-name provider surface, `SHARED_CT_MUL_8X8`, bit `$0004`, brute-check gate. | **Binds only if P2 exports the canonical body.** §3 recommends it does not, so bit `$0004` stays clear in both masks and no §8.3 obligation attaches. |
| — | §8.4 precalc enumeration (unchanged) | Two-form enumeration for every table ≥ 256 B that is REU-resident, hot-loop-read or page-aligned; `precalc_table.inc` byte-for-byte; one including TU. | **Binds in P2.** `src/precalc_table.inc` now present (cmp-identical to the contract root), included from `src/lib_manifest.s` only; rows in §4. |
| — | §6.7 declared non-segment reservations (unchanged) | A library placing an equate-reserved region MUST guard its own image from a TU in no archive: `.import __MAIN_LAST__` / `.assert __MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE, lderror`. Default in exactly one shared include; guard proven to fire in the placing configuration. | **Binds in P2 the moment sqtab exists.** `cfg/mlkem.cfg` already publishes `MAIN` with `define = yes`; the guard goes in `src/main.s` (ships in no archive) and includes the same header. Acceptance: a deliberate overrun (`-D LIB_SHARED_SQTAB_BASE=0x0900`) must fail the link. |
| — | §6.6 footprint pair (unchanged) | Safe-direction per-archive values; release notes state deltas per (profile × variant). | Binds as today; WP4 refreshes from the map. If `mul_tables_init` is placed in a reclaimable init segment, `LIB_MLKEM_COLD_BYTES` becomes non-zero for the first time. |
| — | §6.4 (unchanged) | Manifest gated on the same switches as the code it describes. | **Binds in P2:** the manifest TU must see `SHARED_SQTAB_INIT` (via `CONTRACT_DEFINES`, which already reaches every archive member). The `_D_COLD_SQ`-style footprint correction c64-x25519 carries is optional here because the safe-direction rule permits over-claiming; the masks are not optional. |
| — | §6.5 name surface (unchanged) | Exported symbols, ZP names, segment names, member basenames are contract surface. | Binds; `make check-prefix` is the new mechanical guard (§6). |
| — | §2 ZP registry (unchanged) | `mlkem_` registered (v0.10.7). | Binds; any P2 slot is `mlkem_zp_*` in `src/zp_config.s`. |

Nothing in the diff moves this repo's contract pin in a way that changes
shipped bytes. The pin in `Makefile` and this document is now "v0.13.0 head";
README's divergence table cites v0.11.0 for the P1 record and needs no edit.

## 2. The §8.1 consumption shape this repo adopts

### 2.1 The header — one include, `.ifndef`-guarded

`src/sqtab_base.inc` (new in WP1; fleet-consistent name — chacha and
nist-curves both use `sqtab_base.inc`), included from `src/constants.s` so
every library TU that reads the table sees the same base, and from `src/main.s`
for the §6.7 guard. It is the **only** place the default lives (§6.7 v0.10.2:
"two independent copies of the `.ifndef` default can silently disagree").

```asm
; src/sqtab_base.inc — c64-lib-contract §8.1 placement header (canonical shape).
.ifndef SQTAB_BASE_INC_INCLUDED
SQTAB_BASE_INC_INCLUDED = 1

.ifndef LIB_SHARED_SQTAB_BASE
    LIB_SHARED_SQTAB_BASE = $9000       ; standalone default — see docs/contract-p2-alignment.md §2.2
.endif
sqtab_lo = LIB_SHARED_SQTAB_BASE
sqtab_hi = LIB_SHARED_SQTAB_BASE + $0200

.assert (LIB_SHARED_SQTAB_BASE & $00ff) = 0, error, "sqtab base must be page-aligned"
.assert sqtab_hi = sqtab_lo + $0200,        error, "sqtab_hi must follow sqtab_lo by $0200"

.endif
```

Rules that ride with it:

- `LIB_SHARED_SQTAB_BASE`, `sqtab_lo`, `sqtab_hi` are **never `.export`ed**
  (§8.1 v0.8.5 / v0.9.1). They are source-level equates; a consumer overrides
  with `-D LIB_SHARED_SQTAB_BASE=0x<addr>` in `CONTRACT_DEFINES`, which
  already reaches every archive-member recipe. `make check-prefix` would also
  reject the bare names if they leaked.
- The `-D` value is **`$`-free** (`0xBC00`, never `$BC00`). SPEC §8.1's own
  prose shows a single-quoted `$` form; §2 and this repo's measured make
  behaviour (`$40` → 0, `$$$$40` → the shell PID) make `0x` the only safe
  spelling. Listed as a PATCH-level wording ask in §7.
- Both asserts are plain `error` (not `lderror`): every operand is an
  assemble-time constant, so they fire at ca65 time — the earliest possible.
- The 1,024 B are **not in any segment**: they are outside the 7,680 B window
  by construction (decision 2) and ld65 does not know they exist, which is
  exactly why the §6.7 guard (§2.4) is mandatory.

### 2.2 Standalone default: `$9000`, and why

Constraints, in order:

1. **Page-aligned** (§8.1 assert; CT-strict `abs,x`).
2. **Clear of every sibling default and every consumer-baked value**, so a
   forgotten `-D` in a composed build can never *accidentally* alias a
   sibling's window and pass by luck:
   `$7800` (c64-x25519), `$8000` + `$8400` sqtab2 (c64-ChaCha20-Poly1305),
   `$9C00` (c64-nist-curves), `$B800` (c64-https' x25519 sibling build,
   `build_x25519.sh`), `$BC00` (c64-https' nist-curves build and its
   `TABLES_BSS` anchor — the value c64-https will pass to this library).
3. **RAM under every `$01` banking state.** `$A000-$BFFF` is BASIC ROM in the
   default configuration the standalone test PRG runs in; a default there
   (like c64-https' `$BC00`, which works only because c64-https' boot sets
   `$01 = $36`) would read ROM bytes back from a table the init wrote to RAM
   underneath — silently wrong, never a link error. `$9000-$93FF` is RAM
   always.
4. **Not harness-claimed.** `c64-test-harness` reserves `$C000-$CFFF` as its
   own scratch (bridge stubs at `$C000`/`$C100`, `uci_network` code at
   `$C000`, `memory_policy` "harness-claimed scratch page"). `$C000` was the
   first candidate here and was rejected for this reason; the P2 harness
   config should declare `$9000-$93FF` as a *reserved* region so the policy
   layer knows a non-PRG table lives there.
5. **Headroom for the P2 image.** `MAIN` starts at `$0801`; P1 ends near
   `$1800` with BSS. P2 adds ≥ 6 KB of BSS (dk 2,400 B, ek 1,184 B, ct 1,088 B,
   polyvecs) plus ≤ 6.2 KB code. `$9000` leaves ~34 KB below the window and
   the §6.7 guard turns any overrun into a link error.
6. **Not `$9C00`-adjacent by choice**: `$9800` would also satisfy 1–5 but
   abuts nist-curves' window; non-adjacency makes a misconfiguration obvious
   in a map file rather than one page off.

### 2.3 `SHARED_SQTAB_INIT` — exact semantics, and import-never-stub

The library carries one TU (suggested `src/mlkem_sqtab.s`, member
`mlkem_sqtab.o`, in every archive whose member set reads the table) with this
gate:

```asm
.ifndef SHARED_SQTAB_INIT
; OWNER build (standalone default): this library provides the canonical init.
.export mul_tables_init
.segment "LIB_MLKEM_CODE"          ; or a future LIB_MLKEM_INIT_CODE (§6.6 COLD)
.proc mul_tables_init
        ; fill sqtab_lo/hi[0..510] with floor(n^2/4) by the recurrence
        ; (i+1)^2 = i^2 + 2i + 1; idempotent; no state beyond the table bytes.
        ...
        rts
.endproc
.else
; DEFERRING build: a sibling (or the consumer's own module, §8.0 APP_OWNED)
; owns the table. Import the canonical entry; NEVER export a stub under the
; canonical name (§8.1 v0.9.0: two same-named inits in one composed link is
; the duplicate-identifier failure the switch exists to remove).
.import mul_tables_init
.endif
```

- `mul_tables_init` is the **only** unprefixed symbol this adds, and only in
  owner builds. It is a §8.1 canonical name and is on `check-prefix`'s
  allow-list for exactly that reason. This library has no historical
  `sqtab_init` alias and MUST NOT invent one — that would be a second
  unprefixed export with no clause behind it.
- Idempotency is normative: calling it twice yields the same bytes and no
  other side effect. Table bytes only — no ZP, no flags.
- The library's own callers (`mlkem_keygen` etc.) do **not** call
  `mul_tables_init` internally. Boot-time init is the consumer's job in a
  composed link (§8.0 deferring-consumer row: "boot MUST initialize the
  primitive before first use"); in the standalone PRG `src/main.s` calls it
  once at start. Baking a call into the library would make a deferring build
  call a sibling's init at a time the consumer did not choose.
- In deferral builds the init body and any private scratch it uses are
  gated **out** (§6.4 half two), so the archive shrinks; the safe-direction
  footprint equates may stay put.
- The switch is the consumer's, via `CONTRACT_DEFINES="-D SHARED_SQTAB_INIT"`.
  c64-https already passes it to nist-curves and x25519 and owns the table
  itself (`src/crypto/shared/mul_tables.s`), so the composed P4 build defers.
  §6.3: the switch reaches the manifest TU and is in the invalidation
  signature, so flipping it rebuilds the masks — required by §6.4.

### 2.4 The §6.7 image guard

`src/main.s` (ships in no archive; `cfg/mlkem.cfg` already has
`MAIN: … define = yes`):

```asm
.include "sqtab_base.inc"          ; same default as the placing TUs, source-level
.import __MAIN_LAST__              ; hard import — NOT weak (§6.7 constraint 2)
.assert __MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE, lderror, "image overruns the sqtab window (LIB_SHARED_SQTAB_BASE)"
```

`lderror`, because `__MAIN_LAST__` is a link-time symbol. Acceptance test
(§6.7 constraint 3) belongs in `make check-sqtab-guard` in WP4: build once
with `CONTRACT_DEFINES="-D LIB_SHARED_SQTAB_BASE=0x0900"` and require the
link to **fail**; build normally and require it to pass. Consumers are told
in `mlkem.inc` to mirror the assert against their own `__<AREA>_LAST__`.

### 2.5 §8.0 masks — the exact construction for `src/lib_manifest.s`

Bit constants copied verbatim, `.ifndef`-guarded, **never exported** (§8.0
definition-site rule; the x25519+chacha composed link measured the failure):

```asm
.ifndef LIB_SHARED_PRIMITIVES_SQTAB
  LIB_SHARED_PRIMITIVES_SQTAB      = $0001
.endif
.ifndef LIB_SHARED_PRIMITIVES_REU_MUL
  LIB_SHARED_PRIMITIVES_REU_MUL    = $0002
.endif
.ifndef LIB_SHARED_PRIMITIVES_CT_MUL_8X8
  LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004
.endif
```

Ownership mask — required conditional form (§8.0 "Mask construction"), one
block per primitive this library consumes. With §3's recommendation, that is
**sqtab only**:

```asm
.ifdef SHARED_SQTAB_INIT
  _OWN_SQTAB = 0
.else
  _OWN_SQTAB = LIB_SHARED_PRIMITIVES_SQTAB
.endif
LIB_MLKEM_SHARED_PRIMITIVES = _OWN_SQTAB
```

Consumes mask — set iff the build reads the primitive at all; a deferral
switch does NOT clear it. There is no profile gate in this library (one
member set, one profile), so it is unconditional:

```asm
LIB_MLKEM_SHARED_CONSUMES = LIB_SHARED_PRIMITIVES_SQTAB
.assert (LIB_MLKEM_SHARED_PRIMITIVES & ~LIB_MLKEM_SHARED_CONSUMES) = 0, error, "a build cannot own a primitive it does not consume"
```

Resulting states: standalone `$0001 / $0001` (owner); c64-https composed
`$0000 / $0001` (deferring consumer — exactly one owner elsewhere in the
link, which c64-https' `lib_contract_asserts.s` coverage assert checks).
`mlkem-keccak.a` (FIPS 202 only) must **not** carry these bits — its member
set never reads the table — so either the Keccak-only archive gets its own
manifest configuration (a `-D MLKEM_KECCAK_ONLY` reaching `lib_manifest.o`
for that target, the nist-curves per-variant shape) or the masks are gated
on a define that `lib-keccak` sets. §6.4 forbids one manifest describing two
member sets; WP4 owns the choice, and `check-archives` should pin it.

**If** the NTT implementer overrides §3 and ships the §8.3 body, add the
`_OWN_CT_MUL` block, OR `LIB_SHARED_PRIMITIVES_CT_MUL_8X8` into *both* masks,
and take the whole provider surface (§3.3).

### 2.6 Where sqtab sits in the P4 consumer (for the record, not for this repo)

c64-https bakes `LIB_SHARED_SQTAB_BASE = 0xBC00` (`TABLES_BSS` at `$BA00`,
lo at `+$200`) and passes `-D SHARED_SQTAB_INIT` to every library because it
owns `mul_tables_init` in `src/crypto/shared/mul_tables.s`. Its
`build_x25519.sh` bakes `$B800` for the x25519 sibling — a second value in
the same map. Whichever value P4 passes, this library only needs it to be
page-aligned and `$`-free. **Finding worth flagging:** the 7,680 B
`CRYPTO_OVERLAY` slot decision 1 targets is not empty in the current UCI
cfg — `TLS_DEFRAME_CODE`, `CERT_BUF_BSS` (2 KB), `VIEWER_CODE`,
`X509_NAME_CODE`, `HTTPS_TARGET_RODATA` ride it, and the cfg's own comment
says "~2.5 KB free in every default UCI profile". The window is 7,680 B
nominal; the *available* window is a P4 question the user should have in
front of them before WP4's fit verdict is read as final.

## 3. §8.3 recommendation: private multiply, not the canonical body

**Recommendation: consume §8.1 `sqtab` directly from a private,
`mlkem_`-prefixed, mod-3329-shaped multiply, and do not take §8.3.** Bit
`$0004` stays clear in both masks; no `ct_mul_8x8`, `mul_8x8`,
`smc_sum_a_imm`, `smc_diff_a_imm`, `poly_prod_lo`, `poly_prod_hi` export ever
leaves this repo.

### 3.1 Cycles per butterfly

The butterfly multiply is 12 × 12 → 24 bits (coefficient in `[0, q)`,
zeta in `[0, q)`), then reduce mod 3329. The canonical body is 8 × 8 → 16 with
`a` SMC-baked and `b` in `Y`, so a 12-bit product needs either the 8+4 split
(4 partials, one of which is a full 8 × 8 with the page-carry dispatch) or the
6+6 split (4 partials, all with table index ≤ 126, no page dispatch). Through
`jsr ct_mul_8x8` each partial costs ~50 cycles of body + 12 of call/return +
the two-byte re-bake of `a` for every change of the baked operand (zeta's low
and high parts alternate between partials, so two re-bakes per product) —
roughly 270–300 cycles before the shifts, adds and reduction, ≈ 380–420 all
in. A private inline 6+6 quarter-square body (`lda sqtab_lo,x / sbc sqtab_lo,y`
pairs with no page-carry logic, accumulating directly into the 24-bit
product) is ≈ 160–200 cycles plus the same reduction. Multiply count per
keygen+decaps is of the order of 40–50 k (6 NTTs and 9 basemuls in keygen,
comparable in the decaps re-encrypt, ≈ 900 multiplies per NTT), so the
per-multiply delta is ≈ 5–8 M cycles against a non-Keccak budget of 13–45 M.
That is the difference between the low and the high end of the band, and it
is the one lever P2 has that does not touch Keccak.

### 3.2 The 7,680 B window

Size does not decide it: the canonical body is 59 B + 4 B scratch, a private
inline body is perhaps 120–160 B including the reduction, and the standalone
`mul_tables_init` (~150 B, gated out in every deferring build) is the same
under both. Nothing here moves the fit verdict; only the cycle argument does.

### 3.3 Constant-time obligations — equal under both, on one condition

The NTT's secret operand is the coefficient (`s`, `e`, `r`, the decaps
re-encrypt), never the zeta. A private body is CT-equivalent to the canonical
one iff: no branch on the coefficient; every table it indexes with a
coefficient-derived byte is page-aligned (sqtab already asserts this; any
private reduction table must carry the same `.align 256` + `.assert`, the
`keccak_state` pattern); and the final conditional subtraction is a mask, not
a `bcc`. HANDOFF-P2 decision 2 states exactly this condition. What the
canonical body buys is a *mechanical* CT proof shared with three adopters
(`tools/ct_mul_brute_check.py`); the private body must supply its own —
WP1's red tests should include a cycle-count check that the multiply's cost
is identical across a set of adversarial operand pairs (0, 1, q−1, and the
page-boundary sums 255/256), which VICE's determinism makes exact.

### 3.4 The §8.3 provider/deferral obligations it avoids

Taking §8.3 means, per v0.10.6: export **five** unprefixed names (six with
the `mul_8x8` alias), including `poly_prod_lo`/`poly_prod_hi` — under
chacha's registered `poly_` prefix, tolerated only because they are
canonical; stay **byte-identical** to the chacha body under a cross-adopter
ratchet, so the mod-3329 shaping this library actually wants cannot live in
that routine at all; carry `SHARED_CT_MUL_8X8` with import-never-stub; and
mint a fourth §8.3 provider in a fleet that has three and one owner
(c64-https) that already defers all of them. None of that helps a 12-bit
multiply. The rule that keeps this clean: the private routine is named
`mlkem_*` (e.g. `mlkem_fqmul`), is not exported unless a test hook needs it,
and never uses a canonical name — a "mod-3329-flavoured `ct_mul_8x8`" would
be non-conformant on its face.

### 3.5 If the implementer overrides this

Then take §8.3 whole: copy the 59-byte body from
`c64-ChaCha20-Poly1305/src/lib/poly1305_lib.s` byte-for-byte, export all
five (six) names in owner builds, gate on `SHARED_CT_MUL_8X8` with imports
in the deferring branch, set bit `$0004` conditionally in both masks, run the
contract's `tools/ct_mul_brute_check.py` before merge, and add the six names
to `check-prefix`'s canonical list — they are already there, commented as
"only once the library is a §8.x provider".

## 4. §8.0 / §8.4 precalc-table rows P2 will need

The floor: ≥ 256 B **and** (REU-resident, or hot-loop-read, or page-aligned
for fetch alignment). Every candidate a FIPS 203 implementation on this
target might tabulate, classified:

| Candidate | Size | Region | Floor | Row? | Classification / rationale |
|---|---:|---|---|---|---|
| `sqtab` (§8.1) | 1,024 B | RAM (equate-placed, outside every segment) | ≥256, page-aligned, hot-loop-read | **YES — mandatory** (§8.1 "MUST emit"), name normative, `PRECALC_SHARED_YES` | The shared quarter-square table. |
| `mlkem_zetas` — the 128 NTT twiddles ζ^BitRev7(i) in traversal order | 256 B (128 × 16-bit; whether stored interleaved or as lo/hi planes it is one logical table) | RODATA | exactly 256 B, hot-loop-read (one per butterfly group) | **YES** (at the floor) | Algorithm-specific, `PRECALC_SHARED_NO`: q = 3329 and ζ = 17 are ML-KEM's; ML-DSA (q = 8380417) and any other NTT would not converge on it. Generated by `make tables` from `mlkem_ref.ZETAS`. |
| `mlkem_zetas_basemul` — ζ^(2·BitRev7(i)+1) for BaseCaseMultiply | 256 B if stored separately | RODATA | 256 B, hot-loop-read | **YES if separate**; NO if derived from `mlkem_zetas[64..127]` and their negations at run time (the Kyber-reference trick, 0 B) | Algorithm-specific, `PRECALC_SHARED_NO`. Implementer's call; the doc row appears only if the bytes do. |
| Montgomery / Barrett reduction aid keyed on a product byte | 256–512 B if used | RODATA | ≥256, hot-loop-read, **secret-indexed → MUST be page-aligned** | **YES if used** | Algorithm-specific (`q`-specific), `PRECALC_SHARED_NO`. Note the CT obligation in §3.3. |
| CBD_η=2 byte → coefficient-pair lookup | 256 B (one packed byte per input byte) or 512 B (two) | RODATA | ≥256, hot-loop-read (once per PRF byte) | **YES if used** | Algorithm-specific, `PRECALC_SHARED_NO` — a popcount-difference table shaped for η = 2 is not a general popcount table; no sibling has one. |
| Decompress_10 lookup (`round(q·y/2^10)`) | 2,048 B | RODATA | ≥256, hot-loop-read | would be YES — **but do not build it**: 2 KB of the 6.2 KB window for an operation that is one multiply-and-shift | — |
| Decompress_4 lookup | 32 B (16 × 16-bit) | RODATA | < 256 | NO (exempt) | — |
| Compress_1/4/10 constants, Barrett constants | ≤ 8 B | RODATA | < 256 | NO | — |
| Bit-reversal table | 128 B | RODATA | < 256 | NO — and FIPS 203's in-place NTT needs none | — |
| Keccak tables (P1) | 192 / 25 × 4 / 16 B | RODATA | < 256 | NO (unchanged, see `docs/precalc-tables.md`) | — |

Placement rule for the rows that ship: each `LIB_PRECALC_TABLE` invocation is
added to `src/lib_manifest.s` in the same commit as the table and the
`docs/precalc-tables.md` row (the intake-reviewer-MUST rule blocks any
asymmetry). The `"sqtab"` row is emitted whenever the consumes bit is set —
it is consumption surface, present in deferring builds too — and therefore
must be absent from the FIPS-202-only archive (§2.5).

## 5. Bare `LIB_PRECALC_*` forms — the one deliberate deviation

`precalc_table.inc` emits the deprecated bare `LIB_PRECALC_<name>_*` triple
unless `LIB_NO_BARE_EXPORTS` is defined, and its comment says standalone
adopters "keep the bare exports by default". This library ships **no bare
export of any kind** (the §1 zero-consumer carve-out it was first to take,
and CLAUDE.md's standing invariant that the export surface is byte-identical
with and without `-D LIB_NO_BARE_EXPORTS=1`). `src/lib_manifest.s` therefore
defines `LIB_NO_BARE_EXPORTS = 1` (`.ifndef`-guarded) before the include, so
only the `LIB_MLKEM_PRECALC_*` family is ever emitted, and `check-prefix`
fails the build if a bare form appears.

This is conformant — §8.4 has no `MUST emit` for the bare forms; they are
gated on a define the adopter controls — but the SPEC has no written
zero-consumer carve-out for §8.4 the way §1 and §6.5 do. §1's reasoning
applies verbatim (a library nobody links has no single-library consumer to
protect, and the bare triple is precisely the #43 collision class). Raising
that as a `SHOULD NOT` in §8.4 would be **normative (MINOR)** and is the
user's call; the draft is split out in `docs/upstream/` per the #123 lesson.

## 6. Build plumbing landed in WP5, and what WP1/WP4 still owe

Landed here:

- `src/precalc_table.inc` — cmp-identical to the contract root
  (`sha256 feb98890…`); `.include`d from `src/lib_manifest.s` only, with the
  P2 invocations as a commented placeholder. `od65 --dump-exports` on
  `mlkem_lib_manifest.o` is unchanged before/after (6 exports).
- `make check-prefix` (`tools/check_prefix.sh`): extracts every member of
  every `build/lib/*.a` (od65 cannot read archives), fails on any export not
  under `mlkem_` / `LIB_MLKEM_` / `keccak_` and not one of the seven exact
  §8 canonical names; fails loudly on an empty extraction; negative leg
  verified against a probe archive exporting `poly_ntt` and
  `LIB_PRECALC_x_SIZE`. Wired into `make test`.
- `docs/precalc-tables.md` "P2 (pending)" section.
- `docs/upstream/` drafts (not pushed).

Owed by WP1 (NTT implementer, with this document as the shape):
`src/sqtab_base.inc`, the `mul_tables_init` TU, the masks in
`src/lib_manifest.s`, the `LIB_PRECALC_TABLE` rows for `sqtab` and
`mlkem_zetas`, the §6.7 guard in `src/main.s`, and `main.s` calling
`mul_tables_init` once at start.

Owed by WP4 — **all landed at v0.5.0**: `check-staleness` knob legs on
`LIB_SHARED_SQTAB_BASE` and on the Keccak-only manifest (both legs each);
`check-sqtab-guard` (deliberate overrun at `0x0900` fails the link on the
guard's message); the `mlkem-keccak.a` manifest configuration (§2.5, taken
as a separate manifest object under `-D MLKEM_KECCAK_ONLY=1`, rejected in
`CONTRACT_DEFINES` at parse time); footprint equates 6912 / 1536 refreshed
from a probe link of the shipped archive; README divergence rows 7–14.

## 7. Items that need the user (normative or cross-repo)

1. **§8.4 zero-consumer carve-out for bare `LIB_PRECALC_*`** — a normative
   `SHOULD NOT` mirroring §1's. MINOR. Draft: `docs/upstream/03-normative-ask-precalc-bare.md`.
   This repo does not depend on it landing; it only makes the local
   `LIB_NO_BARE_EXPORTS = 1` a documented practice rather than a private one.
2. **§8.1 `-D` quoting wording** — the clause shows `-D 'LIB_SHARED_SQTAB_BASE=$<addr>'`
   while §2 and every adopter's Makefile say `$`-free. PATCH-level
   clarification; same draft file, separate section, so it can be split
   again if the reviewer wants.
3. **c64-https `CRYPTO_OVERLAY` actual free space** (§2.6) — not a contract
   matter, but decision 1's premise. Consumer-side, P4.
4. **`mlkem-keccak.a` manifest split** — if WP4 chooses a define reaching
   `lib_manifest.o` for the Keccak-only archive, that is a new §6.2 knob and
   §6.3 makes it either rejected or invalidating; the adopters row must say
   which. Not a SPEC change, but a row entry the user signs off on.
