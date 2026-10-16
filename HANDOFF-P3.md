# c64-mlkem — P3 handoff brief (bounded optimisation + upstream intake)

Written 2026-08-29 by the P3 supervising session. `HANDOFF-P2.md` and
`CLAUDE.md` remain authoritative for everything they cover; this brief only
adds P3's scope and rules.

## Scope (user decision, 2026-08-29)

P3 is two independent lanes. **Fit against the consumer's real overlay window
is explicitly deferred** — do not split images, do not spend bytes chasing the
~2.5 KB figure. Hardware validation waits for the U64E.

- **Lane A — cycle reduction, bounded.** Measured levers only, each landed as
  its own commit with before/after numbers from the calibrated instrument.
  Hard limits: total library code+rodata stays **≤ 7,680 B** (`make
  check-manifest`); every suite and all 45 mutants stay green; constant-time
  pins stay identical across inputs; no new exports (ABI 2 unchanged).
- **Lane B — c64-lib-contract intake.** Open the PRs drafted in
  `docs/upstream/` against `../c64-lib-contract`, split exactly as the README
  there prescribes. Do not merge them.

## Lane A — known levers, in the order to try

| Lever | Where | Expected | Cost |
|---|---|---|---|
| Fold the 128⁻¹ (3303) scaling into the last INTT layer | `ntt.s` | −45k × 5 INTT ≈ −0.2M | ~0 B |
| Page-align the Keccak RC table | `keccak.s` | build-invariant headline; tens of cycles × 88 | ≤ 255 B BSS/rodata pad — measure |
| θ: unroll the `D` step per column (drop per-byte mod-40 indexing) | `keccak.s` | θ is 36% of 456k; a 10–15% θ cut ≈ −50k × 88 ≈ −4M | bytes — measure |
| Inline the block-constant multiply into the butterflies | `ntt.s` | −21k/NTT × 11 ≈ −0.25M | ~400 B |
| Per-block nibble tables for NTT layers 0–3 | `ntt.s` | −60k/NTT × 11 ≈ −0.7M | tables — measure |

Keccak is 65% of keygen+decaps (88 permutations), so θ is the only lever
worth more than ~1%; do it after the two free ones. Record any lever that was
tried and rejected, with its numbers, in the README "Where the cycles go".

## Lane A rules (the P2 protocol, unchanged)

- The read-only suites (`tools/test_*.py`, `tools/mlkem_ref.py`) define
  correctness. They are not edited for an optimisation.
- After each lever: `make test` green, `make test-mutants` 45/45 killed
  (patches that no longer apply are regenerated for the SAME fault — a fault
  that can no longer exist is replaced by its nearest equivalent and the
  README table updated), `make bench bench-kem` numbers recorded.
- Never run two VICE-driven targets concurrently.
- Work on a branch; the supervisor opens the PR.

## Reporting back

Lane A: per-lever before/after cycles and bytes, the final KeyGen / Encaps /
Decaps numbers, footprint vs 7,680 B, and the list of levers rejected. Lane B:
PR URLs, their classification (PATCH/MINOR) and `make verify` status.

---

---

## SESSION HANDOFF — 2026-09-24 (supersedes the 2026-09-01 handoff)

State of the world for the next session. Verified at `main` a8b27f7, not
assumed.

### Done and public
- **v0.5.1 tagged and released** (Latest). The tag sits on the PR #2 merge
  e40c49c.
- **PR #5, hardware validation (merged).** `make rig` / `rig-full` /
  `rig-turbo` (`tools/rig_*.py`) run on the U64E (fw 3.15; `U64_HOST`
  defaults to 10.43.23.81).
  - At 1 MHz the cycle counts **equal VICE exactly**: Keccak 339,688; KeyGen
    21,801,702; Encaps 24,880,455; Decaps 29,597,879.
  - Decaps is **constant-time on hardware**: a valid ct and ct with c1 or c2
    tampered all give 29,597,879.
  - At 48 MHz turbo every output is correct. The CIA ticks once per 47 CPU
    cycles, so the speed-up is 47×; the rigs assert no counts at turbo.
  - New trap, recorded in CLAUDE.md: host reads of C64 memory steal CPU
    cycles on the U64E (about 10 + 1.15 cycles per byte for each
    `read_bytes`).
  - The rigs are not part of `make test`.
- **The mutation gate is 48/48** (WP1 15, WP2 13, WP3 18, P1 2). It gains the
  first Keccak/sponge mutants and `wp3-cmp-mismatch-timing`, a pure timing
  leak that only T1 kills.
- **PR #6: the contract target is now SPEC 1.2.3** (on main, untagged; latest
  tag v1.2.2).
  - `check-manifest` uses the §5 placed span: 7,208 / 1,947, declared 7424 /
    2048.
  - `check-precalc` is pinned to tag v1.2.2 via `CONTRACT_PRECALC_REF`.
  - Retired-clause citations are gone.
  - Shipped artifacts are unchanged.
- **PR #7: header dependencies now come from ca65 `--create-full-dep`**, with
  `.DELETE_ON_ERROR` and a `deps1` tag in `CONFIG_SIG`. Before this, a value
  edit to `constants.s` shipped a stale PRG. It is guarded by `check-deps`,
  `check-deps-rebuild` and `check-deps-selftest` (about 40 s, no VICE).
  - The first `make` in any tree built before #7 rebuilds everything once;
    that is expected.
- **Repo is clean:** only `main`, no worktrees, no open PRs of ours.

### Open, not started
1. **Adopters row upstream** (c64-lib-contract `adopters.md`) still cites
   v0.5.0. A row-only PR with v0.5.1 numbers is needed: RESIDENT 7424;
   placed span 7,208; contiguous 7,231; the cycles above; 48/48; hardware-
   validated on the U64E. That is an outward-facing PR, so confirm with the
   user first.
2. **When contract 1.2.3 (or later) is tagged,** move `CONTRACT_PRECALC_REF`
   deliberately. Do not track the contract's `main`.

### Deferred by explicit user decision (do NOT start unprompted)
- **Fit (P4):** the c64-https `CRYPTO_OVERLAY` has only ~2.5 KB actually free.
  A consumer needs **7,231 B contiguous** (7,208 plus a 23 B CODE→RODATA gap;
  ≤ 63 B only while RODATA directly follows CODE at `align = $40`).
  Split-vs-replan is a joint decision with c64-https.

### How the user wants work run
- **PRs for everything.** The user merges. After a merge, clean up the
  worktree and branch (local and origin).
- **Protocol:**
  - A red author (a fresh agent) writes failing checks first.
  - The implementer may not edit them.
  - A fresh-context adversarial reviewer mutates both the fix and the checks,
    and runs `make test` plus `make test-mutants`.
  - Surviving checker mutants go back to the red author.
  - The PR opens only after an accept verdict.
- **Local model:** use the local model (Qwen3.6 on the lab box) for drafting,
  always with a Claude reviewer.
  - Call it as `LA_KEY_ID=kcb3b03f1
    /Users/someone/Documents/ebullientprism/tools/local-agent/invoke.sh`.
    The key is this repo's own, read from the Keychain; never echo it.
  - Set `LA_MAX_TOKENS` ≥ 16384, because it is a reasoning model.
  - There is no concurrency cap (the server queues); set a generous
    `LA_TIMEOUT`. Haiku is the fallback.
  - Qwen reliably gets mechanics right, but loses or **invents** facts when it
    adapts text or lacks context, and never says so. Review every line.
- **Parallel VICE is fine:** up to 10 instances via c64-test-harness 0.12.4.
  Never run two `make`s in one build tree.
- **U64E:** available, and all access goes through the harness device queue.
- **Supervising:** check long-running agents actively; do not wait on
  notifications. Two agents once sat idle for ~5 h after their background work
  finished. Agent message timestamps are UTC.

Session memory (decisions and open items) is mirrored in the Claude memory dir:
`p2-plan-decisions.md` and `local-model-qwen.md`.

## SESSION HANDOFF — 2026-10-16 (v0.6.0 state; read with the 2026-09-24 one)

### What PR #10 (v0.6.0) contains
- **`mlkem_decaps_seed`**: Decaps from the 64 B KeyGen seed `d‖z`, no
  `dk`/`ek` buffer. 50,794,288 cycles (keygen + `mlkem_decaps` on the same
  inputs: 51,057,588). +333 B code: 329 B for the entry and its two element
  helpers (`el_habs`, `el_su`), plus 4 B (`jsr kpke_keygen_core` + `rts`) in
  `kpke_keygen`. +0 BSS. Resident 7,541 B, declared 7680; headroom in the
  7,680 B window is 76–139 B, depending on the consumer's CODE→RODATA gap.
- **`LIB_MLKEM_POLY_BSS`**: the eight K-PKE polynomials (4,096 B, `bss`,
  `align = $100`) are a fourth segment, required whenever `mlkem_kem.o` is
  linked, so c64-https can place them under I/O at `$D000`. `LIB_MLKEM_BSS`
  keeps 2,545 B in the standard link (2,312–3,197 B across member
  orderings). README divergence 15.
- **ABI 2 → 3.** The export surface is additive, but a v0.5.1-conforming cfg
  that declares three segments now fails to link (`Missing memory area
  assignment for segment 'LIB_MLKEM_POLY_BSS'`). SPEC §1 counts "a changed
  memory model" and §7 moves the counter "when a consumer conforming to the
  previously documented contract can be broken by the change" (read against
  contract main, 1.2.3; the clause is not "subject to the deprecation
  cycle"). Consumer fix: add the `LIB_MLKEM_POLY_BSS` line to its cfg; a
  Keccak-only consumer omits it or marks it `optional = yes`. Gate by
  equality (`.assert LIB_MLKEM_ABI_VERSION = 3`).
- `make check-version` (in `make test`) pins the four version equates in both
  archives, the three-segment-fails / four-segment-links legs, and proves it
  fires on a wrong ABI. `EXPECTED_ABI` in the Makefile moves only per SPEC §7.
- Seven new `seed-*` mutants; the gate is **55/55**.

### The measured cost to state plainly
A client that keeps only the seed pays KeyGen + `mlkem_decaps_seed` =
21,803,250 + 50,794,288 = **72,597,538 cycles**, **above** the roadmap's
40–70M budget (`make bench-kem` prints the line). Holding `dk` it pays
51,057,588: the seed path costs +21,539,950 cycles (about 21 s at 1.023 MHz)
per handshake. What it saves is holding `dk` between KeyGen and Decaps;
`mlkem_keygen` still writes `dk` through `mlkem_arg_dk`, so KeyGen still needs a
transient 2,400 B buffer. That matters for the c64-https overlay plan.

### Review history
The suite landed red first (20954dd), then the implementation (f55d9bc), by
the same agent. In-PR adversarial rounds: the first two predate 150f421
(e75ea3a, and the layout review at 556bf7b, 2026-10-07); the third round's
fixes are 150f421. At 150f421 the full gate ran 55/55 killed, and an
independent fresh-context review (2026-10-16) added 9 throwaway mutants of
`mlkem_decaps_seed`, all killed (not in the repo). A further review round
(this session) led to the pre-release fixes: ABI 3, divergence 15, the
handshake cost, `check-version`, the image-guard form and doc corrections.
Those fix commits go up as part of PR #10 before the merge.

### Open items
- **No hardware rig covers `mlkem_decaps_seed`** (`rig_*.py` predate it).
  VICE only.
- **Constant-time is measured on one key only** (the cycle pins in
  `test_decaps_seed.py`), not across keys.
- **`LIB_MLKEM_POLY_BSS` at `$D000` is verified at link only**, never run
  (the `$01` banking around every ML-KEM call is the consumer's).
- **Upstream `c64-lib-contract` `ADOPTERS.md` (line 32) still says
  `LIB_MLKEM_ABI_VERSION = 2`** and needs updating there. Do not touch the
  contract repo from here. The adopters row also still cites v0.5.0; the
  2026-09-24 handoff lists that as "Open, not started" (outward-facing PR,
  confirm with the user first).
- Still deferred by explicit user decision: the c64-https overlay fit (P4).

### Next step
Merge PR #10, tag v0.6.0 on the merge, then c64-https P4 wiring (add the
`LIB_MLKEM_POLY_BSS` line, re-plan the overlay).

### How work is run
The 2026-09-24 handoff's "How the user wants work run" still applies (PRs for
everything, user merges, red author first, fresh adversarial reviewer). This
session's split: Sonnet implements and runs the tests; Opus does a fresh
adversarial review each round.
