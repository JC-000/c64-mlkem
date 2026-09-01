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

## SESSION HANDOFF — 2026-09-01 (supervising session restart)

State of the world for the next session. Verified, not assumed.

### Done and public
- **v0.5.0 tagged, pushed, released** (P2 complete); releases backfilled for
  v0.2.0–v0.4.0, "Latest" badge on v0.5.0.
- **Lane B done.** c64-lib-contract intake: #156 (adopters row) **merged**,
  #157 (§8.1 `$`-free, → v0.14.2) **merged**, #158 (§8.4 bare-precalc
  carve-out, → v0.15.0) **merged**. `docs/upstream/README.md` records them.
- **Lane A done, awaiting merge.** `p3/optimisation` branch, PR
  https://github.com/JC-000/c64-mlkem/pull/2 — **OPEN, user has not merged**.
  v0.5.1: Keccak-f[1600] **339,688** (link-invariant), KeyGen 21,801,702,
  Encaps 24,880,455, Decaps 29,597,879, keygen+decaps **51,399,581** (−17%),
  7,208 B shipped (472 B under the window). Supervisor-verified on a clean
  rebuild: `make test` OK, bench reproduces to the cycle, 45/45 mutants.

### Immediately actionable, in order
1. **PR #2**: the user merges (or requests changes). After merge: tag
   `v0.5.1` (annotated, style of `git tag -n` v0.5.0), push tag, `gh release
   create` from the tag message, `--latest`.
2. **Contract drift**: SPEC at origin is **0.17.1 (2026-08-31)** — FOUR
   releases past the 0.13.0 the P2 conformance work targeted (0.14.x–0.17.x
   landed in three days; #157/#158 are inside that run). Nobody has assessed
   0.15.0→0.17.1 against this repo. Diff §12 changelog from 0.14.1 up and
   re-run the WP5-style clause-verdict pass (`docs/contract-p2-alignment.md`
   is the model). Watch specifically for anything touching §8.1/§8.4 (our
   PRs may have been amended in later releases) and any new §14.
3. **Adopters row** upstream cites v0.5.0 numbers; after v0.5.1 tags, a
   row-refresh PR (PATCH, row-only) with the new RESIDENT (7424) and cycles.

### Deferred by explicit user decision (do NOT start unprompted)
- **Fit**: c64-https `CRYPTO_OVERLAY` has only ~2.5 KB actually free vs our
  7,208 B. Split-vs-replan is a joint P4 decision with c64-https.
- **Hardware validation** (`rig_*.py`, none exist yet): U64E is tied up with
  firmware testing. When free: cycle counts should reproduce at 1 MHz; check
  turbo behaviour even though this library has no REU/device I/O.

### Repo mechanics the next session must know
- **PRs are now the convention for c64-mlkem** (user asked for a PR record;
  P1/P2 went direct-to-main, P3 onward does not).
- 11 git worktrees under `.claude/worktrees/` — all merged, safe to
  `git worktree remove` + prune; user was told, hasn't asked.
- The P2/P3 protocol that the user explicitly wants kept (see
  `HANDOFF-P2.md`): red tests by a separate agent from the spec; implementer
  may not edit tests; adversarial mutation gate (45 mutants, `make
  test-mutants`) before merge; `wp2-rodata-align-reverted` must be re-picked
  after ANY code-size change (layout-dependent by construction, documented in
  tools/mutants/README.md); NEVER run two VICE-driven make targets
  concurrently; oracle red ⇒ everything downstream meaningless.
- Session memory (decisions + open items) also lives in the Claude memory
  dir: `p2-plan-decisions.md` there mirrors this section.
