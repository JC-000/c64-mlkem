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
