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
