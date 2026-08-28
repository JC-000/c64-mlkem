# PR draft — c64-lib-contract (registry/status only, PATCH)

**Title:** adopters: c64-mlkem v0.5.0 — §6.3 invalidation branch implemented; Phase 2 §8.1 consumption, §8.4 rows, per-archive §6.4 manifest

**Labels:** adopters, patch

## Summary

Status-row update for `c64-mlkem`. **Zero normative change** — no SPEC.md
edit, no RFC-2119 keyword added or altered. Row text is in
`docs/upstream/01-adopters-row.md` of the c64-mlkem repo (this PR applies it
verbatim to `adopters.md`).

Three things the row now records:

1. **§6.3 (v0.11.1) is implemented and pinned** — the 0.11.1 changelog
   entry says "`c64-mlkem` is unassessed against this paragraph"; that was
   true on 2026-08-23 and is not now. c64-mlkem `79b80e1` lands the
   invalidation branch with two properties worth the fleet's attention,
   both measured on the host toolchain (GNU Make 3.81): the signature
   compare runs at **parse time** (a recipe-time delete leaves make
   convinced the PRG exists and the link is skipped — no output file), and
   invalidation **deletes** objects rather than depending on a stamp file
   (1-second mtime granularity makes a same-second stamp compare
   not-newer, so nothing rebuilds). `make check-staleness` asserts both
   §6.3 legs on linked PRGs. No member-set axis exists, so the rejection
   branch is n/a — the c64-x25519 shape.

2. **Phase 2 (v0.5.0) makes the library a §8.1 `sqtab` consumer.**
   Canonical header shape, both asserts, `mul_tables_init` in owner builds
   and `.import` under `SHARED_SQTAB_INIT`, §6.7 guard proven to fire by
   `make check-sqtab-guard`, conditional masks measured with `od65`
   (`$0001/$0001` standalone, `$0000/$0001` deferring, `$0000/$0000` for the
   Keccak-only archive). **§8.3 is deliberately not taken** and **§8.2 is
   not applicable** (no REU); the row says so, with the reasoning linked, so
   a reviewer does not read a clear `$0004` as an omission.

3. **§8.4 rows shipped**: `"sqtab"` (1024/RAM/YES), `"mlkem_zetas"`
   (256/RODATA/NO) and `"mlkem_rtab"` (1024/RAM/NO — the mod-q reduction
   tables, built at init like `sqtab`); `precalc_table.inc` cmp-identical to
   this repo's root. The manifest TU defines `LIB_NO_BARE_EXPORTS` locally
   so only the prefixed family is emitted — conformant as the macro is
   written (the bare triple is gated on a define the adopter controls); the
   *normative* question of whether §8.4 should say so for zero-consumer
   libraries is **not** in this PR (separate draft, separate classification).

4. **§6.4 manifest per member set**: `mlkem-keccak.a` ships its own manifest
   object (`-D MLKEM_KECCAK_ONLY=1`, separate object directory, target-
   selected); the selector is rejected in `CONTRACT_DEFINES` at parse time
   (§6.3 rejection branch). This is a row entry the reviewer should look at:
   it is a per-target define reaching a manifest TU, the nist-curves
   per-variant shape, and the adopters row should say whether the fleet
   wants that recorded as "rejected" or "honored per target".

Measured for the row (all `make bench-kem` / `make check-manifest`, VICE
cycle-exact): keygen 26,835,087 · encaps 30,221,505 · decaps 35,093,202
cycles (keygen+decaps 61.9M, 65% Keccak); 6,719 B code+rodata shipped,
6,641 B BSS.

Also recorded: `make check-prefix`, the library-side guard that fails on any
archive export outside `mlkem_` / `LIB_MLKEM_` / `keccak_` / the exact §8
canonical names.

## Checklist

- [ ] `adopters.md` row cells replaced per the draft; no other file touched
- [ ] No SPEC.md change (grep the diff for `MUST|SHOULD|MAY` — zero)
- [ ] Classification: PATCH (v0.13.1 if released alone)
- [ ] Row text carries the v0.5.0 measured masks, the `LIB_MLKEM_PRECALC_*`
      export list from `od65`, and the §6.7 firing-test result (all in
      `01-adopters-row.md`); refresh only if v0.5.0 is re-tagged
