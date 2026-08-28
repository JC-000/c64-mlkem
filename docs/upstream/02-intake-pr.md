# PR draft — c64-lib-contract (registry/status only, PATCH)

**Title:** adopters: c64-mlkem — §6.3 invalidation branch implemented; Phase 2 §8.1 consumption in flight

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

2. **Phase 2 makes the library a §8.1 `sqtab` consumer** (in flight, not
   tagged). Canonical header shape, both asserts, `mul_tables_init` in owner
   builds and `.import` under `SHARED_SQTAB_INIT`, §6.7 guard, conditional
   masks (`$0001/$0001` standalone, `$0000/$0001` deferring). **§8.3 is
   deliberately not taken** and **§8.2 is not applicable** (no REU); the
   row says so, with the reasoning linked, so a reviewer does not read a
   clear `$0004` as an omission.

3. **§8.4 rows planned** for `"sqtab"` (mandatory) and `"mlkem_zetas"`
   (256 B, at the floor); `precalc_table.inc` is already in place
   cmp-identical to this repo's root. The manifest TU defines
   `LIB_NO_BARE_EXPORTS` locally so only the prefixed family is emitted —
   conformant as the macro is written (the bare triple is gated on a define
   the adopter controls); the *normative* question of whether §8.4 should
   say so for zero-consumer libraries is **not** in this PR (separate
   draft, separate classification).

Also recorded: `make check-prefix`, the library-side guard that fails on any
archive export outside `mlkem_` / `LIB_MLKEM_` / `keccak_` / the exact §8
canonical names.

## Checklist

- [ ] `adopters.md` row cells replaced per the draft; no other file touched
- [ ] No SPEC.md change (grep the diff for `MUST|SHOULD|MAY` — zero)
- [ ] Classification: PATCH (v0.13.1 if released alone)
- [ ] Row to be refreshed again at the c64-mlkem P2 tag (v0.5.0) with the
      measured masks, the `LIB_PRECALC_*` export list from `od65`, and the
      §6.7 firing-test result
