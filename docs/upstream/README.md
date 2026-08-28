# Upstream drafts for c64-lib-contract — NOT pushed, NOT opened

Drafted by WP5 on 2026-08-28 against contract head `c771935` (SPEC 0.13.0).
The user opens PRs; these files are the text.

The split follows the #123 lesson (see `mem:contract_alignment`): a registry
or status-row change is **PATCH, zero normative change**, and must not share
a PR with anything that adds or alters an RFC-2119 keyword. Count keywords
before and after to classify; do not argue.

| File | Kind | Classification | Open when |
|---|---|---|---|
| `01-adopters-row.md` | registry/status row text | PATCH | now — corrects the v0.11.1 "unassessed" note (§6.3 is implemented) and records P2's planned §8 consumption as *in flight* |
| `02-intake-pr.md` | PR title + description for 01 | PATCH | with 01 |
| `03-normative-ask-precalc-bare.md` | §8.4 zero-consumer carve-out (`SHOULD NOT` emit bare `LIB_PRECALC_*`) + a PATCH-level §8.1 `-D` quoting wording fix | MINOR (part A) / PATCH (part B) — keep them in **separate** PRs from 01/02 and from each other | only if the user wants it; this repo does not depend on it |

**No registry-only prefix PR is needed for P2.** Every planned P2 export is
under `mlkem_` / `LIB_MLKEM_` (registered in v0.10.7), and the only
unprefixed name P2 adds — `mul_tables_init`, owner builds only — is the §8.1
canonical init, which needs no registration. If that changes, the prefix is
registered in the same PR that introduces the symbol, as a PATCH row-only
change, and `tools/check_prefix.sh`'s allow-list is extended in the same
c64-mlkem commit with the clause cited.
