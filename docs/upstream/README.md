# Upstream drafts for c64-lib-contract — OPENED 2026-08-29 (not merged)

Drafted by WP5 on 2026-08-28 against contract head `c771935` (SPEC 0.13.0).
Opened by P3 Lane B on 2026-08-29 against contract `origin/main` at `b45b212`
(SPEC 0.14.1, tagged). These files remain the drafts; the PR text as opened
was corrected against the shipped v0.5.0 numbers (`od65`/`ar65` on the built
archives) and the v0.14.1 base.

| PR | Branch | Classification | Version |
|---|---|---|---|
| [#156](https://github.com/JC-000/c64-lib-contract/pull/156) — adopters row (01 + 02) | `docs/adopters-c64-mlkem-v0.5.0` | PATCH, row-only, zero keywords in the diff | none |
| [#157](https://github.com/JC-000/c64-lib-contract/pull/157) — §8.1 `-D` example `$`-free (03 part B) | `spec/8-1-sqtab-base-dollar-free` | PATCH, keyword counts unchanged | 0.14.2 |
| [#158](https://github.com/JC-000/c64-lib-contract/pull/158) — §8.4 zero-consumer carve-out (03 part A) | `spec/8-4-precalc-bare-zero-consumer` | MINOR, +1 normative `SHOULD NOT` | 0.15.0 |

Deviations from the drafts: 03-B's proposed "Values MUST be `$`-free"
sentence was not added (it would duplicate §6.2's and move the count — the
examples now reference §2/§6.2 instead); the v0.11.1 "unassessed" changelog
line is left in place (v0.11.1 is tagged, the sentence was true at the tag;
the row supersedes it); the contract README banner still says c64-mlkem
v0.4.0 and is left for a currency PR of the #131 kind. #157 and #158 both
bump the version against the same base — whichever merges second needs a
trivial rebase.

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
