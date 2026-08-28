# Normative asks (drafts) — open ONLY with the user's decision, and separately

Neither of these is needed for c64-mlkem P2 to be conformant. They are
raised because the P2 alignment pass found the SPEC silent (A) or
self-inconsistent (B) on something this repo had to decide anyway. Keep A
and B in **different PRs**: A adds an RFC-2119 keyword (MINOR), B corrects
an example (PATCH). Neither goes in the same PR as the adopters row.

---

## A. §8.4 — zero-consumer carve-out for the bare `LIB_PRECALC_*` triple (MINOR)

**Title:** spec(§8.4): a library with no released consumers SHOULD NOT emit the deprecated bare `LIB_PRECALC_<name>_*` forms

**Proposed text** (after the "Canonical `precalc_table.inc`" paragraph):

> **Zero-consumer carve-out (v0.14.0).** The bare `LIB_PRECALC_<name>_*`
> triple exists for the same reason as §1's bare version exports — so
> existing single-library consumers keep working through v0.x — and it is
> the same collision class ([#43](https://github.com/JC-000/c64-lib-contract/issues/43)):
> two adopters enumerating `"sqtab"` emit the identical bare symbol. A
> library onboarding with **no released consumers** (§1's scope test:
> no tagged release any consumer pins, checkable from tags and
> `consumers.md`) SHOULD NOT emit the bare forms at all; it does so by
> defining `LIB_NO_BARE_EXPORTS` in the single TU that includes the macro,
> `.ifndef`-guarded so a consumer's build-wide `-D` is not a redefinition.
> The canonical `precalc_table.inc` is unchanged: the bare emission is
> already gated on that define. `SHOULD NOT` rather than `MUST NOT` for §1's
> reason — the forms are harmless in a single-library link. First library
> on this path: `c64-mlkem` (Phase 2), whose export surface is byte-identical
> with and without `-D LIB_NO_BARE_EXPORTS=1` as a standing invariant.

**Why it is MINOR:** new `SHOULD NOT` in a clause that had only the
`LIB_NO_BARE_EXPORTS` mechanism and no rule for who sets it. Same
classification as v0.11.0's two carve-outs, for the same reason.

**No adopter is affected.** All four incumbents have released consumers and
keep emitting the bare triple through v0.x.

---

## B. §8.1 — the `-D` example carries a `$` (PATCH)

**Title:** spec(§8.1): show the `LIB_SHARED_SQTAB_BASE` override `$`-free, matching §2

§8.1 reads: *the consumer overrides via `ca65 -D 'LIB_SHARED_SQTAB_BASE=$<addr>'`
(single-quoted — §2's `$`-hex quoting note)* and later *supplies one
`-D 'LIB_SHARED_SQTAB_BASE=$<addr>'`*. Every adopter Makefile and every
c64-https integration script passes `0x<addr>` — and through GNU make the
quoted form still fails: `$40` and `$$40` both reach ca65 as `0`, `$$$$40`
as the shell PID (measured in c64-mlkem and recorded in its CLAUDE.md;
c64-mlkem's `zp_config.s` carries the same warning). The single quotes
protect the value from the *shell*, not from *make*, which is where the
fleet's defines are composed.

**Proposed change:** replace both examples with
`ca65 -D LIB_SHARED_SQTAB_BASE=0x<addr>` and drop the "single-quoted" aside;
add one sentence: *Values MUST be `$`-free (`0x` or decimal) — §2's rule
applies to every §8.x placement equate.* If the reviewer reads that
sentence as a new MUST rather than §2's existing one restated, it is
MINOR, and the example fix alone stays PATCH; split accordingly.

**Adopters affected:** none in code; every shipped Makefile already
conforms to the corrected wording.
