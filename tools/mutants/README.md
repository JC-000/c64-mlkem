# tools/mutants — mutation-gate manifests

HANDOFF-P2.md requires that, before a work package merges, deliberate faults
applied to a copy of the green tree (`build/mutants/`, driven by
`tools/mutate.py`) each turn the suite red. **A surviving mutant is a
test-suite defect and blocks the merge.**

Mutants are declared here *before* the implementation exists, so they are
written as **manifests**, not patches: the red-test author names the fault
and the test that must kill it; the `.patch` is produced at gate time against
the actual green source and added next to the manifest.

## Manifest form

One TOML file per work package: `wp<N>.toml`. Each mutant is a table in the
`[[mutant]]` array:

```toml
[[mutant]]
id      = "wp2-cbd-short"            # unique, kebab-case, prefixed by WP
routine = "mlkem_sample_cbd2"        # exported symbol the fault lives in
fault   = "consume 127 of the 128 PRF bytes"   # what the patch does, one line
class   = "off-by-one"               # off-by-one | rounding | order | bound | ct
kill    = "tools/test_sampler.py --only cbd"   # the command that must go red
expect  = "mlkem_sample_cbd2 [all-0xFF]: index 254"  # substring of the failure
patch   = ""                         # filled at gate time: wp2-cbd-short.patch
```

`kill` is the narrowest invocation that must fail; the whole suite is run as
well. `expect` pins that the failure is *localised* — a mutant that turns the
suite red only through some unrelated downstream check is still a
localisation defect and is reported as such.

`tools/mutate.py` (WP gate tooling) reads every `wp*.toml`, applies each
`patch` to `build/mutants/<id>/`, builds, runs `kill`, and requires a
non-zero exit whose output contains `expect`.
