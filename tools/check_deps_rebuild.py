#!/usr/bin/env python3
"""check_deps_rebuild.py — `make check-deps-rebuild`: an incremental build
after a header edit equals a clean build of the same edited tree.

check-deps asks make which objects it WOULD rebuild; this check does it and
compares what comes out, so it also catches a fix whose prerequisites are
right but whose rebuild still ships something stale (an archive not re-made,
a probe not relinked, a .d file that lags the edit by one build).

For each distinct header in the include graph (every file some TU includes
other than its own primary source — derived from ca65, see depgraph.py; a
header this script has no edit for FAILS, so a new include cannot slip past):

  1. fresh scratch copy of a WARM tree (all five artifacts built);
     mtimes normalised: sources T_SRC, build outputs T_BUILD;
  2. apply a value-changing edit to the header, then `touch -t T_EDIT` it —
     an hour newer than every output. No sleeping: GNU Make 3.81 compares at
     1-second granularity, and an edit landing in the same second as the
     objects would otherwise be a wall-clock coin toss (see depgraph.T_*);
  3. incremental `make` of every artifact;
  4. a SECOND `make` must invoke no ca65, ld65 or ar65 at all (counted by
     PATH wrappers, so `@`-silenced recipes are counted too) and leave the
     artifacts unchanged — an unchanged tree rebuilds NOTHING;
  5. `rm -rf build` and a clean `make` of the same edited tree;
  6. the incremental and clean artifacts must be identical, compared as:
       - linked images and their maps/labels, byte for byte (the PRG and
         both probe links, which pull every archive member);
       - each archive's member list, and each member's `od65 --dump-all`;
       - every object in every object tree, `od65 --dump-all`.
     od65 dumps, never raw .o/.a bytes: ca65 stamps a wall-clock
     OPT_DATETIME into every object, and that one line is dropped. The dump
     keeps the Files section, which records each included file's size and
     mtime at assembly time — so an object that was NOT re-assembled after
     its header changed differs from the clean one even when its code bytes
     happen not to depend on the edited value (the latent sqtab_base.inc
     case).
  7. the clean edited build must differ in CONTENT (images, or dumps with the
     file-mtime lines removed) from the clean unedited baseline, or the edit
     proves nothing and the check fails.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depgraph as dg  # noqa: E402

# header -> (exact text, replacement). Each must match exactly once and must
# change what the build emits; both are asserted. Chosen so the edited tree
# still assembles and links.
EDITS = {
    # the adversarial-review repro: sponge.o / sample.o immediates
    "src/constants.s": ("SHAKE128_RATE   = 168", "SHAKE128_RATE   = 136"),
    # §8.1 window; baked into ntt/sqtab abs,x sites. Every TU includes it
    # through constants.s, so every object's Files record changes.
    "src/sqtab_base.inc": ("LIB_SHARED_SQTAB_BASE = $9000", "LIB_SHARED_SQTAB_BASE = $9400"),
    # round-0 iota constant (keccak.o rodata)
    "src/keccak_tables.inc": (".byte $01, $00, $00, $00, $00, $00, $00, $00   ; round  0",
                              ".byte $03, $00, $00, $00, $00, $00, $00, $00   ; round  0"),
    # zetas[0] low byte (ntt.o rodata)
    "src/mlkem_tables.inc": (".byte $01, $C1, $14, $D9,", ".byte $02, $C1, $14, $D9,"),
    # §8.4 region code: changes the manifest's LIB_MLKEM_PRECALC_*_REGION exports
    "src/precalc_table.inc": ("PRECALC_REGION_RAM     = $01", "PRECALC_REGION_RAM     = $02"),
}

DATETIME = re.compile(r"^\s*Data:\s+\d+\s+\(.*\)\s*$")


def od65_dump(s, path):
    out = subprocess.run([s.od65, "--dump-all", path], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True).stdout
    lines = out.splitlines()[1:]                    # first line is the file name
    keep, skip_next = [], False
    for i, l in enumerate(lines):
        # drop the OPT_DATETIME payload: "Type: 0x40 (OPT_DATETIME)" then "Data: <n> (<date>)"
        if "OPT_DATETIME" in l:
            skip_next = True
            keep.append(l)
            continue
        if skip_next and DATETIME.match(l):
            skip_next = False
            continue
        skip_next = False
        keep.append(l)
    return "\n".join(keep)


def fingerprint(s, tree):
    """{component name: content} for every artifact of a built tree."""
    fp = {}
    for img in dg.IMAGES:
        p = os.path.join(tree, img)
        if not os.path.exists(p):
            dg.die("FATAL: %s was not built" % img)
        with open(p, "rb") as f:
            fp[img] = f.read()
    for a in dg.ARCHIVES:
        p = os.path.join(tree, a)
        if not os.path.exists(p):
            dg.die("FATAL: %s was not built" % a)
        members = subprocess.run([s.ar65, "t", p], stdout=subprocess.PIPE, text=True).stdout.split()
        fp[a + " (member list)"] = " ".join(members)
        d = tempfile.mkdtemp(dir=s.root)
        subprocess.check_call([s.ar65, "x", p] + members, cwd=d)
        for m in members:
            fp["%s:%s" % (a, m)] = od65_dump(s, os.path.join(d, m))
        shutil.rmtree(d)
    build = os.path.join(tree, "build")
    for dirpath, _, files in os.walk(build):
        for n in files:
            if n.endswith(".o"):
                p = os.path.join(dirpath, n)
                fp[os.path.relpath(p, tree)] = od65_dump(s, p)
    return fp


def content(fp):
    """Fingerprint minus source-file mtimes, for the 'edit changed output' test."""
    out = {}
    for k, v in fp.items():
        if isinstance(v, str):
            v = "\n".join(l for l in v.splitlines() if "Modification time" not in l)
        out[k] = v
    return out


def headers_of(g):
    return sorted({d for src, deps in g.values() for d in deps if d != src})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the scratch trees")
    a = ap.parse_args()

    s = dg.Scratch(keep=a.keep)
    fail = []
    try:
        warm = s.copy_tree("warm")
        # Sources get T_SRC BEFORE the warm build: ca65 records each input's
        # mtime in the object's Files section, so an object assembled before
        # a later renormalisation would differ from its clean twin for a
        # reason that has nothing to do with dependencies.
        dg.normalise_mtimes(warm)
        rc, out, recs = s.make(warm, dg.TARGETS, graph=True)
        if rc != 0:
            print(out)
            dg.die("FATAL: clean scratch build failed")
        g = dg.graph_from_records(warm, recs)
        base = content(fingerprint(s, warm))
        headers = headers_of(g)
        print("check-deps-rebuild: headers in the include graph: %s" % " ".join(headers))

        for h in headers:
            if h not in EDITS:
                fail.append("FAIL %s: included by %s but has no value-changing edit in "
                            "tools/check_deps_rebuild.py EDITS — add one"
                            % (h, " ".join(o for o, (_, d) in sorted(g.items()) if h in d)))
                continue
            old, new = EDITS[h]
            nfail = len(fail)
            tree = s.copy_tree("edit-" + h.replace("/", "_"), src=warm)
            dg.normalise_mtimes(tree)
            hp = os.path.join(tree, h)
            with open(hp) as f:
                text = f.read()
            if text.count(old) != 1:
                fail.append("FAIL %s: edit anchor %r matches %d times (expected 1) — "
                            "update EDITS" % (h, old, text.count(old)))
                continue
            with open(hp, "w") as f:
                f.write(text.replace(old, new))
            dg.set_mtime(hp, dg.T_EDIT)

            rc, out, recs = s.make(tree, dg.TARGETS)
            if rc != 0:
                print(out)
                fail.append("FAIL %s: incremental build after the edit failed" % h)
                continue
            rebuilt = sorted(os.path.normpath(r["obj"]) for r in recs
                             if r["tool"] == "ca65" and "obj" in r) or \
                [" ".join(r["argv"][-1:]) for r in recs if r["tool"] == "ca65"]
            inc = fingerprint(s, tree)

            rc, out2, recs2 = s.make(tree, dg.TARGETS)
            again = dg.invocations(recs2)
            if rc != 0:
                print(out2)
                fail.append("FAIL %s: second make failed" % h)
            elif again:
                fail.append("FAIL %s: second make on an unchanged tree still ran %d tool "
                            "invocation(s): %s" % (h, len(again), "; ".join(
                                "%s %s" % (r["tool"], " ".join(r["argv"])) for r in again)))
            elif fingerprint(s, tree) != inc:
                fail.append("FAIL %s: second make changed an artifact" % h)

            shutil.rmtree(os.path.join(tree, "build"))
            rc, out3, _ = s.make(tree, dg.TARGETS)
            if rc != 0:
                print(out3)
                fail.append("FAIL %s: clean build of the edited tree failed" % h)
                continue
            clean = fingerprint(s, tree)

            if content(clean) == base:
                fail.append("FAIL %s: the edit %r -> %r does not change any artifact; "
                            "the probe is vacuous — pick a value-changing edit" % (h, old, new))
            diff = sorted(k for k in set(inc) | set(clean) if inc.get(k) != clean.get(k))
            if diff:
                imgs = [k for k in diff if k in dg.IMAGES]
                objs = [k for k in diff if ":" not in k and k.endswith(".o")]
                mems = [k for k in diff if k not in imgs and k not in objs]
                fail.append("FAIL %s: incremental build differs from a clean build of the "
                            "same edited tree\n    linked images: %s\n    stale objects: %s"
                            "\n    archive members: %s" % (h, " ".join(imgs) or "-",
                                                         " ".join(objs) or "-",
                                                         " ".join(mems) or "-"))
            elif len(fail) == nfail:
                print("  ok %-24s incremental == clean (%d re-assembled); second make ran nothing"
                      % (h, len(rebuilt)))
    finally:
        s.close()

    if fail:
        print("\n".join(fail))
        print("check-deps-rebuild: FAIL (%d)" % len(fail))
        sys.exit(1)
    print("check-deps-rebuild: OK (%d headers: incremental == clean after a value edit; "
          "an unchanged tree rebuilds nothing)" % len(headers))


if __name__ == "__main__":
    main()
