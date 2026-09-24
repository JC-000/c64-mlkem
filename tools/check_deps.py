#!/usr/bin/env python3
"""check_deps.py — `make check-deps`: every object's prerequisites, as make
RESOLVES them, cover every file its TU actually includes.

The failure this guards against is silent: a header edit on a warm tree
answers "Nothing to be done", exits 0 and ships stale objects. Measured on
v0.5.1 main: SHAKE128_RATE 168 -> 136 in src/constants.s rebuilt nothing, and
the warm PRG differed from a clean build at byte 1685.

Method (seconds, no VICE, scratch copy of the working tree):
  1. Clean build of every artifact (PRG, mlkem.a, mlkem-keccak.a, both probe
     links) with PATH wrappers recording, for each ca65 invocation, the full
     dependency list ca65 itself reports for that exact command line (see
     tools/depgraph.py). That is the true include graph, per object tree and
     per configuration, nested includes followed by the assembler.
  2. Normalise mtimes: sources T_SRC, build outputs T_BUILD. `make -n` must
     then run no ca65, ld65 or ar65 — a warm, unchanged tree rebuilds NOTHING (generated
     .d files are a classic source of spurious rebuilds).
  3. For every file in the graph: set it alone to T_EDIT (newer than every
     output by an hour — no sleeping, no 1-second-granularity coin toss), ask
     make with `-n` which objects it would assemble, and require every object
     whose TU includes that file to be among them. This interrogates make's
     own resolution (explicit rules, pattern rules, included .d files alike),
     so it is indifferent to the shape of the fix.

Fails naming `object -> missing header`. Extra rebuilds are reported, not
failed (over-approximation is safe; it is not the bug class here).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depgraph as dg  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the scratch tree")
    ap.add_argument("-q", "--quiet", action="store_true", help="do not print the graph")
    a = ap.parse_args()

    s = dg.Scratch(keep=a.keep)
    fail = []
    try:
        tree = s.copy_tree("tree")
        rc, out, recs = s.make(tree, dg.TARGETS, graph=True)
        if rc != 0:
            print(out)
            dg.die("FATAL: clean scratch build failed")
        g = dg.graph_from_records(tree, recs)
        if not g:
            dg.die("FATAL: no ca65 invocation was observed — wrapper not on PATH?")

        if not a.quiet:
            print("check-deps: include graph (ca65 --create-full-dep, per object):")
            for obj in sorted(g):
                src, deps = g[obj]
                print("  %-34s %s" % (obj, " ".join(d for d in deps if d != src) or "-"))

        # Leg 0: unchanged warm tree assembles nothing.
        dg.normalise_mtimes(tree)
        rc, out, _ = s.make(tree, dg.TARGETS, dry=True)
        spurious = sorted(dg.ca65_objects_in_dry_run(out))
        if rc != 0:
            print(out)
            dg.die("FATAL: make -n failed on the warm tree")
        for o in spurious:
            fail.append("FAIL %s: re-assembled on an UNCHANGED warm tree (spurious rebuild)" % o)
        # ...and nothing is re-linked or re-archived either.
        for l in dg.tool_lines_in_dry_run(out, ("ld65", "ar65")):
            fail.append("FAIL unchanged warm tree would still run: %s" % l[:200])

        files = sorted({d for _, deps in g.values() for d in deps})
        for f in files:
            dg.normalise_mtimes(tree)
            dg.set_mtime(os.path.join(tree, f), dg.T_EDIT)
            rc, out, _ = s.make(tree, dg.TARGETS, dry=True)
            if rc != 0:
                print(out)
                dg.die("FATAL: make -n failed after touching %s" % f)
            would = dg.ca65_objects_in_dry_run(out)
            need = {o for o, (_, deps) in g.items() if f in deps}
            for o in sorted(need - would):
                fail.append("FAIL %s: missing prerequisite %s (the TU includes it; "
                            "make does not rebuild the object when it changes)" % (o, f))
            extra = sorted(would - need - set(spurious))
            if extra and not a.quiet:
                print("  note: touching %s also re-assembles %s (safe over-approximation)"
                      % (f, " ".join(extra)))
    finally:
        s.close()

    if fail:
        print("\n".join(fail))
        print("check-deps: FAIL (%d gap(s))" % len(fail))
        sys.exit(1)
    print("check-deps: OK (%d objects, %d files: every include is a prerequisite as make "
          "resolves it; unchanged tree runs no ca65/ld65/ar65)" % (len(g), len(files)))


if __name__ == "__main__":
    main()
