#!/usr/bin/env python3
"""test_check_deps.py — `make check-deps-selftest`: the two dependency checkers
must go RED on known-broken Makefiles.

A checker nobody tests can be switched off by a one-line edit, and `make test`
stays green: skipping check_deps_rebuild's second make, or an invocations()
that always returns [], was measured to leave every real-tree run green. So
each case below applies one Makefile mutation to a scratch copy of the working
tree (the checkers under test are that copy's tools/, i.e. THIS tree's) and
requires the named checker to exit 1 with a specific FAIL line. A FATAL (exit
2) does not count: a crashed checker is not a checker that saw the bug.

Also guards the wiring: `test:` must still depend on check-deps,
check-deps-rebuild and this self-test.

Cases (mutant class each kills, from the fix/make-deps adversarial review):
  F1   kobj recipe without --create-full-dep   -> check-deps
  F7b  FORCE on the mlkem-lib.prg probe         -> check-deps (leg 0 ld65) AND
                                                   check-deps-rebuild (second make)
  F6   no build-scheme tag in CONFIG_SIG        -> check-deps-rebuild pre-scheme-tree
  F7   probe without the archive prerequisite   -> check-deps-rebuild (image)
  F9   shipped sqtab_base.inc not re-copied     -> check-deps-rebuild (shipped file)
  F8   obj .d restored to the previous build's  -> check-deps-rebuild new-include
Rebuild cases run only the scenario they need (--only), in parallel, each in
its own scratch trees; wall time is a few seconds per case.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import depgraph as dg  # noqa: E402


def sub(pattern, repl, flags=0):
    """A Makefile mutation that must match exactly once."""
    def f(text):
        new, n = re.subn(pattern, repl, text, flags=flags)
        if n != 1:
            raise AssertionError("fixture anchor %r matched %d times (expected 1)" % (pattern, n))
        return new
    return f


def append(extra):
    return lambda text: text + extra


OBJ_RECIPE = r"(\$\(OBJ_DIR\)/mlkem_%\.o:[^\n]*\n\t)([^\n]*)"

CASES = [
    ("F1-kobj-no-dep",
     [sub(r"(\t\$\(CA65\)[^\n]*MLKEM_KECCAK_ONLY=1[^\n]*?)\s*--create-full-dep\s+\S+", r"\1")],
     [("check_deps.py", [], r"^FAIL build/kobj/mlkem_lib_manifest\.o: missing prerequisite "
                            r"src/precalc_table\.inc")]),
    ("F7b-force-probe",
     [sub(r"^(\$\(LIB_PROBE\):[^\n]*)$", r"\1 FORCE", re.M), append("\nFORCE:\n")],
     [("check_deps.py", [], r"^FAIL unchanged warm tree would still run: ld65 .*mlkem-lib\.prg"),
      ("check_deps_rebuild.py", ["--only", "src/constants.s"],
       r"^FAIL src/constants\.s: second make on an unchanged tree still ran .*ld65")]),
    ("F6-no-scheme-tag",
     [sub(r"^CONFIG_SIG := \w+\|", "CONFIG_SIG := ", re.M)],
     [("check_deps_rebuild.py", ["--only", "pre-scheme-tree"],
       r"^FAIL pre-scheme-tree: incremental build differs")]),
    ("F7-probe-no-archive",
     [sub(r"^(\$\(LIB_PROBE\):) \$\(ARCHIVE\)", r"\1", re.M)],
     [("check_deps_rebuild.py", ["--only", "src/keccak_tables.inc"],
       r"^    linked images / shipped files: .*build/mlkem-lib\.prg")]),
    ("F9-shipped-header-no-prereq",
     [sub(r"^\$\(LIB_DIR\)/sqtab_base\.inc: \$\(SRC_DIR\)/sqtab_base\.inc \| \$\(LIB_DIR\)\n\t@cp \$< \$@",
          "$(LIB_DIR)/sqtab_base.inc: | $(LIB_DIR)\n\t@cp $(SRC_DIR)/sqtab_base.inc $@", re.M)],
     [("check_deps_rebuild.py", ["--only", "src/sqtab_base.inc"],
       r"^    linked images / shipped files: .*build/lib/sqtab_base\.inc")]),
    ("F8-d-lags-one-build",
     [sub(OBJ_RECIPE, r"\1cp $(@:.o=.d) $(@:.o=.d).tmp 2>/dev/null || true; \2; "
                      r"mv $(@:.o=.d).tmp $(@:.o=.d) 2>/dev/null || true")],
     [("check_deps_rebuild.py", ["--only", "new-include"],
       r"^FAIL new-include: incremental build differs")]),
]


def run_case(root, case):
    name, muts, expects = case
    tree = os.path.join(root, name)
    shutil.copytree(REPO, tree, ignore=shutil.ignore_patterns(
        ".git", ".claude", ".serena", ".ca65-ls", "build", "__pycache__", "vectors"))
    mk = os.path.join(tree, "Makefile")
    with open(mk) as f:
        text = f.read()
    try:
        for m in muts:
            text = m(text)
    except AssertionError as e:
        return ["FAIL %s: %s — update the fixture" % (name, e)]
    with open(mk, "w") as f:
        f.write(text)
    out = []
    env = dict(os.environ)
    for k in dg.SCRUB_ENV:
        env.pop(k, None)
    for tool, args, pat in expects:
        p = subprocess.run([sys.executable, os.path.join(tree, "tools", tool)] + args,
                           cwd=tree, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
        hit = re.search(pat, p.stdout, re.M)
        if p.returncode == 1 and hit:
            out.append("  ok    %-28s %s FAILs as required" % (name, tool))
        else:
            tail = "\n".join("        | " + l for l in p.stdout.splitlines()[-6:])
            out.append("FAIL %s: %s exited %d%s — the checker no longer detects this mutant\n%s"
                       % (name, tool, p.returncode,
                          "" if hit else " without a line matching %r" % pat, tail))
    return out


def wiring():
    with open(os.path.join(REPO, "Makefile")) as f:
        text = f.read()
    m = re.search(r"^test:([^\n]*)$", text, re.M)
    deps = m.group(1).split() if m else []
    out = []
    for t in ("check-deps", "check-deps-rebuild", "check-deps-selftest"):
        if t not in deps:
            out.append("FAIL wiring: `test:` no longer depends on %s" % t)
    for t, script in (("check-deps", "check_deps.py"),
                      ("check-deps-rebuild", "check_deps_rebuild.py"),
                      ("check-deps-selftest", "test_check_deps.py")):
        r = re.search(r"^%s:[^\n]*\n((?:\t[^\n]*\n)+)" % re.escape(t), text, re.M)
        if not r or script not in r.group(1):
            out.append("FAIL wiring: the %s recipe no longer runs tools/%s" % (t, script))
    if not out:
        out.append("  ok    wiring: test -> check-deps, check-deps-rebuild, check-deps-selftest")
    return out


def main():
    root = os.path.realpath(tempfile.mkdtemp(prefix="c64-mlkem-depself."))
    try:
        lines = wiring()
        with ThreadPoolExecutor(len(CASES)) as ex:
            for r in ex.map(lambda c: run_case(root, c), CASES):
                lines += r
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("\n".join(lines))
    bad = [l for l in lines if l.startswith("FAIL")]
    if bad:
        print("check-deps-selftest: FAIL (%d)" % len(bad))
        sys.exit(1)
    print("check-deps-selftest: OK (%d mutant cases, every one detected)" % len(CASES))


if __name__ == "__main__":
    main()
