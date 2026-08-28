#!/usr/bin/env python3
"""mutate.py — mutation gate driver (HANDOFF-P2 "Mutation gate before merge").

For every mutant in a manifest: copy the source tree into
build/mutants/<name>/, apply the mutant's patch, build, run the named test
command, and report PASS only if the test FAILED (the mutant was killed).
A mutant whose test still passes SURVIVES; any survivor, missing patch, patch
that does not apply, or mutant that does not build makes the exit status
nonzero. (A mutant that fails to BUILD is reported as such, not as killed:
a patch that no longer applies to the current tree is a stale gate, and a
stale gate proves nothing.)

Generic on purpose — WP1, WP2 and WP3 all use it with their own manifests.

Manifest (JSON):
    {
      "default_test": "make test-ntt",           # optional
      "build": "make",                            # optional, default "make"
      "mutants": [
        {
          "name":  "ntt-wrong-zeta",
          "patch": "ntt-wrong-zeta.patch",        # relative to the manifest
          "test":  "make test-ntt",               # optional, overrides default
          "description": "...",
          "expect": "..."                         # free text: what should catch it
        }, ...
      ]
    }

Patches are `git diff` / unified-diff format applied with `patch -p1` from
the copy's root.

Usage:
    python3 tools/mutate.py [--manifest tools/mutants/manifest.json]
                            [--only NAME[,NAME]] [--keep] [--list]

    --only   run a subset
    --keep   leave build/mutants/<name>/ in place on success (default: kept
             only for survivors, so the diff is at hand)
    --list   print the manifest and exit
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MUTANT_ROOT = os.path.join(PROJECT_ROOT, "build", "mutants")

# What a copy of the tree needs. Everything tracked by git, minus build output.
EXCLUDE_TOP = {"build", ".git", ".claude", "__pycache__"}


def tracked_files():
    r = subprocess.run(["git", "ls-files", "-z"], cwd=PROJECT_ROOT,
                       capture_output=True, check=True)
    files = [f for f in r.stdout.decode().split("\0") if f]
    # Untracked-but-needed inputs (fetched vectors, generated tables) are
    # copied too if present: a mutant must build exactly like the real tree.
    for extra in ("tools/vectors", "src/keccak_tables.inc", "src/mlkem_tables.inc"):
        p = os.path.join(PROJECT_ROOT, extra)
        if os.path.isdir(p):
            for dp, _, fns in os.walk(p):
                for fn in fns:
                    rel = os.path.relpath(os.path.join(dp, fn), PROJECT_ROOT)
                    if rel not in files:
                        files.append(rel)
        elif os.path.isfile(p) and extra not in files:
            files.append(extra)
    return [f for f in files if f.split(os.sep, 1)[0] not in EXCLUDE_TOP]


def copy_tree(dst):
    if os.path.exists(dst):
        shutil.rmtree(dst)
    for rel in tracked_files():
        src = os.path.join(PROJECT_ROOT, rel)
        if not os.path.exists(src):
            continue
        out = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copy2(src, out)


def run(cmd, cwd, env=None, log=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    r = subprocess.run(cmd, shell=True, cwd=cwd, env=e,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if log:
        with open(log, "ab") as fh:
            fh.write(f"\n$ {cmd}\n".encode())
            fh.write(r.stdout)
    return r.returncode, r.stdout.decode(errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=os.path.join(PROJECT_ROOT, "tools", "mutants",
                                                       "manifest.json"))
    ap.add_argument("--only", default="")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    with open(args.manifest) as fh:
        man = json.load(fh)
    mdir = os.path.dirname(os.path.abspath(args.manifest))
    default_test = man.get("default_test", "make test")
    build_cmd = man.get("build", "make")
    mutants = man["mutants"]
    if args.only:
        want = set(args.only.split(","))
        mutants = [m for m in mutants if m["name"] in want]
        unknown = want - {m["name"] for m in mutants}
        if unknown:
            print(f"unknown mutant(s): {', '.join(sorted(unknown))}")
            return 2

    if args.list:
        for m in mutants:
            print(f"{m['name']:32} {m.get('patch') or '(no patch yet)':32} "
                  f"{m.get('test', default_test)}")
        return 0

    os.makedirs(MUTANT_ROOT, exist_ok=True)
    results = []
    t0 = time.time()
    for m in mutants:
        name = m["name"]
        test = m.get("test", default_test)
        patch = m.get("patch")
        wd = os.path.join(MUTANT_ROOT, name)
        log = os.path.join(MUTANT_ROOT, f"{name}.log")
        if os.path.exists(log):
            os.remove(log)
        print(f"\n=== mutant {name}: {m.get('description', '')}")

        if not patch or not os.path.isfile(os.path.join(mdir, patch)):
            print(f"    MISSING PATCH  ({patch or 'none listed'})")
            results.append((name, "missing-patch"))
            continue

        copy_tree(wd)
        rc, out = run(f"patch -p1 --forward < {os.path.join(mdir, patch)!r}", wd, log=log)
        if rc != 0:
            print(f"    PATCH FAILED (stale mutant?)\n{out[-800:]}")
            results.append((name, "patch-failed"))
            continue

        rc, out = run(build_cmd, wd, log=log)
        if rc != 0:
            print(f"    BUILD FAILED (a mutant must build; fix the patch)\n{out[-800:]}")
            results.append((name, "build-failed"))
            continue

        rc, out = run(test, wd, env={"C64_SKIP_BUILD": "1"}, log=log)
        tail = "\n".join(out.strip().splitlines()[-6:])
        expect = m.get("expect", "")
        if rc != 0 and expect and expect not in out:
            # Red, but not for the reason the manifest names: the fault was
            # caught only by some unrelated downstream check, so the suite
            # does not LOCALISE it. HANDOFF-P2 treats that as a gate failure.
            print(f"    KILLED NON-LOCALLY (test exit {rc}, expect substring absent: {expect!r})")
            for line in tail.splitlines():
                print(f"      | {line}")
            results.append((name, "non-local-kill"))
        elif rc != 0:
            print(f"    KILLED  (test exit {rc})")
            for line in tail.splitlines():
                print(f"      | {line}")
            results.append((name, "killed"))
            if not args.keep:
                shutil.rmtree(wd, ignore_errors=True)
        else:
            print(f"    SURVIVED — the suite did not notice. Tree kept at {wd}")
            for line in tail.splitlines():
                print(f"      | {line}")
            results.append((name, "survived"))

    print(f"\n--- mutation gate: {len(results)} mutants in {time.time() - t0:.0f}s")
    bad = 0
    for name, status in results:
        mark = "PASS" if status == "killed" else "FAIL"
        if status != "killed":
            bad += 1
        print(f"  {mark}  {name:32} {status}")
    if bad:
        print(f"\nFAIL: {bad} mutant(s) not killed (or killed only non-locally). A "
              f"surviving mutant is a test-suite defect and blocks the merge (HANDOFF-P2).")
        return 1
    print("\nOK: every mutant killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
