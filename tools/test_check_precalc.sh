#!/bin/sh
# test_check_precalc.sh — self-test of tools/check_precalc.sh against a
# throwaway contract repo, so each way the checker can be quietly weakened
# turns this red.
#
#   test_check_precalc.sh [checker]     (default: tools/check_precalc.sh)
#
# The throwaway contract repo holds THREE different precalc_table.inc
# contents, one per place a weakened checker might read from:
#   TAGGED  committed and tagged v1.0.0           <- the only correct comparand
#   HEADV   a later commit, set up as origin/HEAD <- "compare against origin/HEAD"
#   DIRTY   uncommitted, in the working tree      <- "compare against the working tree"
# The checker under test is copied into a scratch adopter tree
# (<t>/tools/check_precalc.sh + <t>/src/precalc_table.inc), exactly the layout
# it resolves its local copy from. Seconds, no build tree, no network.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
checker=${1:-$here/check_precalc.sh}
[ -f "$checker" ] || { echo "FAIL: no checker at $checker"; exit 1; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/test_check_precalc.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
c=$tmp/contract
a=$tmp/adopter
mkdir -p "$c" "$a/tools" "$a/src"
cp "$checker" "$a/tools/check_precalc.sh"
chmod +x "$a/tools/check_precalc.sh"

TAGGED='; precalc_table.inc — tagged canonical copy
.macro LIB_PRECALC_TABLE name, size
.endmacro
'
HEADV='; precalc_table.inc — later upstream comment edit on main
.macro LIB_PRECALC_TABLE name, size
.endmacro
'
DIRTY='; precalc_table.inc — uncommitted local edit in the contract checkout
.macro LIB_PRECALC_TABLE name, size
.endmacro
'
g() {
    git -C "$c" -c user.name=selftest -c user.email=selftest@invalid -c commit.gpgsign=false \
        -c tag.gpgsign=false -c core.hooksPath=/dev/null "$@" > "$tmp/git.log" 2>&1 \
      || { echo "FAIL: selftest fixture: git $*"; cat "$tmp/git.log"; exit 1; }
}
g init -q
printf '%s' "$TAGGED" > "$c/precalc_table.inc"
printf '**Version:** 1.0.0 (selftest)\n' > "$c/SPEC.md"
g add -A; g commit -q -m tagged; g tag v1.0.0
printf '%s' "$HEADV" > "$c/precalc_table.inc"
printf '**Version:** 1.0.1 (selftest)\n' > "$c/SPEC.md"
g commit -q -am later
head=$(git -C "$c" rev-parse HEAD)
git -C "$c" update-ref refs/remotes/origin/main "$head"
git -C "$c" symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main
printf '%s' "$DIRTY" > "$c/precalc_table.inc"
# sanity: the three comparands really are distinct and where they should be
[ "$(git -C "$c" show v1.0.0:precalc_table.inc)" != "$(git -C "$c" show origin/HEAD:precalc_table.inc)" ] \
  && ! git -C "$c" diff --quiet \
  || { echo "FAIL: selftest fixture repo not built as intended"; exit 1; }

fails=0
# case <description> <expected: pass|fail> <local copy content|-> <dir> <ref>
case_() {
    desc=$1; want=$2; content=$3; dir=$4; ref=$5
    if [ "$content" = "-" ]; then :; else printf '%s' "$content" > "$a/src/precalc_table.inc"; fi
    set +e
    out=$("$a/tools/check_precalc.sh" "$dir" "$ref" 2>&1)
    rc=$?
    set -e
    case $want in
        pass) ok=$([ "$rc" -eq 0 ] && echo y || echo n) ;;
        fail) ok=$([ "$rc" -eq 1 ] && echo y || echo n) ;;
    esac
    if [ "$ok" = y ]; then echo "  ok    $desc (rc=$rc)"
    else echo "  FAIL  $desc (rc=$rc, wanted $want)"; printf '%s\n' "$out" | sed 's/^/          /'; fails=$((fails + 1)); fi
}

case_ "local == tagged copy passes  [reads origin/HEAD or the working tree]"          pass "$TAGGED" "$c" v1.0.0
case_ "local == origin/HEAD copy fails  [compares against origin/HEAD; self-cmp; exit 0]" fail "$HEADV" "$c" v1.0.0
case_ "local == dirty working copy fails  [compares against the working tree]"       fail "$DIRTY" "$c" v1.0.0
case_ "local == tagged + 1 byte fails  [self-cmp; exit 0 on difference]"             fail "$TAGGED " "$c" v1.0.0
case_ "missing contract dir fails  [skip when dir missing]"                          fail "$TAGGED" "$tmp/nonexistent" v1.0.0
case_ "missing ref fails  [skip when ref missing]"                                   fail "$TAGGED" "$c" v9.9.9
case_ "empty ref fails  [ref defaulted/ignored]"                                     fail "$TAGGED" "$c" ""
case_ "later ref selects the later copy  [ref argument ignored]"                    pass "$HEADV" "$c" origin/HEAD

if [ "$fails" -ne 0 ]; then echo "check-precalc-selftest: FAIL ($fails case(s))"; exit 1; fi
echo "check-precalc-selftest: OK"
