#!/usr/bin/env bash
# check-release-class.sh — pin how a tag's SHAPE decides what gets published.
#
# WHY THIS EXISTS. release.yml decides two outward-facing things from the tag
# name alone: whether the GitHub release is marked pre-release, and what the
# post-publish read-back asserts. Both decisions are `case` statements, and a
# `case` statement has two properties that make it quietly dangerous here:
#
#   1. ARM ORDER IS SEMANTIC. `v[0-9]*.[0-9]*.[0-9]*` SUBSUMES every
#      pre-release tag, because `[0-9]*` means one digit followed by anything
#      — it matches `v26.0.0-alpha.4` as happily as `v26.0.0`. Swap the two
#      arms and every alpha, beta and rc publishes as a STABLE release. No
#      compiler reads a case statement's order.
#   2. TWO CONTROLS THAT SHARE A CLASS LIST ARE ONE CONTROL. The create step
#      and the read-back both test `*-alpha*|*-beta*|*-rc*`. For a suffix
#      NEITHER knows (-dev, -pre, -snapshot, -preview) they agreed that the
#      tag was stable, and the read-back reported success. That was measured,
#      not theorised, on 2026-09-05, in a guard whose own error message
#      claimed it was "refusing to guess".
#
# Publishing is outward-facing and editing a published release is forbidden
# here without Carey, so the cost of being wrong is not a red check — it is a
# stable release that strangers download. This gate reads the ACTUAL workflow
# file and exercises its ACTUAL case statements against a pinned table.
#
# Usage: check-release-class.sh [path/to/release.yml]
#        check-release-class.sh --self-test   (proves the gate can fail)

set -uo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "FAIL: not inside a git work tree — refusing to run against an unknown source" >&2
  exit 2
}
WF="${1:-$ROOT/.github/workflows/release.yml}"
[ -f "$WF" ] || { echo "FAIL: no such workflow file: $WF" >&2; exit 2; }

# --- extract the Nth `case "$GITHUB_REF_NAME" in ... esac` body, verbatim ---
extract() {
  awk -v want="$1" '
    /case "\$GITHUB_REF_NAME" in/ { n++; if (n == want) { inb = 1; next } }
    inb && /^[[:space:]]*esac[[:space:]]*$/ { exit }
    inb { print }
  ' "$WF"
}

NBLOCKS=$(grep -c 'case "\$GITHUB_REF_NAME" in' "$WF")
if [ "$NBLOCKS" -ne 2 ]; then
  # Fail closed. A gate that passes because it found nothing to check is the
  # exact defect this repository has recorded more than once.
  echo "FAIL: expected exactly 2 tag-class case statements in $(basename "$WF"), found $NBLOCKS." >&2
  echo "      Either a decision point was added without a control, or one was removed." >&2
  exit 1
fi

B1=$(extract 1)
B2=$(extract 2)
[ -n "$B1" ] && [ -n "$B2" ] || { echo "FAIL: a case block extracted empty — the parser and the file disagree" >&2; exit 1; }

# --- run one extracted block against one tag, in a subshell ---
# Prints "PRE=<v> WANT=<v>" on classification; exits non-zero if the block
# refuses (an arm running `exit 1`), which is a VERDICT, not an error.
run_block() {
  ( GITHUB_REF_NAME="$2"; PRE=UNSET; WANT=UNSET
    eval "case \"\$GITHUB_REF_NAME\" in
$1
esac" >/dev/null 2>&1
    printf 'PRE=%s WANT=%s\n' "$PRE" "$WANT" )
}

verdict1() { local o; o=$(run_block "$B1" "$1") || { echo REFUSE; return; }
  case "$o" in *"PRE=--prerelease"*) echo prerelease ;; *"PRE= "*|*"PRE="*) echo stable ;; esac; }
verdict2() { local o; o=$(run_block "$B2" "$1") || { echo REFUSE; return; }
  case "$o" in *"WANT=true"*) echo true ;; *"WANT=false"*) echo false ;; *) echo UNSET ;; esac; }

# --- the pinned table: tag | create-step verdict | read-back verdict ---
# The -dev/-pre/-snapshot/-preview rows are the regression cases. Before
# 2026-09-05 every one of them published as a STABLE release with both
# controls reporting success.
TABLE='v26.0.0-alpha.4|prerelease|true
v26.0.0-alpha|prerelease|true
v26.0.0-beta.1|prerelease|true
v26.0.0-rc.1|prerelease|true
v26.0.0|stable|false
v26.1.3|stable|false
v26.0.0-dev.1|REFUSE|REFUSE
v26.0.0-pre.1|REFUSE|REFUSE
v26.0.0-snapshot|REFUSE|REFUSE
v26.0.0-preview.2|REFUSE|REFUSE
nightly|REFUSE|false
26.0.0|REFUSE|false'

fails=0; checked=0
while IFS='|' read -r tag e1 e2; do
  [ -n "$tag" ] || continue
  checked=$((checked + 1))
  g1=$(verdict1 "$tag"); g2=$(verdict2 "$tag")
  if [ "$g1" != "$e1" ]; then
    echo "FAIL: tag '$tag' — create step classified '$g1', pinned '$e1'" >&2; fails=$((fails + 1))
  fi
  if [ "$g2" != "$e2" ]; then
    echo "FAIL: tag '$tag' — read-back classified '$g2', pinned '$e2'" >&2; fails=$((fails + 1))
  fi
done <<< "$TABLE"

# --- arm-order controls: the properties the table cannot see ---
# A table check passes if the arms are reordered AND the pinned answers happen
# to survive; these assert the structural reason the answers are right.
order_check() {
  local blk="$1" name="$2" first="$3" second="$4"
  local a b code
  # COMMENTS ARE NOT ARMS. The first draft of this check located the arms with
  # a bare grep and failed instantly — on the explanatory comment above the
  # arms, which quotes the very patterns it describes. The gate was right that
  # something was out of order; my probe was reading prose as code. This
  # repository has recorded that same mistake before, matching `#[ignore]`
  # inside a comment. Strip comment lines first, then locate the arms.
  code=$(echo "$blk" | grep -v '^[[:space:]]*#')
  a=$(echo "$code" | grep -n -- "$first" | head -1 | cut -d: -f1)
  b=$(echo "$code" | grep -n -- "$second" | head -1 | cut -d: -f1)
  if [ -z "$a" ] || [ -z "$b" ]; then
    echo "FAIL: $name — could not locate both arms ('$first', '$second')" >&2; return 1
  fi
  if [ "$a" -ge "$b" ]; then
    echo "FAIL: $name — the '$first' arm must precede '$second'; the later pattern subsumes the earlier one and would capture it" >&2
    return 1
  fi
  return 0
}
order_check "$B1" "create step" '\*-alpha\*' 'v\[0-9\]' || fails=$((fails + 1))
order_check "$B1" "create step" '\*-\*)' 'v\[0-9\]'     || fails=$((fails + 1))
order_check "$B2" "read-back"   '\*-alpha\*' '\*-\*)'   || fails=$((fails + 1))

if [ "$fails" -ne 0 ]; then
  echo "check-release-class: $fails failure(s) across $checked pinned tags" >&2
  exit 1
fi
echo "check-release-class: OK — $checked tag shapes pinned across both case statements, arm order asserted in both"
