#!/usr/bin/env bash
# Stop hook: the turn cannot end with a dirty or malformed ledger.
# Exit 2 blocks Claude from stopping and feeds stderr back as instruction —
# the unskippable half of the LANES mechanism (same shape as the pre-push
# gate: a convention became a mechanism).
#
# Two checks, both provable:
#   1. The routing invariant: a left arrow in LANES.md is a parse error.
#   2. Never leave LANES.md uncommitted — a dirty shared ledger is silent
#      drift waiting to happen.
# Fail-open if git itself is unavailable (e.g. the macl anomaly, pattern 9):
# never block for a reason we cannot prove.
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
[ -f policy/LANES.md ] || exit 0
if ! git status --porcelain -- policy/LANES.md >/dev/null 2>&1; then
  echo "LEDGER GATE: git unavailable — skipping (fail-open, pattern-9 aware)." >&2
  exit 0
fi
# Scoped to relay lines (^NAME <-) and ledger entries (| ... <-): the law's
# own prose legitimately QUOTES the left arrow to define it, and a naive
# character grep flags the statute for citing the crime — the negative
# control caught exactly that on first run.
LA="$(printf '\xe2\x86\x90')"
if grep -E -q "^[A-Z][A-Z_ -]* ${LA}|^[^|]*\|.*${LA}" policy/LANES.md; then
  echo "LEDGER GATE: a relay/entry line in policy/LANES.md uses a LEFT ARROW — parse error per the routing invariant. Every relay line is SENDER -> RECIPIENT with the right arrow; fix the entry, commit, then end the turn." >&2
  exit 2
fi
if [ -n "$(git status --porcelain -- policy/LANES.md)" ]; then
  echo "LEDGER GATE: policy/LANES.md has uncommitted changes — commit (and push) the ledger before ending the turn." >&2
  exit 2
fi
exit 0
