#!/usr/bin/env bash
# mutants-nightly.sh — scheduled mutation-testing scaffold (foundation queue #2).
#
# WHY: truth_chain.rs (the scoring core) has NEVER been mutation-tested —
# the audit's P4 finding — and engine/src/analysis.rs's last full run is
# stale (143 mutants, 109 caught, 7 missed — pre-ten-control). The doctrine
# from the project's own history: mutation testing is how "tests that
# can't fail" get caught (score_dkim went 13 survivors → 0 the same way).
#
# SHAPE: cargo-mutants on a SMALL, NAMED TARGET SET first — scoring + seal,
# the two frozen-file-doctrine crates-paths — never the whole tree blind.
# Nightly-scoped (scheduled job), NOT per-PR: mutation runs are too slow
# for the PR gate; the value is trend + survivors, not blocking.
#
# OUTPUT: a dated report under docs/mutation/ with counts + the survivor
# list; [SILENT] when nothing changes vs the last report (the doorbell
# discipline). A NEW SURVIVOR in scoring or seal paths is report-worthy;
# the ratchet baseline only shrinks.
#
# Requirements: cargo-mutants (installed 27.1.0); the crate must build with
# its dev-deps in a scratch target dir (cargo-mutants copies).

set -euo pipefail
REPO="$(git rev-parse --show-toplevel)"
CRATE="${1:-engine}"           # scaffold default: the scoring core
OUT_DIR="$REPO/docs/mutation"
STAMP=$(date -u +%Y-%m-%d)
OUT="$OUT_DIR/mutants-${CRATE}-${STAMP}.md"
mkdir -p "$OUT_DIR"

cd "$REPO/$CRATE"
{
  echo "# cargo-mutants — $CRATE — $STAMP"
  echo ""
  echo "- commit: $(git rev-parse --short HEAD)"
  echo "- command: cargo mutants --copy-target=false -j 2"
  echo ""
} > "$OUT"

# Scoped: score + seal + analysis are the load-bearing paths per the audit.
cargo mutants --copy-target=false -j 2 2>&1 | tail -40 >> "$OUT" || true

# Extract the headline counts for the silent/loud decision
MUTANTS=$(grep -cE '^[a-z].*::' "$OUT" 2>/dev/null || true)
CAUGHT=$(grep -c 'caught' "$OUT" 2>/dev/null || true)
MISSED=$(grep -c 'missed' "$OUT" 2>/dev/null || true)

echo "report: $OUT (rough scan: $MUTANTS lines, $CAUGHT caught-ish, $MISSED missed-ish)"
echo "review by hand: the .md above carries the full cargo-mutants tail"
