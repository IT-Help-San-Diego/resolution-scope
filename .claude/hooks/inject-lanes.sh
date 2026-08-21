#!/usr/bin/env bash
# UserPromptSubmit hook: inject the shared ledger + its sha into context at
# every turn start — the "cannot-not-see" half of the LANES mechanism.
# Harness-executed (deterministic), not model-remembered. Fail-open: a missing
# ledger or broken git must never block a turn (the pre-push family rule:
# never block for a reason you cannot prove).
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
[ -f policy/LANES.md ] || exit 0
sha=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "== policy/LANES.md @ ${sha} (injected by UserPromptSubmit hook — read before acting; append per its contract before ending the turn) =="
cat policy/LANES.md
