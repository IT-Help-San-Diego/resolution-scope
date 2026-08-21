#!/usr/bin/env bash
# Wire the tracked .githooks/ directory as this clone's hooks path.
#
# Run ONCE per clone — including the other lanes (Claude Code, Claude Science),
# whose sandboxes clone the repo fresh. The hook itself lives in the repo
# (.githooks/pre-push) and is version-controlled; this script just points git
# at it, because `core.hooksPath` is a per-clone setting (in .git/config) and
# cannot be committed.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "core.hooksPath -> .githooks"
echo "installed hooks:"
ls -la .githooks/
