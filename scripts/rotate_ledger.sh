#!/usr/bin/env bash
# rotate_ledger.sh — archive LANES.md history, keep the working head small.
#
# WHY (foundation audit P1, 2026-08-31): the whole ledger was being injected
# into every claude-code turn — 585KB/~146K tokens, ~73% of a 200K window,
# growing 120-190KB/day. The coordination mechanism was about to stop
# fitting in its own context. This rotation keeps the mechanism and moves
# the history, verbatim, to an append-only archive.
#
# WHAT IT KEEPS (the read-for-every-turn surface):
#   * the contract header (everything up to the first timestamped entry)
#   * ALL lines matching DECISION NEEDED / BLOCKED that are still open
#     (i.e., appear later in the file than any line resolving their id)
#   * the LAST 50 timestamped entries
#
# WHAT IT MOVES: everything else, VERBATIM, to policy/LANES_ARCHIVE.md,
# under a rotation marker naming the block-hash (sha256, first 16 hex) of
# the archived block — so any reader can verify the archive is byte-exact
# and un-gapped. The archive is append-only; a second rotation appends
# below the first with its own marker.
#
# GATE: refuses to run if the last-50 window would eat an open DECISION/
# BLOCKED line (those must survive into the working head, never archive).
#
# Design: claude-code foundation audit 2026-08-31T23:49Z; ratified by
# Carey's GO 2026-09-01 (items one and two). Doorbell compatibility: the
# lane_doorbell.sh lanes arm already reads lanes-HASH (sha256 first-16),
# shipped 2026-08-31 ahead of this rotation per deferral-ships-tripwire.
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
LEDGER="$REPO/policy/LANES.md"
ARCHIVE="$REPO/policy/LANES_ARCHIVE.md"
KEEP_ENTRIES="${KEEP_ENTRIES:-50}"

[ -f "$LEDGER" ] || { echo "rotate_ledger: no ledger at $LEDGER" >&2; exit 1; }

# --- 1) split: header (pre-first-entry) vs entries --------------------------
# (no grep|head pipe: under `set -o pipefail` grep SIGPIPEs once head exits)
FIRST_ENTRY_LINE=$(grep -nE '^2026-[0-9]{2}-[0-9]{2}T' "$LEDGER" | sed -n '1p' | cut -d: -f1 || true)
[ -n "$FIRST_ENTRY_LINE" ] || { echo "rotate_ledger: no timestamped entries — nothing to rotate" >&2; exit 0; }
HEADER_END=$((FIRST_ENTRY_LINE - 1))
TOTAL_LINES=$(wc -l < "$LEDGER" | tr -d ' ')
ENTRY_LINES=$((TOTAL_LINES - HEADER_END))

# --- 2) find the line where the last-KEEP entries begin ---------------------
KEEP_START=$(python3 - "$LEDGER" "$HEADER_END" "$KEEP_ENTRIES" <<'PY'
import sys
ledger, header_end, keep = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
lines = open(ledger).read().split('\n')
entries = [(i, l) for i, l in enumerate(lines) if l.startswith('2026-')]
n = len(entries)
if n <= keep:
    # NOTHING to rotate: keep_start beyond EOF → empty archive block.
    print(len(lines) + 2); sys.exit(0)
# keep_start = 1-based line number of the (n-keep+1)-th entry
idx = entries[n - keep][0] + 1
# back up to include blank-line separators preceding it
while idx > 1 and lines[idx - 2].strip() == '':
    idx -= 1
print(idx)
PY
)

# --- 3) open DECISION/BLOCKED must survive into the head --------------------
python3 - "$LEDGER" "$KEEP_START" <<'PY'
import sys, re
ledger, keep_start = sys.argv[1], int(sys.argv[2])
lines = open(ledger).read().split('\n')
# ids declared open anywhere; skip the contract's own format-example
# placeholders (<id>, <...>) and anything inside a ``` fence (the Line
# format section documents the vocabulary with sample lines).
in_fence = False
open_ids = {}
for i, l in enumerate(lines, 1):
    if l.strip().startswith('```'):
        in_fence = not in_fence
        continue
    if in_fence:
        continue
    for pat in (r'DECISION NEEDED (\S+?):', r'BLOCKED (\S+?):'):
        m = re.search(pat, l)
        if m and not m.group(1).startswith('<'):
            open_ids.setdefault(m.group(1), i)
# an id is closed if a LATER entry declares it ruled/resolved/GO'd/landed —
# the ledger's own closing vocabulary (measured: receipts-go closed by
# "CAREY RULED ... receipts-go = GO", which a literal RESOLVED match missed)
resolved = set()
close_words = re.compile(r'RESOLVED|RULED|WITHDRAWN|SUPERSEDED', re.I)
go_words = re.compile(r'\bGO\b|\blanded\b', re.I)
for i, l in enumerate(lines, 1):
    for oid, opened_at in open_ids.items():
        if oid in l and i > opened_at and (close_words.search(l) or go_words.search(l)):
            resolved.add(oid)
still_open = {oid: ln for oid, ln in open_ids.items() if oid not in resolved}
stranded = {oid: ln for oid, ln in still_open.items() if ln < keep_start}
if stranded:
    print(f"rotate_ledger: REFUSING — open DECISION/BLOCKED line(s) would be archived: {stranded}", file=sys.stderr)
    sys.exit(3)
PY

# --- 4) archive the block, verbatim, with its hash --------------------------
BLOCK_HASH=$(sed -n "1,$((KEEP_START - 1))p" "$LEDGER" | shasum -a 256 | cut -c1-16)
STAMP=$(date -u +%Y-%m-%dT%H:%MZ)
{
  if [ -f "$ARCHIVE" ]; then
    cat "$ARCHIVE"
    echo ""
  fi
  echo "── ROTATION $STAMP — entries through line $((KEEP_START - 1)) archived verbatim; block sha256[:16] = $BLOCK_HASH"
  sed -n "1,$((KEEP_START - 1))p" "$LEDGER"
} > "$ARCHIVE.tmp" && mv "$ARCHIVE.tmp" "$ARCHIVE"

# --- 5) write the new working head -------------------------------------------
# Open DECISION/BLOCKED lines older than the keep-window are COPIED FORWARD
# into the head under a standing section, so an open ask can never be
# archived away — the ask survives rotation until ruled.
OPEN_FORWARD=$(python3 - "$LEDGER" "$KEEP_START" <<'PY'
import sys, re
ledger, keep_start = sys.argv[1], int(sys.argv[2])
lines = open(ledger).read().split('\n')
in_fence = False
open_ids = {}
for i, l in enumerate(lines, 1):
    if l.strip().startswith('```'):
        in_fence = not in_fence
        continue
    if in_fence:
        continue
    for pat in (r'DECISION NEEDED (\S+?):', r'BLOCKED (\S+?):'):
        m = re.search(pat, l)
        if m and not m.group(1).startswith('<'):
            open_ids.setdefault(m.group(1), i)
resolved = set()
close_words = re.compile(r'RESOLVED|RULED|WITHDRAWN|SUPERSEDED', re.I)
go_words = re.compile(r'\bGO\b|\blanded\b', re.I)
for i, l in enumerate(lines, 1):
    for oid, opened_at in open_ids.items():
        if oid in l and i > opened_at and (close_words.search(l) or go_words.search(l)):
            resolved.add(oid)
for oid, ln in sorted(open_ids.items(), key=lambda kv: kv[1]):
    if oid not in resolved and ln < keep_start:
        print(lines[ln - 1])
PY
)
{
  sed -n "1,${HEADER_END}p" "$LEDGER"
  echo "## Archive pointer"
  echo ""
  echo "History lives in \`policy/LANES_ARCHIVE.md\` (append-only, verbatim)."
  echo "Last rotation: $STAMP; archived block sha256[:16] = $BLOCK_HASH."
  if [ -n "$OPEN_FORWARD" ]; then
    echo ""
    echo "## Open decisions carried forward (never archived until ruled)"
    echo ""
    echo "$OPEN_FORWARD"
  fi
  echo ""
  sed -n "${KEEP_START},${TOTAL_LINES}p" "$LEDGER"
} > "$LEDGER.tmp" && mv "$LEDGER.tmp" "$LEDGER"

NEW_BYTES=$(wc -c < "$LEDGER" | tr -d ' ')
OLD_BYTES=$(wc -c < "$ARCHIVE" | tr -d ' ')
echo "rotate_ledger: OK — working head now $NEW_BYTES bytes; archive $OLD_BYTES bytes; block hash $BLOCK_HASH"
