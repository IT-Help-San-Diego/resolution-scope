#!/usr/bin/env bash
# check-lean-pins.sh — every theorem's axiom set is audited, directly or
# transitively, and every pin actually ASSERTS rather than prints.
#
# WHY THIS EXISTS. Scoring.lean pins each public theorem's axiom set with
# `#guard_msgs` + `#print axioms`, so a proof that starts depending on a new
# axiom fails at `lean`. Nothing enforced COVERAGE: that a theorem HAS a pin.
# Measured 2026-09-05, not reasoned: appending a twentieth theorem with no pin
# and running the CI job's exact command, `lean -DwarningAsError=true`, exits
# 0. `lean` cannot know a project convention, and no other job or script in
# this repository mentions the pins at all.
#
# WHAT THE FIRST DRAFT OF THIS GATE GOT WRONG, kept here because it is the
# reason the rule below is shaped the way it is. It required EVERY theorem to
# carry its own pin, and immediately failed on a clean main, naming four
# `private theorem`s. That was not a defect: `#print axioms` is TRANSITIVE.
# Measured by mutation — replacing the proof of the private lemma
# `filter_eq_nil_of_all_false` with `sorry` makes the PINNED public theorem
# `empty_surface_is_none` fail its own `#guard_msgs`, its axiom set moving from
# [propext] to [propext, sorryAx]. So private helpers are audited THROUGH the
# theorems that use them, and a gate demanding individual pins would have
# failed a correct tree.
#
# THE RULE, therefore:
#   - every PUBLIC theorem carries its own pin
#   - every PRIVATE theorem is reachable from some pinned theorem, so its
#     axioms surface in a pinned set; an unreachable one is audited by nothing
#   - every pin is wrapped in `#guard_msgs` (an unwrapped `#print axioms`
#     PRINTS the axiom set and passes whatever it is, which looks like an
#     audit and is not one)
#   - no `sorry` in code
#   - and it fails closed if it finds no theorems at all
#
# Usage: check-lean-pins.sh [path/to/Scoring.lean]

set -uo pipefail
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "FAIL: not inside a git work tree — refusing to run against an unknown source" >&2; exit 2; }
SRC="${1:-$ROOT/engine/lean/Scoring.lean}"
[ -f "$SRC" ] || { echo "FAIL: no such Lean source: $SRC" >&2; exit 2; }

python3 - "$SRC" <<'PYEOF'
import re, sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text()

# COMMENTS ARE NOT CODE. Both probe errors this gate's author made the same day
# were matches on prose: "sorry" inside a quoted commit message, and an
# identifier regex that stopped at a namespace dot. Strip comments; allow dots.
nb = re.sub(r'/-.*?-/', '', src, flags=re.S)
nb = "\n".join(re.sub(r'--.*$', '', l) for l in nb.split("\n"))
lines = nb.split("\n")
ID = r"[A-Za-z_][A-Za-z0-9_.']*"
DECL = re.compile(rf"^\s*(private\s+|protected\s+)?(?:@\[[^\]]*\]\s*)?(theorem|lemma)\s+({ID})")

decls, order = {}, []
for i, l in enumerate(lines):
    m = DECL.match(l)
    if m:
        name = m.group(3).split('.')[-1]
        decls[name] = {"private": bool(m.group(1)), "start": i, "body": ""}
        order.append(name)
for k, name in enumerate(order):
    end = decls[order[k+1]]["start"] if k+1 < len(order) else len(lines)
    decls[name]["body"] = "\n".join(lines[decls[name]["start"]:end])

pins = [x.split('.')[-1] for x in re.findall(rf'#print\s+axioms\s+({ID})', nb)]
fails = []

if not decls:
    fails.append("found ZERO theorems — the parser and the file disagree, or the file moved")

# public theorems must be pinned; stale pins must not exist
for name, d in decls.items():
    if not d["private"] and name not in pins:
        fails.append(f"public theorem '{name}' has no `#print axioms` pin — its axiom set is unaudited")
for x in pins:
    if x not in decls:
        fails.append(f"`#print axioms {x}` names nothing this file proves — a stale pin audits a theorem that no longer exists")

# private theorems must be REACHABLE from a pinned theorem, transitively
reach, frontier = set(p for p in pins if p in decls), [p for p in pins if p in decls]
while frontier:
    cur = frontier.pop()
    for other in decls:
        if other in reach:
            continue
        if re.search(rf"(^|[^A-Za-z0-9_.']){re.escape(other)}([^A-Za-z0-9_']|$)", decls[cur]["body"]):
            reach.add(other); frontier.append(other)
for name, d in decls.items():
    if d["private"] and name not in reach:
        fails.append(f"private theorem '{name}' is unpinned AND unreachable from any pinned theorem — nothing audits its axioms")

# every pin must ASSERT, not print
for i, l in enumerate(lines):
    if '#print axioms' in l:
        if '#guard_msgs' not in "\n".join(lines[max(0, i-3):i+1]):
            m = re.search(rf'#print\s+axioms\s+({ID})', l)
            fails.append(f"pin for '{m.group(1) if m else '?'}' at line {i+1} is not wrapped in `#guard_msgs` — it PRINTS the axiom set instead of ASSERTING it")

for i, l in enumerate(lines):
    if re.search(r"(^|[^A-Za-z_])sorry([^A-Za-z_]|$)", l):
        fails.append(f"`sorry` in code at line {i+1} — an admitted goal is not a proof")

if fails:
    for f in fails: print("FAIL: " + f, file=sys.stderr)
    print(f"check-lean-pins: {len(fails)} failure(s)", file=sys.stderr)
    raise SystemExit(1)
pub = sum(1 for d in decls.values() if not d["private"])
priv = len(decls) - pub
print(f"check-lean-pins: OK — {pub} public theorems each pinned, {priv} private reachable from a pin, {len(pins)} pins all #guard_msgs-wrapped, no sorry")
PYEOF
