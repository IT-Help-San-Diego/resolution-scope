#!/usr/bin/env bash
# check-seal-scheme-consistency.sh — the seal's self-consistency tripwire.
#
# WHY (foundation queue #3; the v5-birthday F1 lesson): when SEAL_SCHEME bumps,
# the KAT doctrine demands a byte-frozen known-answer test minted AT
# INTRODUCTION. The v5 bump almost shipped without one (2e's F1 — "nothing
# pins v5 BYTES today") and the guard that closed it lived in review comments,
# not in the tree. This script makes the invariant mechanical:
#
#   every scheme the engine names must have, in the same file:
#     1. a KAT test whose name contains the scheme's version token
#     2. a 128-hex-char frozen literal inside that test
#     3. (for non-current schemes) a frozen-builder arm that dispatches to it
#
# A scheme bump that forgets its KAT fails THIS check on the bump commit,
# not at review time, and not weeks later in production.
#
# Zero-dependency: grep + python3 stdlib only. Exit 0 = consistent;
# exit 1 = inconsistent (named reasons). Add to CI beside the citation
# boundary gate.

set -euo pipefail
REPO="$(git rev-parse --show-toplevel)"
SEAL="$REPO/engine/src/seal.rs"
fail=0

python3 - "$SEAL" <<'PY'
import re
import sys

seal_path = sys.argv[1]
src = open(seal_path).read()
problems = []

# 1) collect every scheme the engine names (SEAL_SCHEME*, v<N> in doc strings)
const_re = re.compile(r'pub const (SEAL_SCHEME\w*)\s*:\s*&str\s*=\s*"([^"]+)"')
schemes = {name: value for name, value in const_re.findall(src)}
if not schemes:
    problems.append("no SEAL_SCHEME constants found — is the path right?")
current = schemes.get("SEAL_SCHEME")
if not current:
    problems.append("SEAL_SCHEME (the current scheme) is missing")

for name, value in schemes.items():
    m = re.search(r"-v(\d+)$", value)
    if not m:
        problems.append(f"{name} = {value!r} does not end in -v<N>")
        continue
    ver = m.group(1)

    # 2) a KAT test naming this scheme version, with a 128-hex literal
    kat_re = re.compile(
        r"fn (v%s_known_answer[a-z_]*is_byte_frozen)\(\)" % re.escape(ver)
    )
    kat = kat_re.search(src)
    if not kat:
        # v1 was pre-KAT; only guard schemes >= 2 (v2 introduced resolver_identity)
        if int(ver) >= 2:
            if name == "SEAL_SCHEME":
                problems.append(
                    f"CURRENT scheme v{ver} has NO known-answer byte-frozen test — "
                    f"the KAT doctrine requires minting it AT INTRODUCTION "
                    f"(v{ver}_known_answer_seal_is_byte_frozen missing)"
                )
            else:
                problems.append(
                    f"retained scheme v{ver} ({name}) has no known-answer test; "
                    f"retained schemes stay re-derivable AND pinned"
                )
        continue
    # the test body must carry a 128-hex literal
    body = src[kat.start(): kat.start() + 3000]
    # join Rust line-continuation string literals: "...abc\
    #              def..." is ONE literal of abc+def
    # Robust join: pull every maximal hex run from the test body and
    # concatenate. KAT literals are split by Rust's backslash-newline
    # continuation with indent whitespace; concatenating all hex runs in
    # order reproduces the literal (the only other hex-ish tokens in a KAT
    # body are short, e.g. "0.0.0-kat", and cannot pollute a 128-hex check).
    parts = re.findall(r'[0-9a-f]{8,}', body)
    joined = "".join(parts)
    if len(joined) < 128:
        problems.append(
            f"{kat.group(1)} carries no full 128-hex frozen literal "
            f"(found {len(joined)} hex chars) — a KAT without its literal pins nothing"
        )

# 3) the current scheme must have a builder path: direct or via dispatch
if current:
    m = re.search(r"-v(\d+)$", current)
    if m:
        ver = m.group(1)
        dispatch = re.search(r"fn canonical_input_under_scheme[\s\S]{0,400}?", src)
        has_builder = (
            f"canonical_input_v{ver}" in src
            or re.search(r"SEAL_SCHEME_V\d\s*\|.*=>", src) is not None
        )
        if not has_builder and int(ver) >= 5:
            problems.append(
                f"current scheme v{ver} has no canonical_input_v{ver} builder or "
                f"dispatch arm — seals minted under it cannot be re-derived"
            )

# 4) prior schemes stay re-derivable: each retained constant is dispatched
for name, value in schemes.items():
    if name == "SEAL_SCHEME":
        continue
    m = re.search(r"-v(\d+)$", value)
    if not m:
        continue
    ver = m.group(1)
    if f'"{value}"' not in src.split("fn canonical_input_under_scheme", 1)[-1] and \
       f"SEAL_SCHEME_V{ver}" not in src.split("fn canonical_input_under_scheme", 1)[-1]:
        # v3/v4 share the frozen builder under dispatch; presence in the fn is the check
        seg = src.split("fn canonical_input_under_scheme", 1)
        if len(seg) == 2 and value not in seg[1][:400] and f"SEAL_SCHEME_V{ver}" not in seg[1][:400]:
            problems.append(
                f"retained scheme v{ver} is not dispatched in "
                f"canonical_input_under_scheme — its stored rows cannot re-derive"
            )

for p in problems:
    print(f"SEAL-SCHEME: {p}", file=sys.stderr)
sys.exit(1 if problems else 0)
PY
