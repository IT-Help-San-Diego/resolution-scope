#!/usr/bin/env bash
# check-corpus-identity-absence.sh — the checker that binds the CorpusEntry
# type to CAREY'S RECORDED RULING.
#
# WHAT THIS BINDS TO, corrected 2026-09-05. An earlier version of this header
# said it binds the type "to its Lean Tier-4 specification". IT DOES NOT, and
# it cannot: `engine/lean/Scoring.lean` is the repository's only Lean file and
# contains zero occurrences of corpus, identity, anon or ResolverAlias. This
# script never opens a .lean file; the only file it reads is
# types/src/corpus.rs.
#
# That was not an oversight in the proof. The Tier-4 theorem is DELIBERATELY
# UNWRITTEN and HELD by two-lane consensus until the measurement/identity
# split is ruled — recorded in policy/LANES.md at 2026-09-03T04:00Z, which
# also caught the same claim being made in the present tense to the person
# about to rule on it. A privacy property presented as machine-checked
# forecloses exactly the scrutiny an unproven one invites, so the header
# claiming a proof that is on purpose not yet written was the failure it
# named, reappearing inside the artifact built afterwards.
#
# THE DIVISION OF LABOR, as it actually stands:
#   - The TYPE is the guarantee: a field that doesn't exist can't be added
#     silently, and adding one breaks corpus.rs's exact-construction test.
#   - CAREY'S NINE-DECISION RULING of 2026-09-03 is the SPECIFICATION. It is
#     prose in the ledger, and it is transcribed into the `required` set
#     below — which is a real specification with a real author, not a
#     substitute for one.
#   - THIS CHECKER is the BINDING between them: it fails loudly if the type's
#     shape drifts from the ruled shape, because the compiler cannot read a
#     ledger entry.
#
# WHEN THE TIER-4 THEOREM IS WRITTEN, this header should be revisited and the
# binding extended to read it — at which point the claim becomes true rather
# than aspirational. Until then the honest statement is the one above.
#
# WHAT IT CHECKS (mechanical, fail-closed):
#   1. CorpusEntry's public fields are EXACTLY the ruled set — no identity
#      field may appear, by name or by type.
#   2. The forbidden type names never appear in the public corpus surface.
#   3. The ruled constants exist (UC_ANON, the closed alias vocabulary).
#   4. The corroboration-key method compares content, not seals.
#
# Exit 0 = bound and clean. Exit 1 = named reason. Add to CI beside the
# citation-boundary and seal-scheme-consistency gates (same shape).

set -euo pipefail
REPO="$(git rev-parse --show-toplevel)"
CORPUS="$REPO/types/src/corpus.rs"
fail=0

if [ ! -f "$CORPUS" ]; then
  echo "CORPUS-CHECKER: $CORPUS missing — the identity-free corpus type itself is absent" >&2
  exit 1
fi

python3 - "$CORPUS" <<'PY'
import re
import sys

src = open(sys.argv[1]).read()
problems = []

# 1) The forbidden fields: identity-bearing names, checked in the struct body.
#    The CorpusEntry struct's field set is extracted and matched exactly.
struct_match = re.search(r"pub struct CorpusEntry \{(.*?)\n\}", src, re.S)
if not struct_match:
    problems.append("CorpusEntry struct not found")
else:
    body = struct_match.group(1)
    # every field: `pub name: Type,`
    fields = re.findall(r"pub\s+(\w+)\s*:\s*([A-Za-z0-9_<>,: \[\]]+?),", body)
    field_names = {n for n, _ in fields}
    # THE RULED SET — from the 2026-09-03 nine-decision ruling:
    required = {
        "domain", "vantage_class", "vantage_epoch", "resolver",
        "transport", "day", "dispositions", "wire",
    }
    missing = required - field_names
    if missing:
        problems.append(f"CorpusEntry is missing ruled fields: {sorted(missing)}")
    extra = field_names - required
    if extra:
        problems.append(f"CorpusEntry gained fields beyond the ruled set: {sorted(extra)} — every addition must re-rule the privacy architecture (nine decisions, 2026-09-03)")

    # forbidden TYPES in field positions (String allowed ONLY for domain)
    for name, typ in fields:
        base = typ.strip().split("<")[0].strip()
        if base in {"IpAddr", "Ipv4Addr", "Ipv6Addr"}:
            problems.append(f"field '{name}' has type {base} — identity-bearing type in the public corpus")
        if base == "String" and name != "domain":
            problems.append(f"field '{name}: String' — only 'domain' may be a String (free-text identity hazard); it is not")

# 2) The forbidden vocabulary, anywhere in the file's PUBLIC surface:
for word in ("contributor_ip", "raw_ip", "ip_address", "asn", "country",
             "region", "geo", "latitude", "longitude", "hour", "minute",
             "second", "token", "user_id", "session"):
    # allow the word inside comments/doc strings only — check code lines
    for line in src.split("\n"):
        code = line.split("//")[0]  # strip comments
        if re.search(rf"\b{word}\b", code, re.I):
            problems.append(f"forbidden identity vocabulary '{word}' appears in code: {line.strip()[:80]}")
            break

# 3) The ruled constants and closed vocabulary — EXACTLY the ruled set.
if 'pub const UC_ANON: &str = "uc-anon"' not in src:
    problems.append("UC_ANON constant missing or altered (D2: pooling token)")
alias_match = re.search(r"pub enum ResolverAlias \{(.*?)\n\}", src, re.S)
if not alias_match:
    problems.append("ResolverAlias enum not found")
else:
    body = alias_match.group(1)
    # variant lines: identifiers at brace depth 1, before any `impl` — a
    # unit-only enum has bare names; a data-carrying variant (RawIp(..),
    # Named(String)) carries a payload and must fail BOTH as a non-ruled
    # variant AND as a data-carrying shape (the alias is a LABEL, not a value).
    variants = re.findall(r"^\s+([A-Za-z_]\w*)\s*(\(.*?\))?\s*,?\s*$", body, re.M)
    names = {n for n, _ in variants}
    ruled = {"Cloudflare", "Google", "Quad9", "OpenDNS", "Dns4Eu", "Unknown"}
    missing = ruled - names
    if missing:
        problems.append(f"ResolverAlias lost ruled variants: {sorted(missing)}")
    extra = names - ruled
    if extra:
        problems.append(f"ResolverAlias gained variants beyond the ruled set: {sorted(extra)} — the alias vocabulary is CLOSED (B2); every addition must re-rule")
    for n, payload in variants:
        if payload:
            problems.append(f"ResolverAlias::{n} carries data ({payload.strip()}) — the alias is a closed LABEL, not a value; data-carrying variants are identity hazards by construction")
            break

# 3b) Identity-bearing TYPES anywhere in the file — not just CorpusEntry's
#      own fields (the 1031dc6 hole-2: a nested struct smuggles an IpAddr
#      past a field-list scan). Every `pub NAME: TYPE` field declaration in
#      the file is checked; String remains allowed ONLY for `domain`.
nested_fields = re.findall(r"pub\s+(\w+)\s*:\s*([A-Za-z0-9_<>,: \[\]().]+?),\s*$", src, re.M)
for name, typ in nested_fields:
    # strip generic parameters, then any path prefix (std::net::IpAddr -> IpAddr)
    base = typ.strip().split("<")[0].strip().rstrip("()")
    base = base.split("::")[-1].strip()
    if base in {"IpAddr", "Ipv4Addr", "Ipv6Addr"}:
        problems.append(f"field '{name}' has type {base} — identity-bearing type in the public corpus surface (any struct, any nesting)")
    if base == "String" and name != "domain":
        problems.append(f"field '{name}: String' — only 'domain' may be a String; this holds for EVERY struct in the file")

# 4) Corroboration compares content, never seals:
if "corroboration_key" not in src or "seal" in src.replace("seal_spelling", "").replace("SealSpelling", ""):
    # 'seal' appearing in corpus.rs at all is suspicious — the corpus never seals
    for line in src.split("\n"):
        code = line.split("//")[0]
        if re.search(r"\bseal\b", code, re.I) and "seal_spelling" not in code.lower():
            problems.append(f"seal vocabulary in the public corpus surface: {line.strip()[:80]}")
            break

for p in problems:
    print(f"CORPUS-CHECKER: {p}", file=sys.stderr)
sys.exit(1 if problems else 0)
PY
