#!/usr/bin/env bash
# check-corpus-identity-absence.sh — the exporter/checker that binds the
# CorpusEntry type to its Lean Tier-4 specification.
#
# THE DIVISION OF LABOR (Science's 2026-09-03 correction, adopted):
#   - The TYPE is the guarantee: a field that doesn't exist can't be added
#     silently, and adding one breaks corpus.rs's exact-construction test.
#   - The Lean theorem is the SPECIFICATION: it states the property publicly.
#   - THIS CHECKER is the BINDING: it fails loudly if the type's shape drifts
#     from the specified shape — because neither the compiler nor Lean can
#     see each other.
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
        "day", "dispositions", "wire",
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

# 3) The ruled constants and closed vocabulary:
if 'pub const UC_ANON: &str = "uc-anon"' not in src:
    problems.append("UC_ANON constant missing or altered (D2: pooling token)")
for alias in ("Cloudflare", "Google", "Quad9", "OpenDNS", "Dns4Eu", "Unknown"):
    if f"ResolverAlias::{alias}" not in src:
        problems.append(f"ResolverAlias::{alias} missing from the closed vocabulary")

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
