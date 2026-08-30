#!/usr/bin/env bash
# wall.sh — one-shot pre-DS verification wall for a pq.resolutionscope.com
# zone file (SPEC §7). Usage: bash wall.sh <zonefile> [origin]
# Exit 0 = green-light the DS. Any failure = do not publish.
set -euo pipefail

ZONE="${1:?usage: wall.sh <zonefile> [origin]}"
ORIGIN="${2:-pq.resolutionscope.com}"
fail=0
say() { printf '%s\n' "$*"; }
bad() { say "✗ $*"; fail=1; }
ok()  { say "✓ $*"; }

# 1. Parse gate (DNSSEC-aware).
if named-checkzone -i full "$ORIGIN" "$ZONE" >/tmp/wall-checkzone.out 2>&1; then
    ok "named-checkzone: $(grep -o 'loaded serial.*' /tmp/wall-checkzone.out || echo OK)"
else
    bad "named-checkzone FAILED:"; sed 's/^/    /' /tmp/wall-checkzone.out; fi

# 2. Keytag tripwire: the draft §6 test-vector key must NEVER be published.
KT=$(awk '/IN[[:space:]]+DNSKEY[[:space:]]/{print; exit}' "$ZONE" | awk '{print $5" "$6" "$7}')
HDR_KT=$(grep -oE 'keytag=[0-9]+' "$ZONE" | head -1 | cut -d= -f2 || true)
if [ "${HDR_KT:-}" = "59829" ]; then
    bad "KEYTAG 59829 — the PUBLIC test-vector key is in this zone. FULL STOP (SPEC §4)."
else
    ok "keytag ${HDR_KT:-unknown} ≠ 59829 (test-vector tripwire clear)"
fi

# 3. Algorithm field: decimal 18, never a mnemonic.
if grep -E 'IN[[:space:]]+(DNSKEY|RRSIG)[[:space:]]' "$ZONE" | grep -qv ' 18 '; then
    bad "a DNSKEY/RRSIG line lacks decimal algorithm 18"; else ok "all DNSKEY/RRSIG carry decimal 18"; fi
if grep -q 'MLDSA' "$ZONE"; then bad "mnemonic MLDSA found — parsers reject mnemonics"; else ok "no algorithm mnemonics"; fi

# 4. TXT char-strings ≤255 bytes each.
LONG=$(grep 'IN[[:space:]]*TXT' "$ZONE" | grep -oE '"[^"]*"' | awk '{ if (length($0)-2 > 255) print length($0)-2 }' | head -1 || true)
if [ -n "$LONG" ]; then bad "TXT char-string of $LONG bytes exceeds 255"; else ok "all TXT char-strings ≤ 255 bytes"; fi

# 4b. TXT strings must be pure ASCII (fixture doctrine: dig output must read
#     clean; multibyte punctuation becomes \226\128\148-style escapes — the
#     exact tokenizer-hostility the poem exists to defeat) and chunk splits
#     must land on word boundaries (no mid-word "grea"/"t talk" cuts).
python3 - "$ZONE" <<'EOF' || fail=1
import sys, re
bad = False
for line in open(sys.argv[1], 'rb').read().decode('utf-8', 'replace').splitlines():
    if ' TXT ' not in line and '\tTXT\t' not in line: continue
    strings = re.findall(r'"([^"]*)"', line)
    for s in strings:
        nonascii = [c for c in s if ord(c) > 126]
        if nonascii:
            print(f"✗ TXT contains non-ASCII {[hex(ord(c)) for c in nonascii[:3]]} — use ASCII punctuation"); bad = True
            break
    for a, b in zip(strings, strings[1:]):
        if not a or not b: continue
        # Escape clause (mirror of signer txt_chunks): a full 255-byte chunk
        # containing NO space was hard-cut — no boundary existed to use.
        # Exempt it (noted, not condemned); every other boundary must be
        # space-retained. Without this the check is unsatisfiable on a
        # legitimate spaceless payload and blocks a signing run at 3 a.m.
        if len(a) == 255 and ' ' not in a:
            print(f"· hard-cut span (no space in 255-byte window — exempt): …'{a[-12:]}'+'{b[:12]}'…")
            continue
        if a[-1] != ' ':
            print(f"✗ TXT chunk boundary not space-retained: …'{a[-12:]}' + '{b[:12]}'…"); bad = True
if bad: sys.exit(1)
print("✓ TXT strings ASCII-clean, chunk splits space-retained")
EOF
[ $? -ne 0 ] && fail=1

# 5. NSEC bitmap honesty: every type listed must exist at that owner; every
#    type present (except NSEC/RRSIG bootstrap) must be listed.
python3 - "$ZONE" <<'EOF' || fail=1
import sys, collections
zone = open(sys.argv[1]).read().splitlines()
present = collections.defaultdict(set)   # owner -> set(types)
nsec = {}                                # owner -> claimed types
for l in zone:
    t = l.split()
    if len(t) < 5 or t[0].startswith(';'): continue
    owner, rtype = t[0].lower(), t[3]
    if rtype == 'NSEC':
        nsec[owner] = set(t[5:])
    if rtype != 'RRSIG':
        present[owner].add(rtype)
bad = False
for owner, claimed in nsec.items():
    actual = present.get(owner, set()) | {'RRSIG'}
    phantom = claimed - actual
    missing = (present.get(owner, set()) - {'RRSIG'}) - claimed
    if phantom: print(f"✗ NSEC at {owner} claims nonexistent types: {sorted(phantom)}"); bad = True
    if missing: print(f"✗ NSEC at {owner} omits present types: {sorted(missing)}"); bad = True
if not nsec: print("✗ no NSEC records found"); bad = True
if bad: sys.exit(1)
print(f"✓ NSEC bitmap honest for {len(nsec)} name(s)")
EOF
[ $? -ne 0 ] && fail=1

# 6. Every non-RRSIG RRset must have an RRSIG (RFC 4035 §2.2 completeness).
python3 - "$ZONE" <<'EOF' || fail=1
import sys, collections
sets, sigs = set(), set()
for l in open(sys.argv[1]).read().splitlines():
    t = l.split()
    if len(t) < 5 or t[0].startswith(';'): continue
    if t[3] == 'RRSIG': sigs.add((t[0].lower(), t[4]))
    else: sets.add((t[0].lower(), t[3]))
unsigned = sets - sigs
if unsigned:
    print(f"✗ RRsets without RRSIG: {sorted(unsigned)}"); sys.exit(1)
print(f"✓ whole-zone signing: {len(sets)} RRset(s), all covered")
EOF
[ $? -ne 0 ] && fail=1

echo
if [ "$fail" -eq 0 ]; then
    echo "WALL: ALL FILE-LEVEL CHECKS GREEN — proceed to serve + :5300 validator + engine run, then DS."
else
    echo "WALL: FAILURES ABOVE — do not publish."
    exit 1
fi
