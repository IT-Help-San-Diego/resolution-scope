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
HDR_KT=$(grep -oE 'keytag[ =][0-9]+' "$ZONE" | head -1 | grep -oE '[0-9]+' || true)
if [ "${HDR_KT:-}" = "59829" ]; then
    bad "KEYTAG 59829 — the PUBLIC test-vector key is in this zone. FULL STOP (SPEC §4)."
else
    ok "keytag=${HDR_KT:-unknown} ≠ 59829 (test-vector tripwire clear)"
fi

# 3. Algorithm field: decimal values only, never a mnemonic.
#    pq.resolutionscope.com  — algo 18 only (strict)
#    pq-dualds.*             — algo 18 AND algo 8 both required; no others allowed
DKRR=$(grep -E 'IN[[:space:]]+(DNSKEY|RRSIG)[[:space:]]' "$ZONE" || true)
if [ "$ORIGIN" = "pq-dualds.resolutionscope.com" ]; then
    # Dual-algorithm fixture: must carry BOTH algo 18 and algo 8.
    HAS18=$(echo "$DKRR" | grep -c ' 18 ' || true)
    HAS8=$( echo "$DKRR" | grep -c ' 8 '  || true)
    if [ "$HAS18" -gt 0 ]; then
        ok "algo 18 (ML-DSA-44) present: ${HAS18} record(s)"
    else
        bad "no algo-18 DNSKEY/RRSIG — pq-dualds requires algo 18"
    fi
    if [ "$HAS8" -gt 0 ]; then
        ok "algo 8 (RSASHA256) present: ${HAS8} record(s)"
    else
        bad "no algo-8 DNSKEY/RRSIG — pq-dualds requires algo 8"
    fi
    # Reject any algorithm that is neither 8 nor 18.
    BADALGOS=$(echo "$DKRR" | grep -vE ' (8|18) ' || true)
    if [ -n "$BADALGOS" ]; then
        bad "DNSKEY/RRSIG with unexpected algorithm (expected only 8 or 18):"
        echo "$BADALGOS" | sed 's/^/    /'
    else
        ok "no unexpected algorithms in DNSKEY/RRSIG records"
    fi
else
    # Standard pq. zone: algorithm 18 only.
    if echo "$DKRR" | grep -qv ' 18 '; then
        bad "a DNSKEY/RRSIG line lacks decimal algorithm 18"
    else
        ok "all DNSKEY/RRSIG carry decimal 18"
    fi
fi
if grep -q 'MLDSA' "$ZONE"; then bad "mnemonic MLDSA found — parsers reject mnemonics"; else ok "no algorithm mnemonics"; fi

# 4. TXT char-strings ≤255 bytes each.
LONG=$(grep 'IN[[:space:]]*TXT' "$ZONE" | grep -oE '"[^"]*"' | awk '{ if (length($0)-2 > 255) print length($0)-2 }' | head -1 || true)
if [ -n "$LONG" ]; then bad "TXT char-string of $LONG bytes exceeds 255"; else ok "all TXT char-strings ≤ 255 bytes"; fi

# 4b. TXT strings must be pure ASCII and chunk splits on word boundaries.
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
        if a and b and a[-1] not in ' .!?;' and b[0] != ' ':
            # Escape clause: when the preceding chunk is at the 255-byte cap
            # and contains no space, the split was forced — no word boundary
            # exists in the window, so a hard cut is the only legal option.
            if len(a) == 255 and ' ' not in a:
                continue
            print(f"✗ TXT chunk split mid-word: …'{a[-12:]}' + '{b[:12:]}'…"); bad = True
if bad: sys.exit(1)
print("✓ TXT strings ASCII-clean, chunk splits on word boundaries")
EOF
[ $? -ne 0 ] && fail=1

# 5. NSEC bitmap honesty.
python3 - "$ZONE" <<'EOF' || fail=1
import sys, collections
zone = open(sys.argv[1]).read().splitlines()
present = collections.defaultdict(set)
nsec = {}
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

# 6. Whole-zone signing completeness (RFC 4035 §2.2).
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

# 11. In-bailiwick glue: every NS whose target is at or below $ORIGIN
#     must have a corresponding A or AAAA record in the zone file.
#     Out-of-bailiwick-only zones (e.g. pq-dualds → ns1.resolutionscope.com)
#     pass trivially — there is no glue to provide.
python3 - "$ZONE" "$ORIGIN" <<'EOF' || fail=1
import sys
zone_file, origin = sys.argv[1], sys.argv[2].rstrip('.').lower()
lines = open(zone_file).read().splitlines()
ns_targets = set()
addr_owners = set()
for l in lines:
    t = l.split()
    if len(t) < 5 or t[0].startswith(';'):
        continue
    rtype = t[3]
    if rtype == 'NS':
        ns_targets.add(t[4].rstrip('.').lower())
    elif rtype in ('A', 'AAAA'):
        addr_owners.add(t[0].rstrip('.').lower())
# In-bailiwick: target == origin or target ends with ".origin"
ib = sorted(ns for ns in ns_targets
            if ns == origin or ns.endswith('.' + origin))
if not ib:
    print(f"✓ check 11: no in-bailiwick NS — glue trivially passes "
          f"({len(ns_targets)} NS, all out-of-bailiwick)")
    sys.exit(0)
bad = False
for ns in ib:
    if ns not in addr_owners:
        print(f"✗ check 11: in-bailiwick NS '{ns}' has no A/AAAA glue in zone")
        bad = True
if bad:
    sys.exit(1)
print(f"✓ check 11: all {len(ib)} in-bailiwick NS have A/AAAA glue records")
EOF
[ $? -ne 0 ] && fail=1

# 12. NSEC3 absence: our PQ zones use NSEC (plain denial-of-existence).
#     NSEC3 / NSEC3PARAM records must not appear.  If NSEC3 were present
#     with opt-out (RFC 5155 §3.1.2, flags bit 0), unsigned delegations
#     could be injected without detection — reject outright.
N3=$(grep -cE 'IN[[:space:]]+(NSEC3|NSEC3PARAM)[[:space:]]' "$ZONE" || true)
if [ "$N3" -gt 0 ]; then
    bad "check 12: found $N3 NSEC3/NSEC3PARAM record(s) — zone must use plain NSEC"
    grep -E 'IN[[:space:]]+(NSEC3|NSEC3PARAM)[[:space:]]' "$ZONE" | head -3 | sed 's/^/    /'
else
    ok "check 12: no NSEC3/NSEC3PARAM — zone uses plain NSEC (correct)"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "WALL: ALL FILE-LEVEL CHECKS GREEN — proceed to serve + :5300 validator + engine run, then DS."
else
    echo "WALL: FAILURES ABOVE — do not publish."
    exit 1
fi
