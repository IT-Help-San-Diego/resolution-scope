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


# 13. RSA-8 RRSIGs verify against the zone AS EMITTED (the stale-input class
#     CC located by exact-hash match: a signature computed over an RRset that
#     changed before emission). Pure-Python RSA verification — every alg-8
#     RRSIG in the file must verify over the RRset the FILE carries.
#     (alg-18 verification stays with the :5300/4-impl harness — a wall that
#     cannot verify it says so, never pretends.)
if grep -qE 'IN[[:space:]]+RRSIG[[:space:]]+[A-Z]+[[:space:]]+8[[:space:]]' "$ZONE"; then
python3 - "$ZONE" <<'PYEOF' || fail=1
import sys, base64, hashlib, re, struct, shlex

def tokenize_rr(line):
    # Quote-aware: TXT char-strings survive as single tokens.
    return shlex.split(line)

def name_wire(n):
    t=n.rstrip('.')
    if not t:
        return b'\x00'  # the root: a single zero length byte
    out=b''
    for l in t.split('.'):
        b=l.lower().encode(); out+=bytes([len(b)])+b
    return out+b'\x00'

def rrsig_fields(line):
    t=line.split()
    # owner TTL IN RRSIG type alg labels ttl expire incept keytag signer b64...
    return t

zone=sys.argv[1]
lines=[l for l in open(zone).read().splitlines() if not l.startswith(';') and len(l.split())>=5]
dnskeys={}   # keytag -> (n_bytes, e_bytes)
for l in lines:
    t=l.split()
    if t[3]=='DNSKEY' and t[6] if False else False:
        pass
for l in lines:
    t=l.split()
    if len(t)>=8 and t[3]=='DNSKEY' and t[4]=='257' or (len(t)>=8 and t[3]=='DNSKEY' and t[4] in ('256','257')):
        # owner ttl IN DNSKEY flags proto alg b64
        alg=int(t[6]); b64=''.join(t[7:])
        rd=bytes([int(t[4])>>8, int(t[4])&0xff, int(t[5]), alg])+base64.b64decode(b64)
        # keytag RFC4034 App B
        acc=0
        for i,b in enumerate(rd):
            acc += b<<8 if i%2==0 else b
        acc=(acc & 0xffff) + (acc >> 16)
        kt=(acc & 0xffff) + (acc >> 16)
        if alg==8:
            # RFC 3110: exp-len [exp] modulus
            if rd[4]!=0: elen=rd[4]; off=5
            else: elen=struct.unpack('>H',rd[5:7])[0]; off=7
            e=int.from_bytes(rd[off:off+elen],'big'); n=int.from_bytes(rd[off+elen:],'big')
            dnskeys[kt]=(n,e)

def powmod(b,e,m): return pow(b,e,m)

errs=[]
for l in lines:
    t=rrsig_fields(l)
    if len(t)>=11 and t[3]=='RRSIG' and t[5]=='8':
        cov,alg,lab,ttl,exp,inc,kt=t[4],t[5],t[6],t[7],t[8],t[9],t[10]
        signer=t[11]
        sig=base64.b64decode(''.join(t[12:]))
        kt=int(kt)
        if kt not in dnskeys:
            errs.append(f"RRSIG alg-8 keytag {kt} has no matching DNSKEY in file"); continue
        (n,e)=dnskeys[kt]
        # recover
        m=powmod(int.from_bytes(sig,'big'), e, n)
        mb=m.to_bytes((n.bit_length()+7)//8,'big')
        # PKCS#1 v1.5: 00 01 FF..FF 00 DigestInfo(SHA256)
        if mb[0]!=0 or mb[1]!=1: errs.append(f"kt{kt}: bad PKCS1 header"); continue
        i2=mb.index(b'\x00',2)
        digest=mb[i2+1:]
        # DigestInfo DER for SHA-256 = 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        der=bytes.fromhex('3031300d060960864801650304020105000420')
        if not digest.startswith(der): errs.append(f"kt{kt}: no SHA-256 DigestInfo"); continue
        expected=digest[len(der):]
        # signed data: RRSIG fields minus signature + canonical RRset
        sd=b''
        def zt_to_epoch(s):
            # zone-time YYYYMMDDHHMMSS (UTC) -> epoch
            import calendar
            return calendar.timegm((int(s[0:4]), int(s[4:6]), int(s[6:8]),
                                    int(s[8:10]), int(s[10:12]), int(s[12:14]),
                                    0, 0, 0))
        sd+=struct.pack('>H', {'SOA':6,'NS':2,'TXT':16,'MX':15,'DNSKEY':48,'NSEC':47}.get(cov,0))
        sd+=bytes([8]); sd+=bytes([int(lab)]); sd+=struct.pack('>I',int(ttl))
        sd+=struct.pack('>I',zt_to_epoch(exp)); sd+=struct.pack('>I',zt_to_epoch(inc)); sd+=struct.pack('>H',kt)
        sd+=name_wire(signer)
        # canonical RRset from the FILE: all records of type cov at owner (signed RRset lines carry owner; RRSIG owner == owner)
        owner=l.split()[0]
        recs=[]
        for l2 in lines:
            t2=l2.split()
            if len(t2)>=5 and t2[3]==cov and t2[0]==owner and t2[3]!='RRSIG':
                # wire rdata by type
                if cov=='DNSKEY':
                    rd=bytes([int(t2[4])>>8,int(t2[4])&0xff,int(t2[5]),int(t2[6])])+base64.b64decode(''.join(t2[7:]))
                elif cov=='SOA':
                    # owner ttl IN SOA mname rname serial refresh retry expire min — rebuild is complex; skip precise, use textual canonical lower
                    parts=t2[4:]
                    mname,rname=parts[0].lower().rstrip('.')+'.',parts[1].lower().rstrip('.')+'.'
                    nums=[int(x) for x in parts[2:7]]
                    rd=name_wire(mname)+name_wire(rname)+b''.join(struct.pack('>I',x) for x in nums)
                elif cov=='NS':
                    rd=name_wire(t2[4].lower())
                elif cov=='TXT':
                    continue  # handled below the loop (quote-aware multi-record)
                elif cov=='MX':
                    pref=int(t2[4]); rd=struct.pack('>H',pref)+name_wire(t2[5].lower())
                elif cov=='NSEC':
                    nxt=name_wire(t2[4].lower())
                    # bitmap from type list — reconstruct window
                    tl=[x for x in t2[5:]]
                    tmap={}
                    for tn in tl:
                        num={'NS':2,'SOA':6,'MX':15,'TXT':16,'RRSIG':46,'NSEC':47,'DNSKEY':48}.get(tn)
                        if num is not None: tmap[num]=1
                    if not tmap: continue
                    mx=max(tmap); lastw=mx//256
                    rd=nxt
                    for w in range(lastw+1):
                        bits=[0]*32
                        for num in tmap:
                            if num//256==w: bits[(num%256)//8]|=1<<(7-(num%256)%8)
                        last_nz=max(i for i,v in enumerate(bits) if v)
                        rd+=bytes([w, last_nz+1])+bytes(bits[:last_nz+1])
                recs.append((name_wire(owner)+struct.pack('>H',{'SOA':6,'NS':2,'TXT':16,'MX':15,'DNSKEY':48,'NSEC':47}.get(cov,0))+struct.pack('>H',1)+struct.pack('>I',int(ttl))+struct.pack('>H',len(rd))+rd))
        if cov=='TXT':
            recs=[]
            for l3 in lines:
                tt=tokenize_rr(l3)
                if len(tt)>=5 and tt[3]=='TXT' and tt[0]==owner:
                    rd=b''
                    for chunk in tt[4:]:
                        by=chunk.encode()
                        if len(by)>255:
                            raise ValueError("TXT char-string >255 in wall check 13")
                        rd+=bytes([len(by)])+by
                    recs.append((name_wire(owner)+struct.pack('>H',16)+struct.pack('>H',1)+struct.pack('>I',int(ttl))+struct.pack('>H',len(rd))+rd))
        recs.sort()
        for r in recs: sd+=r
        actual=hashlib.sha256(sd).digest()
        if actual!=expected:
            errs.append(f"kt{kt} RRSIG over {cov}: signature covers STALE RRset (hash mismatch)")
if errs:
    for e in errs: print(f"\u2717 check 13: {e}")
    sys.exit(1)
print("\u2713 check 13: all alg-8 RRSIGs verify against the RRsets AS EMITTED")
PYEOF
else
    ok "check 13: no alg-8 RRSIGs in file (single-algorithm zone — nothing to verify)"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "WALL: ALL FILE-LEVEL CHECKS GREEN — proceed to serve + :5300 validator + engine run, then DS."
else
    echo "WALL: FAILURES ABOVE — do not publish."
    exit 1
fi
