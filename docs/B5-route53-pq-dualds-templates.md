# B5 Route 53 Upsert Drafts — pq-dualds.resolutionscope.com
# STATUS: TEMPLATES ONLY — B3 (the dual-signed zone) DOES NOT EXIST YET.
# Every value below is a placeholder keyed to the hermes build that will
# produce it. Execute ONLY after: keygen runs, signer extended (alg-8 path),
# zone built + wall green (dual-mode check 3) + :5300 validates + deployed.
#
# The SciSpace design (SCISPACE_lanes_n_science_corrected.md, 2026-08-30T18:35Z)
# calls for: KSK-8 RSA-SHA256 + KSK-18 ML-DSA-44, every RRset dual-RRSIG'd,
# TWO DS records at the parent, TXT self-declaration dual-sign=YES +
# rfc6840-5.11=STRIP-ATTACK-VULNERABLE, corpus-excluded=YES.
#
# INTEGRITY FLAG (recorded in the ledger): SciSpace's drop carried a LANES
# entry claiming pq-dualds was already live at serial 2026083103 on both
# boxes — that serial is pq2's; the receipts were misattributed. Measured:
# no dualds zone on either auth box, no dualds RRs in Route 53, no alg-8
# path in the signer. The spec is sound; the "B3 CONFIRMED" entry is not.

ZID=Z06861878ZCLQVLWIW76   # resolutionscope.com hosted zone (parent)

# Step 1 — NS delegation + glue for the fixture's own auth box (as designed,
# pqns serves it; NO separate glue needed — pqns lives in the parent zone):
cat > /tmp/b5-ns.json <<EOF
{"Comment":"pq-dualds delegation (dual-DS migration specimen, SciSpace design 2026-08-30T18:35Z)",
 "Changes":[
  {"Action":"UPSERT","ResourceRecordSet":{"Name":"pq-dualds.resolutionscope.com","Type":"NS","TTL":3600,
   "ResourceRecords":[{"Value":"pqns.resolutionscope.com"},{"Value":"pqns2.resolutionscope.com"}]}},
  {"Action":"UPSERT","ResourceRecordSet":{"Name":"pq-dualds.resolutionscope.com","Type":"TXT","TTL":3600,
   "ResourceRecords":[{"Value":"\"v=spf1 -all\""}]}},
  {"Action":"UPSERT","ResourceRecordSet":{"Name":"_dmarc.pq-dualds.resolutionscope.com","Type":"TXT","TTL":3600,
   "ResourceRecords":[{"Value":"\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;\""}]}},
  {"Action":"UPSERT","ResourceRecordSet":{"Name":"*._domainkey.pq-dualds.resolutionscope.com","Type":"TXT","TTL":3600,
   "ResourceRecords":[{"Value":"\"v=DKIM1; p=\""}]}},
  {"Action":"UPSERT","ResourceRecordSet":{"Name":"pq-dualds.resolutionscope.com","Type":"MX","TTL":3600,
   "ResourceRecords":[{"Value":"0 ."}]}}
 ]}
EOF
aws route53 change-resource-record-sets --hosted-zone-id $ZID --change-batch file:///tmp/b5-ns.json

# Step 2 — THE DUAL DS (only after the zone serves + :5300 validates):
# KSK-18 keytag/digest and KSK-8 keytag/digest come from the build's own
# output — the signer prints them; keytag computed per RFC 4034 App. B,
# digest = SHA-256(owner | DNSKEY RDATA), verified by an independent
# re-derivation before publish (the pq2 discipline).
cat > /tmp/b5-ds.json <<EOF
{"Comment":"pq-dualds DUAL DS — the migration state no live specimen holds (SciSpace design)",
 "Changes":[
  {"Action":"UPSERT","ResourceRecordSet":{"Name":"pq-dualds.resolutionscope.com","Type":"DS","TTL":900,
   "ResourceRecords":[
     {"Value":"<KSK18_KEYTAG> 18 2 <KSK18_SHA256_DIGEST>"},
     {"Value":"<KSK8_KEYTAG> 8 2 <KSK8_SHA256_DIGEST>"}
   ]}}
 ]}
EOF
aws route53 change-resource-record-sets --hosted-zone-id $ZID --change-batch file:///tmp/b5-ds.json

# KEYTAG/DIGEST placeholders are filled from:
#   signer output line "; DNSKEY keytag=N DS=<hex>" (KSK-18)
#   the KSK-8 build's equivalent output (alg-8 path does not exist yet —
#   REQUIRED BUILD: RSA-SHA256 keygen + dual-RRSIG signing mode in the
#   Rust signer; Route 53 managed-KSK cannot serve a child zone we host)
# DS TTL 900 per the CC-adjudicated visibility ruling.

# RESEARCH ACCEPTANCE (the question the specimen answers, per the design):
#   (a) validate via alg-8 (expected — :5300 + Cloudflare + Google show AD)
#   (b) attempt alg-18 (unexpected)
#   (c) SERVFAIL (broken)
#   (d) silent insecure downgrade (unexpected)
# Measure from :5300 + Paris + Mac the day the DS pair lands. The
# RFC 6840 §5.11 strip-attack surface (strip alg-18 RRSIG → zone still
# validates via alg-8, no alarm) is the LABELED phenomenon, not a defect
# of the specimen.
