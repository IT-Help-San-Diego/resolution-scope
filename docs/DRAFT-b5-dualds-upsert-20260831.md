# DRAFT — B5: Route 53 upserts for pq-dualds (NOT EXECUTED — TEMPLATE ONLY)

STATUS per hermes premise-check @588aed3: the pq-dualds B-plan document does NOT
yet exist in any reachable artifact (no zone, no KSK-8, wall has 8 checks).
Nothing here authorizes a build. The zone NAME and NS set below are template
assumptions to be verified against the actual B-plan when SciSpace exports it;
only the change-batch SHAPE is asserted. Values remain <FILL> until
hermes-computed keys exist.

Drafted by claude-code per relay instruction. The two DS rdata values MUST come
from hermes's computed KSK-18 and KSK-8 (fresh KMS keys per family rule — never
shared across zones). Sequencing per sign-first-DS-last: run ONLY after the
pq-dualds zone is served and verified on BOTH boxes (pqns + pqns2).

Hosted zone: resolutionscope.com — Z06861878ZCLQVLWIW76
TTLs: NS 3600 (specimen standard); DS 900 (post-Science-ruling standard).

`b5-dualds-change-batch.json`:
```json
{
  "Comment": "B5: pq-dualds delegation + dual-alg DS (18 + 8) — labeled specimen",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "pq-dualds.resolutionscope.com.",
        "Type": "NS",
        "TTL": 3600,
        "ResourceRecords": [
          { "Value": "pqns.resolutionscope.com." },
          { "Value": "pqns2.resolutionscope.com." }
        ]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "pq-dualds.resolutionscope.com.",
        "Type": "DS",
        "TTL": 900,
        "ResourceRecords": [
          { "Value": "<KSK18_KEYTAG> 18 2 <KSK18_SHA256_DIGEST_UPPERHEX>" },
          { "Value": "<KSK8_KEYTAG> 8 2 <KSK8_SHA256_DIGEST_UPPERHEX>" }
        ]
      }
    }
  ]
}
```

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z06861878ZCLQVLWIW76 \
  --change-batch file://b5-dualds-change-batch.json
```

Post-checks (both required before any ledger claim):
```bash
dig @ns-341.awsdns-42.com +norecurse pq-dualds.resolutionscope.com DS   # expect BOTH DS, TTL 900
dig @ns-341.awsdns-42.com +norecurse pq-dualds.resolutionscope.com NS   # expect referral, both NS
```

Notes: (1) both DS records ride ONE RRset — a single UPSERT, atomic; (2) corpus
filter must gain pq-dualds.resolutionscope.com BEFORE the zone goes live
(fixture-never-counts rule); (3) this specimen deliberately reproduces the
kochen-specker dual-alg DNSKEY size class — the EDNS/fragmentation behavior IS
the experiment; wall + battery vantages should record transport mode per query.
