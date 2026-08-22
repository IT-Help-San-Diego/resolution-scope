# Arm 2 — RFC known-answer vectors

**Status:** corpus drafted, §-citations verified against current RFC text
(2026-08-21, rfc-editor.org) by Hermes, then independently re-verified by
**SciSpace** (2026-08-22) reading all 9 RFCs at the byte level. SciSpace
confirmed the two original corrections AND found eight more §-level
imprecisions (SPF qualifier semantics, DMARC p= tag location, CDS match/differ
sections). All eight verified first-hand against the RFC text and corrected
below. Net: the corpus is now section-accurate against the primary sources.

## Why now

Arm 1 (N-version differential, Go vs Rust) found a real bug and ran 7/8 controls
at 100% parity. But Arm 1 is structurally blind to a *shared doctrinal error* —
when both engines misread the same RFC, they agree, and the differential reports
false confidence.

The `DnssecRequired` case (2026-08-21) is the first live proof: both engines
agreed DANE="Absent" for `it-help.tech`, and both were wrong — the RFC 7672
DNSSEC precondition is evaluated at the **MX host's zone**, not the mail domain's
apex. N-version testing could never have caught it. Only a known-answer vector
against the RFC itself could.

## Method (per CALIBRATION-STUDY-SPEC §Arm 2)

A **known-answer vector** = (RFC, §, normative statement, input shape,
expected disposition). The RFC is the oracle, not the other engine.

## Citation verification log (2026-08-21, all against rfc-editor.org current text)

- **DMARC = RFC 9989** (May 2026, Standards Track, obsoletes 7489+9091). ✓
- **CAA = RFC 8659** (Nov 2019, Standards Track, obsoletes 6844). ✓
- **SPF = RFC 7208** (Apr 2014, obsoletes 4408). ✓
- **DKIM = RFC 6376** (Sep 2011, STD 76, obsoletes 4871/5672). ✓
- **DANE = RFC 7672** (Oct 2015, Standards Track). ✓
- **MTA-STS = RFC 8461** (Sep 2018, Standards Track). ✓
- **null MX = RFC 7505** (Jun 2015, Standards Track). ✓
- **CDS/CDNSKEY = RFC 7344** (Sep 2014, **Informational** — NOT Standards Track). ✓
- **CDS/CDNSKEY delete signal = RFC 8078** (Mar 2017, Standards Track,
  **Updates 7344**) — the null-CDS "remove my DS" algorithm. ✓

### Two citation defects found and corrected (the arm's first real catches)

1. **DANE DNSSEC requirement is §1.3.2, not §4.** §1.3.2 "Insecure Server
   Name without DNSSEC" states the rule directly: "secure verification of SMTP
   TLS certificates matching the server name is not possible without DNSSEC";
   §2.1.1 lists the resolver requirements. §4 is "Server Key Management" — the
   code comment at `analysis.rs:235` citing "§4" was wrong.
2. **CDS/CDNSKEY is Informational, not Standards Track.** RFC 7344's own
   status line says "not an Internet Standards Track specification; it is
   published for informational purposes." A vector citing it as normative
   over-claims.

### SciSpace independent pass (2026-08-22) — eight more corrections

SciSpace read all 9 RFCs from rfc-editor.org and found these additional
§-imprecisions. **Each was re-verified first-hand against the RFC text before
acceptance** (SPF 7208: §4.6.2 qualifier table + §4.5 "none" result; DMARC
9989: §4.7 policy record format; CDS 7344: §4.1/§5/§6.2):

| vector | was | corrected to | RFC anchor |
|---|---|---|---|
| S1, S2 | 7208 §5.1 | **§4.6.2** | §5.1 only says `all` "always matches"; the `-`/`~` qualifier semantics are the §4.6.2 table |
| S3 | 7208 §3 | **§4.5** | §4.5 "Selecting Records": "If the resultant record set includes no records, check_host() produces the 'none' result." |
| M1–M3 | 9989 §4.5 | **§4.7** | §4.5 is overview; §4.7 "DMARC Policy Record Format" defines the `p=` values (`none`/`quarantine`/`reject`) |
| N1 | 7344 §4 | **§4.1 (§5)** | §4.1 processing rules + §5 "When the Parent DS is in sync with the CDS/CDNSKEY" |
| N2 | 7344 §4 | **§6.2** | §6.2 "Using the New CDS/CDNSKEY Records": "if the … CDS/CDNSKEY and DS differ, it may apply the changes" |
| N3 | 7344 §4 | **§4.1** | §4.1 "If there is neither CDS nor CDNSKEY RRset in the Child, this signals [no change]" |

The arm's prior "two defects" (DANE §1.3.2, CDS Informational) were both
re-confirmed by SciSpace as correct.

### SciSpace's own gap-section citations were wrong (corrected first-hand)

The two *new* claims in SciSpace's "gaps" section carried fabricated citations,
caught only because every §-claim is re-verified against the RFC before code is
written:

- **G2 (null CDS delete-DS):** SciSpace cited "RFC 7344 §4.3" with RDATA
  `0 0 0 00`. RFC 7344 has **no §4.3**, and its §4.1 explicitly states "this
  document does not support removing all keys." The null-CDS delete signal is
  actually **RFC 8078 §4 "DNSSEC Delete Algorithm"** (Standards Track, Updates
  7344), with canonical RDATA `CDS 0 0 0 0` — hickory models it first-class as
  `algorithm: None` (the "requesting deletion" branch).
- **G4 (CAA `issuewild`):** SciSpace cited "RFC 8659 §4.2". The `issuewild`
  property is **§4.3** — §4.2 is the `issue` property, §4.3 is `issuewild`.

The lesson is symmetric and load-bearing for the whole verification loop: a
verifier that correctly checks an *existing* table can still hallucinate the
*citations of its own new claims*. The only defense is the one already in
force — never accept a §-citation on a peer's say-so, re-read the RFC first.

## The vectors (citation = verified)

### 1. DNSSEC

| # | RFC § | normative statement | input | expected disposition |
|---|---|---|---|---|
| D1 | 4035 §4.3 | signed + DS at parent → validates | DNSKEY present, proof Secure | `SignedAndDelegated` (Present) |
| D2 | 4035 §4.3 | DNSKEY present, no DS → insecure delegation ("island") | DNSKEY present, proof Insecure | `SignedNotDelegated` (Indet) |
| D3 | 4035 §4.3 | no DNSKEY → unsigned | no DNSKEY | `Unsigned` (Absent) |
| D4 | 4035 §4.3 | validation fails → bogus/broken | proof Bogus / SERVFAIL | `BrokenChain` (Absent) |

### 2. SPF (RFC 7208)

| # | § | statement | input | expected |
|---|---|---|---|---|
| S1 | 7208 §4.6.2 | `all` mechanism; `-all` = "no other hosts authorized" (hard fail) | `v=spf1 ... -all` | enforced (Present) |
| S2 | 7208 §4.6.2 | `~all` = soft-fail (advisory) | `v=spf1 ... ~all` | deployed-not-enforcing |
| S3 | 7208 §4.5 | no SPF TXT → None result | (absent) | `NotConfigured` (Absent) |
| S4 | 7505 §3 | null MX ⇒ SPF not applicable | MX `0 .` | `NoMail` (NotApplicable) |

### 3. DKIM (RFC 6376)

| # | § | statement | input | expected |
|---|---|---|---|---|
| K1 | 6376 §3.6.1 | empty `p=` = key revoked (deliberate withdrawal) | `v=DKIM1; p=` | `Revoked` (Absent, severity High) — *shipped* |
| K2 | 6376 §3.6.1 | wildcard `*._domainkey` proves nothing per-selector | sentinel resolves | `Wildcard` (Indet) — *shipped* |
| K3 | 6376 §3.6.1 | valid key | `v=DKIM1; p=MIGf...` | `Verified` (Present) |

### 4. DMARC (RFC 9989)

| # | § | statement | input | expected |
|---|---|---|---|---|
| M1 | 9989 §4.7 | `p=reject` = reject failures | `v=DMARC1; p=reject` | enforced (Present) |
| M2 | 9989 §4.7 | `p=none` = monitor | `p=none` | monitoring |
| M3 | 9989 §4.7 | no DMARC | (absent) | `NotConfigured` (Absent) |

### 5. DANE (RFC 7672)

| # | § | statement | input | expected |
|---|---|---|---|---|
| A1 | 7672 §1.3.2 | DANE requires DNSSEC; without it, secure SMTP TLS verification is impossible | MX host zone unsigned | **`DnssecRequired`** — *shipped* |
| A2 | 7505 §3 | null MX ⇒ no mail server to pin | MX `0 .` | `NoMail` (NotApplicable) |
| A3 | 7672 §2.2 | signed host zone + TLSA | TLSA present | `TlsaPublished` (Present) |
| A4 | 7672 §2.2 | signed host zone + no TLSA | TLSA NODATA | `NotConfigured` (Absent) |

### 6. MTA-STS (RFC 8461)

| # | § | statement | input | expected |
|---|---|---|---|---|
| T1 | 8461 §3.1 | `_mta-sts` TXT (v=STSv1; id=) signals a policy | `v=STSv1; id=...` | Present (with fetched policy) |
| T2 | 8461 §3.1 | no discovery TXT = no policy | (absent) | `NotConfigured` (Absent) |

### 7. CAA (RFC 8659)

| # | § | statement | input | expected |
|---|---|---|---|---|
| C1 | 8659 §4.2 | `issue` restricts CA | `0 issue "letsencrypt.org"` | restricted |
| C2 | 8659 §3 | no CAA RRset = any CA may issue | (absent) | default-permissive |
| C3 | 8659 §4.2 | `issue ";"` = no CA | `0 issue ";"` | fully restricted |
| C4 | 8659 §4.3 | `issuewild ";"` = no wildcard cert | `0 issuewild ";"` | `WildcardFullyRestricted` — *shipped* |

### 8. CDS/CDNSKEY (RFC 7344 **Informational**; delete signal = RFC 8078)

| # | § | statement | input | expected |
|---|---|---|---|---|
| N1 | 7344 §4.1 (§5) | CDS matches DS = normal | CDS present, matches | Present — **deferred** (see `cds-match-differ-scope-out.md`) |
| N2 | 7344 §6.2 | CDS ≠ DS = rollover in progress | CDS present, differs | rollover-in-progress — **deferred** (cross-zone comparison, not measured) |
| N3 | 7344 §4.1 | no CDS | (absent) | `NotConfigured` (Absent) |
| N4 | 8078 §4 | null CDS/CDNSKEY (algorithm 0) = delete DS | `CDS 0 0 0 0` | `DeletionRequested` — *shipped* |

## SciSpace design rulings + corpus gaps (accepted 2026-08-22)

Two design questions were put to SciSpace and ruled; five corpus gaps were
flagged. Status below is the **current engine state** (verified against
`analysis.rs`), so "gap" is classified honestly as documentation-gap vs
code-gap.

### Rulings

- **Ruling A — CAA `issue ";"` is a distinct state, not "has CAA".**
  RFC 8659 §4.2 gives `issue ";"` an explicit normative definition ("request
  no issuance"). **SHIPPED** — `CaaDisposition::FullyRestricted` is now a
  distinct state wired ahead of `Configured` (and `WildcardFullyRestricted`)
  in the CAA scoring arm, with a §4.2-anchored assertion + negative controls.
- **Ruling B — keep CDS match-vs-differ, with an Informational calibration
  note.** The rollover-in-progress inference is grounded in §6.2 and is
  security-relevant, but RFC 7344 is Informational — so the disposition is an
  *observation* ("CDS ≠ DS present"), not a mandate on the parent. **Engine
  status:** `CdsDisposition` is presence-based; the match/differ comparison is
  not part of this pure-function surface. Accepted; calibration note added to
  the code comment.

### Gaps (engine state verified)

| gap | RFC | engine state | classification |
|---|---|---|---|
| G1 — `p=quarantine` | 9989 §4.7 | `DmarcDisposition::Quarantine` **already exists** | doc-gap — assertion added |
| G5 — SPF `+all` | 7208 §4.6.2 | `SpfDisposition::OtherPolicy` **already covers it** (never misread as HardFail) | doc-gap — assertion added; the "open-relay red flag" *severity* nuance is a design refinement, carded |
| G2 — null CDS (delete-DS) | **8078 §4** (not 7344 §4.3) | **`CdsDisposition::DeletionRequested` shipped** | code-gap — closed |
| G3 — MTA-STS `mode=testing` vs `enforce` | **8461 §3.2 (fields) / §5 (mode semantics)** — *not §3.3* | `mta_sts_policy_state` **already splits** Enforce vs TestingOrNone; report maps them to severity **Ok vs Medium** | doc-gap — assertions added (4: enforce/testing/none/invalid) |
| G4 — CAA `issuewild ";"` | **8659 §4.3** (not §4.2) | **`CaaDisposition::WildcardFullyRestricted` shipped** | code-gap — closed |

**G3 correction:** SciSpace cited "RFC 8461 §3.3" for the mode semantics.
§3.3 is "HTTPS Policy Fetching". The mode field is enumerated in **§3.2**
("MTA-STS Policies") and its three-mode *semantics* ("enforce" MUST NOT
deliver / "testing" report-but-deliver / "none" no active policy) are in **§5**
("Policy Application"). The distinction itself already existed in the engine —
this is the same class as G1/G5 (doc-gap, not code-gap), now pinned.

**Ruling A is now also shipped** (`CaaDisposition::FullyRestricted`), so the
"distinct state" ask is closed as a real enum variant, not left as a code
comment.

## Remaining build

- A harness that turns the table into a runnable, content-addressed corpus
  (frozen inputs, not live DNS) — RFC vectors are mostly *constructed inputs*
  (a TXT string, a proof state), so they're deterministic and offline-testable.
- Feed the same vectors to the Go analyzer to close the shared-error gap on
  that side too.
