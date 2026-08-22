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

### 8. CDS/CDNSKEY (RFC 7344, **Informational**)

| # | § | statement | input | expected |
|---|---|---|---|---|
| N1 | 7344 §4.1 (§5) | CDS matches DS = normal | CDS present, matches | Present |
| N2 | 7344 §6.2 | CDS ≠ DS = rollover in progress | CDS present, differs | rollover-in-progress |
| N3 | 7344 §4.1 | no CDS | (absent) | `NotConfigured` (Absent) |

## SciSpace design rulings + corpus gaps (accepted 2026-08-22)

Two design questions were put to SciSpace and ruled; five corpus gaps were
flagged. Status below is the **current engine state** (verified against
`analysis.rs`), so "gap" is classified honestly as documentation-gap vs
code-gap.

### Rulings

- **Ruling A — CAA `issue ";"` is a distinct third state, not "has CAA".**
  RFC 8659 §4.2 gives `issue ";"` an explicit normative definition ("request
  no issuance"). Accepted in principle. **Engine status:** `CaaDisposition` is
  presence-based (Configured/NotConfigured) today; the fully-restricted
  semantics are recorded at the record-value level but not graded. This is the
  "value-grading" next-pass decision the code comment at `analysis.rs`
  (CAA block) already flags — carded, not yet built.
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
| G2 — null CDS `0 0 0 00` (delete-DS) | 7344 §4.3 | not distinguished — presence-based | **code-gap**, carded |
| G3 — MTA-STS `mode=testing` vs `enforce` | 8461 §3.3 | `MtaStsDisposition::Enforced`/`NotEnforced` exist, but mode-grading in the fetched body is not asserted here | doc-gap (partial) — carded |
| G4 — CAA `issuewild` | 8659 §4.2 | not distinguished — presence-based | **code-gap**, carded |

## Remaining build

- A harness that turns the table into a runnable, content-addressed corpus
  (frozen inputs, not live DNS) — RFC vectors are mostly *constructed inputs*
  (a TXT string, a proof state), so they're deterministic and offline-testable.
- Feed the same vectors to the Go analyzer to close the shared-error gap on
  that side too.
