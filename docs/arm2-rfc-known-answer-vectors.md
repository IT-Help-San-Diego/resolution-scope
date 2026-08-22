# Arm 2 — RFC known-answer vectors

**Status:** corpus drafted + §-citations VERIFIED against current RFC text
(2026-08-21, rfc-editor.org). Verification done by Hermes directly — the
Claude-Science §-check was the one step this arm could not leave to a paid
lane, and it is done. The load-bearing finding: the original table carried TWO
wrong citations, corrected here.

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
| S1 | 7208 §5.1 | `all` mechanism; `-all` = "no other hosts authorized" (hard fail) | `v=spf1 ... -all` | enforced (Present) |
| S2 | 7208 §5.1 | `~all` = soft-fail (advisory) | `v=spf1 ... ~all` | deployed-not-enforcing |
| S3 | 7208 §3 | no SPF TXT → None result | (absent) | `NotConfigured` (Absent) |
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
| M1 | 9989 §4.5 | `p=reject` = reject failures | `v=DMARC1; p=reject` | enforced (Present) |
| M2 | 9989 §4.5 | `p=none` = monitor | `p=none` | monitoring |
| M3 | 9989 §4.5 | no DMARC | (absent) | `NotConfigured` (Absent) |

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
| N1 | 7344 §4 | CDS matches DS = normal | CDS present, matches | Present |
| N2 | 7344 §4 | CDS ≠ DS = rollover in progress | CDS present, differs | rollover-in-progress |
| N3 | 7344 §4 | no CDS | (absent) | `NotConfigured` (Absent) |

## Remaining build

- A harness that turns the table into a runnable, content-addressed corpus
  (frozen inputs, not live DNS) — RFC vectors are mostly *constructed inputs*
  (a TXT string, a proof state), so they're deterministic and offline-testable.
- Feed the same vectors to the Go analyzer to close the shared-error gap on
  that side too.
