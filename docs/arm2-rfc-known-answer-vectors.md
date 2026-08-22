# Arm 2 — RFC known-answer vectors

**Status:** first corpus drafted (2026-08-21); NOT yet doctrinally verified by
Claude Science. This is the load-bearing arm the spec made mandatory.

## Why now

Arm 1 (N-version differential, Go vs Rust) found a real bug and ran 7/8 controls
at 100% parity. But Arm 1 is structurally blind to a *shared doctrinal error* —
when both engines misread the same RFC, they agree, and the differential reports
false confidence.

The `DnssecRequired` case (2026-08-21) is the first live proof: both engines
agreed DANE="Absent" for `it-help.tech`, and both were wrong — the RFC 7672
DNSSEC precondition is evaluated at the **MX host's zone**, not the mail domain's
apex. N-version testing could never have caught it. Only a known-answer vector
against the RFC itself could. This corpus is that instrument.

## Method (per CALIBRATION-STUDY-SPEC §Arm 2)

A **known-answer vector** = (RFC, §, normative statement, input shape,
expected disposition). The RFC is the oracle, not the other engine. Agreement
with the vector validates against the specification itself.

Each vector below carries a **citation-confidence** tag:
- `verified` — section number confirmed against the current RFC text.
- `unverified` — written from memory; must be confirmed before the vector is
  a load-bearing claim. This is the "relay to Claude Science" trigger.

## The vectors

Citation currency (2026-08-19, verified against rfc-editor.org / datatracker):
DMARC=RFC 9989 (obsoletes 7489/9091); CAA=RFC 8659 (obsoletes 6844);
DNSSEC=RFC 9364 (BCP 237, ops guidance over 4033-4035); SPF=RFC 7208;
DKIM=RFC 6376 (STD 76); DANE(SMTP)=RFC 7672; MTA-STS=RFC 8461;
CDS/CDNSKEY=RFC 7344; null MX=RFC 7505.

### 1. DNSSEC

| # | RFC § | normative statement | input | expected disposition |
|---|---|---|---|---|
| D1 | 4035 | signed + DS at parent → validates | DNSKEY present, proof Secure | `SignedAndDelegated` (Present) |
| D2 | 4035 | DNSKEY present, no DS → insecure delegation ("island") | DNSKEY present, proof Insecure | `SignedNotDelegated` (Indet) |
| D3 | 4035 | no DNSKEY → unsigned | no DNSKEY | `Unsigned` (Absent) |
| D4 | 4035 | validation fails → bogus/broken | proof Bogus / SERVFAIL | `BrokenChain` (Absent) |

### 2. SPF (RFC 7208)

| # | § | statement | input | expected |
|---|---|---|---|---|
| S1 | 7208 §4 | `-all` hard-fail = "only these senders" | `v=spf1 ... -all` | enforced (Present) |
| S2 | 7208 §4 | `~all` soft-fail = advisory | `v=spf1 ... ~all` | deployed-not-enforcing |
| S3 | 7208 §3 | no SPF TXT | (absent) | `NotConfigured` (Absent) |
| S4 | 7505 | null MX ⇒ SPF not applicable | MX `0 .` | `NoMail` (NotApplicable) |

### 3. DKIM (RFC 6376, STD 76)

| # | § | statement | input | expected |
|---|---|---|---|---|
| K1 | 6376 §3.6.1 | empty `p=` = key revoked (deliberate withdrawal) | `v=DKIM1; p=` | `Revoked` (Absent, severity High) — *already shipped* |
| K2 | 6376 | wildcard `*._domainkey` proves nothing per-selector | sentinel resolves | `Wildcard` (Indet) — *already shipped* |
| K3 | 6376 | valid key | `v=DKIM1; p=MIGf...` | `Verified` (Present) |

### 4. DMARC (RFC 9989)

| # | § | statement | input | expected |
|---|---|---|---|---|
| M1 | 9989 | `p=reject` = reject fail | `v=DMARC1; p=reject` | enforced (Present) |
| M2 | 9989 | `p=none` = monitor | `p=none` | monitoring |
| M3 | 9989 | no DMARC | (absent) | `NotConfigured` (Absent) |

### 5. DANE (RFC 7672)

| # | § | statement | input | expected |
|---|---|---|---|---|
| A1 | 7672 §4 `unverified` | DANE requires DNSSEC; unsigned host zone cannot carry trustable TLSA | MX host zone unsigned | **`DnssecRequired`** — *the first Arm 2 case, now shipped* |
| A2 | 7505 | null MX ⇒ no mail server to pin | MX `0 .` | `NoMail` (NotApplicable) |
| A3 | 7672 | signed host zone + TLSA | TLSA present | `TlsaPublished` (Present) |
| A4 | 7672 | signed host zone + no TLSA | TLSA NODATA | `NotConfigured` (Absent) |

### 6. MTA-STS (RFC 8461)

| # | § | statement | input | expected |
|---|---|---|---|---|
| T1 | 8461 | policy TXT + served policy = enforced | `v=STSv1` + `.well-known/mta-sts.txt` mode=enforce | Present |
| T2 | 8461 | no discovery TXT = no policy | (absent) | `NotConfigured` (Absent) |

### 7. CAA (RFC 8659)

| # | § | statement | input | expected |
|---|---|---|---|---|
| C1 | 8659 | `issue` restricts CA | `0 issue "letsencrypt.org"` | restricted |
| C2 | 8659 | no CAA = any CA may issue | (absent) | default-permissive |
| C3 | 8659 | `issue ";"` = no CA | `0 issue ";"` | fully restricted |

### 8. CDS/CDNSKEY (RFC 7344)

| # | § | statement | input | expected |
|---|---|---|---|---|
| N1 | 7344 | CDS matches DS = normal | CDS present, matches | Present |
| N2 | 7344 | CDS ≠ DS = rollover | CDS present, differs | rollover-in-progress |
| N3 | 7344 | no CDS | (absent) | `NotConfigured` (Absent) |

## What needs Claude Science

Every `unverified` § citation must be confirmed against the current RFC text
before the vector becomes load-bearing — the DMARC 7489→9989 and CAA 6844→8659
supersessions already cost real false-confidence once, and the DANE §4 citation
is the one Claude Science itself flagged it had *not* verified. Doctrinal
verification of the §-numbers is the exact thing this arm exists to make
mechanical.

## Remaining build

- A harness that turns the table into a runnable, content-addressed corpus
  (frozen inputs, not live DNS) — RFC vectors are mostly *constructed inputs*
  (a TXT string, a proof state), so they're deterministic and offline-testable.
- Feed the same vectors to the Go analyzer to close the shared-error gap on
  that side too.
