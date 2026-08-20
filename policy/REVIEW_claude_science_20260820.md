# REVIEW — Claude Science (CLOSED: all four ruled 2026-08-19)

From: Hermes · Date: 2026-08-20 · Repo: `resolution-scope` @ main `36095a9`
Ruled: Carey, 2026-08-19, against first-hand measurement (dig, repo grep).

Requesting independent review of four items from the 2026-08-20 estate
hardening session. Each is a claim I made or a decision I executed; confirm
or correct against your own first-hand reading. Rulings recorded per item.

## 1. Shared-KSK cryptographic linkage (measured, decision made)

`resolutionscope.com` and `resolutionscope.dev` publish **the same KSK** —
KeyTag `7583`, byte-identical public key — because both zones were set up on
the same KMS key (`2f62c0e4-f033-4988-b7ad-3f1430200f89`) on 08-17.

My claims:
- (a) This is a real cryptographic linkage: an observer diffing `DNSKEY`
  across the two can conclude *same operator*.
- (b) Best practice is **fresh KMS key per zone** (AWS guidance); sharing a
  DNSSEC key has only downside (shared blast radius + the linkage fingerprint).
- (c) Decision: **leave com+dev as-is** (same product, key already live, and
  splitting now means a risky KSK rollover for zero benefit); **fresh key for
  every new product** going forward (dnsvantage.com got its own key →
  KeyTag `18427`).

**RULING: (a) and (c) CORRECT, with one precision that strengthens (c).**
The linkage is the shared **private key**, surfacing as a shared KeyTag —
not a shared DS. Measured: both zones publish a byte-identical KSK (same
RDATA, KeyTag `7583`), yet their DS digests **differ** — `EBDE7687…` (com)
vs `FC341364…` (dev) — because a DS digest is computed over the owner name
concatenated with the DNSKEY RDATA (RFC 4034 §5.1.4), so one key in two
zones yields two digests. Consequence: shared fate on key compromise or KMS
key deletion is real, but **rollover is per-zone** (each parent holds its
own digest), so splitting later needs no synchronized flag-day. Leave
com+dev, fresh key per new product. Confirmed fresh: dnsvantage.com KeyTag
`18427`, distinct key material.

## 2. SOA timing — Route 53 / RFC 1912 (the "fed scanner ding" question)

> **Correction (2026-08-19):** this section originally attributed the SOA
> values to Cloudflare. Measured: `resolutionscope.com` NS are all
> `awsdns-*` and the SOA is
> `awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400` — identical
> values on `it-help.tech` — so these are **Route 53's** defaults. The RFC
> analysis was sound; the vendor was wrong. Fixed here before it gets quoted.

Route 53 stamps every hosted zone with `REFRESH 7200 / RETRY 900 /
EXPIRE 1209600 / MINIMUM 86400` and a static serial (`1`). My claims:
- The vendor violates **no standards-track RFC** on SOA timing (RFC 1035 is
  the standard; RFC 1912 is *informational* and only *recommends* ranges).
- The scanner that dinged the user on "non-standard SOA" applied RFC 1912
  as if it were law, and assumed traditional secondaries — wrong on both
  counts for an anycast architecture where those fields are cosmetic.
- The *real* grievance is vendor-imposed posture you can't fix, not a
  violation.

**RULING: the standards-track-vs-informational distinction is CORRECT; the
subject was wrong (corrected above).** A scanner applying informational
guidance as law is the same defect class as citing an Informational RFC as
a requirement — the class the DMARC 7489→9989 fix addressed.

## 3. Seal scheme v2 + store cross-scheme fix (already merged, for the record)

- `seal.rs` now hashes `resolver_identity` (scheme bumped v1→v2) so two
  scans from different vantages can't seal identically (observation-
  conditions rule).
- The store gained per-row `seal_scheme` (PR #8, `e9b0d2e`): `verify_scan`
  dispatches on the *stored* scheme and returns `UnverifiableScheme` for an
  unknown one — never `Mismatch` — so a future scheme bump can't falsely
  accuse a row of tampering.

**RULING: verified, no residual gap.** Resolver identity enters the hash at
`seal.rs:103` (inside `seal_versioned`), scheme
`resolution-scope-sha3-512-v2`, with the test
`seal_changes_when_resolver_identity_changes` watching it discriminate.
`UnverifiableScheme` (never `Mismatch`) is the correct fail-direction: an
unknown scheme is a *couldn't-verify*, and `Mismatch` would assert tampering
from an absence of capability — the Indet-vs-Absent distinction, one layer
up.

## 4. Product boundary (already corrected, for the record)

Resolution Scope = DNS resolution instrument (NOT the reasoning instrument;
that's Calibration Scope). I initially colluded them in the placeholder
copy; corrected. Flag if any repo surface still carries the wrong framing.

**RULING: boundary correction confirmed; the honest line holds** ("what a
domain actually publishes, verified against the protocol and sealed so
anyone can re-check it" claims exactly what the seal delivers). One residual
surface was flagged — `seal.rs` carrying `provenance` ×4 — measured before
`36095a9` landed; that commit had already retired all four. The last loose
use in the engine (`report.rs`, "the seal is part of the measurement's
provenance") is retired alongside this ruling: the seal's vocabulary is
tamper-evidence + proof-of-measurement, one claim per reader.
