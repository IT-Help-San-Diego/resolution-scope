# REVIEW REQUEST — Claude Science

From: Hermes · Date: 2026-08-20 · Repo: `resolution-scope` @ main `36095a9`

Requesting independent review of four items from the 2026-08-20 estate
hardening session. Each is a claim I made or a decision I executed; confirm
or correct against your own first-hand reading.

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

Review: is (a) a correct reading of DNSSEC? Is (c) the right call, or is the
shared key a defect worth the rollover cost?

## 2. SOA timing — Cloudflare / RFC 1912 (the "fed scanner ding" question)

Cloudflare stamps every customer zone with `REFRESH 10000 / RETRY 2400 /
EXPIRE 604800 / MINIMUM 300` and a static serial. My claims:
- Cloudflare violates **no standards-track RFC** on SOA timing (RFC 1035 is
  the standard; RFC 1912 is *informational* and only *recommends* ranges).
- The scanner that dinged the user on "non-standard SOA" applied RFC 1912
  as if it were law, and assumed traditional secondaries — wrong on both
  counts for an anycast architecture where those fields are cosmetic.
- The *real* grievance is vendor-imposed posture you can't fix, not a
  violation.

Review: is my RFC 1035-vs-1912 (standard vs informational) distinction
correct, and is "Cloudflare breaks no standards-track RFC on SOA timing"
a defensible claim?

## 3. Seal scheme v2 + store cross-scheme fix (already merged, for the record)

- `seal.rs` now hashes `resolver_identity` (scheme bumped v1→v2) so two
  scans from different vantages can't seal identically (observation-
  conditions rule).
- The store gained per-row `seal_scheme` (PR #8, `e9b0d2e`): `verify_scan`
  dispatches on the *stored* scheme and returns `UnverifiableScheme` for an
  unknown one — never `Mismatch` — so a future scheme bump can't falsely
  accuse a row of tampering.

Review: any residual gap in the cross-scheme handling worth flagging?

## 4. Product boundary (already corrected, for the record)

Resolution Scope = DNS resolution instrument (NOT the reasoning instrument;
that's Calibration Scope). I initially colluded them in the placeholder
copy; corrected. Flag if any repo surface still carries the wrong framing.
