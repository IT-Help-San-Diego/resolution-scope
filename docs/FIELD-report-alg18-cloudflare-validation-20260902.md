# FIELD REPORT — Cloudflare validates ML-DSA (algorithm 18): a dated first observation of real-world post-quantum DNSSEC validation

**Date:** 2026-09-02 (event bracketed 2026-08-31T16:03Z → 2026-09-01T16:03:38Z)
**Series:** Resolution Scope decay series, Days 0–5, specimen windows pq.resolutionscope.com and pq2.resolutionscope.com
**Status:** First observation. Perishable as a claim — recorded with its full evidence chain the day after the event was caught.

## The observation

**Cloudflare's public resolver (1.1.1.1) now validates DNSSEC zones signed
solely with ML-DSA-44 (algorithm 18, draft-westerbaan-dnssec-mldsa),
returning AD=True with no Extended DNS Error.** Two days earlier the same
series recorded the documented Day-0 split: EDE-1 "no supported DNSKEY
algorithm" at Cloudflare, silent no-AD downgrade at Google/Quad9/OpenDNS,
full validation only at the alg-18-implementing PowerDNS master on :5300.

Independently corroborated on a third zone outside our estate:
`mldsa.huque.com` — the spec author's own zone — returns the same
pattern (Cloudflare AD=True, Google AD=False).

## The confound, eliminated by the zone's own contents

The dual-algorithm DS set (`13, 18` at delegation) makes a naive reading
unsound: RFC 6840 §5.11 permits a validator to ignore an unsupported
algorithm and fall back, so AD=True could in principle ride the alg-13 DS
alone. **The zones eliminate that path by construction — measured
first-hand 2026-09-02:**

| zone | DS algs (parent) | DNSKEY algs (zone) | RRSIG algs (SOA) |
|---|---|---|---|
| pq2.resolutionscope.com | 18 visible at vantage | **18 only** | 18 only |
| pq.resolutionscope.com | 18 visible at vantage | **18 only** | 18 only |
| mldsa.huque.com | 18 visible at vantage | **18 only** | 18 only |

No alg-13 DNSKEY exists and no alg-13 RRSIG exists. There is no alg-13
path a validator could take: **AD=True is reachable only by verifying the
ML-DSA signature.** (Design note: the dual-DS `13,18` shape exists at the
registry for transitional safety per the SPEC's baseline; the zone-side
single-alg signing is what makes the observation attributable.)

Google's AD=False is *correct* behavior, not a violation: with no working
fallback and no alg-18 support, there is nothing for Google to validate
with. The resolver population now splits into three measured classes at
Day-5: **validating** (Cloudflare; the :5300 PowerDNS master),
**honestly-unable** (Google — EDE-1/no-AD per RFC 4035 §5.2 strip semantics),
and **silently-downgrading** (the Day-0 quartet minus Cloudflare; re-measure
pending as of this writing).

## Dating

The transition is bracketed by the series, not inferred from one read:
Days 0–4 are uniformly AD=False + EDE 1 at Cloudflare (five consecutive
reads, 2026-08-30 → 2026-08-31T16:03Z); Day-5 (2026-09-01T16:03:38Z) is the
first AD=True. **The flip happened inside a 24-hour window.** "Last week"
is positively excluded by the Day-4 read.

## What this is and is not

- **Is:** the first dated observation, caught by a purpose-built specimen,
  of a major public resolver crossing from "refuses alg-18" to "validates
  alg-18" — the first real-world PQ-DNSSEC validation by a mainstream
  resolver that our series has recorded.
- **Is not:** a claim that Cloudflare announced, documented, or committed
  to alg-18 support; a measurement of Google/Quad9/OpenDNS's current state
  (re-measure pending); a claim about deployment *rate* (three zones is an
  existence proof, not prevalence).
- **Limits, stated:** the ML-DSA signature itself was not independently
  verified by this report's author (no local implementation invoked);
  the claim rests on the AD flag plus the structural absence of any other
  validation path. The day-5 row and this report share that limit. The
  signer's own KAT + three-verifier interop (PowerDNS master, Go 1.27
  crypto/mldsa, NSD) cover the signature side at build time.

## Why it matters to the instrument

This is the event the specimen was built to catch: a resolver-population
transition on a new algorithm, dated to a 24h bracket, with the confound
designed out at the zone. The decay series converts "alg-18 is somewhere in
resolver software" into a dated, re-measurable ecological fact. The next
series read (Day-6+) carries the re-measure of the silent-downgrade quartet
and the persistence check of Cloudflare's flip.

## Provenance

- Decay series: docs/DECAY-day0…day5 (batches via the standard specimen
  battery; Day-5 batch b_1788278514_e5e4f2cc8a37, HTTP 202, rows
  16:03:01–16:04:10Z; engine app_version 26.51.0-140-g812c18080)
- Independent corroboration + confound re-measured from the hermes lane
  vantage 2026-09-02 (dig @1.1.1.1 DNSKEY/DS/SOA+AD on all three zones;
  receipts in this file's tables)
- Specimen design: SPEC-mldsa44-signer-20260830.md; baseline pre-registration
  in BASELINE; exclusion from our own corpus statistics per the
  labeled-control conditions (pq-fixture-go, ruled GO 2026-08-30)
- First drafted from the 2026-09-02T06:30Z lane corrections (the dating its
  source could not do) and the specimen-caught-it brief
