# Flux detector — negative-control study (Claude Science, 2026-08-20)

The first live measurement of whether the flux signal's discriminator
survives contact with benign domains. Result: **the ASN-dispersion threshold
is the only discriminator that survives a negative-control set — and the code
already ships it.**

## What the code keys on (verified against source, not memory)

- `engine/src/flux.rs::dispersion` counts **distinct origin ASNs** (the
  union) and **transitions** across consecutive observations. It never keys
  on address-set change. The word "churn" appears only in doc comments
  *explaining why address churn is excluded* — no Jaccard/address-diff path
  exists in the repo.
- The proxy gate runs **before** counting: `asn_classification.rs` partitions
  each resolved ASN into `Origin` / `ProxyEdge` / `SharedCloudAmbiguous`;
  `ProxyEdge` and `SharedCloudAmbiguous` are **excluded from the dispersion
  basis and recorded with a reason** (they are facts about the CDN, not the
  origin). `www.apple.com` and `nsa.gov` rotate *inside* Akamai — counting
  that would flag benign infra.
- Unknown ASN → `Origin` by default (fail toward *measurable*, never toward
  "not observable") — pinned by `unknown_asn_defaults_to_origin`.

## The study (three arms, all measured live, single vantage)

1. **Reliability** — 4 samples × 8 verdict signals × 10 domains: only the
   address set was ever unstable; every DNSSEC / mail-policy / auth flag was
   byte-identical across all samples. The verdicts rest on stable ground.
2. **Churn** — 8 samples × 6 domains: 4 of 6 rotated their address set
   (`google.com` mean Jaccard 0.429); `/24` aggregation did NOT stabilize any
   of the four.
3. **Discriminator** — Team Cymru origin-ASN on every address seen: all 6
   specimens = exactly **one** distinct ASN.

## The finding, precisely

> A dispersion counter keyed on **address change** flags 4 of 6 benign
> domains. Keyed on **distinct origin ASN**, it flags 0 of 6.

So the ASN threshold is not a design preference — it is the only one of the
two that survives a negative-control set. This is exactly what the shipped
code does, and the code's own unit tests already pin the three properties the
study independently confirmed (proxy-exclusion, unknown→origin,
ASN-set-transitions).

## What it does NOT establish (stated, not buried)

- **No malicious specimen measured** — the false-negative rate is unknown.
- **Single vantage** — steering and rotation are not separable.
- **n = 6** — bounds nothing about multi-CDN failover, a known benign
  multi-ASN class.
- **Minutes-long window** — slow rotation is invisible.

## The one open arm

The `>1 distinct ASN → Dispersing` rule has been tested only against the
**false-positive class** (benign single-ASN domains, where it correctly stays
quiet). It has NOT been tested against its own **false-positive class**:
a benign **multi-CDN failover** domain (two origins behind two distinct
operator ASNs, legitimately rotating). That is the next measurement — a
single genuine multi-ASN benign specimen — before the `>1` threshold can be
claimed calibrated in both directions.

## Status

The numbers are the detector's baseline, not to be re-derived. The design is
confirmed by measurement; the calibration is one arm short (multi-ASN benign).
