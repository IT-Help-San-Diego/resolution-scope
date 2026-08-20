# Flux detector — negative-control study (Claude Science, 2026-08-20, v3)

The first live measurement of whether the flux signal's discriminator survives
contact with benign domains. Result: **ASN dispersion is the only discriminator
that survives a negative-control set — and the code already ships it.** A v2
coverage correction (union vs re-sample) and an nsa.gov multi-operator specimen
refined the claim; the conclusion held.

## What the code keys on (verified against source, not memory)

- `engine/src/flux.rs::dispersion` counts **distinct origin ASNs** (the union)
  and **transitions** across consecutive observations. It never keys on
  address-set change. The word "churn" appears only in doc comments
  *explaining why address churn is excluded* — no Jaccard/address-diff path
  exists in the repo.
- The proxy gate runs **before** counting: `asn_classification.rs` partitions
  each resolved ASN into `Origin` / `ProxyEdge` / `SharedCloudAmbiguous`;
  `ProxyEdge` and `SharedCloudAmbiguous` are **excluded from the dispersion
  basis and recorded with a reason**. `www.apple.com` and `nsa.gov` (web) rotate
  *inside* Akamai — counting that would flag benign infra.
- Unknown ASN → `Origin` by default (fail toward *measurable*, never toward
  "not observable") — pinned by `unknown_asn_defaults_to_origin`.

## The study (three arms, measured live, single vantage)

1. **Reliability** — 4 samples × 8 verdict signals × 10 domains: only the
   address set was ever unstable; every DNSSEC / mail-policy / auth flag was
   byte-identical across all samples. The verdicts rest on stable ground.
2. **Churn** — 8 samples × 6 domains: 4 of 6 rotated their address set
   (`google.com` mean Jaccard 0.429); `/24` aggregation did NOT stabilize any
   of the four.
3. **Discriminator** — Team Cymru origin-ASN on every address seen: all
   specimens = exactly **one** distinct ASN.

### v2 correction (coverage, not conclusion)

The ASN arm originally **re-sampled** two fresh addresses per domain instead of
mapping the **observed unions**, so `nsa.gov` and `www.apple.com` each got a
1-ASN count from a single address — which cannot show rotation stays
intra-operator — while the artifact and figure axis both claimed "all observed
addresses." Re-measured with full coverage: **18 addresses observed, 18 mapped
(100%)** — `cia.gov` 5, `google.com` 4, `nsa.gov` 3, and 2 each for
`www.apple.com`, `cloudflare.com`, `ietf.org`. All 18 still resolve to exactly
**one** distinct origin ASN. The conclusion survives, now on real coverage.

## The finding, precisely

> A dispersion counter keyed on **address change** flags 4 of 6 benign domains.
> Keyed on **distinct origin ASN**, it flags 0 of 6.

## The multi-operator specimen — and the scoping rule it forces

`nsa.gov` **mail** infrastructure is the first genuinely multi-operator benign
specimen found: **two origin ASNs (AS345, AS5374) across 20 addresses on 6 MX
hosts**. It is NOT a CDN artifact. Its structure:

- `pri-jeemsg.eemsg.mail.mil` (9 addrs) + `sec-jeemsg` (7 addrs) → AS345
- four `*.ncsc.mil` hosts (1 addr each) → AS5374

**Zero hosts span more than one ASN** — it is a clean per-host partition: two
operators, each serving its own named hosts. This is multi-operator
*architecture* (a stable partition across names), NOT fast-flux (one name whose
addresses move between operators over time). Counting distinct ASNs over a whole
domain's address union **conflates the two**.

**The rule that follows:** dispersion must be computed **per resolved name over
time**, never over the union of every name a domain publishes. The fix is the
counting *scope*, not the threshold.

### Code verification (this lane's measurement)

`dispersion()`'s **assessment** keys on `transitions == 0` (the origin-ASN set
changing between consecutive observations), NOT on `distinct_origin_asns > 1` —
so the Rust engine already does **not** fire on nsa.gov: a stable {345, 5374}
partition reads `Stable`, `transitions == 0`. The `distinct_origin_asns` field
*is* a domain-level union with no per-name key (it reports `2` for nsa.gov), but
it is a **reported shape**, and no consumer outside `flux.rs` reads it as a
threshold. Pinned by the regression test
`stable_multi_operator_partition_reads_stable_not_dispersing`.

The residual surface is honest and named: `observe_flux` resolves only the apex
(A/AAAA of one name), so multi-name unions are not yet on the path — but if
multi-name resolution (MX/www/CNAME targets) ever lands and flattens its ASNs
into one set, a stable multi-operator partition would inflate
`distinct_origin_asns` and any future `>1 ASN` threshold would misread it. The
per-name key is the durable guard that must accompany that work.

## Second negative-control batch (widened baseline)

Twelve more candidates — nytimes, bbc, linkedin, reddit, twitch, spotify,
airbnb, shopify, salesforce, zoom, dropbox, paypal — all **single-ASN**,
including airbnb at 18 observed addresses. The benign single-operator baseline
is now **18 specimens**, and the only multi-operator benign case found at all
was in **mail** infrastructure rather than web serving — which is also where
the per-name scoping fix does its work.

## The rate distinction — third assessment state (implemented)

Modelling the shipped `transitions == 0` rule over five real sequence shapes
surfaced the residual that actually matters: **one transition and n−1
transitions both read `Dispersing`** — so a legitimate single failover
(`{A},{A},{B},{B}`) or an operator added mid-window (`{A},{A},{A,B}`) scores
identically to continuous rotation. This is the false-positive class the study
left open, arriving as "operators that change once" rather than "multiple
operators."

Fix (shipped — not a threshold, a third state keyed on transition COUNT):

- `transitions == 0` → `Stable`
- `transitions == 1` → `Transient` (one observed change, insufficient to
  characterise as rotation)
- `transitions >= 2` → `Dispersing` (the set does not settle)

`transition_rate` (`transitions ÷ (observations−1)` — the share of transition
*boundaries* that fired, bounded [0,1] regardless of window) is also reported so
the "1-in-4 vs 3-in-4" distinction is visible to a reader, but the assessment
keys on the COUNT, not the rate. Regression-pinned:
`single_failover_reads_transient_not_dispersing`,
`operator_added_mid_window_reads_transient_not_dispersing`,
`oscillation_reads_dispersing`, `transition_rate_is_none_without_a_window`.

## What it does NOT establish (stated, not buried)

- **No malicious specimen measured** — the false-negative rate is unknown.
- **Single vantage** — steering and rotation are not separable.
- **Minutes-long window** — slow rotation is invisible.
- **The three 2-address specimens show co-ASN membership, not a characterised
  rotation pool.**

## The multi-vantage arm — ECS does not deliver it (measured + corrected 2026-08-20)

Separating geographic *steering* from temporal *rotation* needs a second
vantage. EDNS Client Subnet (RFC 7871) looked like the cheap mechanism — a
single resolver answers "as if" the query came from a different source prefix,
no second probe location. It is not, and this section records the measured
reason rather than a policy guess.

**Policy (stands on its own, from the RFC and Cloudflare's FAQ):** ECS is a MAY,
not a MUST — RFC 7871 §7.3.2 lets the resolver use the client-supplied ADDRESS
only "if the local policy allows." Cloudflare's 1.1.1.1 FAQ states it does not
send the ECS header (privacy-motivated). Neither line is a *measurement*; both
are policy statements, and they are cited here as policy only.

**Measurement (Claude Science, corrected run, 2026-08-20):** two routable
subnets (23.0.0.0/24 vs 81.0.0.0/24) against both resolvers, on
`www.apple.com` and `www.microsoft.com`. **The addresses are identical in all
four cases** — neither resolver returned a subnet-specific answer for either
name. The two failures are distinguishable, and the distinction matters: Google
echoed scope `/0` (the resolver *stating* the answer is not subnet-specific),
while Cloudflare omitted the field entirely (no signal about whether the hint
was used at all).

**What this means, stated at the right width:** the ECS route to multi-vantage
produces no vantage-specific answer through either public resolver for these
names — a stronger negative than "Cloudflare ignores it." It is *not* evidence
that Cloudflare ignores ECS (identical addresses are consistent with ignoring,
but Google returned identical addresses too while accepting the parameter). The
honest claim is narrower: Cloudflare gives no scope feedback, so an arm built on
it cannot know whether it measured anything.

**The one durable guardrail:** require a **non-zero echoed scope prefix** before
treating a client-subnet comparison as a vantage measurement. On this data that
check fails for both resolvers — correctly, since neither produced a
vantage-specific answer. **Multi-vantage therefore needs genuinely separate
probe locations; it is not the cheap arm. The malicious-specimen arm is now the
cheaper of the two.**

## Status

The numbers are the detector's baseline, not to be re-derived. The discriminator
is confirmed by measurement in the false-positive direction (18 single-ASN
benign + 1 multi-operator benign, all correctly quiet on ASN dispersion). The
per-name scoping rule is recorded and regression-pinned. The rate distinction
(one transition = `Transient`, not `Dispersing`) is implemented and
regression-pinned. Remaining open arms: a malicious fast-flux specimen
(false-negative rate) — now the *cheaper* of the two, and multi-vantage
separation of steering from rotation, which needs genuinely separate probe
locations (the ECS route measured dead in the section above).
