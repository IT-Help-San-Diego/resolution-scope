# DESIGN PRINCIPLE — dynamic (self-healing) vendor attribution (2026-08-26)

**Question (Carey):** when we call out a vendor honestly ("Route 53 chose not to publish
CDS"), should those fields be *dynamic* so that the moment Amazon/Google ships the control,
the tool flips to "correct" and the warning *goes away by itself* — instead of a hardcoded
snapshot that rots? Is that asking too much?

**Answer: it is the right instinct, and 80% of it is already the architecture — because the
instrument measures, it never memorizes.** The remaining 20% is a real, bounded piece of
work (host-identity attribution), already carded.

## What is already dynamic (verified against the code, 2026-08-26)

1. **The verdict re-measures every scan.** `engine/src/analysis.rs:37
   analyse_domain()` re-queries DNS from scratch on every run. There is no stored
   "provider is failing" bit anywhere. If Amazon ships CDS tomorrow, the *very next* scan
   of an AWS-hosted zone reads `published — automated DS maintenance signaled` / OK.
   Nothing to flip; nothing to clear; the old warning simply is no longer computed.

2. **There is no hardcoded vendor capability claim in the engine.** Grep over
   `engine/src/` + `cli/src/` for `route 53 | route53 | amazon | cloudflare | cannot |
   does not support | not supported` returns **zero verdict-affecting matches**. The only
   `cloudflare` hits are the test-resolver config, a DKIM selector, and doc comments. The
   tool has never said "your provider can't do this" — it says what it *measured about
   your domain*: `not published — zone exists, no CDS/CDNSKEY`.

   **Boundary case that must be named, or this sentence gets quoted wrong:**
   `engine/src/asn_classification.rs` IS a hardcoded vendor-adjacent table (Cloudflare /
   Akamai / Fastly / Sucuri / Imperva / KeyCDN = `ProxyEdge`; Amazon / Google / Microsoft
   = `SharedCloudAmbiguous`). So the precise claim is **"zero *capability* tables affect
   *verdicts*"** — NOT "zero vendor tables exist." The ASN table is a network-*role*
   table: slow-changing BGP facts that feed the flux vantage only, never a control
   verdict, never the seal, and its comments deliberately fail toward *measurable*
   (unknown ASN → measurable, not "not observable"). It is the governed exception —
   and the one list a future session must keep honest. Maintenance rule: role rows are
   dated, and a row nobody can re-source gets removed, not trusted.

3. **The one attribution the engine *does* carry is a measurement, not a capability
   claim.** `tlsa_zone` (DANE) is derived by `classify_tlsa_zone(domain_apex,
   host_apex)` → `SameZone | DescendantZone | ForeignZone | NoMxHost | ZoneUnmeasured`
   (`engine/src/analysis.rs:1000-1011`). It classifies a *measured zone relationship* —
   "your MX host lives in a foreign unsigned zone, so a trustable TLSA can't exist" — never
   "Google doesn't support DANE." It self-heals exactly because it re-classifies the
   relationship every scan.

4. **The "vendor chose not to" language lives only in the research/advising layer, and it
   is dated + measured there.** `docs/RESEARCH-cds-cdnskey-threat-model-20260826.md` says
   "Route 53 does not publish CDS" *as a timestamped measurement* ("0 of 6 signed Route 53
   zones, measured 2026-08-26"), not as an eternal fact. A dated measurement is already
   dynamic: it expires on its own face the moment it is re-measured.

5. **Golden fixtures are the one live-assertion hazard — corrected (2026-08-26).** The
   earlier version of this doc wrongly claimed they are "frozen measurements." Measured:
   they are NOT. `macro_rules! golden_fixture_test` (`engine/src/analysis.rs:1702`)
   builds a LIVE resolver (`make_test_resolver()`, real Cloudflare DoT) and calls
   `analyse_domain()` against the real internet, then asserts a hardcoded
   `TriState::Present` for `cloudflare.com`, `example.com`, `ietf.org`,
   `whitehouse.gov` — all `#[ignore]`d. That inverts the safety argument: a frozen
   capture self-heals by irrelevance (never consults the world); a live assertion with a
   hardcoded expectation is a standing claim about four third-party zones that goes false
   the day any of them changes DNSSEC posture, and the failure reads as *our* defect.
   The `#[ignore]` makes it worse — "wired but never fires" in CI. **Fix (the principle
   applied verbatim, carded not yet built):** record the observation date beside each
   expectation so a failure reads "the world changed since <date>", or make them true
   frozen captures against recorded responses — which is what this doc originally
   (wrongly) assumed they were. Note the tree already anticipates this class: the
   `#[ignore]`d island test at analysis.rs:3142 carries a comment that it "DIES the day
   resolutionscope.com's DS lands" — the pattern is known, just not yet applied to the
   golden fixtures.

## The one thing that IS worth building (the 20%)

The instrument already reports CDS-absence honestly *without naming the host*. What it does
NOT do is name *who* the DNS host is, so it cannot say "this particular absence is a
host-capability fact, not your negligence." That is the `cds_host_capability` attribution
card.

**If built, it must be built as a measurement, not a vendor table** — otherwise we create
exactly the hardcoded-rot the dynamic-field instinct is guarding against:

- **Host identity** = derived from the NS-set (same discipline as `tlsa_zone`'s apex
  classification), never a hand-maintained "Route 53 = can't publish CDS" map.
- **The "does this host publish CDS" fact** = a *running population measurement* ("N of M
  zones we've observed on this host publish CDS, as of <date>"), which flips automatically
  the moment the first post-change scan lands — because it is re-derived from observations,
  not asserted from a vendor list.
- **Capability-free wording rule (the load-bearing one):** the tool may say "your zone does
  not publish CDS, and in our running sample its host publishes none" — it must **never**
  say "your provider *cannot*." "Cannot" is a memory; "does not (measured N of M)" is a
  re-reading of the world. The difference is the whole point.

When Amazon ships CDS: the verdict flips on the next scan (already true), AND the host
population fact flips as its first post-change observation accrues (built by this card),
AND the dated research claim expires on re-measurement (already true). Three independent
mechanisms, none of them a stored bit that needs manual clearing.

## The protective rule, stated once

**A "provider is failing / chose not to" claim is only ever a timestamped measurement of
observed state, never a hardcoded capability assertion — and the instrument's verdicts are
always re-computed from live DNS, never stored.** This is the same measure-don't-animate
doctrine that already governs every control; this note just extends it explicitly to the
host-attribution layer so nobody "helpfully" reintroduces a vendor table.
