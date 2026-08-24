# CDS-vs-DS measurement — N1/N2 rate at rest (2026-08-24)

Live DNS spot-check (read-only, `dig` against the recursive resolver), to answer
debrief §5's scope question: **among zones that PUBLISH CDS, how often does CDS
differ from the parent DS** — the "rollover in progress" (N2) signal.

## Result

| zone | publishes CDS? | CDS == DS? |
|---|---|---|
| cloudflare.com | yes | ✅ in-sync (N1) |
| ietf.org | yes | ✅ in-sync (N1) |
| isc.org | yes | ✅ in-sync (N1) |
| iis.se | yes | ✅ in-sync (N1) |
| whitehouse.gov | yes | ✅ in-sync (N1) |
| internetsociety.org | yes | ✅ in-sync (N1) |
| nasa.gov | no | — (NotPublished) |
| paypal.com | no | — (NotPublished) |
| bankofamerica.com | no | — (NotPublished) |
| comlaude.com | no | — (NotPublished) |
| akamai.com | no | — (NotPublished) |

## Findings

1. **N2 rate = 0%** in this sample — 6 of 6 CDS-publishing zones have CDS == DS.
   "Rollover in progress" (CDS ≠ DS) is a *transient* state: CDS is published to
   enable a rollover, and once it completes the CDS matches the new DS. A
   periodic scanner at rest almost never catches the mid-rollover window.

2. **The dominant state is "no CDS published"** — 5 of 11 signed zones (45%)
   don't publish CDS. This corroborates the Aug-21 ruling (CDS is optional
   automation, a standing declaration, not a rollover signal; absence ≠ "no
   rollover in progress", absence = "manual DS maintenance").

3. **Implication for the N1/N2 grading decision:** building match-vs-differ
   grading has near-zero steady-state yield — it would only fire during an
   active rollover. The honest value is *during* rollover detection (a transient
   the scanner must hit by timing), not a resting-state taxonomy. This weighs
   toward **deferring** N1/N2 as a standalone finding and instead surfacing CDS
   match/mismatch only as a live-observation note when it actually differs.

## Honest limits

- N = 11 zones, 6 publishers — a spot check, NOT a rate with confidence bounds.
  No large-scale CDS-vs-DS corpus measurement exists (unlike DMARCguard's SPF
  qualifier breakdown). Treat as indicative, not a prevalence claim.
- Key tags reproduced byte-identical between CDS and DS in all six publishers,
  which independently re-confirms the operator-clustering observation from the
  ruling (Cloudflare's shared KSK tag 2371 across four zones).
