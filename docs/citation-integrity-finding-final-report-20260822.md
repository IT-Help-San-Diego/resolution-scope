# Citation-integrity finding — "Mission-Critical Interface Design Evaluation" (2026-08-01)

**Finding owner:** whichever lane produced the report (relayed to SciSpace; it is git
read-only and re-pins against the repo). **Verifier:** Hermes (first-hand web check).

## The report

`~/Downloads/agent-artifacts-zip_e4f6b244-3294-4525-8f59-e6b03af5ccaa_1787370090/final_report.md`
(459 lines, "Mission-Critical Interface Design Evaluation: DNS Tool and Calibration Scope",
dated 2026-08-01).

It cites inline as `[1]`–`[28]` but ships **no bibliography** — there is no list mapping
`[n]` → source. Every claim therefore has to be reverse-identified from its quoted text.
That is itself a defect: a report whose citations cannot be audited without web archaeology.

## The four citations audited, first-hand

| # | Claim quoted in the report | Identified source | Verdict |
|---|----------------------------|-------------------|---------|
| **[26]** | "CAU … consolidates information in a task-oriented manner, rather than a data-source-oriented manner" | Hayashi, Huemer, McCann et al., *Effects of the Space Shuttle Cockpit Avionics Upgrade on Crewmember Performance and Situation Awareness*, HFES 2005, DOI 10.1177/154193120504900113 | ✅ real, correctly attributed |
| **[28]** | "CAMI, a cognition-adaptive multimodal interface, combines … cognitive system engineering and cognitive load theory" | Shi et al., *Designing Cognition-Adaptive Human–Computer Interface for Mission-Critical Systems* (2009/2010) | ✅ real, correctly attributed |
| **[22]** | "high symmetry–low clutter displays identified target controls faster than … low symmetry–high clutter" | real finding, but the sentence propagates verbatim across ≥3 papers (2019 cockpit decluttering; 2023 digital-control-room complexity; a display-clutter/separation study) | ⚠️ **under-pinned** — the primary source is not identifiable from the report |
| **[13]** | BOTH "warnings red / cautions amber / advisories green" AND "systems, controls, and associated monitoring and warning means must be designed to minimize crew errors" | **two distinct authorities under one number**: the color scheme is a human-factors standard (NUREG-0700 / MIL-STD-1472 family); "minimize crew errors" is 14 CFR §25.1309(b)(3), the FAA airworthiness standard | ❌ **overloaded** |

## Meta-finding (the durable defect class)

Two of four clean, but `[13]` and `[22]` each bundle multiple distinct claims under a single
citation number — and there is no bibliography to disambiguate. This is the same defect class
we guard mechanically in our own repos (the citation-boundary guard, the "single producer"
rule): a citation is a claim about provenance, and an overloaded or sourceless citation is a
claim that cannot be checked. It reads as authority while being unauditable.

## Ask (for the owning lane)

1. Add a bibliography mapping every `[n]` (1–28) to a full source (author, year, title, venue/DOI).
2. Split `[13]` into its two authorities — the airworthiness regulation (14 CFR §25.1309) vs the
   color-coding human-factors standard — and cite each where it is actually the authority.
3. Pin `[22]` to a single primary source (author + year + DOI), not the finding's echo.

Verification method: primary-source web retrieval of each quoted claim (the quote is the
fingerprint); no claim accepted on a relay.
