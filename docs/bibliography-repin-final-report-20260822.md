# Bibliography Re-Pin — "Mission-Critical Interface Design Evaluation" (final_report.md)

**Status:** first-hand verified where marked ✅; relayed from SCISPACE where marked ⧉; still
unidentified where marked ❓. **Verified 2026-08-22 (Hermes, primary-source web retrieval).**

**Source report:** `~/Downloads/agent-artifacts-zip_e4f6b244-…_1787370090/final_report.md` (459 lines,
28 inline citations `[1]`–`[28]`, **no bibliography**).

---

## ⚠️ Corpus discrepancy (flag to SCISPACE)

SCISPACE's transcript summary refers to a "**259-paper `.papertable` corpus**". The actual
mission-critical corpus on disk — `paper_table_mission-criti_rqadTA.csv` (identical across all
6 artifact-zip dirs) — is **86 papers / 65 unique DOIs**, not 259. And crucially, **most of the
28 citations do not originate from that table**: they cite primary human-factors and regulatory
literature (NUREG-0700, 14 CFR §25.1309, Moray's direct-perception work, Tharanathan's SSSI
overview displays) that the SciSpace-scraped table does not contain. The papertable-matching
strategy is therefore under-powered; direct claim-text verification is the reliable path.

---

## [13] SPLIT (the overloaded citation)

`[13]` bundles **two distinct authorities** under one number. Split:

### [13a] — 14 CFR §25.1309(b)(3) (airworthiness regulation)
**Claim:** "Systems, controls, and associated monitoring and warning means must be designed to
minimize crew errors which could create additional hazards."
**Authority:** Code of Federal Regulations, Title 14, §25.1309(b)(3) (transport-category
airplanes; the parallel clause for normal/utility aircraft is §23.1309(b)(3)). This is a
*certification requirement* about error-tolerant system design, not a display-color guideline.
**First-hand:** the exact sentence is quoted verbatim in FAA and NTSB documents (e.g. the NTSB
"Assumptions Used in the Safety Assessment Process…" report, and NASA/FAA HFE references).

### [13b] — NUREG-0700 / MIL-STD-1472H (human-factors color-coding convention)
**Claim:** "A powerful learned association links red with danger, yellow with caution, and green
with normal operations. Warnings should be red, cautions amber/yellow, and advisories green."
**Authority:** the color-coding scheme is human-factors guidance, in NUREG-0700
("Human-System Interface Design Review Guidelines", NRC) and MIL-STD-1472 (DoD human-engineering
design criteria; the report elsewhere cites the H revision). This is a *display-convention*
standard, unrelated to the airworthiness clause in [13a].

> The two are different in kind — a regulation (what a system must do to be airworthy) vs a
> design guideline (how to render status so operators read it correctly). Citing both under
> `[13]` makes the number unauditable. Use `[13a]` and `[13b]`.

---

## Full citation map

| # | Status | Identification |
|---|--------|----------------|
| 1 | ❓ | General HFE framing ("mission-critical interfaces demand design principles… nuclear control rooms face similar challenges"). Broad; needs a specific primary source. |
| 2 | ✅ | **Tharanathan, Laberge, Bullemer & McLain (2010)**, *Functional versus Schematic Overview Displays: Impact on Operator Situation Awareness in Process Monitoring*, HFES Proc. — DOI 10.1177/154193121005400411. (The "single-sensor-single-indicator" displays claim originates here.) |
| 3 | ❓ | "Evolution of user interfaces… increasing information complexity… perceptive capacity and usability." |
| 4 | ⧉ | Zeng et al. (2024) — DOI 10.1017/aer.2024.103 (SCISPACE). |
| 5 | ❓ | "Three-layer plant image model" for NPP operator mental models. Could not pin (search returns noise). Likely a Korean/Japanese NPP HFE paper. |
| 6 | ✅ | **NUREG-0700** (NRC Human-System Interface Design Review Guidelines) — the color-coding guidance: red for alarms, grey for reduced salience (closed valves/off pumps), green for active flow. |
| 7 | ❓ | "Information to be compared/integrated should be spatially proximate/grouped" — human-factors display-layout guideline. |
| 8 | ❓ | "Overview displays should be a stable frame of reference…" — nuclear overview-display guidance. |
| 9 | ❓ | "Shape highlighting of data icons… improves attention capture in NPP visual search" — specific NPP paper. |
| 10 | ❓ | "Interface info grouped by task relevance; color coding per visual-perception structure." |
| 11 | ❓ | "ATC: geometry symbol-property changes preferred over color/opacity for soft cues" — ATC paper. |
| 12 | ❓ | "Gestures + animated feedback… massive information flows, little cognitive load." |
| 13 | ✅ SPLIT | **[13a]** 14 CFR §25.1309(b)(3) · **[13b]** NUREG-0700 / MIL-STD-1472H (see above). |
| 14 | ⧉ | Vizcarra et al. — DOI 10.3390/designs10010008 (SCISPACE; claim is "real-time feedback → improved performance" — re-verify this actually matches the Vizcarra paper). |
| 15 | ⧉ | Wang et al. (2023) — DOI 10.1371/journal.pone.0292849 (21mm/18mm touch targets). |
| 16 | ❓ | "Control accessibility: reach envelope, frequency of use, relative position." |
| 17 | ❓ | "EHR lab in-progress status" — healthcare/electronic-health-record (an outlier in a mission-critical report). |
| 18 | ✅ | **Moray et al. (1994)**, *A Direct Perception Interface for Nuclear Power Plants*, HFES Proc. — DOI 10.1177/154193129403800905. (Exact claim: "supported better diagnostic performance, but did not improve memory for quantitative information.") |
| 19 | ❓ | "NPP MCRs: digital shift + analog/digital coexistence → cognitive effort." |
| 20 | ❓ | "32% return / 35% training / 30% supervisory time" — specific ROI numbers; needs the exact source. |
| 21 | ❓ | "Virtuosi color gradations for current instructions" — a specific named system. |
| 22 | ✅ PINNED | **Hugo & Gertman (2013)**, *A Qualitative Method to Estimate HSI Display Complexity*, Nuclear Engineering and Technology 45(2):141–150. This is the PRIMARY source of the "high symmetry–low clutter displays identified target controls faster" finding; three later papers (2019 cockpit decluttering, 2023 control-room complexity, a driving/side-task study) merely echo it. |
| 23 | ❓ | "Deep hierarchies → unwanted navigation + keyhole effects." |
| 24 | ❓ | "Animated feedback after user operation → usability; acknowledge gestures." |
| 25 | ⧉ | Cantu et al. — DOI 10.1145/3450522.3451246 (SCISPACE). |
| 26 | ✅ | Hayashi, Huemer, McCann et al. (2005), *Space Shuttle Cockpit Avionics Upgrade (CAU)*, HFES — DOI 10.1177/154193120504900113. |
| 27 | ✅ DUP | **Duplicate of [15]** — same Wang et al. 2023 claim (21mm/18mm touch targets) re-cited under a different number. Renumber to [15]. |
| 28 | ✅ | Shi et al. (2009/2010), *Designing Cognition-Adaptive Human–Computer Interface for Mission-Critical Systems* (CAMI). |

---

## Net state

- **First-hand pinned (Hermes):** [2], [6], [13a], [13b], [18], [22], [26], [27]=[15].
- **Relayed (SCISPACE, needs second-pass re-verify before citing as fact):** [4], [14], [15], [25].
- **Still unidentified:** [1], [3], [5], [7]–[12], [16], [17], [19]–[21], [23], [24].

The single highest-leverage remaining step is a claim-text → primary-source sweep of the ~15
unidentified markers, one web search each. The `[14]` relay (Vizcarra 10.3390/designs10010008) is
suspicious — the "real-time feedback" claim does not obviously match a 2026 UI/UX design paper —
and should be re-verified before it is trusted.
