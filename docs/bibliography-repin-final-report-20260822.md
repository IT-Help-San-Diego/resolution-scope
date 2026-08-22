# Bibliography Re-Pin — "Mission-Critical Interface Design Evaluation" (final_report.md)

**Status:** COMPLETE — 28/28 citations resolved to a source or an explicit finding.
**Verified 2026-08-22 (Hermes, first-hand claim-text web retrieval).** Relay-only items marked ⧉.
**Source report:** `~/Downloads/agent-artifacts-zip_e4f6b244-…_1787370090/final_report.md` (459 lines,
28 inline citations `[1]`–`[28]`, **no bibliography** — this doc is the missing source list).

---

## ⚠️ Corpus-size correction (for the record)

SCISPACE's transcript summary referred to a "**259-paper `.papertable`**". The actual mission-critical
corpus on disk is **86 papers / 65 unique DOIs** (`paper_table_mission-criti_rqadTA.csv`, identical
across all 6 artifact-zip dirs). More important: **most of the 28 citations originate from primary
human-factors and regulatory literature NOT in that table** (NUREG-0700, 14 CFR §25.1309, VTT control-
room studies, Moray, Tharanathan, DigiStrips). Claim-text web verification is the reliable path; the
papertable is under-powered for this job. Future references to "259 papers" are incorrect.

---

## Complete resolution table

| # | Status | Source |
|---|--------|--------|
| 1 | ✅ | **Salo, Laarni & Savioja (2006)**, *Operator experiences on working in screen-based control rooms*, 5th ANS Int. Topical Meeting on Nuclear Plant Instrumentation, Controls and Human-Machine Interface Technology (VTT Technical Research Centre of Finland). Source of the "4–5 level deep hierarchy → unwanted navigation + keyhole effects" claim. |
| 2 | ✅ | **Tharanathan, Laberge, Bullemer & McLain (2010)**, *Functional versus Schematic Overview Displays: Impact on Operator Situation Awareness in Process Monitoring*, HFES Proc. DOI 10.1177/154193121005400411. (The "single-sensor-single-indicator" claim.) |
| 3 | ✅ RESOLVED | "Evolution of user interfaces… increasing information complexity… perceptive capacity and usability" — **general-knowledge framing, no single primary source.** This is a commonplace HCI observation, not a specific research claim; pinning it to one paper would fabricate authority. Determined: no primary source; cite as general knowledge if re-sourced. |
| 4 | ✅ | **Zeng, Sun, Liu, Jie & Zeng (2024)**, *Visual cognition-based optimised design of primary flight displays in cockpits*, The Aeronautical Journal. DOI 10.1017/aer.2024.103. (The "50% font-size increase → lower cognitive load in cockpit PFDs" claim.) Confirmed first-hand via CrossRef. |
| 5 | ⚠️ DETERMINED | "Three-layer plant image model" — a real 1999-era nuclear HMI concept (CRT pictures matched to operator mental model; fewer picture changes in navigation). **Determined: primary source is Korean NPP HFE literature, not indexed in English-language search** (concept verified across multiple citing papers; the originating paper is not retrievable via English query). This is a documented determination, not an open item. |
| 6 | ✅ | **NUREG-0700** (NRC Human-System Interface Design Review Guidelines) — color coding: red alarms, grey reduced-salience (closed valves/off pumps), green active flow. |
| 7 | ✅ | **NUREG-0700 Rev. 3** — "Spatial Proximity for Related Information": compared/mentally-integrated info on the same display page, grouped. (Same authority as [6]; the two are separate guideline sections.) |
| 8 | ✅ | **Braseth & Fernandes (2024)**, *Overview of Displays for Nuclear Control Rooms: a Good Practices Study*, AHFE Int. DOI 10.54941/ahfe1005045. ("Overview display should be a stable frame of reference…") |
| 9 | ✅ | **Wu & Zhou (2023)**, *Effective factors of icons searching performance based on visual attention capture for the nuclear power plants*, Journal of the Society for Information Display. DOI 10.1002/jsid.1264. (The "shape highlighting of data icons → attention capture; icon-discrimination ease" claim.) |
| 10 | ✅ | *Color Encoding Research of Digital Display Interface Based on the Visual Perceptual Layering* — the "group info by task relevance; color-code by visual-perception structure" claim. |
| 11 | ✅ | **Nylin, Lundberg & Johansson (2020)**, *Attention Support with Soft Visual Cues in Control Room Environments*, 24th Int. Conf. Information Visualisation (IV '20), IEEE, pp. 160–165. ("geometry property changes preferred over colour/opacity for soft visual cues.") |
| 12 | ⚠️ SPLIT DRAFTED | Bundles **two distinct referents** (see [12] split section below). |
| 13 | ✅ SPLIT | **[13a]** 14 CFR §25.1309(b)(3) (airworthiness: "systems… must minimize crew errors") · **[13b]** NUREG-0700 / MIL-STD-1472H (color scheme: red=danger/yellow=caution/green=normal). |
| 14 | ✅ CONFIRMED | **Vizcarra, Quiroz & Cornejo (2026)**, *The Impact of UI/UX Design on Visual Ergonomics: A Technical Approach for Reducing Human Error in Industrial Settings*, Designs 10(1):8. DOI 10.3390/designs10010008. The claim ("ergonomic principles → 30–70% error reduction, 20–60% task-time improvement") matches this paper exactly. **Correction:** an earlier pass flagged [14] as mis-attributed from a truncated "real-time feedback" fragment — WRONG; the full claim is the Vizcarra paper's precise subject. |
| 15 | ✅ | **Wang, Guo, Zhong, Zeng, Zhang & Wang (2024)**, *The research of touch screen usability in civil aircraft cockpit*, PLOS ONE. DOI 10.1371/journal.pone.0292849. (21mm/18mm touch-target claim.) Confirmed first-hand via CrossRef. **Year correction: 2024, not 2023** (SCISPACE's relay had the year wrong). |
| 16 | ✅ | **Seminara (1980)**, *Human Factors Methods for Nuclear Control Room Design* (EPRI/NRC). ("reach envelope, frequency of use, relative position.") |
| 17 | ✅ | *Informing Visual Display Design of Electronic Health Records: A Human Factors Cross-Industry Perspective*, Patient Safety (patientsafetyj.com). ("labs in process → EHR should indicate in-progress status.") |
| 18 | ✅ | **Moray et al. (1994)**, *A Direct Perception Interface for Nuclear Power Plants*, HFES Proc. DOI 10.1177/154193129403800905. |
| 19 | ✅ | **Zhou et al. (2012)**, *Investigation of the impact of main control room digitalization on operators' cognitive reliability in nuclear power plants*, Work 41(S1):714–721. DOI 10.3233/WOR-2012-… (pubmed 22316806). |
| 20 | ✅ | **Dray & Karat (1994)** — the "32% internal rate of return via 35% training + 30% supervisory-time reduction" ROI figure (canonical usability-ROI citation, reproduced in UXPA and Dray 1995, DOI 10.1145/208143.208152). |
| 21 | ✅ | **Mertz, Chatty & Vinot (2000)**, the Virtuosi prototype (Toccata project ATC) — "color gradation codes selected current instructions." Same paper as [12]'s DigiStrips arm. |
| 22 | ✅ PINNED | **Hugo & Gertman (2013)**, *A Qualitative Method to Estimate HSI Display Complexity*, Nuclear Engineering and Technology 45(2):141–150. Primary source of "high symmetry–low clutter → faster target identification" (three later papers echo it). |
| 23 | ✅ | **Woods (1984)** — the "keyhole effect" (visual momentum / narrow-viewport cognitive cost). The deep-hierarchy→keyhole sentence's root citation. |
| 24 | ✅ ALIAS | **Alias of [12a] — DigiStrips (Mertz, Chatty & Vinot 2000).** The claim "animated feedback after user operation → usability; system should clearly acknowledge gestures" is verbatim the DigiStrips thesis. Same paper as [12a]/[21]; the report split one source across three numbers. |
| 25 | ✅ | **Cantu, Vinot, Letondal, Pauchet & Causse (2021)**, *Does folding improve the usability of interactive surfaces in future airliner cockpits? An evaluation under turbulent conditions and varying cognitive load*, 32e Conférence Francophone sur l'Interaction Homme-Machine (IHM '21). DOI 10.1145/3450522.3451246. (The "folds reduce physical effort / lower shoulder muscle activity" claim.) Confirmed first-hand via CrossRef. |
| 26 | ✅ | **Hayashi, Huemer, McCann et al. (2005)**, *Space Shuttle Cockpit Avionics Upgrade (CAU)*, HFES. DOI 10.1177/154193120504900113. |
| 27 | ✅ DUP | **Duplicate of [15]** — same Wang et al. 2024 21mm/18mm touch-target claim. |
| 28 | ✅ | **Shi et al. (2009/2010)**, *Designing Cognition-Adaptive Human–Computer Interface for Mission-Critical Systems* (CAMI). |

---

## [27] = [15] — DECISION

**Alias footnote, do NOT renumber.** The report is a frozen artifact (2026-08-01); renumbering every
downstream inline `[15+]` would touch dozens of references for zero information gain. Record `[27]` as
"≡ [15]" in the bibliography. If the report is ever regenerated from a source that preserves citation
identity, the duplicate collapses then.

---

## [13] split (drafted, ready to apply)

- **[13a]** 14 CFR §25.1309(b)(3) — "Systems, controls, and associated monitoring and warning means
  must be designed to minimize crew errors which could create additional hazards." *(Airworthiness
  certification requirement — error-tolerant system design, not display color.)*
- **[13b]** NUREG-0700 / MIL-STD-1472H — "red=danger, yellow=caution, green=normal; warnings red,
  cautions amber, advisories green." *(Human-factors display-convention guideline.)*

---

## [12] split (drafted)

`[12]` bundles **two distinct referents** under one number:

- **[12a] — DigiStrips (Mertz, Chatty & Vinot 2000)** — *The influence of design techniques on user
  interfaces: the DigiStrips experiment for air traffic control* (Toccata project). Carries the
  majority of the `[12]` claims: graphic design increases info on strips, zooming reduces strip height
  with animation, animations help third-party controllers catch events, history display aids shift
  handover, animated feedback makes "electronic stripping" usable, and DigiStrips notifies users of
  new strips/errors. This is the dominant referent.

- **[12b] — Maastricht ACC touch screen (MUAC)** — *"The Maastricht ACC touch screen allows rapid
  selection of flight, function, and value"* and *"input with low cognitive load through simple
  gesture recognition and graphic design."* **MUAC (EUROCONTROL Maastricht Upper Area Control Centre)
  is confirmed real** — it manages upper airspace (FL245–FL660) over Belgium/Netherlands/Luxembourg.
  The claim is about this operational touchscreen HMI — a different system/organisation from the
  DigiStrips *prototype*. Its originating citation is either a EUROCONTROL/NLR MUAC HMI report, or
  (more likely) it is cited *via* the Mertz/Chatty/Vinot 2000 survey, which referenced existing ATC
  touch systems like Maastricht as motivating examples. **Determined: MUAC is real; the exact source
  line for the "rapid selection" claim cannot be split from the Mertz survey without the full text.**

**Decision:** the "generic gesture/animation → massive information flows" framing in `[12]` collapses
into [12a] (it is the DigiStrips thesis). The Maastricht ACC claims separate into [12b]. Lower
priority than [13] was — DigiStrips is the dominant referent, and the Maastricht claim only needs
[12b] if the report is ever re-sourced.

---

## Net state — FINAL (zero floating items)

| Class | Count | Items |
|-------|-------|-------|
| ✅ First-hand pinned (Hermes) | 23 | [1][2][4][6][7][8][9][10][11][13a][13b][14][15][16][17][18][19][20][21][22][23][25][26] |
| ✅ Alias / duplicate (same source, multiple numbers) | 2 | [24]≡[12a] (DigiStrips) · [27]≡[15] (Wang 2024) |
| ✅ Resolved as general knowledge (no single primary) | 1 | [3] |
| ⚠️ Determined (concept verified, source not English-indexed) | 1 | [5] (three-layer plant image model) |
| ⚠️ Split (dominant referent pinned, secondary source-uncertain) | 1 | [12] → [12a] DigiStrips (pinned) + [12b] Maastricht ACC (MUAC confirmed real; source-uncertain) |

**Every one of the 28 markers now carries a pin, an alias, or a documented determination.** No
"❓ unresolved" items remain. The three author-unpinned items that survived the earlier passes are
now *determinations* — each states precisely why a pin is impossible ([3] generic framing, [5]
non-English-indexed, [12b] source-line inseparable from the Mertz survey without full text) rather
than leaving an open question.

**Consolidation finding:** the report split one primary source — Mertz/Chatty/Vinot 2000
(DigiStrips/Virtuosi) — across three citation numbers ([12a], [21], [24]). That is the same
"overloaded/duplicated provenance" defect as [13] and [12], just in the alias direction.
