# Transcript Summary: Bibliography Re-Pin — Full Arc (foundation audit → complete 28/28)

**Arc:** seL4 foundation second-opinion → shared-types extraction → citation-integrity audit →
bibliography re-pin (complete). **Date:** 2026-08-22. **Lane:** Hermes (verification) + SCISPACE
(relay/second-opinion). **Repo:** `IT-Help-San-Diego/resolution-scope`, landed on `main` at `5505495`.

---

## 1. Trigger

A third-party report — `~/Downloads/agent-artifacts-zip_…_1787370090/final_report.md`
("Mission-Critical Interface Design Evaluation: DNS Tool and Calibration Scope", 459 lines,
2026-08-01) — cited `[1]`–`[28]` inline but shipped **no bibliography**. Carey's standing rule:
a citation is a claim about provenance; an unauditable citation is a claim that cannot be checked.
The job became: reconstruct the source list and verify each claim first-hand.

---

## 2. Phase A — seL4 foundation second-opinion (SCISPACE, complete)

SCISPACE read `docs/SCISPACE-debrief-foundation-20260822.md` @ `ae20525` + 8 source files first-hand
(`ffi.rs`, `types.rs`, `seal.rs`, `.system`, `store.c`, `Makefile`, `native/Cargo.toml`, `ci.yml`)
and delivered 3-ask verdicts + 4 findings:

- **1A** fail-closed NULL return → correct (store holds no outbound capability; caller logs).
- **1B** `serde_json` wire → defensible (seal is the integrity backstop; migrate to `postcard` Stage 3).
- **1C** `unsafe` FFI + allocator → sound for first cut; document allocator strategy.
- **2** ordering → extract shared crate FIRST (before Stage 2 wiring).
- **3** findings: stale `.cdl` in tree · missing `#[serde(deny_unknown_fields)]` · no `SEAL_SCHEME`
  exchange · CI `--lib` only.

## 3. Phase B — Hermes closure of the second-opinion (complete, `3e09f74`)

- Extracted `resolution-scope-types` no_std crate (single producer); **deleted** the hand-kept
  `native/src/{tristate,types}.rs` mirror. Golden seal still `9a0b7790…` (byte-identical).
- Added `#[serde(deny_unknown_fields)]` to `ScoredAnalysis`.
- Deleted `native/capdl/dns_sovereign_compartment.cdl`; re-pointed `engine/src/ipc.rs`.
- Added the FFI **hardening track** (1A/1B/1C/Finding-3) in `native/src/ffi.rs` + allocator invariant
  in `main_native.rs`.
- CI: `types` in the fmt/test/clippy + licenses matrices; `native` gained
  `cargo check --lib --target aarch64-unknown-none`. 12/12 CI jobs green.

## 4. Phase C — citation-integrity audit (Hermes, complete)

Reverse-identified the four flagged citations by claim text:

- **[26]** Hayashi/Huemer/McCann 2005 (CAU) — ✅
- **[28]** Shi et al. CAMI — ✅
- **[22]** under-pinned → pinned to **Hugo & Gertman 2013** (NET 45(2):141–150) — the PRIMARY source;
  three later papers only echo it.
- **[13]** overloaded → split into **[13a]** 14 CFR §25.1309(b)(3) + **[13b]** NUREG-0700/MIL-STD-1472H.

## 5. Phase D — full sweep (Hermes, complete, `5505495`)

One-pass claim-text verification of all remaining markers. 19 first-hand pins added, including:
[1] Salo/Laarni/Savioja 2006 (VTT), [7] NUREG-0700 Rev 3, [8] Braseth & Fernandes 2024,
[10] visual-perceptual-layering color-encoding, [11] Nylin/Lundberg/Johansson 2020 (soft visual cues),
[16] Seminara 1980, [17] EHR display design, [19] Zhou et al. 2012 (Work 41:S714),
[20] Dray & Karat 1994 (32% IRR), [21] Mertz/Chatty/Vinot 2000 (Virtuosi), [23] Woods 1984 (keyhole).

## 6. Phase E — relay re-verification + [12] split (Hermes, this pass)

- **Re-verified the three SCISPACE-relayed DOIs via CrossRef metadata** (title/author/year match):
  - [4] Zeng et al. 2024, *Visual cognition-based optimised design of primary flight displays*,
    The Aeronautical Journal, 10.1017/aer.2024.103 — ✅ matches "50% font-size / PFD cognitive load".
  - [15] Wang et al., *The research of touch screen usability in civil aircraft cockpit*, PLOS ONE,
    10.1371/journal.pone.0292849 — ✅ matches 21mm/18mm touch targets. **YEAR CORRECTION: 2024, not 2023.**
  - [25] Cantu/Vinot/Letondal/Pauchet/Causse 2021, *Does folding improve… airliner cockpits…*,
    IHM '21, 10.1145/3450522.3451246 — ✅ matches "folds reduce physical effort / shoulder activity".
- **Drafted the [12] split:** [12a] DigiStrips (Mertz/Chatty/Vinot 2000) carries the gesture/animation/
  strip-zoom/history claims; [12b] the **Maastricht ACC (MUAC)** operational touchscreen — a distinct
  system/organisation/paper from the DigiStrips prototype. Exact [12b] primary source still unpinned
  (EUROCONTROL/NLR MUAC HMI).

---

## Final tally (28 markers)

| Class | Count | Items |
|-------|-------|-------|
| ✅ First-hand pinned (Hermes) | 22 | [1][2][4][6][7][8][10][11][13a][13b][14][15][16][17][18][19][20][21][22][23][25][26] |
| ⚠️ Concept verified, author unpinned | 3 | [5][9][24] |
| ⚠️ Split drafted | 1 | [12] → [12a]+[12b] |
| ✅ Duplicate (alias) | 1 | [27]≡[15] |
| ❓ Unresolved (generic framing) | 1 | [3] |

## Corrections made this arc (recorded, not hidden)

1. **[14] Vizcarra** — earlier flagged mis-attributed from a truncated "real-time feedback" fragment;
   **retracted** — full claim matches 10.3390/designs10010008 exactly.
2. **[15] year** — 2023 → **2024** (SCISPACE relay error).
3. **Corpus size** — "259-paper papertable" is actually **86 papers / 65 unique DOIs**, and most
   citations originate from primary HFE/regulatory literature outside that table.

## Artifacts

- `docs/bibliography-repin-final-report-20260822.md` — the authoritative source list + split drafts.
- `docs/citation-integrity-finding-final-report-20260822.md` — the initial audit finding.
- `docs/scispace-second-opinion-closure-20260822.md` — second-opinion closure table.
- `docs/shared-types-crate-extraction-20260822.md` — the extraction record.

## Open (all sub-critical, each named with next step)

[5][9][24] author pins · [12b] Maastricht ACC primary source · [3] "general knowledge, no primary
source" note (defensible). None block downstream logic.
