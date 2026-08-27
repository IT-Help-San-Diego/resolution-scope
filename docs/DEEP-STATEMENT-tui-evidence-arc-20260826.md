# Resolution Scope — TUI & Evidence Arc: Deep Statement

_2026-08-26 · author: Hermes lane · status: for four-mind review (Claude Science, SciSpace, Claude Code)_

This is the consolidated record of what changed tonight and what is now on the
table, so the other lanes can read the whole arc from one artifact and rule on
the open questions. It is a statement, not a spec: the spec/ruling files remain
the authority; this is the map of the terrain.

---

## Part 1 — What changed tonight (the TUI arc, in order)

All commits are on `origin/main`; the newest is `4676ef1`.

| Commit | Change | Why |
|---|---|---|
| `7f7fc76` | **Deleted the PASS/FAIL translation.** The verdict word now renders the machine's own state name — `PRESENT` / `ABSENT` / `INDET` / `N/A` — instead of an invented `PASS`/`FAIL` in all three surfaces (engine report, CLI, TUI) plus the site specimen. TUI also colors the word by *severity*, not presence. | `PASS`/`FAIL` collapsed broken-with-absent and strong-with-weak, re-introducing exactly the conflation RFC 4033 §5 exists to prevent (Bogus vs Insecure get different words). The judgment now lives in severity + tier + consequence, not a two-letter verdict. Seal is byte-identical (it hashes `disposition=tri`, never the display word). |
| `79ce937` | **Framing word colored by mode + fixed a stale-key bug.** "BLUE TEAM · defend" now renders blue, "RED TEAM · assess" red (was amber/orange via `p.warn`). Also corrected three stale strings that told the user the seal was at key **7** when the code pins it at **9**. | The word "blue" must BE blue. The 7→9 mismatch was the "I keep asking and never get an answer" bug — the UI was gaslighting the user. |
| `64f172b` | **Descriptive framing tail on roomy terminals.** Added a width-gated tail after the framing word. | Speak to the owner AND the hacker/assessor register. |
| `6d42804` | **Apple key glyphs (Option A)** — `⎋ ⏎ ⇥ ①-⑨`. **REVERTED.** | Measured after the fact: no single terminal font carries all four glyphs. They rendered as tofu. |
| `33ef061` | **Word keycaps + brand gradient.** Replaced glyphs with words; `RESOLUTION` got a red→green gradient. | Wingdings-proof. |
| `2ac0f48` | **Reverted the gradient → solid accent.** | The word is too short; the gradient read as a rainbow (the classic Unix rainbow-terminal look we're leaving behind), and a rainbow is carrier color in the brand mark. |
| `4f7820e` | **Bracketed keycaps.** `[enter] open` / `[esc] back` / `[tab] next` with box-only separators (still fits 80 cols). | A bracketed word reads as a keycap, more visible than a bare word (the `less`/`vim`/`mc` rule). Single-letter keys (`m r d q`) stay bare. |
| `4676ef1` | **Dropped "what it costs you".** Blue framing tail is now `· what to fix`. | "What it costs you" was my own wording (not CISA) and overreached — the instrument measures posture, not financial consequence. |

**Current header state (verified cell-level from the render buffer):**

```
🦉  RESOLUTION SCOPE │ BLUE TEAM · defend · what to fix │ domain 1/1 it-help.tech
engine 26.0.0-alpha.1-… · resolver cloudflare · … UTC · measured in 10.5s · seal …
keys 1-9│↑↓/jk│[enter] open│[esc] back│m red│r rescan│[tab] next│d new│q quit
1:Summary │ 2:DNSSEC │ 3:DANE │ 4:SPF·DKIM·DMARC │ 5:MTA-STS │ 6:CAA/CDS │ 9:Seal
```

Red mode (`m`) flips the accent to red, the framing to `RED TEAM · assess · the
attacker's view`, and `m red`→`m blue` (the help line names the flip *target*).

**Pin tests landed:** `brand_is_solid_accent_not_a_gradient`,
`help_line_is_words_not_glyphs_and_fits_80`. 61/61 green, clippy clean.

---

## Part 2 — The evidence gap (the real finding)

The detail tabs (2–6) show the *truth chain* — severity, tri-state, the static
`measured` label, RFC requirement, consequence — but **not the raw DNS records
the verdict was computed from.** The record is the proof; the label is the
summary. A reader currently has to trust the label.

Ground truth, read from the code:

- `score_spf` (`engine/src/analysis.rs:432`) **extracts the exact TXT bytes**
  (`spf_records: Vec<String>` of `v=spf1 … ~all`), classifies them, and
  **returns only the disposition** — the `Vec` drops at function end.
- `ScoredAnalysis` (`types/src/dispositions.rs:530`) has **no raw-record
  field** — only `tri` + `disposition` per control.
- `ControlReport.measured` (`engine/src/truth_chain.rs:155`) is a `&'static str`
  label (`"softfail (~all) — publisher's weaker assertion"`), not the record.
- The HTML renderer (`cli/src/render.rs`) emits the same layers as the TUI:
  severity label + `tri_icon` + `measured` + consequence. No record bytes.

So this is a **capture feature**, not a render tweak. The bytes are in hand at
classification time and thrown away.

---

## Part 3 — Three requirements now on the table

### A. Raw records in detail tabs 2–6, color-coded (proof above explanation)

The record must render **above** the explanation, not replace it. The big-picture
questions and the consequence text **stay** — the record is added as evidence.

**Color legend (proposed, for ruling):**

| Color | Meaning |
|---|---|
| **Green** | well-formed AND the strong/correct state (`-all`, `p=reject`, key valid) |
| **Yellow** | well-formed but a caveat — **valid, not wrong** (`~all` softfail, `p=quarantine`) |
| **Red** | malformed / broken (bad syntax, conflicting SPF, unparseable key) |

The load-bearing distinction to rule on: **yellow = "valid but weak," never
"wrong."** Softfail is a real choice, not a mistake. If yellow means "error" we
re-introduce the same conflation we just deleted from the verdict words. Color
annotates *formatting + strength*; the verdict word stays separate.

**Scope order:** start with the four TXT-record controls — **SPF, DKIM, DMARC,
CAA** — because those are literally the "copy the record from your provider"
strings (the strongest proof), then DNSSEC/DANE/MTA-STS/CDS/CDNSKEY.

### B. Persist all intel to the database

The store crate already persists `(domain, engine_version, seal, seal_scheme,
verdict)` + `lookup_receipts`. Requirement: **the raw records per control must
also persist**, so the DB is the full evidence store — a reader can pull the
records that produced a sealed verdict, not just the verdict.

Schema question for Science: per-control JSON column on `scans`, or a separate
`records` table keyed to `scan_id` (mirroring `lookup_receipts`)? And are the
records **sealed** (part of the preimage) or **unsealed evidence** (like the
receipts — provenance that rides alongside, never inside, the seal)?

### C. The Owl Semaphore "triggered owls" must appear somewhere

Not wired anywhere in this codebase today — verified: `owl`/`semaphore` match
only in `docs/` discussion, zero in `.rs`. The Owl Semaphore (Klein four-group:
I / σᵥ / C₂ / σₕ, epistemic stances, *not* truth-values) is a separate framework
(`owl-semaphore` repo, DOI 10.5281/zenodo.21524422).

**Open question:** what maps a DNS verdict to an owl stance? The four owls are
stances toward a *claim* (Normative "is", Non-Normative "reflects", Critical
"inverts", Metacognitive "examines"), not document-type tags. Does a DNS
disposition trigger an owl at all, or is the owl a *separate* classification
layer that the verdict feeds into? This is the design question for Science.

---

## Part 4 — Parity note (what the family already does)

The **DNS Tool** (Go, `dnstool.it-help.tech`) — the mature sibling — **already
shows raw records on its web page**, with RFC citations displayed beside
verdicts. This is not a new idea; it is the proven pattern the resolution-scope
surfaces must reach parity with. The requirement already exists in the family;
it has not been inherited into this repo.

---

## Part 5 — Open questions for the four-mind

1. **Color legend** — is green/yellow/red = strong/valid-but-weak/broken the
   right annotation? (Especially: does "yellow" read as *caveat* not *error*?)
2. **Owl mapping** — does a DNS disposition trigger an owl stance, and if so
   what's the mapping? Or is the Owl Semaphore a separate layer?
3. **Sealed vs unsealed** — are the raw records part of the seal preimage, or
   unsealed evidence (like receipts)?
4. **DB schema** — per-control JSON vs a `records` table?
5. **Scope confirmation** — TXT controls (SPF/DKIM/DMARC/CAA) first, then the
   rest, agreed?

_End of statement. Hermes lane — pending Science/SciSpace ruling._
