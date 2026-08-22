# Calibration Study — the next validation layer

**Status:** proposed → **all three arms have run** (2026-08-20 through 2026-08-22).
This header is updated from "proposed / nothing measured" to record that the study
is no longer a proposal. Results live in their own homes: **Arm 1** (N-version
differential, 8-domain join, 2 real findings) → `docs/arm1-20260821/`; **Arm 2**
(RFC known-answer corpus, CI-enforced `rfc_known_answer_vectors()` + Go-parent
port PR #472) → `docs/arm2-rfc-known-answer-vectors.md`; **Arm 3** (mutation,
the three `zone_apex_of` survivors closed 2026-08-22, re-measure in
`docs/mutation-analysis-20260820/`). The "before" table below is the pre-study
baseline that motivated the work — a snapshot, kept for provenance, not a live
count (analysis.rs has since grown from 1,918 → ~2,886 lines and 29 → 70 tests).

## The gap this closes

Measured on `resolution-scope` @ main, engine source:

| file | lines | tests | tests/line | mutation evidence | negative-control study |
|---|---|---|---|---|---|
| `analysis.rs` | 1918 | 29 | 1 per 66 | none | none |
| `flux.rs` | 783 | 27 | 1 per 29 | published | published |

`analysis.rs` holds the scoring logic for **all eight scored controls** (~3.6 tests
per control). `flux.rs` holds **one adjunct signal** that feeds no score.

Documentation depth is uneven in the same direction, though less starkly than a
first count suggested: across `docs/*.md`, counting every spelling of each control
name, `dnssec` appears 54 times and `flux` 26, against `caa` 2, `cds` 4 (incl.
`cdnskey`), `dkim` 5, `spf` 6, `dmarc` 6, and `mta_sts` 7 (5 `mta-sts` + 2
`mtasts`). A first pass counted only the underscore token `mta_sts` and reported
zero — an instrument artifact of one chosen spelling, corrected here. The
source-level measurement above is what the task rests on; doc counts are context.

**The component that received the full validation treatment is the least
load-bearing one.** Every verdict that reaches a public report comes out of the
un-validated file. That inversion is the finding, and it sets the next task.

## Three arms, in dependency order

### Arm 1 — N-version differential: Go analyzer vs Rust engine
The project has **two independent implementations of the same eight controls** —
`dns-tool-intel`'s Go analyzer and `resolution-scope`'s Rust engine — written by
different lanes at different times against the same RFCs. That is a genuine
differential pair, available with no third-party API, no rate limit, and no
network grant. Disagreement is actionable on both sides.

Run both over a frozen domain corpus; record every per-control disagreement.

**Known limitation, to be stated in the artifact:** both implementations were
written against the same doctrine documents, so a *doctrinal* error is replicated
in both and invisible to this arm. N-version testing bounds implementation
divergence, not specification error. Arm 2 is what addresses that.

### Arm 2 — known-answer vectors from the RFCs
Where a standard publishes a worked example, agreement with it validates against
the specification itself rather than against another implementation that may share
the bug. This is calibration against a reference standard in the metrological
sense, and it is the only arm that can catch a shared doctrinal error.

### Arm 3 — mutation testing on `analysis.rs`
Same recipe as `flux.rs`: `cargo mutants --file src/analysis.rs`, raw
`outcomes.json` committed, deterministic extractor, narrative in a separate file.
Runs last because mutation testing on logic still moving is waste; arms 1-2 are
what settle it.

## Epistemic constraints (non-negotiable, these are the study's method)

1. **Three-way disagreement classification, never two.** Each disagreement is
   *ours wrong*, *theirs wrong*, or *the spec is genuinely ambiguous*. A two-way
   split forces every ambiguity into somebody's error column and inflates whichever
   side the classifier likes less.

2. **The reference-uncertainty trap.** Most scanners have no "unmeasured" state.
   Comparing a tri-state instrument against a binary reference **systematically
   penalises the honest one** — "we said indeterminate, they said fail" scores as
   a miss when it is the instrument being more careful. Capture the reference's own
   uncertainty state, or exclude those rows and say how many were excluded.

3. **Per-control agreement rates, never an aggregate.** One number hides that
   DNSSEC may be at 99% while DANE is at 60%. The aggregate is the least
   informative statistic the study can produce.

4. **Frozen, content-addressed corpus.** Record each domain's raw answers with a
   checksum. A live-DNS corpus makes the agreement rate irreproducible — the zone
   changed, not the code.

5. **Publish the raw comparison, not the rate.** Same standard as the mutation
   evidence: a number that can only be confirmed by asking its author is an
   assertion. Commit the per-domain per-control table; let the rate be derived.

6. **A disagreement is a finding before it is a bug.** Neither implementation is
   the oracle. Whichever is wrong, the artifact records what the RFC says and why.

## What this study cannot establish

- Nothing about controls absent from the corpus. A domain set with no DANE
  deployment bounds nothing about DANE.
- Nothing about false-negative rates — that needs adversarial specimens, which
  remains an open arm of the flux study and is not fixed here.
- Nothing about the doctrine itself in Arm 1 alone (see the limitation above).

## Why this is different from what the field does

DNS security scanners publish scores. **None publishes its own error rate.** An
instrument that states per-control disagreement against an independent reference,
with disagreements classified and the raw comparison committed, is doing what
measurement instruments do and what no scanner in this field does. That claim is
worth making *only* once the number exists and is re-derivable — which is the
whole point of the constraints above.

## Prerequisite for Arm 1 (RESOLVED — Task Zero, 2026-08-20)

The Go tool's machine-readable per-control verdict surface is **`GET /api/analysis/:id`**
(handler `APIAnalysis`, `go-server/internal/handlers/analysis_api.go`; resolved in
commit `c189754`, `docs/CALIBRATION-STUDY-TASK-ZERO.md`). The three guessed paths
(`/api/analyze`, `/api/v1/analyze`, `/analyze.json`) 404'd because the API is
analysis-by-id, not analyze-by-domain: trigger `GET/POST /analyze`, then retrieve
the record. Its `full_results` member is the per-control map. **Do NOT use
`/api/replay/:id` for the join** — its `verdicts` value space is
`info/success/warning/missing` (a severity display map with no indeterminate
state), which collapses exactly the tri-state the study exists to test.

## The machine-readable format (both sides)

Arm 1 joins two implementations on their per-control verdicts. The format
contract, both halves:

- **Rust side** — `resolution-scope <domain> --format json` emits **NDJSON**: one
  `ScoredAnalysis` serialization per line, newline-delimited, so each line is an
  independently parseable record. It carries all eight disposition enums (the
  WHY — e.g. `dane_disposition: "NoMx"` vs `"NoMail"`) and all eight tri-states
  (the collapse — `Present`/`Absent`/`Indet`/`NotApplicable`), never a severity
  label. The sixteen key names are the join contract, pinned by
  `json_carries_all_sixteen_verdict_keys`.
- **Go side** — `/api/analysis/:id`'s `full_results`, the same per-control map.
  Its response self-content-addresses via `X-SHA3-512` (constraint 4 satisfied
  by storing bytes + header). The Go reference is itself tri-state
  (`absent_confirmed` ≠ unmeasured), so constraint 2's binary-reference
  exclusions do not apply to this pairing.

