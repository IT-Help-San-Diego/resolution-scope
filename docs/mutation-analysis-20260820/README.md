# Mutation testing — analysis.rs (the verdict file), 2026-08-20

This is the first mutation evidence for `analysis.rs`, the file that holds all
eight scored controls as disposition enums and produces every verdict that
reaches a public report. It is the file the calibration-study finding points at:
until now it carried **zero** mutation evidence while the adjunct signal
(`flux.rs`, which feeds no score) carried a full study.

## The baseline, measured

```
cargo-mutants 27.1.0
total=101 caught=31 missed=44 timeout=0 unviable=26 success=0
```

**44 missed mutants** — versus `flux.rs` at **0 missed** after its seam work.
The validation gap is real and large.

## Where the misses concentrate (read directly off the per-function table)

- **`score_dkim` — 13 missed.** The single largest cluster: the DKIM disposition
  scoring is almost entirely un-exercised.
- **`score_dane` — 5 missed.**
- **`score_caa` / `score_cds_cdnskey` / `score_mta_sts` — 2 each.**
- **`score_dnssec` / `score_dmarc` / `score_spf` / `record_absence_to_dane` /
  `mta_sts_policy_state` — 1 each.**
- **`fetch_mta_sts_policy` — 3 missed** (the HTTP policy fetch; network-path
  class, same shape as `observe_flux` before its seam).
- **`rand_session_id` / `unix_now` — 2 each** (time/random; replaced with 0/1).
- **8 × `Display::fmt` — 1 each** (string formatting for the disposition enums).

Every one of the eight scored controls has un-killed mutants in its scoring
path. The finding "all eight scored controls live in the un-validated file" is
now a measurement, not an assertion.

## The epistemically-load-bearing miss

The raw mutant list shows the honest-branch arms are un-tested: "delete match
arm `TriState::Indet`" survives in `score_mta_sts`, `score_caa`, and
`record_absence_to_dane`; "delete `!`" survives across `score_dane`,
`score_mta_sts`, `score_caa`, `score_cds_cdnskey`.

`TriState::Indet` is the branch that says **"I could not measure this, so I will
not report absent."** It is the whole point of the tri-state over a binary — the
absence-of-evidence-is-not-evidence-of-absence doctrine — and mutation testing
shows that deleting that arm (silently collapsing indeterminate into absent) is
caught by **no test**. That is the exact silent-failure class this project has
spent its life eliminating, sitting unguarded in the file that produces the
verdicts.

## What this is and is not

**Is:** the raw, re-derivable baseline for the calibration study. Reproduce with
`cargo mutants --file src/analysis.rs` against source commit `b202e74`, then
`python3 scripts/mutation_summary.py mutants.out/outcomes.json`.

**Is not:** a fix. Closing these 44 misses correctly requires the study's own
constraints — RFC known-answer vectors (a shared doctrinal error is invisible to
an N-version arm), and the reference-uncertainty trap (our tri-state against a
binary reference). Those constraints live in the study spec, and the test
vectors must be chosen against them, not invented here. This file records the
gap; it does not pretend to close it.
