# Mutation testing — analysis.rs (the verdict file), 2026-08-20

The file that holds all eight scored controls as disposition enums and produces
every verdict that reaches a public report. Until 2026-08-20 it carried **zero**
mutation evidence while the adjunct signal (`flux.rs`, which feeds no score)
carried a full study.

## The progression (each step's raw `outcomes.json` committed, reproducible)

| source commit | total | caught | missed | unviable | what changed |
|---|---|---|---|---|---|
| `b202e74` | 101 | 31 | **44** | 26 | baseline — the gap, first measured |
| `e1bdd26` | 101 | 32 | 43 | 26 | pin `record_absence_to_dane` Indet→TransientError |
| `cdc9b6b` | 105 | 36 | 39 | 30 | extract 4 Err-branch wrappers (spf/dmarc/mta_sts/caa) |
| `17c6aa9` | 109 | 51 | **26** | 32 | extract DKIM per-selector core |

**Only `missed` is comparable across steps.** Extraction creates new pure
functions, so `total` and `caught` grow (101→109) as the mutable surface expands
— more functions means more mutants to make. The `missed` count is the one
figure that tracks progress cleanly: fewer survivors is the goal, and it fell
44 → 26. (The `total` column counts mutant scenarios only — it excludes the one
baseline `Success` record, so `total = caught + missed + unviable` on every
row.)

```
# current HEAD (17c6aa9)
cargo-mutants 27.1.0
total=109 caught=51 missed=26 timeout=0 unviable=32 success=0
```

## The baseline (44 missed) — where it concentrated

`score_dkim` 13 · `score_dane` 5 · `fetch_mta_sts_policy` 3 ·
`score_caa`/`score_cds_cdnskey`/`score_mta_sts` 2 each ·
`score_dnssec`/`score_dmarc`/`score_spf`/`record_absence_to_dane`/
`mta_sts_policy_state` 1 each · 8 × `Display::fmt` + `rand_session_id` +
`unix_now` = 12 cosmetic.

The structural finding: **every survivor was in an `async` function; every
caught mutant was in a pure sync helper** — the `observe_flux` shape, and the
remedy is extraction, not mocking.

## What has been closed (measured, not asserted)

- **Five `delete match arm TriState::Indet` mutants — all killed, one per
  wrapper, exactly five.** The doctrine "couldn't measure ≠ absent" now has a
  test failing on its deletion in every control that carried it inline:
  `record_absence_to_dane`, `spf_err_to_disposition`, `dmarc_err_to_disposition`,
  `mta_sts_err_to_disposition`, `caa_err_to_disposition`.
- **`score_dkim` 13 → 0** via three extractions with the selector list +
  per-selector outcomes as inputs: `build_dkim_selector_list`,
  `dkim_key_state`, `dkim_disposition_from_probes`.

Scoring-path survivors: 32 → 27 (the five Indet kills, exactly) → 14 (DKIM
extraction, −13: `score_dkim` 13→0, nothing else moved).

The DKIM path is genuinely clean: `dkim_disposition_from_counts` 12/0,
`dkim_disposition_from_probes` 10/0, `build_dkim_selector_list` 5/0,
`dkim_p_value` 5/0. Two functions read 0 caught / 0 missed — `score_dkim` and
`dkim_key_state` — which is the `observe_flux` signature: **not COVERED, but no
longer CONTAINING killable logic** (their only remaining mutants are "unviable"
— the tool could not compile a testable form). Do not read 0/0 as coverage.

## What remains (14 scoring-path + 12 cosmetic)

- `score_dane` 5 (MX/TLSA loop — assembly, not decision core)
- `fetch_mta_sts_policy` 3 (HTTP fetch)
- `score_cds_cdnskey` 2 (`delete !` on empty-answer guards)
- `score_caa` 1, `score_dnssec` 1 (inline `!answers.is_empty()`),
  `score_mta_sts` 1, `mta_sts_policy_state` 1
- 12 cosmetic (8 `Display::fmt` + `rand_session_id` + `unix_now`)

## Method: one assertion per source (mutation-detectable test defects)

A passing test can be wrong in a way ordinary suites cannot reveal, but mutation
testing exposes. The defect that surfaced this session: **combining two
miss-SHAPES in one probe list let each `+=` mutant hide behind the other's
contribution** — the count went *up* when the test changed, which is what
exposed it. A test that passes both before and after a real mutation is not
testing what it claims.

**Rule: each assertable source must be the sole contributor in its own
assertion.** If two arms both increment a counter and a test feeds both, either
arm's mutant survives because the other arm still produces the same count. One
assertion per arm is the only way a mutant in one arm fails the test.

This is the same family as every instrument failure in the session: a check that
cannot distinguish its own sources (`all()` over an empty set, a comparator that
included its own metadata). One control: make the check unable to pass for a
reason other than the one it claims.

## What this is and is not

**Is:** raw, re-derivable evidence, one committed `outcomes.json` per step.
Reproduce with `cargo mutants --file src/analysis.rs` against any listed commit,
then `python3 scripts/mutation_summary.py mutants.out/outcomes.json`.

**Is not:** finished. The remaining scoring-path survivors are the assembly
logic inside async loops; closing them is behaviour-preserving extraction and is
unblocked without the calibration spec. The spec (RFC known-answer vectors,
reference-uncertainty handling) is needed only for the calibration arms, not for
the extraction.
