## What this claims

<!-- One sentence per claim. A claim without a measurement below is a
     proxy assertion and will be bounced (docs/DEFECT-PATTERNS.md §1). -->

## The measurement behind it

<!-- What did you actually run, against what input, at what commit?
     Paste the command and the relevant output. "It should" is not a
     measurement; "I ran X and observed Y" is. -->

## The test that pins it

<!-- Name the test(s). For a fix: show the test failing WITHOUT your
     change (negative control) — a guard never watched failing is a guard
     that cannot fail. -->

## Does the seal or verdict vocabulary change?

- [ ] No — verdict bytes, seal derivation, and the TriState /
      disposition enums are untouched.
- [ ] Yes — and this PR includes: the types/ contract-test update, the
      store cross-version implication (frozen prior-scheme builders,
      known-answer pins), and (if scoring moved)
      `engine/lean/Scoring.lean` still checks.

## Gates run locally

- [ ] `cargo fmt --check`, `cargo test`, `cargo clippy --all-targets -- -D warnings`
      in every crate touched
- [ ] `bash scripts/check-citation-boundary.sh` (if any non-engine source changed)
- [ ] store integration (`cargo test -- --include-ignored` against live
      Postgres) if store/ changed

## What this does NOT cover

<!-- Every verdict names what it did not measure. So does every PR. -->
