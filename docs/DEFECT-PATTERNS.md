# Defect patterns — the recurring shapes, named

This file exists because a courier message referenced "the pattern book" and a
verifying lane correctly flagged that no such file existed — a reference nobody
can reach is a check that cannot fail, and that rule applies to prose too. The
patterns below all have measured instances in this tree; nothing here is
asserted without a pointer.

**The governing rule, under every pattern:** *make the check unable to pass for
a reason other than the one it claims.*

## 1. The proxy assertion

A check (or sentence) asserting something never measured — the verb stronger
than the evidence.

- The seal described as "proof of measurement" on the public site, when
  `engine/src/seal.rs:13-16` states that overclaim is the one thing the
  instrument must not do. Caught by adversarial review; the phrase is now a
  FORBIDDEN string in `site/verify.sh` (site lane, `site-v1`).
- "Verified by running it" written about a check that only ran a lookalike —
  recorded in the corrections to `policy/REVIEW_claude_science_20260820.md`.

Counter-discipline: match the verb to the check actually run; derive claims
from the producer, never from a description of it.

## 2. The gate that can't fire

A guard whose triggering path has never executed — it looks correct for its
whole life because nothing ever reaches it.

- The pre-push parent-CI check read three stdin fields where git sends four;
  the ref comparison never matched and the gate exited before ever invoking
  `gh`. Fixed and negative-controlled in `1b59f6e` (`.githooks/pre-push`).
- The general form is recorded with the fix: a guard written to prevent
  guards-that-can't-fire could not fire.

Counter-discipline: negative control — watch the guard fail once on the input
its caller actually sends. Reading the logic is not feeding it the input.

## 3. Conflation by representation

A type or encoding that erases a distinction the doctrine requires, so a wrong
verdict is produced from structurally honest code.

- DANE's per-host TLSA outcomes as `&[usize]`: an errored lookup and a
  measured-empty answer both arrived as `0`, so an all-errored host list
  returned a measured absence from data that measured nothing. Fixed in
  `88d1095` (`Option<usize>`; all-errors → TransientError).
- The wider family is the Indet-vs-Absent boundary throughout
  `engine/src/tristate.rs` and `truth_chain.rs`.

Counter-discipline: a pure function's signature must name every input it
distinguishes — extraction makes conflations visible precisely because the
signature has to confess them.

## 4. Prose drift from tool output

Narrative numbers detaching from the JSON they summarize.

- A closing summary claimed 16 missed / 4 scoring-path while the committed
  `docs/mutation-analysis-20260820/outcomes.json` said 21 / 9 — corrected in
  that study's README, whose Method section now carries the rule.
- Grep-the-doc offered as verification of the run the doc describes (same
  author both sides) — recorded in the same README's method notes.

Counter-discipline: compute-before-prose — any "X = Y + Z" is printed from the
data before it appears in a sentence. All three instances looked obvious.

## 5. Masking contributors

Two sources feeding one assertion, so either source's defect hides behind the
other's contribution.

- Two miss-shapes combined in one probe list let each `+=` mutant survive
  behind the other's count — exposed by mutation testing, recorded in
  `docs/mutation-analysis-20260820/README.md` ("one assertion per source").
- The DANE all-errored control list is deliberately unmixed for the same
  reason (`dane_all_lookups_errored_is_transient_not_notconfigured`).

Counter-discipline: each assertable source is the sole contributor in its own
assertion.

## 6. The assumed-uniform interface

Two producers treated as one because they carry the same data — the defect
lives in the consumer that assumes a single shape, and it fires at parse time,
before any semantic comparison can even be wrong.

- The two halves of Arm 1 emit different wire shapes: the Rust engine emits
  NDJSON (one object per line), the Go reference one object per
  `/api/analysis/:id` response — recorded with the pin-it-in-the-first-test
  instruction in `docs/CALIBRATION-STUDY-TASK-ZERO.md` ("the join's
  parse-time trap"). Contributed by the hook lane, 2026-08-20.
- The same pairing also differs in vocabulary (`present`/`absent_confirmed`
  vs `Present`/`Absent`/`Indet`) — bridged explicitly by `go_to_tri` in
  `scripts/full_arm_differential.py` rather than assumed identical.

Counter-discipline: name each producer's shape where the consumer is
specified, and pin the asymmetry in the consumer's first test — a join that
has never parsed both real shapes has never run.

## 7. The stale measurement

A finding measured before a fix landed, reported after — true when measured,
false when read.

- `seal.rs` flagged as carrying `provenance` ×4 after `36095a9` had already
  retired all four (recorded in `policy/REVIEW_claude_science_20260820.md`,
  item 4).
- "Committed and pushed" claimed from a remote-tip hash check that could not
  establish it; the ancestry check that could came later and happened to
  agree — true by luck is not verified.

Counter-discipline: timestamp measurements against commits; re-measure at the
ref you are reporting on, not the ref you remember.
