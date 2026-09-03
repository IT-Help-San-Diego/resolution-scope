-- =============================================================================
-- Scoring.lean — the Resolution Scope verdict doctrine, machine-checked
-- =============================================================================
--
-- This file formalizes the four-state verdict and the denominator rule that
-- the engine's `Tally` and `TriState` (engine/src/tristate.rs,
-- engine/src/truth_chain.rs) encode. It is the "logic as universal decoder"
-- layer: a future reader checks these proofs with `lean` alone and confirms
-- the scoring doctrine without running — or trusting — the Rust.
--
-- The one doctrine that matters, stated formally:
--   * a control is measured to be in exactly one of four states;
--   * two are FINDINGS (Present, Absent) and enter the score denominator;
--   * two are NOT findings (Indet = couldn't measure, NotApplicable =
--     doesn't apply) and are EXCLUDED from the denominator;
--   * Indet is NOT Absent — "couldn't measure" is never "measured absence".
--
-- Check with:  lean lean/Scoring.lean   (exit 0 = all proofs verified)

-- ── the four-state verdict ─────────────────────────────────────────────────

inductive TriState where
  | Present
  | Absent
  | Indet
  | NotApplicable
deriving Repr, DecidableEq

-- A state is a FINDING (counts toward the score) iff it is Present or
-- Absent. Indet and NotApplicable are not verdicts about the world.
def countsInDenominator (s : TriState) : Bool :=
  match s with
  | .Present => true
  | .Absent => true
  | .Indet => false
  | .NotApplicable => false

-- ── the no-collapse doctrine ──────────────────────────────────────────────
-- The four states must not collapse into each other. If Indet collapsed into
-- Absent, "couldn't measure" would silently become "measured absence" — the
-- fabricated-measurement class this instrument exists to eliminate.

theorem indet_is_not_absent : TriState.Indet ≠ TriState.Absent := by
  intro h
  cases h

theorem not_applicable_is_not_absent : TriState.NotApplicable ≠ TriState.Absent := by
  intro h
  cases h

theorem indet_is_not_present : TriState.Indet ≠ TriState.Present := by
  intro h
  cases h

theorem not_applicable_is_not_present : TriState.NotApplicable ≠ TriState.Present := by
  intro h
  cases h

theorem indet_is_not_not_applicable : TriState.Indet ≠ TriState.NotApplicable := by
  intro h
  cases h

theorem absent_is_not_present : TriState.Absent ≠ TriState.Present := by
  intro h
  cases h

-- ── the denominator doctrine ──────────────────────────────────────────────
-- Indet and NotApplicable are excluded from the denominator; Present and
-- Absent are included. Each is a theorem, not an assumption.

theorem indet_never_counts : countsInDenominator .Indet = false := rfl
theorem not_applicable_never_counts : countsInDenominator .NotApplicable = false := rfl
theorem present_counts : countsInDenominator .Present = true := rfl
theorem absent_counts : countsInDenominator .Absent = true := rfl

-- A state either counts (a finding) or does not (not a finding) — no third
-- possibility, and the two possibilities are mutually exclusive.
theorem counts_is_exclusive (s : TriState) :
    (countsInDenominator s = true) ↔ ¬ (countsInDenominator s = false) := by
  cases s <;> simp [countsInDenominator]

-- ── the score over a list of states ───────────────────────────────────────
-- The denominator is the count of findings (Present + Absent); the score is
-- the count of Present. Indet and NotApplicable entries leave BOTH counts
-- unchanged — dropping a non-finding is score-neutral.

def countPresent : List TriState → Nat
  | [] => 0
  | .Present :: rest => 1 + countPresent rest
  | _ :: rest => countPresent rest

def countFindings : List TriState → Nat
  | [] => 0
  | s :: rest => (if countsInDenominator s then 1 else 0) + countFindings rest

-- An Indet entry changes neither the present count nor the findings count.
theorem indet_drop_preserves_present (xs : List TriState) :
    countPresent (.Indet :: xs) = countPresent xs := by
  simp [countPresent]

theorem indet_drop_preserves_findings (xs : List TriState) :
    countFindings (.Indet :: xs) = countFindings xs := by
  simp [countFindings, countsInDenominator]

-- A NotApplicable entry is likewise score-neutral.
theorem not_applicable_drop_preserves_present (xs : List TriState) :
    countPresent (.NotApplicable :: xs) = countPresent xs := by
  simp [countPresent]

theorem not_applicable_drop_preserves_findings (xs : List TriState) :
    countFindings (.NotApplicable :: xs) = countFindings xs := by
  simp [countFindings, countsInDenominator]

-- The present count never exceeds the findings count, so the score
-- (present / findings) is bounded above by 1: an instrument cannot report
-- more passes than it scored.
theorem present_le_findings (xs : List TriState) : countPresent xs ≤ countFindings xs := by
  induction xs with
  | nil => simp [countPresent, countFindings]
  | cons s rest ih =>
      cases s <;> simp [countPresent, countFindings, countsInDenominator] <;> omega

/-! ## Axiom audit — the sorry-refusal gate. `lean` exits 0 on
`sorry`, so a proof-hole was invisible to CI. Every theorem's axiom
set is now PINNED EXACTLY: the build fails on any change — a `sorryAx`
appears (proof hole), a foreign axiom appears (smuggled assumption),
or even a foundation axiom appears/disappears (proof drift). propext
and Quot.sound are Lean's standard logical foundations (allowed,
named per-theorem as measured 2026-09-03); sorryAx is not. Mechanism
verified live: exit 1 on mismatch, exit 0 on exact pin. -/
/-- info: 'indet_is_not_absent' does not depend on any axioms -/
#guard_msgs in
#print axioms indet_is_not_absent

/-- info: 'not_applicable_is_not_absent' does not depend on any axioms -/
#guard_msgs in
#print axioms not_applicable_is_not_absent

/-- info: 'indet_is_not_present' does not depend on any axioms -/
#guard_msgs in
#print axioms indet_is_not_present

/-- info: 'not_applicable_is_not_present' does not depend on any axioms -/
#guard_msgs in
#print axioms not_applicable_is_not_present

/-- info: 'indet_is_not_not_applicable' does not depend on any axioms -/
#guard_msgs in
#print axioms indet_is_not_not_applicable

/-- info: 'absent_is_not_present' does not depend on any axioms -/
#guard_msgs in
#print axioms absent_is_not_present

/-- info: 'indet_never_counts' does not depend on any axioms -/
#guard_msgs in
#print axioms indet_never_counts

/-- info: 'not_applicable_never_counts' does not depend on any axioms -/
#guard_msgs in
#print axioms not_applicable_never_counts

/-- info: 'present_counts' does not depend on any axioms -/
#guard_msgs in
#print axioms present_counts

/-- info: 'absent_counts' does not depend on any axioms -/
#guard_msgs in
#print axioms absent_counts

/-- info: 'counts_is_exclusive' depends on axioms: [propext] -/
#guard_msgs in
#print axioms counts_is_exclusive

/-- info: 'indet_drop_preserves_present' depends on axioms: [propext] -/
#guard_msgs in
#print axioms indet_drop_preserves_present

/-- info: 'indet_drop_preserves_findings' depends on axioms: [propext] -/
#guard_msgs in
#print axioms indet_drop_preserves_findings

/-- info: 'not_applicable_drop_preserves_present' depends on axioms: [propext] -/
#guard_msgs in
#print axioms not_applicable_drop_preserves_present

/-- info: 'not_applicable_drop_preserves_findings' depends on axioms: [propext] -/
#guard_msgs in
#print axioms not_applicable_drop_preserves_findings

/-- info: 'present_le_findings' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms present_le_findings

