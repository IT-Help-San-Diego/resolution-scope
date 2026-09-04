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
`sorry`, so a proof-hole was invisible to CI. Every public theorem's
axiom set is now PINNED EXACTLY: the build fails on any change — a
`sorryAx` appears (proof hole), a foreign axiom appears (smuggled
assumption), or even a foundation axiom appears/disappears (proof
drift). propext, Classical.choice and Quot.sound are Lean's standard
logical foundations (allowed, named per-theorem as measured 2026-09-03);
sorryAx is not. The public pins audit the private support lemmas
TRANSITIVELY — a sorry in a helper surfaces as sorryAx in every
theorem that uses it (observed live 2026-09-03: a broken helper
pinned empty_surface_is_none at [propext, sorryAx] until fixed).
Mechanism verified live: exit 1 on mismatch, exit 0 on exact pin. -/
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

/-! ## Tier 1 — the weighted score doctrine (RiskWeightedScoring).

The weight function is a PARAMETER (edit-safety by construction, Carey's
2026-09-03 requirement): every theorem is quantified over ALL non-negative
weight assignments, so a severity re-ruling changes an INSTANCE, never a
proof. The zero-capability of Nat is load-bearing — it is what makes the
Csync zero band expressible.

THE ZERO-WEIGHT NEUTRALITY THEOREM is the Csync ruling (2026-09-01) proven:
a control with weight zero provably cannot move the weighted score.

TWO-FILM NOTE: this section shipped staged on 2026-09-03 with `sorry`
bodies and pins set to [sorryAx] — deliberately CI-red, the gate doing
its job. That staged version is the labeled wrong film, preserved in git
history; the proofs were filled the same day (zero_weight_neutral and
weightedScore_le_100 on [propext, Quot.sound]; empty_surface_is_none on
[propext, Classical.choice, Quot.sound] — all three of Lean's standard
foundation axioms, nothing else), and the pins re-measured to match.
Verified with `lean -DwarningAsError=true`: exit 0, and the pins below
fail the build on any axiom drift. -/

namespace WeightedScoring

/-- Weight assignment: control α ↦ non-negative weight. -/
def WeightFn (α : Type) := α → Nat

/-- The weighted score: covered = Σ w over Present; surface = Σ w over
Present-or-Absent; `some (covered * 100 / surface)` when surface > 0,
`none` otherwise (the never-a-fake-100 doctrine). -/
def weightedScore {α : Type} [BEq α] (w : WeightFn α)
    (pairs : List (α × TriState)) : Option Nat :=
  let covered := (pairs.filter fun p => p.2 == .Present).foldl
    (fun acc p => acc + w p.1) 0
  let surface := (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
    (fun acc p => acc + w p.1) 0
  if surface = 0 then none
  else some (covered * 100 / surface)

/-! ### Private support lemmas

The weight-sum fold is monotone in its base and the Present-filter passes
are a subset of the Present-or-Absent passes; both are proved by induction
GENERALIZED OVER THE FOLD BASE so `omega` never has to look inside
`foldl`. -/

/-- The weight-sum fold is monotone in its base: a bigger starting
accumulator can only give a bigger result. -/
private theorem foldl_mono_base {α : Type} (w : WeightFn α)
    (l : List (α × TriState)) : ∀ (base base' : Nat), base ≤ base' →
    l.foldl (fun acc p => acc + w p.1) base ≤
    l.foldl (fun acc p => acc + w p.1) base' := by
  induction l with
  | nil => intro base base' h; exact h
  | cons x xs ih =>
      intro base base' h
      exact ih (base + w x.1) (base' + w x.1) (Nat.add_le_add_right h (w x.1))

/-- The covered sum never exceeds the surface sum, at ANY fold base:
the Present filter passes are a subset of the Present-or-Absent filter
passes and weights are non-negative. -/
private theorem foldl_mono_filter {α : Type} [BEq α] (w : WeightFn α)
    (pairs : List (α × TriState)) (base : Nat) :
    (pairs.filter fun p => p.2 == .Present).foldl (fun acc p => acc + w p.1) base ≤
    (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
      (fun acc p => acc + w p.1) base := by
  induction pairs generalizing base with
  | nil => exact Nat.le_refl base
  | cons p rest ih =>
      obtain ⟨a, s⟩ := p
      cases s
      · -- Present: both filters keep it, base shifts equally on both sides.
        simp
        exact ih (base + w a)
      · -- Absent: dropped from covered, kept on the surface; base-shift
        -- monotonicity supplies the slack.
        simp
        have h1 := ih base
        have h2 := foldl_mono_base w
          (rest.filter fun p => p.2 == .Present || p.2 == .Absent) base
          (base + w a) (Nat.le_add_right base (w a))
        exact Nat.le_trans h1 h2
      · -- Indet: dropped from both filters; base unchanged.
        simp
        exact ih base
      · -- NotApplicable: dropped from both filters; base unchanged.
        simp
        exact ih base

/-- The public shape used by the score theorem. -/
private theorem covered_le_surface {α : Type} [BEq α] (w : WeightFn α)
    (pairs : List (α × TriState)) :
    (pairs.filter fun p => p.2 == .Present).foldl (fun acc p => acc + w p.1) 0 ≤
    (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
      (fun acc p => acc + w p.1) 0 :=
  foldl_mono_filter w pairs 0

/-- Every predicate false ⇒ the filter is empty. -/
private theorem filter_eq_nil_of_all_false {α : Type} (l : List α) (f : α → Bool)
    (h : ∀ x ∈ l, f x = false) : l.filter f = [] := by
  simpa using h

/-- ZERO-WEIGHT NEUTRALITY (the Csync ruling, as a theorem): a zero-weight
control is provably inert — adding it in any state cannot move the score. -/
theorem zero_weight_neutral {α : Type} [BEq α]
    (w : WeightFn α) (c : α) (hc : w c = 0)
    (pairs : List (α × TriState)) (s : TriState) :
    weightedScore w pairs = weightedScore w (pairs ++ [(c, s)]) := by
  cases s <;>
    simp [weightedScore, List.filter_append, List.foldl_append,
      List.filter_nil, hc]

/-- Bounded: the score never exceeds 100 (covered ≤ surface; weights ≥ 0). -/
theorem weightedScore_le_100 {α : Type} [BEq α]
    (w : WeightFn α) (pairs : List (α × TriState))
    (n : Nat) (h : weightedScore w pairs = some n) :
    n ≤ 100 := by
  have hcs := covered_le_surface w pairs
  simp only [weightedScore] at h
  split at h
  · next _hs => exact absurd h (by simp)
  · next hs =>
      have e : (pairs.filter fun p => p.2 == .Present).foldl
            (fun acc p => acc + w p.1) 0 * 100 /
          (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 = n := Option.some.inj h
      have hpos : 0 < (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 := by omega
      have h3 : (pairs.filter fun p => p.2 == .Present).foldl
            (fun acc p => acc + w p.1) 0 * 100 ≤
          (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 * 100 := Nat.mul_le_mul_right 100 hcs
      have h5 : (pairs.filter fun p => p.2 == .Present).foldl
            (fun acc p => acc + w p.1) 0 * 100 /
          (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 ≤
          (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 * 100 /
          (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 := Nat.div_le_div_right h3
      have h6 : (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 * 100 /
          (pairs.filter fun p => p.2 == .Present || p.2 == .Absent).foldl
            (fun acc p => acc + w p.1) 0 = 100 := by
        rw [Nat.mul_comm]
        exact Nat.mul_div_cancel 100 hpos
      omega

/-- Never a fake 100: no weighted findings ⇒ score is none, not zero. -/
theorem empty_surface_is_none {α : Type} [BEq α]
    (w : WeightFn α) (pairs : List (α × TriState))
    (h : ∀ p ∈ pairs, p.2 != .Present ∧ p.2 != .Absent) :
    weightedScore w pairs = none := by
  have hP : ∀ x ∈ pairs, (x.2 == TriState.Present) = false := by
    intro x hx
    obtain ⟨hp1, _⟩ := h x hx
    obtain ⟨a, s⟩ := x
    cases s
    · simp [bne] at hp1
    · rfl
    · rfl
    · rfl
  have hPA : ∀ x ∈ pairs, (x.2 == TriState.Present || x.2 == TriState.Absent) = false := by
    intro x hx
    obtain ⟨hp1, hp2⟩ := h x hx
    obtain ⟨a, s⟩ := x
    cases s
    · simp [bne] at hp1
    · simp [bne] at hp2
    · rfl
    · rfl
  have f1 : (pairs.filter fun p => p.2 == TriState.Present) = [] :=
    filter_eq_nil_of_all_false pairs _ hP
  have f2 : (pairs.filter fun p => p.2 == TriState.Present || p.2 == TriState.Absent) = [] :=
    filter_eq_nil_of_all_false pairs _ hPA
  simp [weightedScore, f2]

end WeightedScoring

/-- info: 'WeightedScoring.zero_weight_neutral' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms WeightedScoring.zero_weight_neutral

/-- info: 'WeightedScoring.weightedScore_le_100' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms WeightedScoring.weightedScore_le_100

/-- info: 'WeightedScoring.empty_surface_is_none' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms WeightedScoring.empty_surface_is_none
