# Option B — Risk-Weighted Score (SPEC, settled — implementation unblocked)

**Status:** SPEC — settled. Identity-weighting (§12) decided by Carey; the three superseded
state-weighting residues (§4 mapping, §4 subtlety, §11 sketch, test 8) corrected 2026-08-23.
Acceptance tests (§10) are the frozen contract the implementation must satisfy.
**Date:** 2026-08-22 · **Lane:** Hermes (instrument) · **Decision:** Carey approved Option B
(2026-08-22) — "yes to the transparency… best practice is the B… keep the data, change the
thing, disclose like science."

---

## 1. The problem this closes (one frame)

The instrument already tells the truth **per-finding** (each control carries a severity) but
not **per-score**. Two domains score identically:

| Domain | Missing control | Coverage Score | Real risk |
|---|---|---|---|
| A | DNSSEC (High) | 7/8 = 87.5% | serious — zone forgeable, undermines CAA *and* DANE |
| B | CAA (Low) | 7/8 = 87.5% | minor — rare threat, already backstopped by CT logs + mandatory CA checking |

One axis (severity) differentiates; the other (score) flattens. The weighted score makes the
**score** carry the same truth the **severity** already does.

Reality grounding (verified 2026-08-22): the dollar-dominant threat is **email spoofing →
Business Email Compromise** — FBI IC3's own title is "Business Email Compromise: The $55
Billion Scam" ($55.5B exposed, 305,033 incidents, 2013–2023). Certificate mis-issuance (CAA's
threat) is real but rare and already backstopped — see §9.

---

## 2. The two scores, named (non-confusable)

| Label | Formula | Meaning | Status |
|---|---|---|---|
| **Coverage Score** | `present ÷ (present + absent)` | how many measured controls are present | **existing** — unchanged, sealed under the current scheme |
| **Risk-Weighted Score** | see §3 | how much threat surface is actually covered | **new** — derived view, version-tagged |

**Both are always shown together.** Never one replacing the other. This is the NIST-CSF
lesson (§8): a single hidden-weighted number is what *hides* which control is weak — so the
unweighted coverage score stays as the primary, and the weighted score sits beside it.

---

## 3. The formula (normalized, 0–100)

The user's ruling: **reallocation of a fixed denominator, not an unbounded multiplier.** The
weighted score is:

```
            Σ  weight(control_i)   for controls where tri == Present
RWS =   ─────────────────────────────────────────────────────────────  × 100
            Σ  weight(control_i)   for controls where tri ∈ {Present, Absent}
```

- **Bounded 0–100 by construction** (numerator ≤ denominator always).
- `Indet` (Unmeasured) and `NotApplicable` are **excluded from both numerator and
  denominator** — exactly as the Coverage Score already excludes them. A "?" is not a verdict,
  and "doesn't apply" is not "fails".
- When nothing is measured (`denominator == 0`), RWS = 0, **with the same "nothing measured"
  honest label the Coverage Score already emits** — never a fake 100.

This is the CVSS shape (§8): explicit weights combined by a fixed formula into a **bounded**
range, with the qualitative meaning carried by the severity tier, not by an open-ended number.

---

## 4. Weight derivation — identity-weighting, single-producer (no new table)

The weight is **not** a hand-maintained list. It is a pure function of each control's
**absent-state severity** — the "you don't have this" consequence — read from the `*_report`
constructor the code **already computes** in `truth_chain.rs`:

```
identity_weight(control) = severity_number( absent_severity(control) )
```

where `absent_severity(control)` is the `severity` field of that control's "missing" disposition
(`dmarc_report(DmarcDisposition::NotConfigured).severity`, `dane_report(DaneDisposition::NotConfigured, ..).severity`, …), and `severity_number` maps:

```
Critical => 4,   High => 3,   Medium => 2,   Low => 1
```

**SUPERSEDED (revision 1):** the earlier draft derived the weight from the control's *current-state*
severity (`severity_weight(state)`), where a `p=none` DMARC "weighs 2" and a `p=reject` "weighs 0".
That was the state-weighting model §12 rejects: the weight must be the control's **identity**, not
its **state**, so a Present control earns its full weight whether enforcing or not.

The severity semantics (documented at `truth_chain.rs:92–102`):
- **Critical** — deployed but WRONG (broken chain, key/TLSA mismatch).
- **High** — absent enforcement with a direct spoofing/interception surface.
- **Medium** — deployed but not enforcing.
- **Low** — hardening absent (CAA, CDS, TLSA) or a precondition gap.

Because `identity_weight` reads the **absent-state** severity (via the `*_report` constructor for
that control's "missing" disposition), **any future severity re-ruling automatically propagates to
the weight.** No second table to drift. This is the same single-producer rule that governs the seal
and the citation boundary.

> **Identity, not state (the settled ruling — §12):** the weight is the control's fixed identity
> weight, keyed on its absent-state severity, NEVER its current state. A DMARC at `p=none` is
> Present and earns DMARC's FULL identity weight (3), exactly like a `p=reject` DMARC — the
> enforcement gap (`p=none` vs `p=reject`) is carried by the **severity label** (`Medium` vs `Ok`)
> and the **finding narrative**, never a fractional weight. Only High (3) and Low (1) are ever
> produced as identity weights, because no control's "missing" disposition is Medium or Critical.

---

## 5. Concrete current weights (derived from current code severity)

Grounding each control's weight in its **absent-state** severity (the "you don't have this"
consequence the constructors emit today). **CORRECTED 2026-08-23:** an earlier draft here ruled
"MTA-STS/DANE both Medium" — that was wrong and never applied to code. The code carries (and
correctly keeps) MTA-STS=High, DANE=Low. See
`policy/RULING_dane_mtasts_severity_20260822.md` §8 for the correction and the layer-distinction
+ attainability arguments.

| Control | Absent-state severity (code) | Weight | Threat surface (grounded) |
|---|---|---|---|
| DNSSEC | High (unsigned) / Critical (bogus) | 3 (see note) | zone forgery; undermines CAA *and* DANE |
| SPF | High | 3 | email spoofing → BEC |
| DKIM | High (mismatch/revoked) | 3 | email integrity → BEC |
| DMARC | High (absent) | 3 | spoofing enforcement → the $55B control |
| MTA-STS | High (no policy) | 3 | in-transit *enforcement* — plaintext-downgrade surface |
| DANE | Low (no TLSA) | 1 | in-transit *pinning* — cert-substitution, DNSSEC-gated |
| CAA | Low (no CAA) | 1 | cert mis-issuance — rare, CT-backed |
| CDS/CDNSKEY | Low (no CDS) | 1 | rollover hygiene — Informational RFC |

**Maximum denominator = 18** (five High × 3 = 15 [DNSSEC, SPF, DKIM, DMARC, MTA-STS]; three
Low × 1 = 3 [DANE, CAA, CDS]; total 18). A domain missing only CAA: RWS = 17/18 = 94.4% (Coverage
still 87.5%). A domain missing only DMARC: RWS = 15/18 = 83.3%. The gap that Coverage hides is
exactly what RWS reveals.

> **DNSSEC weight note (open, to resolve at implementation):** DNSSEC's absent-state is `High`, but
> its bogus-state is `Critical` (present-but-wrong). Identity-weighting keys the weight on the
> **absent** severity, so DNSSEC = 3 (High), not a range. The `3–4` range in the earlier draft was
> the state-weighting residue. Resolve to a single number (3) before the score is built.

> **Sub-decision RESOLVED (2026-08-23, corrected):** MTA-STS stays **High**, DANE stays **Low** —
> the code's original and correct split. They guard the same hop against *different attacks at
> different layers* (enforcement vs pinning), and attainability agrees (MTA-STS is unilaterally
> deployable, DANE is DNSSEC-gated). Deployability is carried by the `tlsa_zone` field, not by
> severity. See `policy/RULING_dane_mtasts_severity_20260822.md` §8.

---

## 6. Seal interaction (the clean separation)

The seal binds the **eight dispositions** — the raw measurements. The weighted score is a
**derived view**, computed *from* sealed data but **not itself sealed**.

Consequences, stated as invariants:

1. **Seal input is unchanged.** No disposition, no tri-state, no field is added to or removed
   from `canonical_input`. The `SEAL_SCHEME` constant does **not** bump.
2. **The formula version is metadata, not seal input.** A new `SCORING_VERSION: u32` (start 1)
   tags the derived score. Changing the weight mapping or the formula bumps `SCORING_VERSION`
   — **never** `SEAL_SCHEME`.
3. **A sealed verdict re-derives identically under any scoring version.** Because the seal is a
   function of the dispositions alone, re-scoring a stored verdict with a *newer* formula yields
   a different RWS but an *identical* seal. History is not falsified; it is re-viewed under a
   new lens with the lens version disclosed.
4. **No data migration, no re-seal, no flush.** The user's ruling ("keep the data, change the
   thing, disclose like science") is satisfied by construction: old rows stay valid, their RWS
   is computed on read under the current `SCORING_VERSION` and labeled with it.

---

## 7. Disclosure log entry

The pattern already exists (SEAL_SCHEME versioning in the engine). One line, in the engine
changelog, alongside any future SEAL_SCHEME bump:

```
v0.2.0 — introduces Risk-Weighted Score (RWS) alongside Coverage Score.
         Coverage Score (unweighted) is preserved as the primary measurement and remains
         sealed under the existing scheme. RWS is a derived view of the same sealed
         dispositions, computed on read, tagged SCORING_VERSION=1. Formula: Σweight(Present)
         ÷ Σweight(Present+Absent), weight = identity_weight(control) — the control's
         absent-state severity (High 3 / Low 1), never its current state.
```

---

## 8. How the field weights severity (research, grounded)

| Framework | Approach | What we take |
|---|---|---|
| **CVSS v4.0** | fixed formula combines explicit metric values (H/M/L → numeric) into a **bounded 0–10** score, then maps to a qualitative band (None/Low/Medium/High/Critical) | the **bounded + fixed-formula + qualitative-band** shape is exactly RWS: weights → formula → 0–100 → the existing Severity tier is the qualitative band. |
| **NIST CSF 2.0** | **refuses a single numeric score.** Four implementation Tiers (Partial / Risk-Informed / Repeatable / Adaptive), explicitly stated to be *not* maturity levels, reported *per function* so no single number hides which function is weak | the doctrine that keeps Coverage and RWS **two separate numbers** — a lone hidden-weighted score is what NIST deliberately avoids. |
| **CIS Benchmarks** | pass/fail per control, aggregated as "% of controls implemented" — an **unweighted coverage** percentage, optionally grouped by IMPACT profile (Level 1 / Level 2) | the **Coverage Score already is** the CIS number; CIS's "Level 1 vs Level 2" grouping is a cruder cousin of our severity tiering. |

**Synthesis:** our two-number design is **CIS (coverage) + CVSS (bounded weighted risk), held
apart by NIST's warning against a single hidden number.** Each score has a framework precedent;
the novelty is publishing both, honestly labeled, with the weight *derived* from a severity the
instrument already computes.

---

## 9. CAA reality check (why "Low" is correct, not a diss)

Grounded 2026-08-22. The reason CAA is Low is **not** that it's useless — it's that its threat
is rare and already double-backed:

1. **CAA is a note in unprotected DNS.** Compromise the DNS and you delete the CAA record
   before asking the CA to issue. CAA inherits every weakness DNS has.
2. **CAA cannot stop a malicious/compromised CA** — the DigiNotar-class attack. The paper
   *"A Call to Reconsider Certification Authority Authorization"* (arXiv:2411.07702, 4.6M certs
   from CT logs) documents four blind spots that "practically defeat the primary goal."
3. **The real backstops are CT logs + CA/B Forum mandatory checking (2017).** A rogue cert gets
   *seen* (CT) and *revoked* — that's the mitigation that makes mis-issuance survivable.

The **perception lesson** to teach users is the mirror of the DMARC p=none line:

> *"A CAA record is a note in unprotected DNS, not a boundary — and the thing actually
> protecting you is the Certificate Transparency log, not the record. Likewise, DMARC p=none
> is a promise to act, not protection. In both cases, a declarative record is being mistaken
> for an enforcement mechanism — and this instrument's job is to stop that mistake."*

---

## 10. Acceptance tests (the contract — implementation must satisfy all)

These are the tests that will pin the implementation. Written here first so the code is checked
against a frozen contract, not "whatever it does."

1. **Degenerate → equal.** When all measured controls carry equal weight (all Low, or all
   High), RWS == Coverage Score exactly.
2. **Weight reveals what Coverage hides.** Missing DMARC (weight 3) yields a *lower* RWS than
   missing CAA (weight 1), while both yield identical Coverage Score.
3. **Unmeasured excluded.** A control at `Indet` (Unmeasured) is absent from both numerator and
   denominator of RWS — same as Coverage. Adding an unmeasured control must not move RWS.
4. **NotApplicable excluded.** A null-MX domain's DANE `NotApplicable` contributes nothing to
   either sum.
5. **Bounds.** RWS ∈ [0, 100] for every legal disposition combination (exhaustive over a
   hand-built fixture set, not a random sample).
6. **Zero / full.** All-Absent → RWS 0 and Coverage 0; all-Present → RWS 100 and Coverage 100.
7. **Weight is derived, not hardcoded.** Assert `weight(DMARC absent) == 3` *by reading*
   `dmarc_report(DmarcDisposition::NotConfigured).severity == Severity::High` — so a future
   severity re-ruling changes the weight automatically. (One assertion per source, per the
   mutation method.)
8. **Identity weight, not state weight.** A `p=none` DMARC (`dmarc_report(Monitor)`, Present,
   Medium) contributes DMARC's FULL identity weight (3) to the numerator — identical to a
   `p=reject` DMARC (`Ok`). The enforcement gap is a severity fact, never a weight fact: two
   Present DMARCs weigh the same, and their difference lives in the label, not the score.
9. **Seal invariance.** `seal(dispositions)` is byte-identical before and after the RWS code
   lands, and across any `SCORING_VERSION` — proving the formula change did not touch the seal.
10. **Version tagging.** The derived RWS carries `SCORING_VERSION`; a formula change bumps that
    constant and nothing else. A test asserts the two version constants are distinct and
    independently bumpable.

---

## 11. Rust implementation sketch (identity-weighting, supersedes the severity_weight draft)

```rust
// truth_chain.rs — ADD (not edit): the derived score, alongside the existing Tally.

/// Version of the risk-weighting formula. Changing the weight mapping or the
/// formula bumps this — NEVER SEAL_SCHEME (the seal binds dispositions only;
/// this is a derived view over those same sealed dispositions).
pub const SCORING_VERSION: u32 = 1;

/// The consequence weight of a control, keyed on its IDENTITY (its absent-state
/// severity), NOT its current state. Derived from the `*_report` constructor for
/// that control's "missing" disposition — single producer, so a future severity
/// re-ruling propagates automatically. Only High (3) and Low (1) are produced:
/// no control's missing disposition is Medium or Critical.
pub fn identity_weight(control: ControlId) -> u32 {
    match absent_severity(control) {
        Severity::High => 3,
        Severity::Low => 1,
        // Unreachable by construction (absent-state severities are High or Low).
        _ => 0,
    }
}

/// The severity of a control's "you don't have this" disposition — read from the
/// report constructor, never a hand-kept table.
fn absent_severity(control: ControlId) -> Severity {
    match control {
        ControlId::Dnssec => dnssec_report(DnssecDisposition::Unsigned).severity,
        ControlId::Spf => spf_report(SpfDisposition::NotConfigured).severity,
        // DKIM's "missing" state is Revoked (empty p=, unsigned in practice → High),
        // NOT NotFoundDefaults (Unmeasured — the honest "absence not proven" state).
        ControlId::Dkim => dkim_report(DkimDisposition::Revoked).severity,
        ControlId::Dmarc => dmarc_report(DmarcDisposition::NotConfigured).severity,
        ControlId::MtaSts => mta_sts_report(MtaStsDisposition::RecordAbsent).severity,
        ControlId::Dane => dane_report(DaneDisposition::NotConfigured, TlsaZone::SameZone).severity,
        ControlId::Caa => caa_report(CaaDisposition::NotConfigured).severity,
        ControlId::Cds => cds_report(CdsDisposition::NotPublished).severity,
    }
}

/// The risk-weighted score, 0–100. Derived FROM the sealed dispositions via
/// truth_chain() — it is a view, not a measurement, so it is NOT sealed.
/// `None` when nothing is measurable (denominator 0) — same honest "unmeasured"
/// handling as Coverage Score.
pub fn risk_weighted_score(reports: &[ControlReport; 8]) -> Option<u32> {
    let mut covered: u32 = 0;   // Σ identity_weight where tri == Present
    let mut surface: u32 = 0;   // Σ identity_weight where tri ∈ {Present, Absent}
    for r in reports {
        let w = identity_weight(r.control);
        match r.tri {
            TriState::Present => { covered += w; surface += w; }
            TriState::Absent  => { surface += w; }
            TriState::Indet | TriState::NotApplicable => {}
        }
    }
    if surface == 0 { return None; }           // nothing measured — never a fake 100
    Some(covered.saturating_mul(100) / surface)
}

// The existing Tally::percent() (Coverage Score) is UNTOUCHED. Both are exposed;
// the renderer shows both, labeled Coverage Score / Risk-Weighted Score, with
// SCORING_VERSION as metadata on the latter.
```

> **Resolved (identity-weighting):** the revision-1 sketch used `severity_weight(state)` — a
> Present control's *state* severity determined its weight, so an `Ok`/enforced control weighed 0.
> That is superseded by §12: the weight is keyed on the control's **identity** (`identity_weight`),
> so a Present control contributes its full weight whether enforcing (`Ok`) or deployed-but-not
> enforcing (`Medium`). The `Ok => 0` edge is gone — an all-Present domain now correctly reads
> 100 by construction (test 6), because every Present control contributes its identity weight to
> both sums.

---

## 12. DECISION — identity-weighting (confirmed 2026-08-22)

**Resolved by Carey: identity-weighting.** Each control has ONE fixed weight, derived from
its **absent-state** severity (the "you don't have this" consequence): DMARC=3, DNSSEC=3,
SPF=3, DKIM=3, MTA-STS=3, DANE=1, CAA=1, CDS/CDNSKEY=1. A control that is `Present`
contributes its full identity weight to the numerator; `Absent` contributes it to the
denominator only. The enforcement nuance (`p=reject` vs `p=quarantine` vs `p=none`) is
carried by the **severity label** (Ok vs Medium) and the **finding narrative** — never a
fractional weight.

**Why identity, not state (the ruling rationale, verbatim logic):** state-weighting would
require a numeric ranking of *how safe* each configuration is ("quarantine = 2.5, reject =
3"), which fabricates precision for a deliberate-choice axis. A high-value target that runs
`p=quarantine` to *monitor* who attacks it is not "83% as safe as a `p=reject` domain" — it is
*safe, differently*, for a disclosed reason. Identity-weighting lets all genuinely-safe
configurations read as safe (Present = full weight) while the *difference* between them is told
in words — the exact "CIA vs Apple vs NSA all look safe like they are, disclose the why" rule.

**Consequence for the formula:** the weight is a function of the control's **identity**, not
its **state**. `Severity::Ok` and `Severity::Medium` therefore never appear as distinct weights —
a Present control earns its identity weight whether it's enforcing (Ok) or deployed-but-not
enforcing (Medium). The enforcement gap is a severity fact, never a presence fact, and never a
weight fact.

**Implementation note:** this simplifies the sketch in §11 — the weight is
`identity_weight(control)`, not `severity_weight(state)`. The mapping is keyed on `ControlId`,
derived from the absent-state severity of that control (so a future severity re-ruling still
propagates to the weight automatically, via the `*_report` constructor it reads).

**This closes the last open design point. The spec is settled; implementation is unblocked
(Carey 2026-08-23 "let's move forward"; Claude Science go unconditional once the three
state-weighting residues landed — they have).**
