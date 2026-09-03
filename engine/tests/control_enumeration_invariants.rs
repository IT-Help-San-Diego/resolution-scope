//! Foundation invariants for the control enumeration.
//!
//! WHY THIS FILE EXISTS
//! --------------------
//! The engine enumerates its controls in TWO independent places:
//!
//! 1. `ControlId::ALL` — the canonical control list (a `[ControlId; N]`).
//! 2. `truth_chain()` — a hand-written `[ControlReport; N]` array literal that
//!    calls one `*_report()` builder per control.
//!
//! Nothing in the source ties those two enumerations together. Before this
//! file, `ControlId::ALL` was referenced ONLY at its own definition — it was
//! effectively dead, and the array length `N` was hardcoded in ~11 sites
//! across three crates (engine, cli). That coupling is the foundation crack:
//! adding or removing a control means hand-editing every `; N]` and adding a
//! matching arm to `truth_chain()`, with NO mechanical guard. Miss one and the
//! failure is SILENT — a control that is scored but never rendered, a control
//! rendered but never scored, or a `report_for(...).expect(...)` panic at
//! runtime instead of at test time.
//!
//! These tests make `ControlId::ALL` the single source of truth and force
//! `truth_chain()` to agree with it, EXACTLY, for any ScoredAnalysis. If the
//! two enumerations ever diverge, the build goes red here — never in front of
//! a user, never as a silent scoring gap.
//!
//! This is an integration test (separate `tests/` crate) so it exercises only
//! the public surface (`ControlId`, `truth_chain`, `by_severity`, `Tally`,
//! `ScoredAnalysis`) and adds ZERO edits to existing source files.

use resolution_scope_engine::truth_chain::{by_severity, truth_chain, ControlId, Tally};
use resolution_scope_engine::{
    CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
    DmarcDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition, TlsRptDisposition,
    TriState,
};

/// A fully-Indet ScoredAnalysis: every control "couldn't measure". Built
/// through the public struct so it stays a single source of truth with the
/// engine's own tests (mirrors `report.rs::minimal`). The disposition VALUES
/// do not matter to enumeration invariants — only that `truth_chain` emits
/// one report per control — so the honest all-Indet shape is the right fixture.
fn all_indeterminate() -> ScoredAnalysis {
    ScoredAnalysis {
        domain: "example.com".to_string(),
        session_id: 0xdead_beef,
        timestamp_local: 1_700_000_000,
        // "default" here is fixture data, not a vantage: production never
        // emits it after cc/resolver-choice (Science,
        // two-gaps-closed-and-the-vantage-collision.md §4 — analysis.rs:41
        // sealed "default" for the vantage cli sealed as "cloudflare").
        resolver_identity: "default".to_string(),
        dnssec_chain: TriState::Indet,
        dnssec_disposition: resolution_scope_engine::analysis::DnssecDisposition::NoZone,
        spf: TriState::Indet,
        spf_disposition: SpfDisposition::TransientError,
        dkim: TriState::Indet,
        dkim_disposition: DkimDisposition::NotProbed,
        dmarc: TriState::Indet,
        dmarc_disposition: DmarcDisposition::TransientError,
        dane: TriState::Indet,
        dane_disposition: DaneDisposition::TransientError,
        tlsa_zone: resolution_scope_engine::analysis::TlsaZone::ZoneUnmeasured,
        mta_sts: TriState::Indet,
        mta_sts_disposition: MtaStsDisposition::TransientError,
        caa: TriState::Indet,
        caa_disposition: CaaDisposition::NoZone,
        cds_cdnskey: TriState::Indet,
        cds_disposition: CdsDisposition::NoZone,
        tls_rpt: TriState::Indet,
        tls_rpt_disposition: TlsRptDisposition::TransientError,
        csync: TriState::Indet,
        csync_disposition: CsyncDisposition::TransientError,
    }
}

/// The truth chain must carry EXACTLY the controls in `ControlId::ALL` —
/// every one present, none extra, no duplicates. This is the invariant that
/// was previously unguarded: `ControlId::ALL` and the `truth_chain()` array
/// literal were two hand-maintained lists with nothing forcing them to match.
#[test]
fn truth_chain_covers_every_control_exactly_once() {
    let model = truth_chain(&all_indeterminate());

    // Same cardinality as the canonical list — catches a control added to one
    // enumeration but not the other (either direction).
    assert_eq!(
        model.len(),
        ControlId::ALL.len(),
        "truth_chain emits {} reports but ControlId::ALL declares {} controls — \
         the two enumerations have diverged; add/remove the matching *_report() \
         arm in truth_chain() (or the ControlId variant) so they agree",
        model.len(),
        ControlId::ALL.len(),
    );

    // Every canonical control appears exactly once in the model.
    for control in ControlId::ALL {
        let hits = model.iter().filter(|r| r.control == control).count();
        assert_eq!(
            hits, 1,
            "control {control:?} appears {hits} times in truth_chain() — \
             expected exactly once (0 = scored-nowhere silent gap; \
             >1 = duplicate report)",
        );
    }

    // No report carries a control outside the canonical list (guards against a
    // stray builder for a ControlId that was removed from ALL).
    for r in &model {
        assert!(
            ControlId::ALL.contains(&r.control),
            "truth_chain() emitted a report for {:?}, which is not in \
             ControlId::ALL — the canonical list is the single source of truth",
            r.control,
        );
    }
}

/// `by_severity` is a pure permutation of the model: it may reorder, but it
/// must never add, drop, or duplicate a control. A sort that silently loses a
/// row would make a real finding disappear from every worst-first surface.
#[test]
fn by_severity_is_a_pure_permutation() {
    let model = truth_chain(&all_indeterminate());
    let sorted = by_severity(&model);

    assert_eq!(
        sorted.len(),
        model.len(),
        "by_severity changed the control count — it must only reorder"
    );

    for control in ControlId::ALL {
        assert_eq!(
            sorted.iter().filter(|r| r.control == control).count(),
            1,
            "by_severity dropped or duplicated {control:?} — a worst-first sort \
             must be a pure permutation of the model",
        );
    }

    // The tally is a set property, so a permutation cannot change it. This ties
    // the permutation guarantee to the score the user actually sees.
    assert_eq!(
        Tally::of(&sorted),
        Tally::of(&model),
        "by_severity changed the Tally — reordering must not alter the score"
    );
}

/// The Tally must account for EVERY control in exactly one bucket: the four
/// buckets (present / absent / unmeasured / not_applicable) must sum to the
/// full control count. If a future TriState variant is added and Tally::of
/// forgets to bucket it, a control would vanish from the census silently —
/// this makes that omission a red build.
#[test]
fn tally_buckets_account_for_every_control() {
    let model = truth_chain(&all_indeterminate());
    let t = Tally::of(&model);
    let bucketed = t.present + t.absent + t.unmeasured + t.not_applicable;
    assert_eq!(
        bucketed,
        model.len(),
        "Tally buckets sum to {bucketed} but the model has {} controls — \
         a control fell out of the census (an unbucketed TriState variant?)",
        model.len(),
    );

    // An all-Indet scan: every control is 'unmeasured', denominator 0, and the
    // score is an honest 0 — never a fabricated 100 from an empty denominator.
    assert_eq!(
        t.unmeasured,
        model.len(),
        "an all-indeterminate scan must bucket every control as unmeasured"
    );
    assert_eq!(t.denominator(), 0, "nothing measurable => denominator 0");
    assert_eq!(
        t.percent(),
        0,
        "an all-unmeasured scan must never read as a score"
    );
}
