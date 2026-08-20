// report.rs — Report rendering (runs inside the seL4 compartment)
//
// This module is the ONLY module that writes output.  It receives a
// ScoredAnalysis from the IPC channel and writes the report to the path
// granted by cap_local_report.
//
// It has no network access, no resolver, no tokio.  It is pure synchronous
// logic so it can be compiled for a no_std seL4 compartment in the future.

use crate::analysis::ScoredAnalysis;
use crate::seal::seal;
use crate::tristate::TriState;
use crate::truth_chain::{truth_chain, Tally};

/// Render a human-readable text report.
pub fn render_text(a: &ScoredAnalysis) -> String {
    let mut out = String::new();
    out.push_str("Resolution Scope — DNS Analysis Report\n");
    out.push_str(&format!("Domain    : {}\n", a.domain));
    out.push_str(&format!("Timestamp : {}\n", a.timestamp_local));
    out.push_str(&format!("Session   : {:016x}\n", a.session_id));
    // The seal is part of the measurement's provenance, not a footer note:
    // it is re-derivable from the verdict content below, so anyone holding
    // this report can confirm the verdict was not altered after measurement.
    out.push_str(&format!("Seal      : {}\n\n", seal(a)));

    // EVERYTHING below the header renders from the truth-chain model — one
    // verdict channel. Reading the raw ScoredAnalysis tri fields here opened
    // a second channel that could (and did) contradict the model's score line
    // in the same document (adversarial panel, 2026-08-19).
    let model = truth_chain(a);

    out.push_str("Control         Score    Measured\n");
    out.push_str("──────────────  ───────  ────────\n");
    for rep in &model {
        out.push_str(&row(rep.control.name(), rep.tri, rep.measured));
    }

    let t = Tally::of(&model);
    out.push_str(&format!(
        "\nScore: {}/{} ({}%)  |  unmeasured: {}  |  not-applicable: {}\n",
        t.present,
        t.denominator(),
        t.percent(),
        t.unmeasured,
        t.not_applicable
    ));
    out
}

fn row(label: &str, t: TriState, measured: &str) -> String {
    let symbol = match t {
        TriState::Present => "PASS",
        TriState::Absent => "FAIL",
        TriState::Indet => "?   ",
        TriState::NotApplicable => "N/A ",
    };
    format!("{:<16}  {}     {}\n", label, symbol, measured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ScoredAnalysis;
    use crate::truth_chain::truth_chain;

    /// A minimal, fully-Indet verdict — every control honest "couldn't
    /// measure". Sufficient to exercise the report's render path.
    fn minimal() -> ScoredAnalysis {
        // The report only reads domain + the truth-chain model + the seal;
        // disposition fields are irrelevant to rendering. Build through the
        // real public entry so the struct stays a single source of truth.
        ScoredAnalysis {
            domain: "example.com".to_string(),
            session_id: 0xdead_beef,
            timestamp_local: 1_700_000_000,
            dnssec_chain: TriState::Indet,
            dnssec_disposition: crate::analysis::DnssecDisposition::NoZone,
            spf: TriState::Indet,
            spf_disposition: crate::analysis::SpfDisposition::TransientError,
            dkim: TriState::Indet,
            dkim_disposition: crate::analysis::DkimDisposition::NotProbed,
            dmarc: TriState::Indet,
            dmarc_disposition: crate::analysis::DmarcDisposition::TransientError,
            dane: TriState::Indet,
            dane_disposition: crate::analysis::DaneDisposition::TransientError,
            mta_sts: TriState::Indet,
            mta_sts_disposition: crate::analysis::MtaStsDisposition::TransientError,
            caa: TriState::Indet,
            caa_disposition: crate::analysis::CaaDisposition::NoZone,
            cds_cdnskey: TriState::Indet,
            cds_disposition: crate::analysis::CdsDisposition::NoZone,
        }
    }

    #[test]
    fn report_carries_the_seal() {
        let a = minimal();
        let text = render_text(&a);
        let expected = format!("Seal      : {}", seal(&a));
        assert!(
            text.contains(&expected),
            "the report must carry the measurement seal so a reader can verify the verdict"
        );
    }

    #[test]
    fn report_renders_all_eight_controls() {
        let a = minimal();
        let text = render_text(&a);
        let model = truth_chain(&a);
        for rep in &model {
            assert!(
                text.contains(rep.control.name()),
                "report must render control {}",
                rep.control.name()
            );
        }
    }
}
