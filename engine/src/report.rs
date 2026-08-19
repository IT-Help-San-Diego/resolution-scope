// report.rs — Report rendering (runs inside the seL4 compartment)
//
// This module is the ONLY module that writes output.  It receives a
// ScoredAnalysis from the IPC channel and writes the report to the path
// granted by cap_local_report.
//
// It has no network access, no resolver, no tokio.  It is pure synchronous
// logic so it can be compiled for a no_std seL4 compartment in the future.

use crate::analysis::ScoredAnalysis;
use crate::tristate::TriState;
use crate::truth_chain::{truth_chain, Tally};

/// Render a human-readable text report.
pub fn render_text(a: &ScoredAnalysis) -> String {
    let mut out = String::new();
    out.push_str("Resolution Scope — DNS Analysis Report\n");
    out.push_str(&format!("Domain    : {}\n", a.domain));
    out.push_str(&format!("Timestamp : {}\n", a.timestamp_local));
    out.push_str(&format!("Session   : {:016x}\n\n", a.session_id));

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
