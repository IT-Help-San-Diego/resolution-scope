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

/// Render a human-readable text report.
pub fn render_text(a: &ScoredAnalysis) -> String {
    let mut out = String::new();
    out.push_str("Resolution Scope — DNS Analysis Report\n");
    out.push_str(&format!("Domain    : {}\n", a.domain));
    out.push_str(&format!("Timestamp : {}\n", a.timestamp_local));
    out.push_str(&format!("Session   : {:016x}\n\n", a.session_id));

    out.push_str("Control         Score\n");
    out.push_str("──────────────  ───────\n");
    out.push_str(&row("DNSSEC chain", a.dnssec_chain));
    out.push_str(&row("SPF", a.spf));
    out.push_str(&row("DKIM", a.dkim));
    out.push_str(&row("DMARC", a.dmarc));
    out.push_str(&row("DANE", a.dane));
    out.push_str(&row("MTA-STS", a.mta_sts));
    out.push_str(&row("CAA", a.caa));
    out.push_str(&row("CDS/CDNSKEY", a.cds_cdnskey));

    // Explain WHY the DNSSEC verdict is what it is — the disposition carries
    // the distinction the tri-state collapses (island vs couldn't-measure).
    out.push_str(&format!("\nDNSSEC detail: {}\n", a.dnssec_disposition));

    let (present, absent, indet) = tally(a);
    let denominator = present + absent;
    let score = if denominator == 0 {
        0.0
    } else {
        present as f64 / denominator as f64 * 100.0
    };
    out.push_str(&format!(
        "\nScore: {}/{} ({:.0}%)  |  unmeasured: {}\n",
        present, denominator, score, indet
    ));
    out
}

fn row(label: &str, t: TriState) -> String {
    let symbol = match t {
        TriState::Present => "PASS",
        TriState::Absent => "FAIL",
        TriState::Indet => "?   ",
    };
    format!("{:<16}  {}\n", label, symbol)
}

fn tally(a: &ScoredAnalysis) -> (usize, usize, usize) {
    let controls = [
        a.dnssec_chain,
        a.spf,
        a.dkim,
        a.dmarc,
        a.dane,
        a.mta_sts,
        a.caa,
        a.cds_cdnskey,
    ];
    controls.iter().fold((0, 0, 0), |(p, ab, i), &t| match t {
        TriState::Present => (p + 1, ab, i),
        TriState::Absent => (p, ab + 1, i),
        TriState::Indet => (p, ab, i + 1),
    })
}
