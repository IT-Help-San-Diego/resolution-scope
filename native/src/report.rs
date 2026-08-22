// report.rs — report renderer (no_std mirror of engine/src/report.rs header)
//
// The store compartment's renderer: receive a ScoredAnalysis, re-derive the
// seal, render the report, write via cap_local_report. Pure synchronous logic —
// no network, no resolver, no tokio.
//
// MINIMAL SPIKE NOTE: this renders the verdict's SEAL-BINDING content (the
// disposition variant names + tri-states — exactly what the seal hashes), not
// the full human-readable truth-chain (RFC requirement / measured label /
// consequence). The full truth_chain renderer is the shared-crate follow-up;
// until then this renderer is honest about showing the seal's preimage rather
// than pretending to be the production report.

use alloc::format;
use alloc::string::String;

use crate::seal::{canonical_input, seal_versioned};
use crate::types::ScoredAnalysis;

/// Render a text report for a verdict produced by `produced_by` (the engine
/// version the verdict was sealed under — passed in, never this crate's own).
pub fn render_text(a: &ScoredAnalysis, produced_by: &str) -> String {
    let mut out = String::new();
    out.push_str("Resolution Scope — DNS Analysis Report\n");
    out.push_str(&format!("Domain    : {}\n", a.domain));
    out.push_str(&format!("Engine    : {}\n", produced_by));
    out.push_str(&format!("Resolver  : {}\n", a.resolver_identity));
    out.push_str(&format!(
        "Timestamp : {} (unix epoch seconds, UTC)\n",
        a.timestamp_local
    ));
    out.push_str(&format!("Session   : {:016x}\n", a.session_id));
    out.push_str(&format!(
        "Seal      : {}\n\n",
        seal_versioned(a, produced_by)
    ));

    out.push_str("Control         Disposition                   Score\n");
    out.push_str("──────────────  ───────────────────────────  ─────\n");
    out.push_str(&format!(
        "DNSSEC          {:<27}  {:?}\n",
        format!("{:?}", a.dnssec_disposition),
        a.dnssec_chain
    ));
    out.push_str(&format!(
        "SPF             {:<27}  {:?}\n",
        format!("{:?}", a.spf_disposition),
        a.spf
    ));
    out.push_str(&format!(
        "DKIM            {:<27}  {:?}\n",
        format!("{:?}", a.dkim_disposition),
        a.dkim
    ));
    out.push_str(&format!(
        "DMARC           {:<27}  {:?}\n",
        format!("{:?}", a.dmarc_disposition),
        a.dmarc
    ));
    out.push_str(&format!(
        "DANE            {:<27}  {:?}\n",
        format!("{:?}", a.dane_disposition),
        a.dane
    ));
    out.push_str(&format!(
        "MTA-STS         {:<27}  {:?}\n",
        format!("{:?}", a.mta_sts_disposition),
        a.mta_sts
    ));
    out.push_str(&format!(
        "CAA             {:<27}  {:?}\n",
        format!("{:?}", a.caa_disposition),
        a.caa
    ));
    out.push_str(&format!(
        "CDS/CDNSKEY     {:<27}  {:?}\n",
        format!("{:?}", a.cds_disposition),
        a.cds_cdnskey
    ));

    out.push_str("\n── Re-derive the seal (SHA3-512 of these exact bytes) ──\n");
    out.push_str(&canonical_input(a, produced_by));
    out.push_str("──────────────────────────────────────────────────────────\n");
    out
}
