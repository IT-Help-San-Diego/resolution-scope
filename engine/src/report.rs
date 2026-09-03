// report.rs — Report rendering (runs inside the seL4 compartment)
//
// This module is the ONLY module that writes output.  It receives a
// ScoredAnalysis from the IPC channel and writes the report to the path
// granted by cap_local_report.
//
// It has no network access, no resolver, no tokio.  It is pure synchronous
// logic so it can be compiled for a no_std seL4 compartment in the future.

use crate::analysis::ScoredAnalysis;
use crate::seal::{canonical_input, engine_version, seal};
use crate::tristate::TriState;
use crate::truth_chain::{risk_weighted_score, truth_chain, Tally, SCORING_VERSION};

/// Render a human-readable text report.
pub fn render_text(a: &ScoredAnalysis) -> String {
    let mut out = String::new();
    out.push_str("Resolution Scope — DNS Analysis Report\n");
    out.push_str(&format!("Domain    : {}\n", a.domain));
    // The two sealed observation conditions the report previously omitted:
    // engine version (which verdict logic produced it) and resolver identity
    // (which vantage measured it). A seal is re-derivable only when every
    // input it binds is published beside it — omitting these while printing
    // Session (a NON-input) turned "anyone can re-check" into an assertion.
    out.push_str(&format!("Engine    : {}\n", engine_version()));
    out.push_str(&format!("Resolver  : {}\n", a.resolver_identity));
    // The vantage gloss: a pure function of the SEALED string (vocabulary,
    // not wire), so it stays true for a seal re-read in ten years. A legacy
    // opaque label ("default", "test") is named as such.
    out.push_str(&format!(
        "Vantage   : {}\n",
        crate::resolver::ResolverChoice::gloss_of_identity(&a.resolver_identity)
    ));
    // timestamp_local is a Unix epoch (UTC) — label the zone, or a reader who
    // converts it gets a date that disagrees with any Pacific-time prose.
    out.push_str(&format!(
        "Timestamp : {} (unix epoch seconds, UTC)\n",
        a.timestamp_local
    ));
    out.push_str(&format!("Session   : {:016x}\n", a.session_id));
    // The seal is tamper-evidence, not a footer note: it is re-derivable
    // from the verdict content below, so anyone holding this report can
    // confirm the verdict was not altered after measurement.
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
        // The DANE attribution continuation line — rendered as its OWN line,
        // never bolted onto `measured` (which would clip in a fixed-width
        // terminal). Only fires for ForeignZone (MX in a third party's zone).
        if let Some(attr) = rep.dane_attribution() {
            out.push_str(&format!("  \u{21b3} {attr}\n"));
        }
    }

    let t = Tally::of(&model);
    out.push_str(&format!(
        "\nCoverage Score : {}/{} ({}%)  |  unmeasured: {}  |  not-applicable: {}\n",
        t.present,
        t.denominator(),
        t.percent(),
        t.unmeasured,
        t.not_applicable
    ));
    // Risk-Weighted Score — a DERIVED view over the same sealed dispositions,
    // tagged SCORING_VERSION, never itself sealed. Shown beside Coverage (the
    // NIST-CSF rule: a lone hidden-weighted number is what hides which control
    // is weak). "unmeasured" reads back when nothing is measurable.
    match risk_weighted_score(&model) {
        Some(rws) => out.push_str(&format!(
            "Risk-Weighted  : {rws}%  (scoring v{SCORING_VERSION})\n"
        )),
        None => out.push_str(&format!(
            "Risk-Weighted  : unmeasured  (scoring v{SCORING_VERSION})\n"
        )),
    }

    // The re-derivation block: the EXACT bytes the seal hashes, printed from
    // the same single producer (seal::canonical_input) the seal itself uses.
    // Copy these bytes, run SHA3-512, and the hex digest is the seal above —
    // no side channel, no hand-kept mirror to drift.
    out.push_str("\n── Re-derive the seal (SHA3-512 of these exact bytes) ──\n");
    out.push_str(&canonical_input(a, &engine_version()));
    out.push_str("──────────────────────────────────────────────────────────\n");
    out
}

fn row(label: &str, t: TriState, measured: &str) -> String {
    let symbol = match t {
        TriState::Present => "PRESENT",
        TriState::Absent => "ABSENT",
        TriState::Indet => "INDET",
        TriState::NotApplicable => "N/A",
    };
    format!("{:<16}  {:<7}  {}\n", label, symbol, measured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{CsyncDisposition, ScoredAnalysis, TlsRptDisposition};
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
            // "default" here is fixture data, not a vantage: production never
            // emits it after cc/resolver-choice (Science,
            // two-gaps-closed-and-the-vantage-collision.md §4 — analysis.rs:41
            // sealed "default" for the vantage cli sealed as "cloudflare").
            resolver_identity: "default".to_string(),
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
            tlsa_zone: crate::analysis::TlsaZone::ZoneUnmeasured,
            mta_sts: TriState::Indet,
            mta_sts_disposition: crate::analysis::MtaStsDisposition::TransientError,
            caa: TriState::Indet,
            caa_disposition: crate::analysis::CaaDisposition::NoZone,
            cds_cdnskey: TriState::Indet,
            cds_disposition: crate::analysis::CdsDisposition::NoZone,
            tls_rpt: TriState::Absent,
            tls_rpt_disposition: TlsRptDisposition::RecordAbsent,
            csync: TriState::Absent,
            csync_disposition: CsyncDisposition::RecordAbsent,
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
    fn report_publishes_every_seal_input_and_labels_the_zone() {
        // A seal is re-derivable only when every input it binds is published
        // beside it. The two observation conditions the header once omitted
        // (engine version, resolver identity) must now render, the timestamp
        // must name its zone (bare epoch ≠ a date a reader converts), and the
        // canonical input — the exact bytes the seal hashes — must be present
        // so "anyone can re-check" is a literal instruction, not an assertion.
        let a = minimal();
        let text = render_text(&a);
        assert!(text.contains(&format!("Engine    : {}", engine_version())));
        assert!(text.contains(&format!("Resolver  : {}", a.resolver_identity)));
        assert!(text.contains("unix epoch seconds, UTC"));
        assert!(
            text.contains(&canonical_input(&a, &engine_version())),
            "the report must print the seal's exact preimage so a reader can re-derive it"
        );
    }

    /// R1 — the vantage gloss renders beneath `Resolver`, from the sealed
    /// string alone: a current identity expands to its wire description, a
    /// legacy label to the legacy sentence. `Resolver  : default` stays.
    #[test]
    fn report_prints_the_vantage_gloss_beneath_resolver() {
        let a = minimal();
        let text = render_text(&a);
        assert!(text.contains("Resolver  : default\nVantage   : unstructured label \"default\" — sealed before cc/resolver-choice"), "{text}");
        let mut c = minimal();
        c.resolver_identity = "cloudflare".to_string();
        let text = render_text(&c);
        assert!(text.contains("Resolver  : cloudflare\nVantage   : Cloudflare (1.1.1.1) over plain DNS, port 53 — DNSSEC validated by the instrument against the root keys, not by the resolver's word\n"), "{text}");
        let mut q = minimal();
        q.resolver_identity = "quad9/tls".to_string();
        assert!(render_text(&q).contains(
            "Vantage   : Quad9 (9.9.9.9) over DNS-over-TLS, port 853, certificate dns.quad9.net —"
        ));
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

    #[test]
    fn report_renders_dane_attribution_only_for_foreign_zone() {
        // The DANE attribution line ("lives outside this domain's own zone")
        // fires ONLY for ForeignZone — a measurement-faithful statement, never
        // a verdict. SameZone (self-hosted) and ZoneUnmeasured (couldn't walk
        // the cut) must NOT render it.
        let attr = "lives outside this domain's own zone";
        let mut foreign = minimal();
        foreign.dane_disposition = crate::analysis::DaneDisposition::NotConfigured;
        foreign.dane = TriState::Absent;
        foreign.tlsa_zone = crate::analysis::TlsaZone::ForeignZone;
        assert!(render_text(&foreign).contains(attr));

        let mut same = foreign.clone();
        same.tlsa_zone = crate::analysis::TlsaZone::SameZone;
        assert!(!render_text(&same).contains(attr));

        let mut unmeasured = foreign.clone();
        unmeasured.tlsa_zone = crate::analysis::TlsaZone::ZoneUnmeasured;
        assert!(!render_text(&unmeasured).contains(attr));
    }
}
