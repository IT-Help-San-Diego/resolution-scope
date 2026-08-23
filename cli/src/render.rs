// render.rs — the flipper's thin surface dispatcher.
//
// All three render paths delegate to the engine's truth_chain() — the SAME
// per-control assembly the TUI and web renderer use. This crate defines NO
// RFC text, NO verdict logic, and NO control ordering; it selects the
// presentation format and calls the shared model.

use resolution_scope_engine::report::render_text;
use resolution_scope_engine::seal::{seal_versioned, SEAL_SCHEME};
use resolution_scope_engine::truth_chain::{
    by_severity, truth_chain, Audience, ControlReport, Severity, Tally,
};
use resolution_scope_engine::{ScoredAnalysis, TriState};
use resolution_scope_store::StoredScan;

/// Terminal summary: worst-first findings list + score line. The compact
/// "at a glance" view — distinct from the full text report (which is the
/// engine's own render_text), but the same truth_chain() path.
pub fn render_summary(analyses: &[ScoredAnalysis], audience: Audience) -> String {
    let mut s = String::new();
    s.push_str("Resolution Scope \u{2014} Surface Flipper\n");
    s.push_str(&format!("Audience: {}\n\n", audience_label(audience)));

    for a in analyses {
        let model: [ControlReport; 8] = truth_chain(a);
        let ordered: [ControlReport; 8] = by_severity(&model);
        let t = Tally::of(&model);

        s.push_str(&format!("\u{2550}\u{2550} {} \u{2550}\u{2550}\n", a.domain));
        s.push_str("Findings (worst first):\n");
        for rep in &ordered {
            s.push_str(&format!(
                "  {:<10} {:<12} {} {}\n",
                rep.severity.label(),
                rep.control.name(),
                tri_icon(rep.tri),
                rep.measured,
            ));
            s.push_str(&format!("      \u{2192} {}\n", rep.consequence(audience)));
        }
        s.push_str(&format!(
            "\n  Score: {}/{} ({}%)  |  unmeasured: {}  |  n/a: {}\n\n",
            t.present,
            t.denominator(),
            t.percent(),
            t.unmeasured,
            t.not_applicable,
        ));
    }
    s
}

/// Plain text report — delegates to the engine's own renderer (report.rs).
/// Same truth_chain() path, no re-interpretation.
pub fn render_text_report(analyses: &[ScoredAnalysis]) -> String {
    let mut s = String::new();
    for a in analyses {
        s.push_str(&render_text(a));
        s.push('\n');
    }
    s
}

/// Machine-readable report — the engine's own serialization, not a severity
/// map. `ScoredAnalysis` derives Serialize with every disposition enum (the
/// full tri-state and the WHY) plus the tri-state fields; serializing it whole
/// is what makes this the instrument half of the calibration study's Arm 1 —
/// the disposition, not a display label. One JSON object per domain, newline
/// separated, so `resolution-scope example.com --format json | jq` composes.
pub fn render_json(analyses: &[ScoredAnalysis]) -> String {
    let mut s = String::new();
    for a in analyses {
        s.push_str(&serde_json::to_string(a).expect("ScoredAnalysis is Serialize"));
        s.push('\n');
    }
    s
}

/// Sealed-history listing — the store's memory, surfaced.
///
/// Every stored scan is a row the store sealed at write time. This view
/// re-derives each row's seal from its stored verdict + stored engine version
/// via the SAME engine `seal_versioned` the store uses, so the CHECK column is
/// a measurement, not an assertion: a row that hashes back to its own seal is
/// VERIFIED, a drifted one is MISMATCH, and a row sealed under a scheme this
/// build cannot re-derive is UNVERIFIABLE (never "tampered" — the false-
/// accusation the store's scheme-dispatch exists to prevent).
///
/// The score shown is re-derived from the stored verdict through
/// `truth_chain()` and `Tally` — the same path as a live scan; history does
/// not invent a second scoring path.
pub fn render_history(domain: &str, history: &[StoredScan]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "\u{2550}\u{2550} Sealed history \u{2014} {domain} \u{2550}\u{2550}\n"
    ));
    if history.is_empty() {
        s.push_str("  (no stored scans for this domain)\n\n");
        return s;
    }
    s.push_str(&format!(
        "  {} scan(s), oldest first \u{2014} seal scheme {}\n\n",
        history.len(),
        SEAL_SCHEME,
    ));
    for h in history {
        let t = Tally::of(&truth_chain(&h.verdict));
        let prefix = if h.seal.len() >= 16 {
            &h.seal[..16]
        } else {
            &h.seal[..]
        };
        s.push_str(&format!(
            "  #{:<4} engine {:<8}  score {}/{}  seal {}…  {}\n",
            h.id,
            h.engine_version,
            t.present,
            t.denominator(),
            prefix,
            seal_check_label(h),
        ));
    }
    s.push_str(
        "\n  measured_at = unix time the scan ran; seal = re-derivable from the stored verdict\n",
    );
    s.push_str(
        "  (the timestamp is provenance, not part of the seal — the seal covers the verdict)\n\n",
    );
    s
}

/// The verification status of one stored scan, re-derived — not asserted.
fn seal_check_label(s: &StoredScan) -> &'static str {
    if s.seal_scheme != SEAL_SCHEME {
        "UNVERIFIABLE (scheme)"
    } else if seal_versioned(&s.verdict, &s.engine_version) == s.seal {
        "VERIFIED"
    } else {
        "MISMATCH"
    }
}

/// Static HTML page \u{2014} replicates the web renderer's structure but lives
/// in the flipper to avoid a circular dependency. Both call truth_chain().
pub fn render_html_page(analyses: &[ScoredAnalysis], audience: Audience) -> String {
    let mut body = String::new();
    for a in analyses {
        let model: [ControlReport; 8] = truth_chain(a);
        let ordered: [ControlReport; 8] = by_severity(&model);
        let t = Tally::of(&model);

        body.push_str(&format!(
            "<section class=\"domain\">\n<h2>{}</h2>\n\
             <p class=\"score\">Score: <strong>{}/{}</strong> ({}%) \u{00b7} \
             unmeasured: {} \u{00b7} n/a: {}</p>\n\
             <ol class=\"findings\">\n",
            esc(&a.domain),
            t.present,
            t.denominator(),
            t.percent(),
            t.unmeasured,
            t.not_applicable,
        ));

        for rep in &ordered {
            body.push_str(&format!(
                "<li class=\"finding {s}\">\n\
                 <span class=\"sev {s}\">{sev}</span> \
                 <span class=\"control\">{ctrl}</span> \
                 <span class=\"tri\">{tri}</span>\n\
                 <dl class=\"chain\">\n\
                 <dt>measured</dt><dd>{meas}</dd>\n\
                 <dt>rfc</dt><dd>{rfc}</dd>\n\
                 <dt>consequence</dt><dd>{cons}</dd>\n\
                 </dl>\n</li>\n",
                s = sev_class(rep.severity),
                sev = esc(rep.severity.label()),
                ctrl = esc(rep.control.name()),
                tri = tri_icon(rep.tri),
                meas = esc(rep.measured),
                rfc = esc(rep.rfc_requirement),
                cons = esc(rep.consequence(audience)),
            ));
        }
        body.push_str("</ol>\n</section>\n");
    }

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Resolution Scope \u{2014} Flipper</title>\n<style>{css}</style>\n</head>\n<body>\n\
         <header><h1>Resolution Scope</h1>\
         <p class=\"meta\">Surface flipper \u{00b7} {aud} framing \u{00b7} findings worst-first</p></header>\n\
         {body}</body>\n</html>\n",
        css = CSS,
        aud = audience_label(audience),
        body = body,
    )
}

// --- helpers -----------------------------------------------------------------

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn tri_icon(t: TriState) -> &'static str {
    match t {
        TriState::Present => "PASS",
        TriState::Absent => "FAIL",
        TriState::Indet => "?",
        TriState::NotApplicable => "N/A",
    }
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
        Severity::Ok => "ok",
        Severity::Unmeasured => "unm",
        Severity::NotApplicable => "na",
    }
}

fn audience_label(a: Audience) -> &'static str {
    match a {
        Audience::BlueTeam => "blue team",
        Audience::RedTeam => "red team",
    }
}

// Family scotopic identity — the SAME tokens as resolutionscope.com's
// style.css (site lane, three-surface design DNA): a locally generated
// report must read as the same instrument as the public site. Committed
// dark like the site (no light variant); severity ramp mapped into the
// family palette (crit=red, high=copper, med=gold, low/unm=muted).
const CSS: &str = r##":root{color-scheme:dark;--fg:#e6edf3;--bg:#0d1117;--muted:#9aa4ae;--card:#161b22;--line:#30363d;--gold:#d4a853;--crit:#f85149;--high:#c8956a;--med:#d4a853;--low:#9aa4ae;--ok:#3fb950;--unm:#9aa4ae;--na:#c8956a}body{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);max-width:52rem;margin:0 auto;padding:1.5rem}h1{font-size:1.4rem;margin:0;font-family:"SF Mono",Menlo,Consolas,monospace;color:var(--gold)}h2{font-size:1.15rem;margin:1.2rem 0 .2rem;font-family:"SF Mono",Menlo,Consolas,monospace;color:var(--gold)}.meta{color:var(--muted);font-size:.85rem;margin:.2rem 0}.score{margin:.4rem 0}.findings{list-style:none;padding:0;margin:1rem 0}.finding{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.8rem 1rem;margin:.6rem 0}.sev{font-weight:700;font-size:.75rem;letter-spacing:.05em}.sev.crit{color:var(--crit)}.sev.high{color:var(--high)}.sev.med{color:var(--med)}.sev.low{color:var(--low)}.sev.ok{color:var(--ok)}.sev.unm{color:var(--unm)}.sev.na{color:var(--na)}.control{font-weight:700}.tri{color:var(--muted);font-size:.85rem}.chain{margin:.5rem 0 0;font-size:.9rem}.chain dt{float:left;clear:left;width:7.5rem;color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;padding-top:.15rem}.chain dd{margin:0 0 .35rem 8rem}"##;

#[cfg(test)]
mod tests {
    use super::*;
    use resolution_scope_engine::analysis::{
        CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
        DnssecDisposition, MtaStsDisposition, SpfDisposition, TlsaZone,
    };

    fn fixture(domain: &str) -> ScoredAnalysis {
        let dnssec = DnssecDisposition::Unsigned;
        let spf = SpfDisposition::HardFail;
        let dkim = DkimDisposition::NotProbed;
        let dmarc = DmarcDisposition::Reject;
        let dane = DaneDisposition::Mismatch;
        let mta = MtaStsDisposition::Enforced;
        let caa = CaaDisposition::Configured;
        let cds = CdsDisposition::NotPublished;
        ScoredAnalysis {
            domain: domain.to_string(),
            session_id: 0,
            timestamp_local: 0,
            resolver_identity: "default".to_string(),
            dnssec_chain: dnssec.chain(),
            dnssec_disposition: dnssec,
            spf: spf.chain(),
            spf_disposition: spf,
            dkim: dkim.chain(),
            dkim_disposition: dkim,
            dmarc: dmarc.chain(),
            dmarc_disposition: dmarc,
            dane: dane.chain(),
            dane_disposition: dane,
            tlsa_zone: TlsaZone::ForeignZone,
            mta_sts: mta.chain(),
            mta_sts_disposition: mta,
            caa: caa.chain(),
            caa_disposition: caa,
            cds_cdnskey: cds.chain(),
            cds_disposition: cds,
        }
    }

    /// All three renderers consume the same truth_chain() -- the tui summary,
    /// text report, and HTML page all carry the same measured label.
    #[test]
    fn all_surfaces_carry_same_measured_labels() {
        let a = fixture("example.test");
        let model = truth_chain(&a);

        let tui = render_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        let text = render_text_report(std::slice::from_ref(&a));
        let html = render_html_page(&[a], Audience::BlueTeam);

        for rep in &model {
            assert!(
                tui.contains(rep.measured),
                "tui missing measured for {:?}",
                rep.control
            );
            assert!(
                text.contains(rep.measured),
                "text missing measured for {:?}",
                rep.control
            );
            assert!(
                html.contains(&esc(rep.measured)),
                "html missing measured for {:?}",
                rep.control
            );
        }
    }

    /// The audience flip changes consequence text in both tui and html.
    #[test]
    fn audience_flip_changes_consequence_in_tui_and_html() {
        let a = fixture("example.test");
        let model = truth_chain(&a);
        let rep = model
            .iter()
            .find(|r| r.consequence(Audience::BlueTeam) != r.consequence(Audience::RedTeam))
            .expect("fixture has a disposition with distinct framings");

        let tui_blue = render_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        let tui_red = render_summary(std::slice::from_ref(&a), Audience::RedTeam);
        let html_blue = render_html_page(std::slice::from_ref(&a), Audience::BlueTeam);
        let html_red = render_html_page(&[a], Audience::RedTeam);

        assert!(tui_blue.contains(rep.consequence(Audience::BlueTeam)));
        assert!(!tui_blue.contains(rep.consequence(Audience::RedTeam)));
        assert!(tui_red.contains(rep.consequence(Audience::RedTeam)));
        assert!(!tui_red.contains(rep.consequence(Audience::BlueTeam)));

        assert!(html_blue.contains(&esc(rep.consequence(Audience::BlueTeam))));
        assert!(!html_blue.contains(&esc(rep.consequence(Audience::RedTeam))));
        assert!(html_red.contains(&esc(rep.consequence(Audience::RedTeam))));
        assert!(!html_red.contains(&esc(rep.consequence(Audience::BlueTeam))));
    }

    /// The score line is the same in all three surfaces (shared Tally).
    #[test]
    fn score_line_consistent_across_surfaces() {
        let a = fixture("example.test");
        let t = Tally::of(&truth_chain(&a));

        let tui = render_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        let text = render_text_report(std::slice::from_ref(&a));
        let html = render_html_page(&[a], Audience::BlueTeam);

        let score_str = format!("{}/{}", t.present, t.denominator());
        assert!(tui.contains(&score_str), "tui score");
        assert!(text.contains(&score_str), "text score");
        assert!(html.contains(&score_str), "html score");
    }

    /// The domain is caller input; it must reach the page escaped.
    /// (Ported from the retired web crate — its renderer had this test and the
    /// flipper's did not, though both escape. A renderer that escapes without
    /// a test proving it is one regression away from an XSS vector.)
    #[test]
    fn domain_is_escaped() {
        let a = fixture("<script>alert(1)</script>.test");
        let page = render_html_page(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("&lt;script&gt;alert"));
    }

    /// The JSON surface carries the DISPOSITION and the tri-state, not a
    /// severity label — the same constraint that disqualified the Go compact
    /// endpoint. "signed_not_delegated" and "indet" must survive serialization
    /// because Arm 1 needs the tri-state on both sides.
    #[test]
    fn json_carries_disposition_and_tri_state() {
        let a = fixture("example.test");
        let out = render_json(std::slice::from_ref(&a));
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["domain"], "example.test");
        // The full disposition enum survives (not a severity string).
        assert_eq!(v["dnssec_disposition"], "Unsigned");
        // And the tri-state survives alongside it.
        assert_eq!(v["dnssec_chain"], "Absent");
    }

    /// The Arm-1 join contract: ALL EIGHT disposition keys and ALL EIGHT
    /// tri-state keys must be present by their exact field names. The Go-side
    /// harness reads these names to join the two implementations; a renamed
    /// field is a silent broken join, not a test failure — so the names are
    /// the contract, asserted here in full, not a representative sample.
    #[test]
    fn json_carries_all_sixteen_verdict_keys() {
        let a = fixture("example.test");
        let out = render_json(std::slice::from_ref(&a));
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();

        // Eight dispositions (the full enum variant name — the WHY).
        for key in [
            "dnssec_disposition",
            "spf_disposition",
            "dkim_disposition",
            "dmarc_disposition",
            "dane_disposition",
            "mta_sts_disposition",
            "caa_disposition",
            "cds_disposition",
        ] {
            assert!(v.get(key).is_some(), "missing disposition key {key}");
            assert!(
                v[key].is_string(),
                "disposition {key} is not a string enum name"
            );
        }

        // Eight tri-states (the collapse — one of four, never a severity label).
        let tri_states = ["Present", "Absent", "Indet", "NotApplicable"];
        for key in [
            "dnssec_chain",
            "spf",
            "dkim",
            "dmarc",
            "dane",
            "mta_sts",
            "caa",
            "cds_cdnskey",
        ] {
            let val = v
                .get(key)
                .unwrap_or_else(|| panic!("missing tri-state key {key}"));
            let val = val
                .as_str()
                .unwrap_or_else(|| panic!("tri-state {key} is not a string"));
            assert!(
                tri_states.contains(&val),
                "tri-state {key} = {val:?} is not one of the four states"
            );
        }
    }

    // ── Sealed history ────────────────────────────────────────────────

    fn stored(domain: &str, scheme: &str, seal: String) -> StoredScan {
        StoredScan {
            id: 1,
            domain: domain.to_string(),
            engine_version: "0.1.0".to_string(),
            seal,
            seal_scheme: scheme.to_string(),
            verdict: fixture(domain),
        }
    }

    /// The seal check re-derives, it does not assert: a row that hashes back
    /// to its own seal is VERIFIED, a drifted one is MISMATCH, and a row
    /// under an unknown scheme is UNVERIFIABLE (never "tampered").
    #[test]
    fn history_seal_check_three_states() {
        let v = fixture("example.test");
        let good = seal_versioned(&v, "0.1.0");

        let ok = stored("example.test", SEAL_SCHEME, good.clone());
        assert_eq!(seal_check_label(&ok), "VERIFIED");

        let tampered = stored("example.test", SEAL_SCHEME, "deadbeef".repeat(64));
        assert_eq!(seal_check_label(&tampered), "MISMATCH");

        let future = stored("example.test", "resolution-scope-sha3-512-v4", good);
        assert_eq!(seal_check_label(&future), "UNVERIFIABLE (scheme)");
    }

    /// The two tamper directions are distinct failure modes and both must
    /// read MISMATCH. This one is the realistic attack: rewrite the stored
    /// VERDICT while leaving the seal it was sealed under intact. A falsifier
    /// edits the measurement, not the label. The seal check recomputes from
    /// the (now-altered) verdict, so it diverges from the stale seal.
    #[test]
    fn verdict_tamper_reads_mismatch() {
        let original = fixture("example.test");
        let good_seal = seal_versioned(&original, "0.1.0");

        // A stored row sealed from the ORIGINAL verdict, but whose verdict
        // field was rewritten behind the seal's back. Flip a measurement to a
        // DIFFERENT value than the fixture already holds (the fixture's
        // dnssec is Unsigned → chain() == Absent, so flip to Present).
        let mut altered = original.clone();
        altered.dnssec_chain = TriState::Present; // a real change, not a no-op
        let row = StoredScan {
            id: 1,
            domain: "example.test".to_string(),
            engine_version: "0.1.0".to_string(),
            seal: good_seal, // stale: the original verdict's seal
            seal_scheme: SEAL_SCHEME.to_string(),
            verdict: altered, // rewritten measurement
        };
        assert_eq!(seal_check_label(&row), "MISMATCH");
    }

    /// The other direction: the SEAL label is altered while the verdict stays.
    /// Also MISMATCH — but a different failure mode.
    #[test]
    fn seal_tamper_reads_mismatch() {
        let v = fixture("example.test");
        let _good = seal_versioned(&v, "0.1.0");
        let tampered = stored("example.test", SEAL_SCHEME, "deadbeef".repeat(64));
        assert_eq!(seal_check_label(&tampered), "MISMATCH");
    }

    /// The rendered history carries the seal prefix, the verification label,
    /// the re-derived score, and the domain — a reader can confirm the row's
    /// provenance from the listing alone.
    #[test]
    fn history_renders_seal_score_and_check() {
        let v = fixture("example.test");
        let good = seal_versioned(&v, "0.1.0");
        let t = Tally::of(&truth_chain(&v));

        let out = render_history(
            "example.test",
            &[stored("example.test", SEAL_SCHEME, good.clone())],
        );

        assert!(out.contains("example.test"), "domain");
        assert!(out.contains("VERIFIED"), "verification label");
        assert!(out.contains(&good[..16]), "seal prefix");
        assert!(
            out.contains(&format!("{}/{}", t.present, t.denominator())),
            "re-derived score"
        );
    }

    /// Empty history is honest: it says so, it does not fabricate rows.
    #[test]
    fn history_empty_is_explicit() {
        let out = render_history("never-scanned.test", &[]);
        assert!(out.contains("no stored scans"));
    }
}
