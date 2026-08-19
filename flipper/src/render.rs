// render.rs — the flipper's thin surface dispatcher.
//
// All three render paths delegate to the engine's truth_chain() — the SAME
// per-control assembly the TUI and web renderer use. This crate defines NO
// RFC text, NO verdict logic, and NO control ordering; it selects the
// presentation format and calls the shared model.

use resolution_scope_engine::report::render_text;
use resolution_scope_engine::truth_chain::{
    by_severity, truth_chain, Audience, ControlReport, Severity, Tally,
};
use resolution_scope_engine::{ScoredAnalysis, TriState};

/// Terminal summary: worst-first findings list + score line.
/// Mirrors the TUI's summary screen but as plain text (no ratatui dependency).
pub fn render_tui_summary(analyses: &[ScoredAnalysis], audience: Audience) -> String {
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

/// Plain text report \u{2014} delegates to the engine's own renderer (report.rs).
/// Same truth_chain() path, no re-interpretation.
pub fn render_text_report(analyses: &[ScoredAnalysis]) -> String {
    let mut s = String::new();
    for a in analyses {
        s.push_str(&render_text(a));
        s.push('\n');
    }
    s
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

const CSS: &str = r##":root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fafafa;--muted:#666;--card:#fff;--line:#ddd;--crit:#b3261e;--high:#c4441c;--med:#9a6b00;--low:#4a5568;--ok:#1e7f43;--unm:#777;--na:#999}@media(prefers-color-scheme:dark){:root{--fg:#e4e4e4;--bg:#111;--muted:#9a9a9a;--card:#1a1a1a;--line:#333;--crit:#ff6b5e;--high:#ff8a50;--med:#e0b341;--low:#a0aec0;--ok:#5dd48a;--unm:#888;--na:#777}}body{font:16px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg);max-width:52rem;margin:0 auto;padding:1.5rem}h1{font-size:1.4rem;margin:0}h2{font-size:1.15rem;margin:1.2rem 0 .2rem}.meta{color:var(--muted);font-size:.85rem;margin:.2rem 0}.score{margin:.4rem 0}.findings{list-style:none;padding:0;margin:1rem 0}.finding{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.8rem 1rem;margin:.6rem 0}.sev{font-weight:700;font-size:.75rem;letter-spacing:.05em}.sev.crit{color:var(--crit)}.sev.high{color:var(--high)}.sev.med{color:var(--med)}.sev.low{color:var(--low)}.sev.ok{color:var(--ok)}.sev.unm{color:var(--unm)}.sev.na{color:var(--na)}.control{font-weight:700}.tri{color:var(--muted);font-size:.85rem}.chain{margin:.5rem 0 0;font-size:.9rem}.chain dt{float:left;clear:left;width:7.5rem;color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;padding-top:.15rem}.chain dd{margin:0 0 .35rem 8rem}"##;

#[cfg(test)]
mod tests {
    use super::*;
    use resolution_scope_engine::analysis::{
        CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
        DnssecDisposition, MtaStsDisposition, SpfDisposition,
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

        let tui = render_tui_summary(std::slice::from_ref(&a), Audience::BlueTeam);
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

        let tui_blue = render_tui_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        let tui_red = render_tui_summary(std::slice::from_ref(&a), Audience::RedTeam);
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

        let tui = render_tui_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        let text = render_text_report(std::slice::from_ref(&a));
        let html = render_html_page(&[a], Audience::BlueTeam);

        let score_str = format!("{}/{}", t.present, t.denominator());
        assert!(tui.contains(&score_str), "tui score");
        assert!(text.contains(&score_str), "text score");
        assert!(html.contains(&score_str), "html score");
    }
}
