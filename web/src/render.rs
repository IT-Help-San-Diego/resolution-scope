// render.rs — static HTML from the shared truth-chain model.
//
// This surface owns MARKUP AND STYLING ONLY. Every fact on the page — RFC
// requirement, measured label, consequence, severity, tri-state, tally —
// comes from engine::truth_chain (ARCHITECTURE.md §8). A disposition match
// or an RFC number in this crate is a contract violation; the citation half
// is build-enforced by scripts/check-citation-boundary.sh.

use resolution_scope_engine::truth_chain::{by_severity, truth_chain, Audience, Severity, Tally};
use resolution_scope_engine::{ScoredAnalysis, TriState};

/// Minimal HTML escaping for text nodes and attribute values. The engine's
/// strings are static, but the DOMAIN is caller input and must never reach
/// the page unescaped.
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

/// Presentation vocabulary for the tri-state — the same PASS/FAIL/?/N/A the
/// TUI and text report use. Styling, not verdict logic: the collapse itself
/// happened in the model.
fn tri_label(t: TriState) -> &'static str {
    match t {
        TriState::Present => "PASS",
        TriState::Absent => "FAIL",
        TriState::Indet => "?",
        TriState::NotApplicable => "N/A",
    }
}

fn severity_class(s: Severity) -> &'static str {
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

/// Render one domain's report section: score header + findings worst-first,
/// each carrying the full three-layer truth chain.
fn render_domain(a: &ScoredAnalysis, audience: Audience) -> String {
    let model = truth_chain(a);
    let ordered = by_severity(&model);
    let t = Tally::of(&model);

    let mut s = String::new();
    s.push_str(&format!(
        "<section class=\"domain\">\n<h2>{}</h2>\n\
         <p class=\"meta\">scanned at unix {} · session {:016x}</p>\n\
         <p class=\"score\">Score: <strong>{}/{}</strong> ({}%) · \
         unmeasured: {} · not applicable: {}</p>\n\
         <p class=\"meta\">Unmeasured never enters the score — a “?” is not a verdict.</p>\n",
        esc(&a.domain),
        a.timestamp_local,
        a.session_id,
        t.present,
        t.denominator(),
        t.percent(),
        t.unmeasured,
        t.not_applicable,
    ));

    s.push_str("<ol class=\"findings\">\n");
    for rep in &ordered {
        s.push_str(&format!(
            "<li class=\"finding {}\">\n\
             <div class=\"head\"><span class=\"sev {}\">{}</span> \
             <span class=\"control\">{}</span> \
             <span class=\"tri\">{}</span></div>\n\
             <dl class=\"chain\">\n\
             <dt>measured</dt><dd>{}</dd>\n\
             <dt>rfc</dt><dd>{}</dd>\n\
             <dt>consequence</dt><dd>{}</dd>\n\
             </dl>\n</li>\n",
            severity_class(rep.severity),
            severity_class(rep.severity),
            esc(rep.severity.label()),
            esc(rep.control.name()),
            tri_label(rep.tri),
            esc(rep.measured),
            esc(rep.rfc_requirement),
            esc(rep.consequence(audience)),
        ));
    }
    s.push_str("</ol>\n</section>\n");
    s
}

/// Render the full standalone page for one or more scanned domains.
pub fn render_page(analyses: &[ScoredAnalysis], audience: Audience) -> String {
    let mut body = String::new();
    for a in analyses {
        body.push_str(&render_domain(a, audience));
    }
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Resolution Scope</title>\n<style>{}</style>\n</head>\n<body>\n\
         <header><h1>Resolution Scope</h1>\
         <p class=\"meta\">DNS security truth chain · {} framing · findings worst-first</p></header>\n\
         {}\
         </body>\n</html>\n",
        CSS,
        audience_label(audience),
        body
    )
}

const CSS: &str = "\
:root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fafafa;--muted:#666;--card:#fff;--line:#ddd;\
--crit:#b3261e;--high:#c4441c;--med:#9a6b00;--low:#4a5568;--ok:#1e7f43;--unm:#777;--na:#999}\
@media(prefers-color-scheme:dark){:root{--fg:#e4e4e4;--bg:#111;--muted:#9a9a9a;--card:#1a1a1a;\
--line:#333;--crit:#ff6b5e;--high:#ff8a50;--med:#e0b341;--low:#a0aec0;--ok:#5dd48a;--unm:#888;--na:#777}}\
body{font:16px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg);\
max-width:52rem;margin:0 auto;padding:1.5rem}\
h1{font-size:1.4rem;margin:0}h2{font-size:1.15rem;margin:1.2rem 0 .2rem}\
.meta{color:var(--muted);font-size:.85rem;margin:.2rem 0}\
.score{margin:.4rem 0}\
.findings{list-style:none;padding:0;margin:1rem 0}\
.finding{background:var(--card);border:1px solid var(--line);border-radius:8px;\
padding:.8rem 1rem;margin:.6rem 0}\
.head{display:flex;gap:.7rem;align-items:baseline}\
.sev{font-weight:700;font-size:.75rem;letter-spacing:.05em}\
.sev.crit{color:var(--crit)}.sev.high{color:var(--high)}.sev.med{color:var(--med)}\
.sev.low{color:var(--low)}.sev.ok{color:var(--ok)}.sev.unm{color:var(--unm)}.sev.na{color:var(--na)}\
.control{font-weight:700}\
.tri{color:var(--muted);font-size:.85rem}\
.chain{margin:.5rem 0 0;font-size:.9rem}\
.chain dt{float:left;clear:left;width:7.5rem;color:var(--muted);font-size:.75rem;\
text-transform:uppercase;letter-spacing:.05em;padding-top:.15rem}\
.chain dd{margin:0 0 .35rem 8rem}\
";

#[cfg(test)]
mod tests {
    use super::*;
    use resolution_scope_engine::analysis::{
        CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
        DnssecDisposition, MtaStsDisposition, SpfDisposition,
    };

    /// A fixture built directly from dispositions — no network, and the tri
    /// fields are DERIVED via chain(), same as analyse_domain does.
    fn fixture(domain: &str) -> ScoredAnalysis {
        let dnssec = DnssecDisposition::Unsigned;
        let spf = SpfDisposition::SoftFail;
        let dkim = DkimDisposition::NotProbed;
        let dmarc = DmarcDisposition::InvalidPolicy;
        let dane = DaneDisposition::Mismatch;
        let mta = MtaStsDisposition::RecordAbsent;
        let caa = CaaDisposition::Configured;
        let cds = CdsDisposition::NotPublished;
        ScoredAnalysis {
            domain: domain.to_string(),
            session_id: 0xabcd,
            timestamp_local: 1_787_000_000,
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

    /// Every control's full three-layer chain reaches the page verbatim.
    #[test]
    fn page_carries_all_three_layers_for_all_controls() {
        let a = fixture("example.test");
        let page = render_page(std::slice::from_ref(&a), Audience::BlueTeam);
        for rep in &truth_chain(&a) {
            assert!(
                page.contains(&esc(rep.measured)),
                "missing measured for {:?}",
                rep.control
            );
            assert!(
                page.contains(&esc(rep.rfc_requirement)),
                "missing rfc layer for {:?}",
                rep.control
            );
            assert!(
                page.contains(&esc(rep.consequence(Audience::BlueTeam))),
                "missing consequence for {:?}",
                rep.control
            );
        }
    }

    /// Findings render worst-first: the DANE Mismatch (Critical) section must
    /// appear before the CAA Configured (Ok) section in the byte stream.
    #[test]
    fn findings_are_worst_first() {
        let a = fixture("example.test");
        let page = render_page(std::slice::from_ref(&a), Audience::BlueTeam);
        let model = truth_chain(&a);
        let crit = model
            .iter()
            .find(|r| r.severity == Severity::Critical)
            .unwrap();
        let ok = model.iter().find(|r| r.severity == Severity::Ok).unwrap();
        let crit_at = page.find(&esc(crit.measured)).unwrap();
        let ok_at = page.find(&esc(ok.measured)).unwrap();
        assert!(crit_at < ok_at, "Critical must render before Ok");
    }

    /// The audience flip changes framing only where the model differs, and
    /// the page never mixes framings.
    #[test]
    fn audience_flip_swaps_consequences() {
        let a = fixture("example.test");
        let model = truth_chain(&a);
        let rep = model
            .iter()
            .find(|r| r.consequence(Audience::BlueTeam) != r.consequence(Audience::RedTeam));
        let rep = rep.expect("fixture must include a disposition with distinct framings");
        let blue = render_page(std::slice::from_ref(&a), Audience::BlueTeam);
        let red = render_page(std::slice::from_ref(&a), Audience::RedTeam);
        assert!(blue.contains(&esc(rep.consequence(Audience::BlueTeam))));
        assert!(!blue.contains(&esc(rep.consequence(Audience::RedTeam))));
        assert!(red.contains(&esc(rep.consequence(Audience::RedTeam))));
        assert!(!red.contains(&esc(rep.consequence(Audience::BlueTeam))));
    }

    /// The domain is caller input; it must reach the page escaped.
    #[test]
    fn domain_is_escaped() {
        let a = fixture("<script>alert(1)</script>.test");
        let page = render_page(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("&lt;script&gt;alert"));
    }

    /// The score line comes from the shared Tally: this fixture measures
    /// 2 present (SPF softfail scores Present per the enforcement ruling,
    /// CAA configured), 4 absent, 1 unmeasured (DKIM), 0 n/a — wait: DANE
    /// Mismatch is Absent, DMARC invalid Absent, MTA-STS absent, DNSSEC
    /// unsigned Absent. Asserted from chain(), not hand-arithmetic.
    #[test]
    fn score_line_matches_shared_tally() {
        let a = fixture("example.test");
        let t = Tally::of(&truth_chain(&a));
        let page = render_page(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(page.contains(&format!(
            "Score: <strong>{}/{}</strong> ({}%)",
            t.present,
            t.denominator(),
            t.percent()
        )));
    }
}
