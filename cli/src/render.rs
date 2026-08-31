// render.rs — the cli's surfaces: report, summary, HTML, JSON, history.
//
// Every surface delegates to the engine's truth_chain() — the SAME
// per-control assembly the TUI uses — and to the engine's seal producers
// (seal, canonical_input, engine_version, SEAL_SCHEME). This crate defines
// NO RFC text, NO verdict logic, NO consequence text and NO scoring: it
// selects layout and styling and calls the shared model. Grouping rows into
// tiers is layout over the engine's Severity; the tier a row lands in is the
// engine's ruling, not this file's.
//
// The one vocabulary rule every surface shares: the seal is tamper-evidence
// and nothing more (seal.rs). No surface may call it proof that a measurement
// happened.

use resolution_scope_engine::report::render_text;
use resolution_scope_engine::seal::{
    canonical_input, engine_version, seal, seal_versioned, SEAL_SCHEME, V4_BOUNDARY_NOTE,
};
use resolution_scope_engine::truth_chain::{
    by_severity, risk_weighted_score, truth_chain, Audience, ControlReport, Severity, Tally,
    SCORING_VERSION,
};
use resolution_scope_engine::{ScoredAnalysis, TriState};
use resolution_scope_store::StoredScan;

// ── shared vocabulary — one producer per sentence, every surface reads it ──

/// What the Coverage Score counts.
pub const COVERAGE_NOTE: &str = "deployed controls over measured controls";
/// What the Risk-Weighted Score is, and its standing relative to Coverage.
pub const RISK_WEIGHTED_NOTE: &str =
    "the same verdicts weighted by each control's identity — beside Coverage, never instead of it, never sealed";
/// Why `?` and N/A rows carry no score weight.
pub const EXCLUDED_NOTE: &str = "excluded from both scores";
/// The seal's one honest claim.
pub const SEAL_NOTE: &str =
    "tamper-evidence only: hash these exact bytes under the named scheme (every line, the last \
included, ends in a newline) and you re-derive the seal — it proves the verdict you hold is the \
one that was sealed, nothing more";
/// Current staged boundary: visible everywhere the v4 seal is explained.
pub const SEAL_BOUNDARY_NOTE: &str = V4_BOUNDARY_NOTE;

/// Tier labels — layout over the engine's Severity ordering.
pub const TIER_FINDINGS: &str = "FINDINGS";
pub const TIER_ADVISORY: &str = "ADVISORY";
pub const TIER_HOLDING: &str = "HOLDING";
pub const TIER_UNMEASURED: &str = "COULD NOT MEASURE";
pub const TIER_NOT_APPLICABLE: &str = "NOT APPLICABLE";

/// One-line teaching subtitle under the verdict tiers, so a first
/// reading knows which way each heading points. The other two tier names
/// already state their meaning.
pub fn tier_subtitle(tier: &str) -> Option<&'static str> {
    match tier {
        TIER_FINDINGS => Some("controls that need attention"),
        TIER_ADVISORY => Some("low-severity gaps: scored, but not urgent"),
        TIER_HOLDING => Some("controls measured in their correct state"),
        _ => None,
    }
}

/// Which tier a severity renders in. Pure layout: the severity itself is the
/// engine's ruling (truth_chain.rs); this only decides the heading above it.
/// Low is the engine's concession class (a measured gap that still docks the
/// score but does not demand action), so it gets its own heading instead of
/// sitting under "controls that need attention" — placement only, per
/// policy/RULING_cds_cdnskey_20260821.md: the word, the severity, and the
/// arithmetic are untouched.
pub fn tier_of(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High | Severity::Medium => TIER_FINDINGS,
        Severity::Low => TIER_ADVISORY,
        Severity::Ok => TIER_HOLDING,
        Severity::Unmeasured => TIER_UNMEASURED,
        Severity::NotApplicable => TIER_NOT_APPLICABLE,
    }
}

/// The five tiers in display order, each holding its rows worst-first. A
/// tier with no rows is still returned (empty) so a surface can choose to
/// print "none" rather than silently omit the heading. Display order must
/// follow the Severity declaration order so the tier concatenation equals
/// the by_severity order — the TUI cursor walks that equality.
pub fn tiers(model: &[ControlReport; 10]) -> [(&'static str, Vec<ControlReport>); 5] {
    let ordered = by_severity(model);
    let pick = |tier: &'static str| -> Vec<ControlReport> {
        ordered
            .iter()
            .copied()
            .filter(|r| tier_of(r.severity) == tier)
            .collect()
    };
    [
        (TIER_FINDINGS, pick(TIER_FINDINGS)),
        (TIER_ADVISORY, pick(TIER_ADVISORY)),
        (TIER_HOLDING, pick(TIER_HOLDING)),
        (TIER_UNMEASURED, pick(TIER_UNMEASURED)),
        (TIER_NOT_APPLICABLE, pick(TIER_NOT_APPLICABLE)),
    ]
}

/// The measurement conditions a seal binds, gathered once per verdict so
/// every surface prints the same set: engine version, resolver vantage,
/// timestamp, session, seal, scheme. Values are the engine's; this is
/// formatting only.
pub struct Observation {
    pub engine: String,
    pub resolver: String,
    pub epoch: u64,
    pub when_utc: String,
    pub session_hex: String,
    pub seal: String,
    pub scheme: &'static str,
}

impl Observation {
    pub fn of(a: &ScoredAnalysis) -> Observation {
        Observation {
            engine: engine_version(),
            resolver: a.resolver_identity.clone(),
            epoch: a.timestamp_local,
            when_utc: iso_utc(a.timestamp_local),
            session_hex: format!("{:016x}", a.session_id),
            seal: seal(a),
            scheme: SEAL_SCHEME,
        }
    }
    /// The first 16 hex characters — the citable prefix every surface uses.
    pub fn seal_prefix(&self) -> &str {
        &self.seal[..self.seal.len().min(16)]
    }
}

/// Unix epoch seconds → `YYYY-MM-DD HH:MM:SS UTC`, the human form. Pure
/// presentation of the engine's `timestamp_local` (which IS UTC — the field
/// name predates the zone label). Civil-from-days per Howard Hinnant's
/// algorithm; no dependency, no local zone.
pub fn iso_utc(epoch: u64) -> String {
    let (y, mo, d, h, m, s) = civil_utc(epoch);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Unix epoch seconds → the internet date-time form `YYYY-MM-DDTHH:MM:SSZ`
/// (the `Z`-suffixed profile stock JSON tooling parses) — the machine form.
pub fn rfc3339_utc(epoch: u64) -> String {
    let (y, mo, d, h, m, s) = civil_utc(epoch);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_utc(epoch: u64) -> (i64, i64, i64, u64, u64, u64) {
    let days = (epoch / 86_400) as i64;
    let secs = epoch % 86_400;
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, m, s)
}

// ── text surfaces ────────────────────────────────────────────────────────

struct TextOpts {
    /// Print layer 1 (the RFC requirement) under each row.
    rfc: bool,
    /// Print the full seal and the re-derive block.
    rederive: bool,
}

/// The default verb's output: every row in its tier, all three layers, both
/// scores explained in one line each, and the seal with its exact preimage.
pub fn render_report(analyses: &[ScoredAnalysis], audience: Audience) -> String {
    render_text_surface(
        analyses,
        audience,
        TextOpts {
            rfc: true,
            rederive: true,
        },
    )
}

/// Compact at-a-glance view: tiers, measured state, consequence, scores,
/// seal prefix. No RFC layer, no re-derive block — `--format report` for those.
pub fn render_summary(analyses: &[ScoredAnalysis], audience: Audience) -> String {
    render_text_surface(
        analyses,
        audience,
        TextOpts {
            rfc: false,
            rederive: false,
        },
    )
}

fn render_text_surface(analyses: &[ScoredAnalysis], audience: Audience, opts: TextOpts) -> String {
    let mut s = String::new();
    s.push_str("RESOLUTION SCOPE \u{2014} measured and sealed\n");
    s.push_str(&format!("framing: {}\n", audience_label(audience)));

    for a in analyses {
        let model: [ControlReport; 10] = truth_chain(a);
        let t = Tally::of(&model);
        let obs = Observation::of(a);

        s.push_str(&format!(
            "\n\u{2550}\u{2550} {} \u{2550}\u{2550}\n",
            a.domain
        ));
        s.push_str(&format!(
            "engine {} \u{00b7} resolver {} \u{00b7} {} (epoch {}) \u{00b7} session {}\n",
            obs.engine, obs.resolver, obs.when_utc, obs.epoch, obs.session_hex
        ));
        if opts.rederive {
            s.push_str(&format!("seal   {}\n", obs.seal));
            s.push_str(&format!("scheme {}\n", obs.scheme));
        } else {
            s.push_str(&format!(
                "seal   {}\u{2026}  ({}; full seal + re-derive block: --format report)\n",
                obs.seal_prefix(),
                obs.scheme
            ));
        }

        for (tier, rows) in tiers(&model) {
            s.push_str(&format!("\n{tier}\n"));
            if rows.is_empty() {
                s.push_str("  (none)\n");
                continue;
            }
            for rep in &rows {
                s.push_str(&format!(
                    "  {:<10} {:<12} {:<7} {}\n",
                    rep.severity.label(),
                    rep.control.name(),
                    tri_icon(rep.tri),
                    rep.measured,
                ));
                // DANE attribution — its OWN line, directly under the measured
                // state it qualifies, BEFORE the consequence (a reader must
                // know whose zone is meant before reading what to do).
                if let Some(attr) = rep.dane_attribution() {
                    s.push_str(&format!("      \u{21b3} {attr}\n"));
                }
                if opts.rfc {
                    s.push_str(&format!("      rfc  {}\n", rep.rfc_requirement));
                }
                s.push_str(&format!("      \u{2192} {}\n", rep.consequence(audience)));
            }
        }

        s.push_str(&format!(
            "\nCoverage Score : {}/{} ({}%)  \u{2014} {}\n",
            t.present,
            t.denominator(),
            t.percent(),
            COVERAGE_NOTE,
        ));
        s.push_str(&format!(
            "Risk-Weighted  : {}  \u{2014} {}\n",
            weighted_label(&model),
            RISK_WEIGHTED_NOTE,
        ));
        s.push_str(&format!(
            "? (indeterminate): {} \u{00b7} N/A (not applicable): {}  \u{2014} {}\n",
            t.unmeasured, t.not_applicable, EXCLUDED_NOTE,
        ));

        if opts.rederive {
            s.push_str(&format!(
                "\n\u{2500}\u{2500} Re-derive the seal \u{2014} scheme {} \u{2500}\u{2500}\n",
                obs.scheme
            ));
            s.push_str(SEAL_BOUNDARY_NOTE);
            s.push('\n');
            s.push_str(&canonical_input(a, &obs.engine));
            s.push_str(
                "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\n",
            );
            s.push_str(&format!("{SEAL_NOTE}\n"));
        }
    }
    s
}

/// The engine's own minimal render (report.rs) — the compartment's proof
/// surface, unchanged. No audience, no tiers: what the seL4 side will print.
pub fn render_text_report(analyses: &[ScoredAnalysis]) -> String {
    let mut s = String::new();
    for a in analyses {
        s.push_str(&render_text(a));
        s.push('\n');
    }
    s
}

/// Machine-readable report. The engine's own serialization of the verdict
/// (every disposition enum + every tri-state — the Arm-1 join contract, all
/// 16 verdict keys by their exact names) PLUS the measurement conditions a
/// consumer needs to verify and to score without re-implementing either:
/// seal, seal_scheme, engine_version, session_hex, timestamp_utc (internet
/// date-time `…Z`, the same instant as the engine's epoch `timestamp_local`,
/// which is UTC despite its name), coverage, risk_weighted, scoring_version. Additive only
/// — no verdict key is renamed, re-typed or nested; keys serialize sorted.
/// One object per domain, newline separated, so
/// `resolution-scope example.com --format json | jq` composes.
pub fn render_json(analyses: &[ScoredAnalysis]) -> String {
    let mut s = String::new();
    for a in analyses {
        let model = truth_chain(a);
        let t = Tally::of(&model);
        let obs = Observation::of(a);
        let mut v = serde_json::to_value(a).expect("ScoredAnalysis is Serialize");
        let obj = v
            .as_object_mut()
            .expect("ScoredAnalysis serializes as an object");
        obj.insert("seal".into(), obs.seal.clone().into());
        obj.insert("seal_scheme".into(), obs.scheme.into());
        obj.insert("engine_version".into(), obs.engine.clone().into());
        obj.insert("session_hex".into(), obs.session_hex.clone().into());
        obj.insert(
            "timestamp_utc".into(),
            rfc3339_utc(a.timestamp_local).into(),
        );
        obj.insert(
            "coverage".into(),
            serde_json::json!({
                "present": t.present,
                "absent": t.absent,
                "denominator": t.denominator(),
                "percent": t.percent(),
                "unmeasured": t.unmeasured,
                "not_applicable": t.not_applicable,
            }),
        );
        obj.insert(
            "risk_weighted".into(),
            match risk_weighted_score(&model) {
                Some(p) => serde_json::Value::from(p),
                None => serde_json::Value::Null,
            },
        );
        obj.insert("scoring_version".into(), SCORING_VERSION.into());
        s.push_str(&serde_json::to_string(&v).expect("json value serializes"));
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
/// The scores shown are re-derived from the stored verdict through
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
        "  {} scan(s), oldest first \u{2014} this build re-derives seal scheme {}\n\n",
        history.len(),
        SEAL_SCHEME,
    ));
    s.push_str(
        "  id     measured                 engine   coverage     risk-weighted           seal               check\n",
    );
    for h in history {
        let model = truth_chain(&h.verdict);
        let t = Tally::of(&model);
        let prefix = &h.seal[..h.seal.len().min(16)];
        s.push_str(&format!(
            "  #{:<5} {}  {:<8} {:>2}/{:<2} ({:>3}%)  {:<22} {}\u{2026}  {}\n",
            h.id,
            iso_utc(h.verdict.timestamp_local),
            h.engine_version,
            t.present,
            t.denominator(),
            t.percent(),
            weighted_label(&model),
            prefix,
            seal_check_label(h),
        ));
    }
    s.push_str(
        "\n  check = the seal re-derived from the stored verdict and engine version, compared to the stored seal\n",
    );
    s.push_str(
        "  (the timestamp is recorded beside the seal, not inside it \u{2014} the seal covers the verdict)\n\n",
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

// ── HTML surface ─────────────────────────────────────────────────────────

/// Static HTML page: one document per run, the domain in the title, every
/// verdict with its seal and re-derive block. Same truth_chain(), same
/// vocabulary constants as the text surfaces, family style tokens.
pub fn render_html_page(analyses: &[ScoredAnalysis], audience: Audience) -> String {
    let mut body = String::new();
    for a in analyses {
        let model: [ControlReport; 10] = truth_chain(a);
        let t = Tally::of(&model);
        let obs = Observation::of(a);

        body.push_str(&format!(
            "<section class=\"domain\">\n<h2>{dom}</h2>\n\
             <p class=\"meta\">engine {eng} \u{00b7} resolver {res} \u{00b7} {when} \
             (epoch {epoch}) \u{00b7} session {sess}</p>\n\
             <p class=\"meta seal\">seal <code>{seal}</code> <span class=\"scheme\">{scheme}</span></p>\n",
            dom = esc(&a.domain),
            eng = esc(&obs.engine),
            res = esc(&obs.resolver),
            when = esc(&obs.when_utc),
            epoch = obs.epoch,
            sess = esc(&obs.session_hex),
            seal = esc(&obs.seal),
            scheme = esc(obs.scheme),
        ));

        for (tier, rows) in tiers(&model) {
            body.push_str(&format!(
                "<h3 class=\"tier\">{}</h3>\n<ol class=\"findings\">\n",
                esc(tier)
            ));
            if rows.is_empty() {
                body.push_str("<li class=\"none\">none</li>\n");
            }
            for rep in &rows {
                let attr_dd = rep
                    .dane_attribution()
                    .map(|a| format!("<dt>attribution</dt><dd>{}</dd>\n", esc(a)))
                    .unwrap_or_default();
                body.push_str(&format!(
                    "<li class=\"finding {s}\">\n\
                     <span class=\"sev {s}\">{sev}</span> \
                     <span class=\"control\">{ctrl}</span> \
                     <span class=\"tri\">{tri}</span>\n\
                     <dl class=\"chain\">\n\
                     <dt>measured</dt><dd>{meas}</dd>\n\
                     {attr}\
                     <dt>rfc</dt><dd>{rfc}</dd>\n\
                     <dt>consequence</dt><dd>{cons}</dd>\n\
                     </dl>\n</li>\n",
                    s = sev_class(rep.severity),
                    sev = esc(rep.severity.label()),
                    ctrl = esc(rep.control.name()),
                    tri = esc(tri_icon(rep.tri).trim()),
                    meas = esc(rep.measured),
                    attr = attr_dd,
                    rfc = esc(rep.rfc_requirement),
                    cons = esc(rep.consequence(audience)),
                ));
            }
            body.push_str("</ol>\n");
        }

        body.push_str(&format!(
            "<dl class=\"scores\">\n\
             <dt>Coverage Score</dt><dd><strong>{p}/{d}</strong> ({pct}%) <span class=\"note\">{cn}</span></dd>\n\
             <dt>Risk-Weighted</dt><dd><strong>{rws}</strong> <span class=\"note\">{rn}</span></dd>\n\
             <dt>Excluded</dt><dd>? (indeterminate): {u} \u{00b7} N/A (not applicable): {na} <span class=\"note\">{en}</span></dd>\n\
             </dl>\n",
            p = t.present,
            d = t.denominator(),
            pct = t.percent(),
            cn = esc(COVERAGE_NOTE),
            rws = esc(&weighted_label(&model)),
            rn = esc(RISK_WEIGHTED_NOTE),
            u = t.unmeasured,
            na = t.not_applicable,
            en = esc(EXCLUDED_NOTE),
        ));

        body.push_str(&format!(
            "<details class=\"rederive\" open>\n<summary>Re-derive the seal \u{2014} scheme {scheme}</summary>\n\
             <p class=\"note\">{boundary}</p>\n<pre>{pre}</pre>\n<p class=\"note\">{note}</p>\n</details>\n</section>\n",
            scheme = esc(obs.scheme),
            boundary = esc(SEAL_BOUNDARY_NOTE),
            pre = esc(&canonical_input(a, &obs.engine)),
            note = esc(SEAL_NOTE),
        ));
    }

    let title = match analyses {
        [one] => format!("{} \u{2014} Resolution Scope", one.domain),
        _ => format!("{} domains \u{2014} Resolution Scope", analyses.len()),
    };

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n<style>{css}</style>\n</head>\n<body>\n\
         <header><h1>Resolution Scope</h1>\
         <p class=\"meta\">measured and sealed \u{00b7} framing: {aud} \u{00b7} findings worst-first within each tier</p></header>\n\
         {body}</body>\n</html>\n",
        title = esc(&title),
        css = CSS,
        aud = esc(audience_label(audience)),
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

/// The Risk-Weighted label every cli surface prints — one producer, so the
/// report, summary, HTML, TUI and history cannot drift from each other. A
/// DERIVED view over the same sealed dispositions (never sealed itself),
/// tagged with SCORING_VERSION; reads "unmeasured" when nothing is
/// measurable. Always shown BESIDE Coverage, never instead of it.
pub fn weighted_label(model: &[ControlReport; 10]) -> String {
    match risk_weighted_score(model) {
        Some(rws) => format!("{rws}%  (scoring v{SCORING_VERSION})"),
        None => format!("unmeasured  (scoring v{SCORING_VERSION})"),
    }
}

/// The machine's own state name (`TriState`'s `Display`), never a verdict word:
/// the severity label beside it carries the consequence.
pub fn tri_icon(t: TriState) -> &'static str {
    match t {
        TriState::Present => "PRESENT",
        TriState::Absent => "ABSENT",
        TriState::Indet => "INDET",
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

/// One vocabulary for the audience on every surface (text, HTML, TUI).
pub fn audience_label(a: Audience) -> &'static str {
    match a {
        Audience::BlueTeam => "blue \u{2014} defend (what it costs you, what to do)",
        Audience::RedTeam => "red \u{2014} assess (what it exposes to an authorised assessor)",
    }
}

// Family scotopic identity — the SAME tokens as resolutionscope.com's
// style.css (site lane, three-surface design DNA): a locally generated
// report must read as the same instrument as the public site. Committed
// dark like the site (no light variant); severity ramp mapped into the
// family palette (crit=red, high=copper, med=gold, low/unm=muted).
const CSS: &str = r##":root{color-scheme:dark;--fg:#e6edf3;--bg:#0d1117;--muted:#9aa4ae;--card:#161b22;--line:#30363d;--gold:#d4a853;--crit:#f85149;--high:#c8956a;--med:#d4a853;--low:#9aa4ae;--ok:#3fb950;--unm:#9aa4ae;--na:#c8956a}body{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);max-width:52rem;margin:0 auto;padding:1.5rem}h1{font-size:1.4rem;margin:0;font-family:"SF Mono",Menlo,Consolas,monospace;color:var(--gold)}h2{font-size:1.15rem;margin:1.2rem 0 .2rem;font-family:"SF Mono",Menlo,Consolas,monospace;color:var(--gold)}h3.tier{font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:1.2rem 0 .3rem;border-bottom:1px solid var(--line);padding-bottom:.2rem}.meta{color:var(--muted);font-size:.85rem;margin:.2rem 0}.meta.seal code{font-size:.75rem;word-break:break-all;color:var(--fg)}.scheme{font-size:.75rem;color:var(--muted)}.findings{list-style:none;padding:0;margin:.4rem 0}.finding{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.8rem 1rem;margin:.6rem 0}.none{color:var(--muted);font-size:.85rem;padding:.2rem 0}.sev{font-weight:700;font-size:.75rem;letter-spacing:.05em}.sev.crit{color:var(--crit)}.sev.high{color:var(--high)}.sev.med{color:var(--med)}.sev.low{color:var(--low)}.sev.ok{color:var(--ok)}.sev.unm{color:var(--unm)}.sev.na{color:var(--na)}.control{font-weight:700}.tri{color:var(--muted);font-size:.85rem}.chain{margin:.5rem 0 0;font-size:.9rem}.chain dt{float:left;clear:left;width:7.5rem;color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;padding-top:.15rem}.chain dd{margin:0 0 .35rem 8rem}.scores{margin:1.2rem 0;font-family:"SF Mono",Menlo,Consolas,monospace;font-size:.9rem}.scores dt{color:var(--gold);margin-top:.4rem}.scores dd{margin:0}.note{color:var(--muted);font-size:.8rem;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}.rederive{margin:1rem 0;border:1px solid var(--line);border-radius:8px;padding:.6rem 1rem;background:var(--card)}.rederive summary{cursor:pointer;color:var(--gold);font-family:"SF Mono",Menlo,Consolas,monospace;font-size:.9rem}.rederive pre{font-size:.8rem;overflow-x:auto;margin:.6rem 0}"##;

#[cfg(test)]
mod tests {
    use super::*;
    use resolution_scope_engine::analysis::{
        CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
        DmarcDisposition, DnssecDisposition, MtaStsDisposition, SpfDisposition, TlsRptDisposition,
        TlsaZone,
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
        let tls_rpt = TlsRptDisposition::RecordAbsent;
        let csync = CsyncDisposition::RecordAbsent;
        ScoredAnalysis {
            domain: domain.to_string(),
            session_id: 0,
            timestamp_local: 1_787_507_533,
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
            tls_rpt: tls_rpt.chain(),
            tls_rpt_disposition: tls_rpt,
            csync: csync.chain(),
            csync_disposition: csync,
        }
    }

    /// A fixture with every tier populated: one N/A (DANE NoMail), one
    /// unmeasured (DKIM NotProbed), findings and holdings.
    fn fixture_all_tiers(domain: &str) -> ScoredAnalysis {
        let mut a = fixture(domain);
        a.dane_disposition = DaneDisposition::NoMail;
        a.dane = a.dane_disposition.chain();
        a.tlsa_zone = TlsaZone::NoMxHost;
        a
    }

    // ── every surface carries the same truth ─────────────────────────

    #[test]
    fn all_surfaces_carry_same_measured_labels() {
        let a = fixture("example.test");
        let model = truth_chain(&a);

        let report = render_report(std::slice::from_ref(&a), Audience::BlueTeam);
        let summary = render_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        let text = render_text_report(std::slice::from_ref(&a));
        let html = render_html_page(&[a], Audience::BlueTeam);

        for rep in &model {
            for (name, out) in [("report", &report), ("summary", &summary), ("text", &text)] {
                assert!(
                    out.contains(rep.measured),
                    "{name} missing measured for {:?}",
                    rep.control
                );
            }
            assert!(
                html.contains(&esc(rep.measured)),
                "html missing measured for {:?}",
                rep.control
            );
        }
    }

    #[test]
    fn audience_flip_changes_consequence_on_report_summary_and_html() {
        let a = fixture("example.test");
        let model = truth_chain(&a);
        let rep = model
            .iter()
            .find(|r| r.consequence(Audience::BlueTeam) != r.consequence(Audience::RedTeam))
            .expect("fixture has a disposition with distinct framings");

        for render in [render_report, render_summary] {
            let blue = render(std::slice::from_ref(&a), Audience::BlueTeam);
            let red = render(std::slice::from_ref(&a), Audience::RedTeam);
            assert!(blue.contains(rep.consequence(Audience::BlueTeam)));
            assert!(!blue.contains(rep.consequence(Audience::RedTeam)));
            assert!(red.contains(rep.consequence(Audience::RedTeam)));
            assert!(!red.contains(rep.consequence(Audience::BlueTeam)));
            // And the surface SAYS which framing it is in.
            assert!(blue.contains("framing: blue"));
            assert!(red.contains("framing: red"));
        }
        let html_blue = render_html_page(std::slice::from_ref(&a), Audience::BlueTeam);
        let html_red = render_html_page(&[a], Audience::RedTeam);
        assert!(html_blue.contains(&esc(rep.consequence(Audience::BlueTeam))));
        assert!(!html_blue.contains(&esc(rep.consequence(Audience::RedTeam))));
        assert!(html_red.contains(&esc(rep.consequence(Audience::RedTeam))));
        assert!(!html_red.contains(&esc(rep.consequence(Audience::BlueTeam))));
    }

    #[test]
    fn score_line_consistent_across_surfaces() {
        let a = fixture("example.test");
        let t = Tally::of(&truth_chain(&a));
        let score_str = format!("{}/{}", t.present, t.denominator());
        assert!(render_report(std::slice::from_ref(&a), Audience::BlueTeam).contains(&score_str));
        assert!(render_summary(std::slice::from_ref(&a), Audience::BlueTeam).contains(&score_str));
        assert!(render_text_report(std::slice::from_ref(&a)).contains(&score_str));
        assert!(render_html_page(&[a], Audience::BlueTeam).contains(&score_str));
    }

    #[test]
    fn both_scores_render_together_with_their_notes_on_every_surface() {
        // The NIST-CSF rule from the ruling: the risk-weighted number is shown
        // BESIDE coverage, never instead of it, carries its scoring version,
        // and every surface explains both in the same words.
        let a = fixture("example.com");
        let tag = format!("scoring v{SCORING_VERSION}");
        for render in [render_report, render_summary] {
            let out = render(std::slice::from_ref(&a), Audience::BlueTeam);
            assert!(out.contains("Coverage Score :") && out.contains(COVERAGE_NOTE));
            assert!(out.contains("Risk-Weighted  :") && out.contains(&tag));
            assert!(out.contains(RISK_WEIGHTED_NOTE) && out.contains(EXCLUDED_NOTE));
        }
        let html = render_html_page(&[a], Audience::BlueTeam);
        assert!(html.contains("Coverage Score</dt>") && html.contains(&esc(COVERAGE_NOTE)));
        assert!(html.contains("Risk-Weighted</dt>") && html.contains(&tag));
        assert!(html.contains(&esc(RISK_WEIGHTED_NOTE)) && html.contains(&esc(EXCLUDED_NOTE)));
    }

    // ── the seal reaches every surface ───────────────────────────────

    #[test]
    fn seal_and_conditions_on_report_summary_html_and_json() {
        let a = fixture("example.test");
        let obs = Observation::of(&a);
        let full = seal(&a);
        assert_eq!(obs.seal, full);

        let report = render_report(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(report.contains(&full), "report carries the full seal");
        assert!(report.contains(SEAL_SCHEME));
        assert!(report.contains(&format!("engine {}", engine_version())));
        assert!(report.contains("resolver default"));
        assert!(report.contains("2026-08-23 17:52:13 UTC"));
        assert!(
            report.contains(&canonical_input(&a, &engine_version())),
            "report prints the seal's exact preimage"
        );
        assert!(report.contains(SEAL_NOTE));

        let summary = render_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(
            summary.contains(&full[..16]),
            "summary carries the seal prefix"
        );
        assert!(!summary.contains(&full), "summary is compact — prefix only");
        assert!(
            summary.contains("--format report"),
            "summary points at the full form"
        );

        let html = render_html_page(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(html.contains(&full));
        assert!(html.contains(&esc(&canonical_input(&a, &engine_version()))));
        assert!(html.contains(&esc(SEAL_NOTE)));
        assert!(html.contains("<title>example.test \u{2014} Resolution Scope</title>"));

        let json = render_json(std::slice::from_ref(&a));
        let v: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
        assert_eq!(v["seal"], full);
        assert_eq!(v["seal_scheme"], SEAL_SCHEME);
        assert_eq!(v["engine_version"], engine_version());
        assert_eq!(v["session_hex"], "0000000000000000");
        assert_eq!(v["timestamp_utc"], "2026-08-23T17:52:13Z");
    }

    #[test]
    fn report_declares_v4_seal_boundary_for_staged_controls() {
        let a = fixture("example.test");
        let report = render_report(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(
            report.contains("v4 seal binds the original 8 controls")
                || report.contains("v4 seal binds the founding eight controls"),
            "report must disclose that TLS-RPT/CSYNC are staged beside, not inside, the v4 seal"
        );
        assert!(report.contains("TLS-RPT") && report.contains("CSYNC"));
        assert!(
            report.contains("not v4 seal inputs") || report.contains("not inside the v4 seal"),
            "must name the unsealed boundary, not merely say controls exist"
        );
    }

    #[test]
    fn seal_vocabulary_is_tamper_evidence_only() {
        // seal.rs: the seal proves the verdict is the one that was sealed —
        // never that a measurement happened. The retired words must not
        // reappear on any cli surface (site/verify.sh forbids them too).
        let a = fixture_all_tiers("example.test");
        let v = fixture("example.test");
        let row = StoredScan {
            id: 1,
            domain: "example.test".into(),
            engine_version: "0.1.0".into(),
            seal: seal_versioned(&v, "0.1.0"),
            seal_scheme: SEAL_SCHEME.into(),
            verdict: v,
        };
        let everything = [
            render_report(std::slice::from_ref(&a), Audience::BlueTeam),
            render_summary(std::slice::from_ref(&a), Audience::RedTeam),
            render_html_page(std::slice::from_ref(&a), Audience::BlueTeam),
            render_json(std::slice::from_ref(&a)),
            render_history("example.test", &[row]),
        ]
        .join("\n")
        .to_lowercase();
        for forbidden in ["provenance", "proof of measurement", "proof-of-measurement"] {
            assert!(
                !everything.contains(forbidden),
                "retired seal vocabulary: {forbidden}"
            );
        }
    }

    // ── tiers ────────────────────────────────────────────────────────

    #[test]
    fn tiers_group_by_engine_severity_and_keep_worst_first() {
        let a = fixture_all_tiers("example.test");
        let model = truth_chain(&a);
        let groups = tiers(&model);
        assert_eq!(groups[0].0, TIER_FINDINGS);
        assert_eq!(groups[1].0, TIER_ADVISORY);
        assert_eq!(groups[4].0, TIER_NOT_APPLICABLE);
        let total: usize = groups.iter().map(|(_, r)| r.len()).sum();
        assert_eq!(total, 10, "every control lands in exactly one tier");
        for (tier, rows) in &groups {
            for r in rows {
                assert_eq!(tier_of(r.severity), *tier);
            }
            // worst-first inside the tier
            for w in rows.windows(2) {
                assert!(w[0].severity <= w[1].severity);
            }
        }
        assert!(groups[4].1.iter().all(|r| r.tri == TriState::NotApplicable));
        assert!(groups[3].1.iter().all(|r| r.tri == TriState::Indet));
    }

    #[test]
    fn every_tier_heading_appears_and_empty_tiers_say_none() {
        let a = fixture("example.test"); // no N/A row in this fixture
        let report = render_report(std::slice::from_ref(&a), Audience::BlueTeam);
        for tier in [
            TIER_FINDINGS,
            TIER_ADVISORY,
            TIER_HOLDING,
            TIER_UNMEASURED,
            TIER_NOT_APPLICABLE,
        ] {
            assert!(
                report.contains(&format!("\n{tier}\n")),
                "missing tier {tier}"
            );
        }
        let na_idx = report.find(TIER_NOT_APPLICABLE).unwrap();
        assert!(report[na_idx..].contains("(none)"));
        let html = render_html_page(&[a], Audience::BlueTeam);
        assert!(html.contains("<li class=\"none\">none</li>"));
    }

    /// The contract of the ADVISORY tier (Option 3, placement-only): its
    /// membership is the engine's Low census and nothing else. Selection is
    /// keyed on severity — never on control names — so a host shipping a
    /// missing capability moves the row out on the next scan with zero
    /// stored bits. The word FAIL, the severity, and both scores are
    /// untouched by placement (RULING_cds_cdnskey_20260821: relabelling was
    /// rejected; placement is display geometry).
    #[test]
    fn advisory_tier_is_exactly_the_low_census() {
        // Severity → tier, exhaustively.
        for (sev, tier) in [
            (Severity::Critical, TIER_FINDINGS),
            (Severity::High, TIER_FINDINGS),
            (Severity::Medium, TIER_FINDINGS),
            (Severity::Low, TIER_ADVISORY),
            (Severity::Ok, TIER_HOLDING),
            (Severity::Unmeasured, TIER_UNMEASURED),
            (Severity::NotApplicable, TIER_NOT_APPLICABLE),
        ] {
            assert_eq!(tier_of(sev), tier, "{sev:?}");
        }

        // The census rows land in ADVISORY: CDS NotPublished and, on a
        // domain that has them, CAA NotConfigured and DANE NotConfigured /
        // NoMx — every Low arm in the 48-row table is one of these four.
        let mut a = fixture("example.test"); // CDS NotPublished is Low
        a.caa_disposition = CaaDisposition::NotConfigured;
        a.caa = a.caa_disposition.chain();
        a.dane_disposition = DaneDisposition::NotConfigured;
        a.dane = a.dane_disposition.chain();
        a.tlsa_zone = TlsaZone::SameZone;
        let model = truth_chain(&a);
        let groups = tiers(&model);
        let advisory: Vec<_> = groups[1].1.iter().map(|r| r.control.name()).collect();
        for name in ["CDS/CDNSKEY", "CAA", "DANE"] {
            assert!(advisory.contains(&name), "{name} missing from ADVISORY");
        }
        // NoMx is the fourth census arm — same tier.
        a.dane_disposition = DaneDisposition::NoMx;
        a.dane = a.dane_disposition.chain();
        let model = truth_chain(&a);
        let groups = tiers(&model);
        assert!(groups[1].1.iter().any(|r| r.control.name() == "DANE"));

        // FINDINGS never holds a Low row; ADVISORY holds nothing else.
        for (tier, rows) in &groups {
            for r in rows {
                if *tier == TIER_FINDINGS {
                    assert_ne!(r.severity, Severity::Low);
                }
                if *tier == TIER_ADVISORY {
                    assert_eq!(r.severity, Severity::Low);
                }
            }
        }
    }

    // ── attribution and layer order ──────────────────────────────────

    #[test]
    fn dane_attribution_renders_before_the_consequence_on_every_surface() {
        // ForeignZone: the attribution must appear as its OWN line, directly
        // under the measured state and BEFORE the consequence — a reader must
        // know whose zone is meant before reading what to do about it.
        let a = fixture("example.com");
        let attr = "MX host lives outside this domain's own zone";
        for render in [render_report, render_summary] {
            let out = render(std::slice::from_ref(&a), Audience::BlueTeam);
            let i_attr = out.find(attr).expect("attribution present");
            let dane_row = out.find("DANE").unwrap();
            let i_cons = out[i_attr..].find("\u{2192}").unwrap() + i_attr;
            assert!(
                dane_row < i_attr && i_attr < i_cons,
                "measured → attribution → consequence"
            );
            assert!(out.contains(&format!("\u{21b3} {attr}")));
            assert!(
                !out.contains("DANE         FAIL MX host lives"),
                "never a measured suffix"
            );
        }
        let html = render_html_page(&[a], Audience::BlueTeam);
        let i_attr = html.find("<dt>attribution</dt>").unwrap();
        let i_rfc = html[i_attr..].find("<dt>rfc</dt>").unwrap();
        let i_cons = html[i_attr..].find("<dt>consequence</dt>").unwrap();
        assert!(
            i_rfc < i_cons,
            "attribution precedes rfc and consequence in the HTML chain"
        );
    }

    #[test]
    fn dane_attribution_absent_for_same_zone() {
        let mut a = fixture("example.com");
        a.tlsa_zone = TlsaZone::SameZone;
        assert!(!render_report(std::slice::from_ref(&a), Audience::BlueTeam).contains("\u{21b3}"));
        assert!(!render_html_page(&[a], Audience::BlueTeam).contains("<dt>attribution</dt>"));
    }

    #[test]
    fn report_carries_rfc_layer_and_summary_does_not() {
        let a = fixture("example.test");
        let model = truth_chain(&a);
        let report = render_report(std::slice::from_ref(&a), Audience::BlueTeam);
        let summary = render_summary(std::slice::from_ref(&a), Audience::BlueTeam);
        for rep in &model {
            assert!(report.contains(rep.rfc_requirement));
            assert!(!summary.contains(rep.rfc_requirement));
        }
    }

    #[test]
    fn domain_is_escaped() {
        let a = fixture("<script>alert(1)</script>.test");
        let page = render_html_page(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("&lt;script&gt;alert"));
    }

    #[test]
    fn no_internal_jargon_on_user_surfaces() {
        let a = fixture("example.test");
        let all = [
            render_report(std::slice::from_ref(&a), Audience::BlueTeam),
            render_summary(std::slice::from_ref(&a), Audience::BlueTeam),
            render_html_page(&[a], Audience::BlueTeam),
        ]
        .join("\n");
        assert!(!all.to_lowercase().contains("flipper"));
    }

    // ── JSON ─────────────────────────────────────────────────────────

    #[test]
    fn json_carries_disposition_and_tri_state() {
        let a = fixture("example.test");
        let out = render_json(std::slice::from_ref(&a));
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["domain"], "example.test");
        assert_eq!(v["dnssec_disposition"], "Unsigned");
        assert_eq!(v["dnssec_chain"], "Absent");
    }

    /// The Arm-1 join contract: ALL EIGHT disposition keys and ALL EIGHT
    /// tri-state keys must be present by their exact field names AND their
    /// original types. The additions (seal, scores) are siblings; a renamed
    /// or re-typed verdict key is a silent broken join, not a test failure —
    /// so the names are the contract, asserted here in full.
    #[test]
    fn json_carries_all_sixteen_verdict_keys_unchanged_plus_seal_and_scores() {
        let a = fixture("example.test");
        let out = render_json(std::slice::from_ref(&a));
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let raw: serde_json::Value = serde_json::to_value(&a).unwrap();

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
            assert!(
                v[key].is_string(),
                "disposition {key} is not a string enum name"
            );
            assert_eq!(v[key], raw[key], "{key} altered");
        }
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
            let val = v[key]
                .as_str()
                .unwrap_or_else(|| panic!("tri-state {key} is not a string"));
            assert!(tri_states.contains(&val), "tri-state {key} = {val:?}");
            assert_eq!(v[key], raw[key], "{key} altered");
        }
        // Every original key survives with its original value and type.
        for (k, val) in raw.as_object().unwrap() {
            assert_eq!(&v[k], val, "original key {k} altered");
        }
        // The additions.
        let t = Tally::of(&truth_chain(&a));
        assert_eq!(v["coverage"]["present"], t.present);
        assert_eq!(v["coverage"]["denominator"], t.denominator());
        assert_eq!(v["coverage"]["percent"], t.percent());
        assert_eq!(v["coverage"]["unmeasured"], t.unmeasured);
        assert_eq!(v["coverage"]["not_applicable"], t.not_applicable);
        assert_eq!(
            v["risk_weighted"],
            risk_weighted_score(&truth_chain(&a)).unwrap()
        );
        assert_eq!(v["scoring_version"], SCORING_VERSION);
    }

    #[test]
    fn json_risk_weighted_is_null_when_nothing_measured() {
        let mut a = fixture("x.test");
        a.dnssec_disposition = DnssecDisposition::Unreachable;
        a.spf_disposition = SpfDisposition::TransientError;
        a.dkim_disposition = DkimDisposition::NotProbed;
        a.dmarc_disposition = DmarcDisposition::TransientError;
        a.dane_disposition = DaneDisposition::TransientError;
        a.mta_sts_disposition = MtaStsDisposition::TransientError;
        a.caa_disposition = CaaDisposition::TransientError;
        a.cds_disposition = CdsDisposition::TransientError;
        a.tls_rpt_disposition = TlsRptDisposition::TransientError;
        a.csync_disposition = CsyncDisposition::TransientError;
        let v: serde_json::Value =
            serde_json::from_str(render_json(std::slice::from_ref(&a)).trim()).unwrap();
        assert!(v["risk_weighted"].is_null(), "never a fake number");
        assert_eq!(v["coverage"]["denominator"], 0);
    }

    // ── time ─────────────────────────────────────────────────────────

    #[test]
    fn rfc3339_is_the_same_instant_in_machine_form() {
        assert_eq!(rfc3339_utc(1_787_507_533), "2026-08-23T17:52:13Z");
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn report_header_carries_the_session() {
        let a = fixture("example.test");
        let report = render_report(std::slice::from_ref(&a), Audience::BlueTeam);
        assert!(report.contains("session 0000000000000000"));
    }

    #[test]
    fn iso_utc_matches_known_instants() {
        assert_eq!(iso_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(iso_utc(951_782_400), "2000-02-29 00:00:00 UTC"); // leap day
        assert_eq!(iso_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(iso_utc(1_787_507_533), "2026-08-23 17:52:13 UTC");
        assert_eq!(iso_utc(4_102_444_799), "2099-12-31 23:59:59 UTC");
    }

    // ── Sealed history ───────────────────────────────────────────────

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

    #[test]
    fn history_seal_check_three_states() {
        let v = fixture("example.test");
        let good = seal_versioned(&v, "0.1.0");
        assert_eq!(
            seal_check_label(&stored("example.test", SEAL_SCHEME, good.clone())),
            "VERIFIED"
        );
        assert_eq!(
            seal_check_label(&stored("example.test", SEAL_SCHEME, "deadbeef".repeat(64))),
            "MISMATCH"
        );
        assert_eq!(
            seal_check_label(&stored(
                "example.test",
                "resolution-scope-sha3-512-v3",
                good
            )),
            "UNVERIFIABLE (scheme)"
        );
    }

    /// The realistic attack: rewrite the stored VERDICT behind an intact seal.
    #[test]
    fn verdict_tamper_reads_mismatch() {
        let original = fixture("example.test");
        let good_seal = seal_versioned(&original, "0.1.0");
        let mut altered = original.clone();
        altered.dnssec_chain = TriState::Present; // a real change, not a no-op
        let row = StoredScan {
            id: 1,
            domain: "example.test".to_string(),
            engine_version: "0.1.0".to_string(),
            seal: good_seal,
            seal_scheme: SEAL_SCHEME.to_string(),
            verdict: altered,
        };
        assert_eq!(seal_check_label(&row), "MISMATCH");
    }

    #[test]
    fn history_renders_time_seal_scores_and_check() {
        let v = fixture("example.test");
        let good = seal_versioned(&v, "0.1.0");
        let t = Tally::of(&truth_chain(&v));
        let out = render_history(
            "example.test",
            &[stored("example.test", SEAL_SCHEME, good.clone())],
        );
        assert!(out.contains("example.test"));
        assert!(out.contains("VERIFIED"));
        assert!(out.contains(&good[..16]));
        assert!(out.contains(&format!("{}/{}", t.present, t.denominator())));
        assert!(out.contains(&format!("({:>3}%)", t.percent())));
        assert!(
            out.contains("2026-08-23 17:52:13 UTC"),
            "when the scan ran, readable"
        );
        assert!(out.contains(&format!("scoring v{SCORING_VERSION}")));
        assert!(
            !out.contains("measured_at"),
            "no legend for a column that is not printed"
        );
    }

    #[test]
    fn history_empty_is_explicit() {
        let out = render_history("never-scanned.test", &[]);
        assert!(out.contains("no stored scans"));
    }
}
