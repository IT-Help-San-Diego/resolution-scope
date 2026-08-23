//! Resolution Scope TUI — the interactive dashboard.
//!
//! Two framings, toggled with `m` — palette AND consequence framing together,
//! and the header says which is live:
//! - **blue** (defend): regular science/engineering report, blue-on-charcoal
//! - **red** (assess): scotopic red-on-charcoal, consequences framed for an
//!   authorised assessor
//!
//! The dashboard paints BEFORE the first measurement returns and shows a real
//! measuring state — what is being measured, from where, elapsed time — then
//! the truth-chain the moment the engine delivers it. No fake progress: the
//! engine measures the eight controls inside one call, so until it exposes
//! per-control events the honest state is "measuring … {elapsed}s".
//!
//! Keyboard: `1`-`7` jump between tabs (7 = the seal). `q` / Ctrl-C quit.
//! `m` flips framing. `j`/`k` or `↑`/`↓` select (summary) or scroll (detail).
//! `Enter` opens the selected control; `Esc`/`Backspace` return to the summary.
//! `r` re-measures. `Tab`/`Shift-Tab` cycle domains. `d` adds a domain.
//!
//! The TUI owns STYLING ONLY. Verdict meaning — labels, severities,
//! consequences, tally, seal — comes from the engine (ARCHITECTURE.md §8).
//! A match on a disposition enum in this file is a contract violation.

use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::{Frame, Terminal};
use tokio::task::JoinHandle;

use crate::input::canonical_domain;
use crate::render::{
    tier_subtitle, tiers, weighted_label, Observation, COVERAGE_NOTE, EXCLUDED_NOTE,
    RISK_WEIGHTED_NOTE, SEAL_NOTE,
};
use resolution_scope_engine::analysis::analyse_domain_with_selectors;
use resolution_scope_engine::seal::canonical_input;
use resolution_scope_engine::truth_chain::{
    by_severity, truth_chain, Audience, ControlId, ControlReport, Severity, Tally,
};
use resolution_scope_engine::ScoredAnalysis;
use resolution_scope_engine::TriState;

use hickory_resolver::TokioResolver;

// ── palette ────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Palette {
    bg: Color,
    fg: Color,
    accent: Color,
    warn: Color,
    fail: Color,
    pass: Color,
    muted: Color,
    border: Color,
    highlight: Color,
    header_bg: Color,
}

impl Palette {
    // Both palettes use Color::Indexed (256-color ANSI indices) rather than
    // Color::Rgb (24-bit truecolor). Rationale: the red/assess mode is
    // DESIGNED to run on stripped headless terminals (fbterm, raw tty), and
    // fbterm is 256-color only — truecolor RGB sequences get misparsed into
    // magenta/cyan garbage there. Indexed colors render identically on every
    // terminal (256-color AND truecolor), so the palette is deterministic
    // across the whole "truecolor → 256 → 16-color" downgrade ladder. This is
    // the same "one look everywhere" doctrine as the single truth-chain.
    const BLUE: Self = Self {
        bg: Color::Indexed(233),        // #121212 near-black
        fg: Color::Indexed(252),        // #d0d0d0 light grey
        accent: Color::Indexed(33),     // #0087ff blue
        warn: Color::Indexed(214),      // #ffaf00 amber
        fail: Color::Indexed(203),      // #ff5f5f salmon red
        pass: Color::Indexed(71),       // #5faf5f green
        muted: Color::Indexed(244),     // #808080 grey
        border: Color::Indexed(238),    // #444444
        highlight: Color::Indexed(235), // #262626
        header_bg: Color::Indexed(234), // #1c1c1c
    };
    const RED: Self = Self {
        bg: Color::Indexed(232),        // #080808 essentially black
        fg: Color::Indexed(180),        // #d7af87 warm tan (scotopic-friendly)
        accent: Color::Indexed(160),    // #d70000 deep red (title/chrome)
        warn: Color::Indexed(208),      // #ff8700 orange (warnings)
        fail: Color::Indexed(196),      // #ff0000 bright red (failures POP)
        pass: Color::Indexed(28),       // #008700 dim forest green (scotopic)
        muted: Color::Indexed(240),     // #585858 dim grey
        border: Color::Indexed(52),     // #5f0000 dark red
        highlight: Color::Indexed(235), // #262626
        header_bg: Color::Indexed(233), // #121212
    };

    fn for_audience(a: Audience) -> Palette {
        match a {
            Audience::BlueTeam => Palette::BLUE,
            Audience::RedTeam => Palette::RED,
        }
    }
}

// ── navigation tabs ────────────────────────────────────────────────

const TAB_LABELS: &[&str] = &[
    "1:Summary",
    "2:DNSSEC",
    "3:DANE",
    "4:SPF·DKIM·DMARC",
    "5:MTA-STS",
    "6:CAA/CDS",
    "7:Seal",
];
const TAB_SUMMARY: usize = 0;
const TAB_SEAL: usize = 6;

/// Which detail tab shows a given control (Enter on the summary jumps there).
fn tab_for_control(c: ControlId) -> usize {
    match c {
        ControlId::Dnssec => 1,
        ControlId::Dane => 2,
        ControlId::Spf | ControlId::Dkim | ControlId::Dmarc => 3,
        ControlId::MtaSts => 4,
        ControlId::Caa | ControlId::Cds => 5,
    }
}

fn controls_for_tab(tab: usize) -> (&'static str, &'static [ControlId]) {
    match tab {
        1 => (
            "\u{2550}\u{2550} DNSSEC \u{2550}\u{2550}",
            &[ControlId::Dnssec],
        ),
        2 => (
            "\u{2550}\u{2550} DANE (SMTP TLSA) \u{2550}\u{2550}",
            &[ControlId::Dane],
        ),
        3 => (
            "\u{2550}\u{2550} SPF \u{00b7} DKIM \u{00b7} DMARC \u{2550}\u{2550}",
            &[ControlId::Spf, ControlId::Dkim, ControlId::Dmarc],
        ),
        4 => (
            "\u{2550}\u{2550} MTA-STS \u{2550}\u{2550}",
            &[ControlId::MtaSts],
        ),
        5 => (
            "\u{2550}\u{2550} CAA / CDS \u{2550}\u{2550}",
            &[ControlId::Caa, ControlId::Cds],
        ),
        _ => ("\u{2014}", &[]),
    }
}

// ── text layout helpers ────────────────────────────────────────────

/// Word-wrap `text` to `width` columns with a hanging indent: the first line
/// starts with `prefix`, continuation lines are indented to the prefix's
/// width. Pure layout — the fix for consequence sentences wrapping back to
/// column 0 under an indented list.
/// Word-wrap `text` into chunks of at most `avail` columns. A token wider
/// than `avail` (a 128-hex seal) is split into width-sized pieces rather
/// than clipped by the terminal. Always returns at least one chunk.
fn wrap_words(text: &str, avail: usize) -> Vec<String> {
    let avail = avail.max(8);
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let pieces: Vec<String> = if word.chars().count() > avail {
            word.chars()
                .collect::<Vec<_>>()
                .chunks(avail)
                .map(|c| c.iter().collect())
                .collect()
        } else {
            vec![word.to_string()]
        };
        for piece in pieces {
            let wlen = piece.chars().count();
            let clen = current.chars().count();
            if clen > 0 && clen + 1 + wlen > avail {
                chunks.push(std::mem::take(&mut current));
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(&piece);
        }
    }
    if !current.is_empty() || chunks.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn wrap_indent(
    prefix: &str,
    text: &str,
    width: usize,
    prefix_style: Style,
    text_style: Style,
) -> Vec<Line<'static>> {
    let indent = prefix.chars().count();
    let avail = width.saturating_sub(indent);
    wrap_words(text, avail)
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let lead = if i == 0 {
                Span::styled(prefix.to_string(), prefix_style)
            } else {
                Span::styled(" ".repeat(indent), prefix_style)
            };
            Line::from(vec![lead, Span::styled(chunk, text_style)])
        })
        .collect()
}

fn state_icon(s: TriState, pal: Palette) -> (&'static str, Color) {
    match s {
        TriState::Present => ("PASS", pal.pass),
        TriState::Absent => ("FAIL", pal.fail),
        TriState::Indet => (" ?  ", pal.warn),
        TriState::NotApplicable => ("N/A ", pal.muted),
    }
}

fn severity_style(s: Severity, pal: Palette) -> Style {
    match s {
        Severity::Critical => Style::default().fg(pal.fail).add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(pal.fail),
        Severity::Medium => Style::default().fg(pal.warn),
        Severity::Low => Style::default().fg(pal.fg),
        Severity::Ok => Style::default().fg(pal.pass),
        Severity::Unmeasured | Severity::NotApplicable => Style::default().fg(pal.muted),
    }
}

fn report_for(model: &[ControlReport; 8], c: ControlId) -> &ControlReport {
    model
        .iter()
        .find(|r| r.control == c)
        .expect("truth_chain always carries all eight controls")
}

// ── section renderers ──────────────────────────────────────────────

/// Summary: every control in its tier, worst first, with the selection
/// cursor. Tier and order come from the model; the scores from the shared
/// Tally; the selected row expands to attribution + consequence.
/// Columns taken by a summary row before its measured label: cursor(2) +
/// severity(10) + " " + name(12) + " " + glyph(4) + " " + " ".
const ROW_PREFIX: usize = 32;

fn render_summary(
    model: &[ControlReport; 8],
    pal: Palette,
    audience: Audience,
    selected: usize,
    width: usize,
) -> (Vec<Line<'static>>, std::ops::Range<usize>) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut sel_range = 0..0;
    let ordered = by_severity(model);
    let mut idx = 0usize;
    for (tier, rows) in tiers(model) {
        lines.push(Line::from(Span::styled(
            format!("\u{2550}\u{2550} {tier} \u{2550}\u{2550}"),
            Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
        )));
        if let Some(sub) = tier_subtitle(tier) {
            lines.push(Line::from(Span::styled(
                format!("  {sub}"),
                Style::default().fg(pal.muted),
            )));
        }
        if rows.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (none)".to_string(),
                Style::default().fg(pal.muted),
            )));
        }
        for rep in &rows {
            // `idx` walks the by_severity order, which is exactly the tier
            // concatenation — so the cursor index matches `ordered`.
            debug_assert_eq!(ordered[idx].control, rep.control);
            let is_sel = idx == selected;
            let cursor = if is_sel { "\u{25b8} " } else { "  " };
            let row_bg = if is_sel {
                Style::default().bg(pal.highlight)
            } else {
                Style::default()
            };
            let (icon, icon_color) = state_icon(rep.tri, pal);
            let row_start = lines.len();
            // The measured label wraps under itself (hanging indent at the
            // row prefix) instead of clipping at the terminal edge.
            let mut chunks = wrap_words(rep.measured, width.saturating_sub(ROW_PREFIX)).into_iter();
            let first_chunk = chunks.next().unwrap_or_default();
            lines.push(Line::from(vec![
                Span::styled(cursor.to_string(), row_bg.fg(pal.accent)),
                Span::styled(
                    format!("{:<10}", rep.severity.label()),
                    severity_style(rep.severity, pal).patch(row_bg),
                ),
                Span::styled(
                    format!(" {:<12}", rep.control.name()),
                    row_bg.fg(pal.fg).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {icon} "),
                    row_bg.fg(icon_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {first_chunk}"), row_bg.fg(pal.muted)),
            ]));
            for chunk in chunks {
                lines.push(Line::from(Span::styled(
                    format!("{}{chunk}", " ".repeat(ROW_PREFIX)),
                    row_bg.fg(pal.muted),
                )));
            }
            if is_sel {
                // Attribution BEFORE the consequence: whose zone, then what
                // to do. Both are engine strings; this is only their order.
                if let Some(attr) = rep.dane_attribution() {
                    lines.extend(wrap_indent(
                        "      \u{21b3} ",
                        attr,
                        width,
                        Style::default().fg(pal.muted),
                        Style::default().fg(pal.muted),
                    ));
                }
                lines.extend(wrap_indent(
                    "      \u{2192} ",
                    rep.consequence(audience),
                    width,
                    Style::default().fg(pal.fg),
                    Style::default().fg(pal.fg),
                ));
                sel_range = row_start..lines.len();
            }
            idx += 1;
        }
        lines.push(Line::from(""));
    }
    let t = Tally::of(model);
    let score_style = Style::default().fg(pal.accent).add_modifier(Modifier::BOLD);
    let note_style = Style::default().fg(pal.muted);
    lines.extend(wrap_indent(
        &format!(
            "  Coverage Score : {}/{} ({}%)  ",
            t.present,
            t.denominator(),
            t.percent()
        ),
        &format!("\u{2014} {COVERAGE_NOTE}"),
        width,
        score_style,
        note_style,
    ));
    // Risk-Weighted beside Coverage — never instead of it (a lone weighted
    // number is what hides which control is weak).
    lines.extend(wrap_indent(
        &format!("  Risk-Weighted  : {}  ", weighted_label(model)),
        &format!("\u{2014} {RISK_WEIGHTED_NOTE}"),
        width,
        Style::default().fg(pal.accent),
        note_style,
    ));
    lines.extend(wrap_indent(
        &format!(
            "  ? (indeterminate): {} \u{00b7} N/A (not applicable): {}  ",
            t.unmeasured, t.not_applicable
        ),
        &format!("\u{2014} {EXCLUDED_NOTE}"),
        width,
        note_style,
        note_style,
    ));
    lines.push(Line::from(""));
    lines.extend(wrap_indent(
        "  ",
        "enter: open the selected control \u{00b7} 7: the seal and how to re-derive it \u{00b7} j/k past the ends scroll",
        width,
        note_style,
        note_style,
    ));
    (lines, sel_range)
}

/// Detail view: the full truth chain for one or more controls — measured
/// state, attribution, RFC requirement, consequence — straight from the model.
fn render_controls(
    title: &'static str,
    model: &[ControlReport; 8],
    controls: &[ControlId],
    pal: Palette,
    audience: Audience,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            title,
            Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    let label = Style::default().fg(pal.accent);
    for c in controls {
        let rep = report_for(model, *c);
        let (icon, icon_color) = state_icon(rep.tri, pal);
        // Same column order as the summary rows: severity, control, glyph.
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<10}", rep.severity.label()),
                severity_style(rep.severity, pal),
            ),
            Span::styled(
                format!(" {:<12}", rep.control.name()),
                Style::default().fg(pal.fg).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {icon}"),
                Style::default().fg(icon_color).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));
        lines.extend(wrap_indent(
            "  measured     ",
            rep.measured,
            width,
            label,
            Style::default().fg(pal.fg),
        ));
        if let Some(attr) = rep.dane_attribution() {
            lines.extend(wrap_indent(
                "  attribution  ",
                attr,
                width,
                label,
                Style::default().fg(pal.muted),
            ));
        }
        lines.extend(wrap_indent(
            "  rfc          ",
            rep.rfc_requirement,
            width,
            label,
            Style::default().fg(pal.muted),
        ));
        lines.extend(wrap_indent(
            "  consequence  ",
            rep.consequence(audience),
            width,
            label,
            Style::default().fg(pal.fg),
        ));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        "  esc: back to summary".to_string(),
        Style::default().fg(pal.muted),
    )));
    lines
}

/// The seal tab: the measurement conditions the seal binds, the seal itself,
/// the exact preimage, and the one honest claim about what it proves.
fn render_seal(a: &ScoredAnalysis, pal: Palette, width: usize) -> Vec<Line<'static>> {
    let obs = Observation::of(a);
    let label = Style::default().fg(pal.accent);
    let value = Style::default().fg(pal.fg);
    let muted = Style::default().fg(pal.muted);
    let mut lines = vec![
        Line::from(Span::styled(
            "\u{2550}\u{2550} Seal \u{2550}\u{2550}",
            Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for (k, v) in [
        ("  domain    ", a.domain.clone()),
        ("  engine    ", obs.engine.clone()),
        ("  resolver  ", obs.resolver.clone()),
        (
            "  measured  ",
            format!("{} (epoch {})", obs.when_utc, obs.epoch),
        ),
        ("  session   ", obs.session_hex.clone()),
        ("  scheme    ", obs.scheme.to_string()),
    ] {
        lines.push(Line::from(vec![
            Span::styled(k, label),
            Span::styled(v, value),
        ]));
    }
    lines.extend(wrap_indent("  seal      ", &obs.seal, width, label, value));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "\u{2500}\u{2500} Re-derive the seal \u{2014} scheme {} \u{2500}\u{2500}",
            obs.scheme
        ),
        label,
    )));
    for l in canonical_input(a, &obs.engine).lines() {
        lines.push(Line::from(Span::styled(format!("  {l}"), value)));
    }
    lines.push(Line::from(Span::styled(
        "\u{2500}".repeat(width.min(58)),
        label,
    )));
    lines.extend(wrap_indent("  ", SEAL_NOTE, width, muted, muted));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  --format report prints this block for copy/paste   esc: back to summary".to_string(),
        muted,
    )));
    lines
}

/// The lines for a tab, plus the line range the view must keep visible
/// (the selected summary row and its expansion; empty on other tabs).
fn section_for_tab(
    tab: usize,
    result: &ScoredAnalysis,
    pal: Palette,
    audience: Audience,
    selected: usize,
    width: usize,
) -> (Vec<Line<'static>>, std::ops::Range<usize>) {
    let model = truth_chain(result);
    match tab {
        TAB_SUMMARY => render_summary(&model, pal, audience, selected, width),
        TAB_SEAL => (render_seal(result, pal, width), 0..0),
        n => {
            let (title, controls) = controls_for_tab(n);
            (
                render_controls(title, &model, controls, pal, audience, width),
                0..0,
            )
        }
    }
}

/// The scroll offset that keeps `keep` visible inside a viewport of
/// `height` rows, starting from the user's own `scroll`. Pure — the
/// follow-the-cursor rule for the summary, unit-pinned.
fn follow_scroll(scroll: u16, keep: &std::ops::Range<usize>, height: usize, total: usize) -> u16 {
    let height = height.max(1);
    let max_scroll = total.saturating_sub(height);
    let mut s = (scroll as usize).min(max_scroll);
    if keep.end > keep.start {
        // Keep the whole selection in view when it fits, else its first line.
        let need_end = keep.end.min(keep.start + height);
        if need_end > s + height {
            s = need_end - height;
        }
        if keep.start < s {
            s = keep.start;
        }
    }
    s.min(max_scroll) as u16
}

// ── app state ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum InputMode {
    Normal,
    Domain,
}

/// The measurement state for the current domain. `Measuring` is a REAL
/// state: the engine call is in flight on the runtime and the elapsed time
/// is measured, not animated.
enum ScanState {
    Idle,
    Measuring {
        domain: String,
        started: Instant,
        handle: JoinHandle<Result<ScoredAnalysis>>,
    },
    Done {
        result: ScoredAnalysis,
        took: Duration,
        at: Instant,
    },
    Failed {
        domain: String,
        error: String,
    },
}

struct App {
    audience: Audience,
    pal: Palette,
    resolver: TokioResolver,
    resolver_identity: &'static str,
    domains: Vec<String>,
    dkim_selector: Vec<String>,
    current_domain: usize,
    scan: ScanState,
    scroll: u16,
    selected_tab: usize,
    selected_control: usize,
    input_mode: InputMode,
    input_buf: String,
    input_error: Option<String>,
}

/// What a key press asks the loop to do, separated from the App mutation so
/// the key table is unit-testable without a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Quit,
    Rescan,
    SwitchDomain,
    Nothing,
}

impl App {
    fn new(
        resolver: TokioResolver,
        resolver_identity: &'static str,
        domains: Vec<String>,
        dkim_selector: Vec<String>,
        audience: Audience,
    ) -> Self {
        Self {
            audience,
            pal: Palette::for_audience(audience),
            resolver,
            resolver_identity,
            domains,
            dkim_selector,
            current_domain: 0,
            scan: ScanState::Idle,
            scroll: 0,
            selected_tab: TAB_SUMMARY,
            selected_control: 0,
            input_mode: InputMode::Normal,
            input_buf: String::new(),
            input_error: None,
        }
    }

    /// The mode flip changes framing (which consequence string renders) and
    /// palette, never facts — both strings come from the shared model.
    fn toggle_audience(&mut self) {
        self.audience = match self.audience {
            Audience::BlueTeam => Audience::RedTeam,
            Audience::RedTeam => Audience::BlueTeam,
        };
        self.pal = Palette::for_audience(self.audience);
    }

    fn current_domain_name(&self) -> &str {
        self.domains
            .get(self.current_domain)
            .map(String::as_str)
            .unwrap_or("\u{2014}")
    }

    /// Launch the measurement on the runtime and return immediately: the
    /// dashboard keeps painting while the engine works. A previous in-flight
    /// measurement is aborted so its verdict can never land under a different
    /// domain's name.
    fn start_scan(&mut self) {
        if let ScanState::Measuring { handle, .. } = &self.scan {
            handle.abort();
        }
        let domain = self.current_domain_name().to_string();
        let resolver = self.resolver.clone();
        let selectors = self.dkim_selector.clone();
        let d = domain.clone();
        let identity = self.resolver_identity;
        let handle = tokio::spawn(async move {
            analyse_domain_with_selectors(&resolver, &d, &selectors, identity).await
        });
        self.scan = ScanState::Measuring {
            domain,
            started: Instant::now(),
            handle,
        };
        self.scroll = 0;
        self.selected_control = 0;
    }

    /// Collect a finished measurement, if any. Called every loop tick.
    async fn poll_scan(&mut self) {
        let finished =
            matches!(&self.scan, ScanState::Measuring { handle, .. } if handle.is_finished());
        if !finished {
            return;
        }
        let state = std::mem::replace(&mut self.scan, ScanState::Idle);
        if let ScanState::Measuring {
            domain,
            started,
            handle,
        } = state
        {
            let took = started.elapsed();
            self.scan = match handle.await {
                Ok(Ok(result)) => ScanState::Done {
                    result,
                    took,
                    at: Instant::now(),
                },
                Ok(Err(e)) => ScanState::Failed {
                    domain,
                    error: e.to_string(),
                },
                Err(e) => ScanState::Failed {
                    domain,
                    error: format!("measurement task failed: {e}"),
                },
            };
        }
    }

    fn current_result(&self) -> Option<&ScoredAnalysis> {
        match &self.scan {
            ScanState::Done { result, .. } => Some(result),
            _ => None,
        }
    }

    /// The control the summary cursor points at, in severity order.
    fn selected_report(&self) -> Option<ControlReport> {
        self.current_result()
            .map(|r| by_severity(&truth_chain(r))[self.selected_control.min(7)])
    }

    fn next_domain(&mut self) {
        self.current_domain = (self.current_domain + 1) % self.domains.len().max(1);
    }

    fn prev_domain(&mut self) {
        self.current_domain =
            (self.current_domain + self.domains.len() - 1) % self.domains.len().max(1);
    }
}

// ── rendering ──────────────────────────────────────────────────────

fn render_ui(f: &mut Frame, app: &App) {
    let p = app.pal;
    f.render_widget(Block::default().style(Style::default().bg(p.bg)), f.area());

    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    render_header(f, main[0], app);
    render_tabs(f, main[1], app);
    render_content(f, main[2], app);
    render_footer(f, main[3], app);
}

fn framing_word(a: Audience) -> &'static str {
    match a {
        Audience::BlueTeam => "BLUE TEAM \u{00b7} defend",
        Audience::RedTeam => "RED TEAM \u{00b7} assess",
    }
}

/// Header help line, wide and narrow. The wide form's own column count is
/// the header's wide/narrow cutover (every glyph in it is single-column, so
/// `chars().count()` IS its display width) — derived, so the string and the
/// threshold cannot drift apart.
const HELP_WIDE: &str =
    "1-7 tabs · ↑/↓ or j/k select · enter open · esc back · m mode · r re-measure · tab next domain · d new domain · q quit";
const HELP_NARROW: &str = "1-7 · j/k · enter · esc · m · r · tab · d · q";

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let muted = Style::default().fg(p.muted);
    // The brand mark is the owl of the family standard — the same glyph in
    // both modes; the palette carries the epistemic state (blue defend /
    // red assess).
    let mark = "\u{1f989}";
    let line1 = Line::from(vec![
        Span::styled(
            format!("{mark} RESOLUTION SCOPE "),
            Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
        ),
        Span::styled("\u{2502} ", muted),
        Span::styled(framing_word(app.audience), Style::default().fg(p.warn)),
        Span::styled(
            format!(
                " \u{2502} domain {}/{} ",
                app.current_domain + 1,
                app.domains.len()
            ),
            muted,
        ),
        Span::styled(
            app.current_domain_name().to_string(),
            Style::default().fg(p.fg).add_modifier(Modifier::BOLD),
        ),
    ]);
    let wide = usize::from(area.width) >= HELP_WIDE.chars().count();
    // Line 2: the measurement conditions — or the live measuring state.
    let line2 = match &app.scan {
        ScanState::Measuring {
            domain, started, ..
        } => Line::from(vec![
            Span::styled(
                format!(
                    "measuring {domain} \u{2014} {} controls via {} (validating) \u{2026} ",
                    ControlId::ALL.len(),
                    app.resolver_identity
                ),
                Style::default().fg(p.warn),
            ),
            Span::styled(
                format!("{:.1}s", started.elapsed().as_secs_f64()),
                Style::default().fg(p.fg),
            ),
        ]),
        ScanState::Done { result, took, .. } => {
            let obs = Observation::of(result);
            // The seal prefix is the point of this line; at narrow widths
            // the labels go, the prefix stays.
            let conditions = if wide {
                format!(
                    "engine {} \u{00b7} resolver {} \u{00b7} {} \u{00b7} measured in {:.1}s \u{00b7} seal ",
                    obs.engine,
                    obs.resolver,
                    obs.when_utc,
                    took.as_secs_f64()
                )
            } else {
                format!(
                    "{} \u{00b7} {} \u{00b7} {} UTC \u{00b7} {:.1}s \u{00b7} seal ",
                    obs.engine,
                    obs.resolver,
                    obs.when_utc.split(' ').nth(1).unwrap_or(""),
                    took.as_secs_f64()
                )
            };
            Line::from(vec![
                Span::styled(conditions, muted),
                Span::styled(
                    format!("{}\u{2026}", obs.seal_prefix()),
                    Style::default().fg(p.fg),
                ),
                Span::styled(" (7)", muted),
            ])
        }
        ScanState::Failed { domain, error } => Line::from(Span::styled(
            format!("could not measure {domain}: {error}  \u{2014}  r: retry"),
            Style::default().fg(p.fail),
        )),
        ScanState::Idle => Line::from(Span::styled(
            "no measurement yet \u{2014} r: measure",
            muted,
        )),
    };
    let line3 = Line::from(Span::styled(
        if wide { HELP_WIDE } else { HELP_NARROW },
        muted,
    ));
    let widget = Paragraph::new(vec![line1, line2, line3]).block(
        Block::default()
            .style(Style::default().bg(p.header_bg))
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(p.border)),
    );
    f.render_widget(widget, area);
}

fn render_tabs(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let titles: Vec<Line> = TAB_LABELS
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let style = if i == app.selected_tab {
                Style::default().fg(p.accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(p.muted)
            };
            Line::from(Span::styled(*t, style))
        })
        .collect();
    // Trailing-space padding + bare divider: the seven labels total 76
    // columns, so the tab bar fits a stock 80-column terminal.
    let tabs = Tabs::new(titles)
        .select(app.selected_tab)
        .style(Style::default().fg(p.muted))
        .highlight_style(Style::default().fg(p.accent))
        .padding("", " ")
        .divider(Span::styled("\u{2502}", Style::default().fg(p.muted)));
    f.render_widget(tabs, area);
}

fn render_content(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let width = area.width as usize;
    let mut scroll = app.scroll;
    let lines: Vec<Line<'static>> = match &app.scan {
        ScanState::Done { result, .. } => {
            let (lines, keep) = section_for_tab(
                app.selected_tab,
                result,
                p,
                app.audience,
                app.selected_control,
                width,
            );
            scroll = follow_scroll(app.scroll, &keep, area.height as usize, lines.len());
            lines
        }
        ScanState::Measuring {
            domain, started, ..
        } => {
            // The honest waiting screen: what is being measured, from where,
            // how long so far. Pressing r again is absorbed (the in-flight
            // measurement is not restarted) — the footer says so. The
            // controls are listed because they ARE the measurement; no
            // per-control state is shown because the engine reports all
            // eight together (per-control events are engine work).
            let muted = Style::default().fg(p.muted);
            let mut v = vec![
                Line::from(Span::styled(
                    format!("\u{2550}\u{2550} MEASURING {domain} \u{2550}\u{2550}"),
                    Style::default().fg(p.warn).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];
            v.extend(wrap_indent(
                "  ",
                &format!(
                    "{:.1}s elapsed \u{2014} one validating resolver ({}); the engine reports all {} controls together when done",
                    started.elapsed().as_secs_f64(),
                    app.resolver_identity,
                    ControlId::ALL.len()
                ),
                width,
                Style::default().fg(p.fg),
                Style::default().fg(p.fg),
            ));
            v.push(Line::from(""));
            v.extend(wrap_indent(
                "  measuring: ",
                &ControlId::ALL
                    .iter()
                    .map(|c| c.name())
                    .collect::<Vec<_>>()
                    .join(" \u{00b7} "),
                width,
                Style::default().fg(p.warn),
                muted,
            ));
            v.push(Line::from(""));
            v.extend(wrap_indent(
                "  ",
                "nothing is shown before it is measured",
                width,
                muted,
                muted,
            ));
            v
        }
        ScanState::Failed { domain, error } => {
            let mut v = vec![Line::from(Span::styled(
                format!("could not measure {domain}"),
                Style::default().fg(p.fail).add_modifier(Modifier::BOLD),
            ))];
            v.extend(wrap_indent(
                "  ",
                error,
                width,
                Style::default().fg(p.fg),
                Style::default().fg(p.fg),
            ));
            v.push(Line::from(""));
            v.push(Line::from(Span::styled(
                "  r: retry   d: another domain   q: quit",
                Style::default().fg(p.muted),
            )));
            v
        }
        ScanState::Idle => vec![Line::from(Span::styled(
            "Press 'r' to measure, or 'd' to add a domain.",
            Style::default().fg(p.muted),
        ))],
    };
    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .style(Style::default().bg(p.bg))
                .borders(Borders::NONE),
        )
        .scroll((scroll, 0));
    f.render_widget(widget, area);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    if app.input_mode == InputMode::Domain {
        let prompt = match &app.input_error {
            Some(e) => format!(
                " Domain: {}\u{2588}   \u{2717} {e}   (enter: measure  esc: cancel)",
                app.input_buf
            ),
            None => format!(
                " Domain: {}\u{2588}   (enter: measure  esc: cancel)",
                app.input_buf
            ),
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                prompt,
                Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
            )))
            .style(Style::default().bg(p.header_bg)),
            area,
        );
        return;
    }
    let status = match &app.scan {
        ScanState::Done { took, at, .. } => format!(
            "measured in {:.1}s, {}s ago  \u{2502}  domain {}/{}  \u{2502}  {}",
            took.as_secs_f64(),
            at.elapsed().as_secs(),
            app.current_domain + 1,
            app.domains.len(),
            TAB_LABELS[app.selected_tab]
        ),
        ScanState::Measuring { started, .. } => format!(
            "measuring \u{2026} {:.1}s  \u{2502}  domain {}/{}  \u{2502}  r again = ignored",
            started.elapsed().as_secs_f64(),
            app.current_domain + 1,
            app.domains.len()
        ),
        ScanState::Failed { .. } => "measurement failed \u{2014} r: retry".to_string(),
        ScanState::Idle => "no measurement yet \u{2014} r: measure".to_string(),
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            status,
            Style::default().fg(p.muted),
        )))
        .style(Style::default().bg(p.header_bg)),
        area,
    );
}

// ── input ──────────────────────────────────────────────────────────

fn handle_input(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> Action {
    match (code, modifiers) {
        (KeyCode::Char('q'), _) => Action::Quit,
        // Raw mode swallows the terminal's own Ctrl-C; the universal exit
        // must still work.
        (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => Action::Quit,
        (KeyCode::Char('m'), _) => {
            app.toggle_audience();
            Action::Nothing
        }
        (KeyCode::Char('r'), _) => {
            // Absorb repeat presses while a measurement is in flight — an
            // impatient r-mash must not abort and restart the scan that is
            // already running.
            if matches!(app.scan, ScanState::Measuring { .. }) {
                Action::Nothing
            } else {
                Action::Rescan
            }
        }
        // Summary tab: j/k moves the finding cursor, and past either end
        // scrolls the page (so the score lines under the last row are
        // reachable on a 24-row terminal). Detail tabs: j/k scrolls.
        (KeyCode::Char('j'), _) | (KeyCode::Down, _) => {
            if app.selected_tab == TAB_SUMMARY && app.selected_control < 7 {
                app.selected_control += 1;
            } else {
                app.scroll = app.scroll.saturating_add(1);
            }
            Action::Nothing
        }
        (KeyCode::Char('k'), _) | (KeyCode::Up, _) => {
            if app.selected_tab == TAB_SUMMARY && app.scroll > 0 {
                app.scroll -= 1;
            } else if app.selected_tab == TAB_SUMMARY {
                app.selected_control = app.selected_control.saturating_sub(1);
            } else {
                app.scroll = app.scroll.saturating_sub(1);
            }
            Action::Nothing
        }
        (KeyCode::PageDown, _) => {
            app.scroll = app.scroll.saturating_add(10);
            Action::Nothing
        }
        (KeyCode::PageUp, _) => {
            app.scroll = app.scroll.saturating_sub(10);
            Action::Nothing
        }
        (KeyCode::Home, _) => {
            app.scroll = 0;
            Action::Nothing
        }
        (KeyCode::End, _) => {
            // follow_scroll clamps to the last page at render time.
            app.scroll = u16::MAX;
            Action::Nothing
        }
        // Enter on the summary opens the selected control's detail tab.
        (KeyCode::Enter, _) => {
            if app.selected_tab == TAB_SUMMARY {
                if let Some(rep) = app.selected_report() {
                    app.selected_tab = tab_for_control(rep.control);
                    app.scroll = 0;
                }
            }
            Action::Nothing
        }
        // Back to the summary from any detail tab.
        (KeyCode::Esc, _) | (KeyCode::Backspace, _) => {
            app.selected_tab = TAB_SUMMARY;
            app.scroll = 0;
            Action::Nothing
        }
        // Tab/Shift-Tab switch domains — but only when there is more than
        // one. On a single-domain session a switch is a no-op: re-measuring
        // the same domain is `r`'s job, and silently restarting the scan
        // reads as the app freezing (found live, 2026-08-23).
        (KeyCode::BackTab, _) => {
            if app.domains.len() > 1 {
                app.prev_domain();
                Action::SwitchDomain
            } else {
                Action::Nothing
            }
        }
        (KeyCode::Tab, _) => {
            if app.domains.len() > 1 {
                app.next_domain();
                Action::SwitchDomain
            } else {
                Action::Nothing
            }
        }
        (KeyCode::Char('d'), _) => {
            app.input_mode = InputMode::Domain;
            app.input_buf.clear();
            app.input_error = None;
            Action::Nothing
        }
        (KeyCode::Char(c), _) if c.is_ascii_digit() => {
            if let Some(n) = c.to_digit(10) {
                if (1..=TAB_LABELS.len() as u32).contains(&n) {
                    app.selected_tab = n as usize - 1;
                    app.scroll = 0;
                }
            }
            Action::Nothing
        }
        _ => Action::Nothing,
    }
}

/// Domain-entry mode. Enter submits through the input boundary (a bad name
/// stays in the prompt with its reason); Esc cancels WITHOUT re-measuring.
fn handle_input_mode(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> Action {
    match (code, modifiers) {
        (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => Action::Quit,
        (KeyCode::Enter, _) => {
            let raw = app.input_buf.trim().to_string();
            if raw.is_empty() {
                app.input_mode = InputMode::Normal;
                app.input_error = None;
                return Action::Nothing;
            }
            match canonical_domain(&raw) {
                Ok(domain) => {
                    app.domains.push(domain);
                    app.current_domain = app.domains.len() - 1;
                    app.input_mode = InputMode::Normal;
                    app.input_buf.clear();
                    app.input_error = None;
                    Action::SwitchDomain
                }
                Err(e) => {
                    app.input_error = Some(e.to_string());
                    Action::Nothing
                }
            }
        }
        (KeyCode::Esc, _) => {
            app.input_mode = InputMode::Normal;
            app.input_buf.clear();
            app.input_error = None;
            Action::Nothing
        }
        (KeyCode::Backspace, _) => {
            app.input_buf.pop();
            app.input_error = None;
            Action::Nothing
        }
        (KeyCode::Char(c), _) => {
            app.input_buf.push(c);
            app.input_error = None;
            Action::Nothing
        }
        _ => Action::Nothing,
    }
}

// ── terminal session ───────────────────────────────────────────────

/// Restores the user's terminal on every exit path — normal, `?` error, or
/// panic. Without this, an error inside the loop left the shell in raw mode
/// on the alternate screen.
struct TerminalSession;

impl TerminalSession {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        io::stdout().execute(EnterAlternateScreen)?;
        Ok(TerminalSession)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
    }
}

// ── entry point (invoked by the `tui` subcommand) ──────────────────

/// Run the interactive dashboard. The resolver and domains are provided by
/// main.rs; this module owns the terminal session (raw mode, alternate
/// screen, event loop) and the renderers above.
pub async fn run(
    resolver: TokioResolver,
    resolver_identity: &'static str,
    domains: Vec<String>,
    dkim_selector: Vec<String>,
    audience: Audience,
) -> Result<()> {
    let mut app = App::new(
        resolver,
        resolver_identity,
        domains,
        dkim_selector,
        audience,
    );
    app.start_scan();

    // A panic on the UI thread must not strand the terminal. A panic inside
    // the measurement task (another thread) surfaces as ScanState::Failed
    // and must NOT tear the terminal down under a live dashboard — hence
    // the thread guard.
    let ui_thread = std::thread::current().id();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == ui_thread {
            let _ = disable_raw_mode();
            let _ = io::stdout().execute(LeaveAlternateScreen);
        }
        default_hook(info);
    }));

    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    loop {
        app.poll_scan().await;
        terminal.draw(|f| render_ui(f, &app))?;

        // Poll, don't block: the elapsed counter and the finished
        // measurement both need the loop to turn without a keypress.
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        let action = if app.input_mode == InputMode::Domain {
            handle_input_mode(&mut app, key.code, key.modifiers)
        } else {
            handle_input(&mut app, key.code, key.modifiers)
        };
        match action {
            Action::Quit => break,
            // Re-measure on 'r' AND on every domain switch — Tab without a
            // rescan rendered the previous domain's verdicts under the new
            // domain's name (adversarial panel, 2026-08-19).
            Action::Rescan | Action::SwitchDomain => app.start_scan(),
            Action::Nothing => {}
        }
    }
    if let ScanState::Measuring { handle, .. } = &app.scan {
        handle.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    fn test_resolver() -> TokioResolver {
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build()
        .expect("resolver builds without network")
    }

    fn app(domains: &[&str]) -> App {
        App::new(
            test_resolver(),
            "test",
            domains.iter().map(|s| s.to_string()).collect(),
            vec![],
            Audience::BlueTeam,
        )
    }

    #[tokio::test]
    async fn j_past_the_last_row_scrolls_and_k_at_the_top_unscrolls() {
        let mut a = app(&["example.com"]);
        for _ in 0..7 {
            handle_input(&mut a, KeyCode::Char('j'), KeyModifiers::NONE);
        }
        assert_eq!(a.selected_control, 7);
        assert_eq!(a.scroll, 0);
        handle_input(&mut a, KeyCode::Char('j'), KeyModifiers::NONE);
        assert_eq!(a.scroll, 1, "past the last row the page scrolls");
        handle_input(&mut a, KeyCode::Char('k'), KeyModifiers::NONE);
        assert_eq!(a.scroll, 0, "k unscrolls before it moves the cursor");
        handle_input(&mut a, KeyCode::Char('k'), KeyModifiers::NONE);
        assert_eq!(a.selected_control, 6);
        handle_input(&mut a, KeyCode::End, KeyModifiers::NONE);
        assert_eq!(a.scroll, u16::MAX, "clamped at render time");
        handle_input(&mut a, KeyCode::Home, KeyModifiers::NONE);
        assert_eq!(a.scroll, 0);
    }

    #[test]
    fn follow_scroll_keeps_the_selection_in_a_short_viewport() {
        // 30 lines, 17-row viewport (80x24 after header/tabs/footer).
        assert_eq!(follow_scroll(0, &(2..4), 17, 30), 0, "already visible");
        assert_eq!(
            follow_scroll(0, &(20..23), 17, 30),
            6,
            "scrolls down just enough"
        );
        assert_eq!(
            follow_scroll(10, &(2..4), 17, 30),
            2,
            "scrolls up to the selection"
        );
        assert_eq!(
            follow_scroll(u16::MAX, &(0..0), 17, 30),
            13,
            "End clamps to the last page"
        );
        assert_eq!(
            follow_scroll(5, &(0..0), 17, 10),
            0,
            "content shorter than the viewport"
        );
        assert_eq!(
            follow_scroll(0, &(20..40), 5, 50),
            20,
            "selection taller than the viewport: its first line at the top"
        );
    }

    #[test]
    fn summary_fits_its_width_and_reports_the_selected_range() {
        use resolution_scope_engine::analysis::{
            CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
            DnssecDisposition, MtaStsDisposition, SpfDisposition, TlsaZone,
        };
        let a = ScoredAnalysis {
            domain: "example.test".into(),
            session_id: 0,
            timestamp_local: 0,
            resolver_identity: "test".into(),
            dnssec_chain: DnssecDisposition::Unsigned.chain(),
            dnssec_disposition: DnssecDisposition::Unsigned,
            spf: SpfDisposition::SoftFail.chain(),
            spf_disposition: SpfDisposition::SoftFail,
            dkim: DkimDisposition::NotProbed.chain(),
            dkim_disposition: DkimDisposition::NotProbed,
            dmarc: DmarcDisposition::Reject.chain(),
            dmarc_disposition: DmarcDisposition::Reject,
            dane: DaneDisposition::DnssecRequired.chain(),
            dane_disposition: DaneDisposition::DnssecRequired,
            tlsa_zone: TlsaZone::ForeignZone,
            mta_sts: MtaStsDisposition::Enforced.chain(),
            mta_sts_disposition: MtaStsDisposition::Enforced,
            caa: CaaDisposition::Configured.chain(),
            caa_disposition: CaaDisposition::Configured,
            cds_cdnskey: CdsDisposition::NotPublished.chain(),
            cds_disposition: CdsDisposition::NotPublished,
        };
        let model = truth_chain(&a);
        for width in [80usize, 100, 120] {
            let (lines, keep) = render_summary(&model, Palette::BLUE, Audience::BlueTeam, 1, width);
            for l in &lines {
                let w: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
                assert!(w <= width, "width {width}: line {w} cols: {:?}", l);
            }
            assert!(keep.end > keep.start, "selected range reported");
            let sel: String = lines[keep.start]
                .spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect();
            assert!(
                sel.starts_with("\u{25b8} "),
                "range starts at the cursor row: {sel:?}"
            );
            // Every measured label survives the wrap in full.
            let all: String = lines
                .iter()
                .map(|l| {
                    l.spans
                        .iter()
                        .map(|s| s.content.as_ref())
                        .collect::<String>()
                        .trim()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join(" ");
            for rep in &model {
                for word in rep.measured.split_whitespace() {
                    assert!(all.contains(word), "width {width}: lost {word:?}");
                }
            }
        }
    }

    #[test]
    fn summary_subtitles_sit_under_the_two_verdict_tiers() {
        use resolution_scope_engine::analysis::{
            CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
            DnssecDisposition, MtaStsDisposition, SpfDisposition, TlsaZone,
        };
        let a = ScoredAnalysis {
            domain: "example.test".into(),
            session_id: 0,
            timestamp_local: 0,
            resolver_identity: "test".into(),
            dnssec_chain: DnssecDisposition::Unsigned.chain(),
            dnssec_disposition: DnssecDisposition::Unsigned,
            spf: SpfDisposition::SoftFail.chain(),
            spf_disposition: SpfDisposition::SoftFail,
            dkim: DkimDisposition::NotProbed.chain(),
            dkim_disposition: DkimDisposition::NotProbed,
            dmarc: DmarcDisposition::Reject.chain(),
            dmarc_disposition: DmarcDisposition::Reject,
            dane: DaneDisposition::DnssecRequired.chain(),
            dane_disposition: DaneDisposition::DnssecRequired,
            tlsa_zone: TlsaZone::ForeignZone,
            mta_sts: MtaStsDisposition::Enforced.chain(),
            mta_sts_disposition: MtaStsDisposition::Enforced,
            caa: CaaDisposition::Configured.chain(),
            caa_disposition: CaaDisposition::Configured,
            cds_cdnskey: CdsDisposition::NotPublished.chain(),
            cds_disposition: CdsDisposition::NotPublished,
        };
        let model = truth_chain(&a);
        let (lines, _) = render_summary(&model, Palette::BLUE, Audience::BlueTeam, 0, 80);
        let text: Vec<String> = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect();
        let under = |header: &str| -> String {
            let i = text
                .iter()
                .position(|l| l.contains(header))
                .unwrap_or_else(|| panic!("no {header} header"));
            text[i + 1].clone()
        };
        assert_eq!(under("FINDINGS"), "  controls that need attention");
        assert_eq!(
            under("HOLDING"),
            "  controls measured in their correct state"
        );
        // The other two tier names state their meaning — no subtitle.
        assert!(!under("COULD NOT MEASURE").starts_with("  controls"));
        assert!(!under("NOT APPLICABLE").starts_with("  controls"));
    }

    #[test]
    fn help_line_names_the_new_domain_verb() {
        assert!(HELP_WIDE.contains("d new domain"), "{HELP_WIDE:?}");
        assert!(!HELP_WIDE.contains("d add"));
    }

    #[tokio::test]
    async fn quit_keys() {
        let mut a = app(&["example.com"]);
        assert_eq!(
            handle_input(&mut a, KeyCode::Char('q'), KeyModifiers::NONE),
            Action::Quit
        );
        assert_eq!(
            handle_input(&mut a, KeyCode::Char('c'), KeyModifiers::CONTROL),
            Action::Quit,
            "Ctrl-C must quit even in raw mode"
        );
        a.input_mode = InputMode::Domain;
        assert_eq!(
            handle_input_mode(&mut a, KeyCode::Char('c'), KeyModifiers::CONTROL),
            Action::Quit,
            "…and from the domain prompt"
        );
    }

    #[tokio::test]
    async fn shift_tab_is_backtab_and_cycles_backwards() {
        let mut a = app(&["a.com", "b.com", "c.com"]);
        assert_eq!(
            handle_input(&mut a, KeyCode::BackTab, KeyModifiers::SHIFT),
            Action::SwitchDomain
        );
        assert_eq!(a.current_domain, 2, "wrapped to the last domain");
        assert_eq!(
            handle_input(&mut a, KeyCode::Tab, KeyModifiers::NONE),
            Action::SwitchDomain
        );
        assert_eq!(a.current_domain, 0);
    }

    #[tokio::test]
    async fn esc_and_backspace_return_to_summary() {
        let mut a = app(&["example.com"]);
        handle_input(&mut a, KeyCode::Char('3'), KeyModifiers::NONE);
        assert_eq!(a.selected_tab, 2);
        handle_input(&mut a, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(a.selected_tab, TAB_SUMMARY);
        handle_input(&mut a, KeyCode::Char('7'), KeyModifiers::NONE);
        assert_eq!(a.selected_tab, TAB_SEAL);
        handle_input(&mut a, KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(a.selected_tab, TAB_SUMMARY);
        // Digits outside the tab range do nothing.
        handle_input(&mut a, KeyCode::Char('9'), KeyModifiers::NONE);
        assert_eq!(a.selected_tab, TAB_SUMMARY);
    }

    #[tokio::test]
    async fn m_flips_framing_and_palette_together() {
        let mut a = app(&["example.com"]);
        assert_eq!(a.audience, Audience::BlueTeam);
        handle_input(&mut a, KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(a.audience, Audience::RedTeam);
        assert_eq!(framing_word(a.audience), "RED TEAM \u{00b7} assess");
        handle_input(&mut a, KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(a.audience, Audience::BlueTeam);
    }

    #[tokio::test]
    async fn domain_prompt_goes_through_the_input_boundary() {
        let mut a = app(&["example.com"]);
        handle_input(&mut a, KeyCode::Char('d'), KeyModifiers::NONE);
        assert_eq!(a.input_mode, InputMode::Domain);
        for ch in "https://bad/".chars() {
            handle_input_mode(&mut a, KeyCode::Char(ch), KeyModifiers::NONE);
        }
        assert_eq!(
            handle_input_mode(&mut a, KeyCode::Enter, KeyModifiers::NONE),
            Action::Nothing
        );
        assert!(a
            .input_error
            .as_deref()
            .unwrap()
            .contains("bare domain name"));
        assert_eq!(
            a.input_mode,
            InputMode::Domain,
            "stays in the prompt with the reason"
        );
        assert_eq!(a.domains.len(), 1, "nothing bad was added");

        // Esc cancels without a rescan.
        assert_eq!(
            handle_input_mode(&mut a, KeyCode::Esc, KeyModifiers::NONE),
            Action::Nothing
        );
        assert_eq!(a.input_mode, InputMode::Normal);

        // A good name is canonicalised and triggers a measurement.
        handle_input(&mut a, KeyCode::Char('d'), KeyModifiers::NONE);
        for ch in "IT-Help.Tech.".chars() {
            handle_input_mode(&mut a, KeyCode::Char(ch), KeyModifiers::NONE);
        }
        assert_eq!(
            handle_input_mode(&mut a, KeyCode::Enter, KeyModifiers::NONE),
            Action::SwitchDomain
        );
        assert_eq!(a.domains, ["example.com", "it-help.tech"]);
        assert_eq!(a.current_domain, 1);

        // Empty Enter is a cancel, not a rescan.
        handle_input(&mut a, KeyCode::Char('d'), KeyModifiers::NONE);
        assert_eq!(
            handle_input_mode(&mut a, KeyCode::Enter, KeyModifiers::NONE),
            Action::Nothing
        );
        assert_eq!(a.input_mode, InputMode::Normal);
    }

    #[tokio::test]
    async fn r_and_tab_request_a_measurement() {
        let mut a = app(&["example.com", "example.org"]);
        assert_eq!(
            handle_input(&mut a, KeyCode::Char('r'), KeyModifiers::NONE),
            Action::Rescan
        );
        assert_eq!(
            handle_input(&mut a, KeyCode::Tab, KeyModifiers::NONE),
            Action::SwitchDomain
        );
    }

    #[tokio::test]
    async fn tab_is_a_noop_with_a_single_domain() {
        // A single-domain session must not re-measure on Tab — that read as
        // the app freezing (found live, 2026-08-23).
        let mut a = app(&["example.com"]);
        assert_eq!(
            handle_input(&mut a, KeyCode::Tab, KeyModifiers::NONE),
            Action::Nothing
        );
        assert_eq!(
            handle_input(&mut a, KeyCode::BackTab, KeyModifiers::SHIFT),
            Action::Nothing
        );
        assert_eq!(a.current_domain, 0, "still on the only domain");
    }

    #[tokio::test]
    async fn r_is_absorbed_while_measuring() {
        // An impatient r-mash must not restart the in-flight measurement.
        let mut a = app(&["example.com"]);
        a.start_scan();
        assert!(
            matches!(a.scan, ScanState::Measuring { .. }),
            "scan started"
        );
        assert_eq!(
            handle_input(&mut a, KeyCode::Char('r'), KeyModifiers::NONE),
            Action::Nothing,
            "r while measuring is absorbed, not restarted"
        );
    }

    #[test]
    fn tab_bar_fits_eighty_columns() {
        // label + " " + "│" per tab, no divider after the last.
        let total: usize = TAB_LABELS
            .iter()
            .map(|l| l.chars().count() + 1)
            .sum::<usize>()
            + TAB_LABELS.len()
            - 1;
        assert!(total <= 80, "tab bar is {total} columns");
    }

    #[test]
    fn every_control_has_a_detail_tab_whose_label_names_it() {
        for c in ControlId::ALL {
            let tab = tab_for_control(c);
            let (_, controls) = controls_for_tab(tab);
            assert!(controls.contains(&c), "{c:?} not on its own tab");
            // The tab label must carry the control's name (DKIM was missing
            // from "4:SPF/DMARC").
            let label = TAB_LABELS[tab];
            let name = c.name().split('/').next().unwrap();
            assert!(label.contains(name), "tab {label:?} does not name {name}");
        }
    }

    #[test]
    fn wrap_indent_hangs_continuations_under_the_text() {
        let lines = wrap_indent(
            "      \u{2192} ",
            "one two three four five six seven eight nine ten",
            30,
            Style::default(),
            Style::default(),
        );
        assert!(lines.len() >= 2, "must wrap at width 30");
        let first: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        let second: String = lines[1].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(first.starts_with("      \u{2192} one"));
        assert!(
            second.starts_with("        "),
            "continuation indented to the prefix width"
        );
        assert!(
            !second.starts_with("        \u{2192}"),
            "prefix glyph only on the first line"
        );
        for l in &lines {
            let w: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
            assert!(w <= 30, "line {w} wider than 30: {l:?}");
        }
    }

    #[test]
    fn wrap_indent_splits_tokens_wider_than_the_width() {
        // The 128-hex seal has no spaces; it must be split, never clipped.
        let seal = "ab".repeat(64);
        let lines = wrap_indent("  seal  ", &seal, 40, Style::default(), Style::default());
        assert!(lines.len() >= 4);
        let joined: String = lines
            .iter()
            .map(|l| l.spans[1].content.to_string())
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(
            joined.replace(' ', ""),
            seal,
            "every hex character survives"
        );
        for l in &lines {
            let w: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
            assert!(w <= 40, "line {w} wider than 40");
        }
    }

    #[test]
    fn wrap_indent_never_drops_words() {
        let text = "a sentence with several words that must all survive the wrap";
        let lines = wrap_indent("  x ", text, 20, Style::default(), Style::default());
        let joined: Vec<String> = lines
            .iter()
            .map(|l| l.spans[1].content.to_string())
            .collect();
        assert_eq!(joined.join(" "), text);
    }
}
