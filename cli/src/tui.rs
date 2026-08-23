//! Resolution Scope TUI — two-mode terminal DNS analysis dashboard.
//!
//! Two modes, toggled with `m`:
//! - **Covert** (RED-TEAM): scotopic red-on-charcoal, hacker recon look
//! - **Blue** (BLUE-TEAM): regular science/engineering report
//!
//! Keyboard: `1`-`6` jump between report groups. `q` quits. `m` toggles mode.
//! Navigation: `j`/`k` or `↑`/`↓` scroll. `r` re-scans the current domain.
//! `tab`/`shift-tab` cycle domains.

use std::io;
use std::time::Instant;

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
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
use ratatui::{Frame, Terminal};

use resolution_scope_engine::analysis::analyse_domain_with_selectors;
use resolution_scope_engine::truth_chain::{
    by_severity, truth_chain, Audience, ControlId, ControlReport, Severity, Tally,
};
use resolution_scope_engine::ScoredAnalysis;
use resolution_scope_engine::TriState;

use hickory_resolver::TokioResolver;

// ── CLI ────────────────────────────────────────────────────────────
// (The CLI surface lives in main.rs; this module is the interactive
// dashboard body, invoked by the `tui` subcommand.)

// ── palette ────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Blue,
    Covert,
}

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
    // Color::Rgb (24-bit truecolor). Rationale: the covert/red-team mode is
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
    const COVERT: Self = Self {
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
}

// ── navigation tabs ────────────────────────────────────────────────

const TAB_LABELS: &[&str] = &[
    "1:Summary",
    "2:DNSSEC",
    "3:DANE",
    "4:SPF/DMARC",
    "5:MTA-STS",
    "6:CAA/CDS",
];

fn section_for_tab(
    tab: usize,
    result: &ScoredAnalysis,
    pal: Palette,
    audience: Audience,
    selected: usize,
) -> Vec<Line<'static>> {
    let model = truth_chain(result);
    match tab {
        0 => render_summary(&model, pal, audience, selected),
        1 => render_controls("══ DNSSEC ══", &model, &[ControlId::Dnssec], pal, audience),
        2 => render_controls(
            "══ DANE (SMTP TLSA) ══",
            &model,
            &[ControlId::Dane],
            pal,
            audience,
        ),
        3 => render_controls(
            "══ Email Authentication ══",
            &model,
            &[ControlId::Spf, ControlId::Dkim, ControlId::Dmarc],
            pal,
            audience,
        ),
        4 => render_controls("══ MTA-STS ══", &model, &[ControlId::MtaSts], pal, audience),
        5 => render_controls(
            "══ CAA / CDS ══",
            &model,
            &[ControlId::Caa, ControlId::Cds],
            pal,
            audience,
        ),
        _ => vec![Line::from("—")],
    }
}

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

// ── section renderers ──────────────────────────────────────────────
//
// The TUI owns STYLING ONLY. Verdict meaning — labels, severities,
// consequences, tally — comes from engine::truth_chain (ARCHITECTURE.md §8).
// A match on a disposition enum in this file is a contract violation.

fn state_icon(s: TriState, pal: Palette) -> (&'static str, Color) {
    match s {
        TriState::Present => ("PASS", pal.pass),
        TriState::Absent => ("FAIL", pal.fail),
        TriState::Indet => (" ? ", pal.warn),
        TriState::NotApplicable => ("N/A", pal.muted),
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

/// Summary: every control, worst first, with the selection cursor. Severity
/// order comes from the model; the score comes from the shared Tally.
fn render_summary(
    model: &[ControlReport; 8],
    pal: Palette,
    audience: Audience,
    selected: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            "══ Findings (worst first) ══",
            Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    let ordered = by_severity(model);
    for (i, rep) in ordered.iter().enumerate() {
        let is_sel = i == selected;
        let cursor = if is_sel { "▸ " } else { "  " };
        let row_bg = if is_sel {
            Style::default().bg(pal.highlight)
        } else {
            Style::default()
        };
        let (icon, icon_color) = state_icon(rep.tri, pal);
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
                format!(" {} ", icon),
                row_bg.fg(icon_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {}", rep.measured), row_bg.fg(pal.muted)),
        ]));
        if is_sel {
            lines.push(Line::from(Span::styled(
                format!("      → {}", rep.consequence(audience)),
                Style::default().fg(pal.fg),
            )));
        }
    }
    lines.push(Line::from(""));
    let t = Tally::of(model);
    lines.push(Line::from(Span::styled(
        format!(
            "  Score: {}/{} ({}%)  │  unmeasured: {}  │  n/a: {}",
            t.present,
            t.denominator(),
            t.percent(),
            t.unmeasured,
            t.not_applicable
        ),
        Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "  (unmeasured never enters the score — a ? is not a verdict)",
        Style::default().fg(pal.muted),
    )));
    lines
}

/// Detail view: the full truth chain for one or more controls — RFC
/// requirement, measured state, consequence — straight from the model.
fn render_controls(
    title: &'static str,
    model: &[ControlReport; 8],
    controls: &[ControlId],
    pal: Palette,
    audience: Audience,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            title,
            Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for c in controls {
        let rep = report_for(model, *c);
        let (icon, icon_color) = state_icon(rep.tri, pal);
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {} ", rep.control.name()),
                Style::default().fg(pal.fg).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                icon,
                Style::default().fg(icon_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}", rep.severity.label()),
                severity_style(rep.severity, pal),
            ),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  measured   ", Style::default().fg(pal.accent)),
            Span::styled(rep.measured, Style::default().fg(pal.fg)),
        ]));
        // DANE attribution in the DETAIL pane only — the findings list row is
        // an unwrapped Span and would clip a sentence at terminal width.
        if let Some(attr) = rep.dane_attribution() {
            lines.push(Line::from(vec![
                Span::styled("  attribution ", Style::default().fg(pal.accent)),
                Span::styled(attr, Style::default().fg(pal.muted)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("  rfc        ", Style::default().fg(pal.accent)),
            Span::styled(rep.rfc_requirement, Style::default().fg(pal.muted)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  consequence ", Style::default().fg(pal.accent)),
            Span::styled(rep.consequence(audience), Style::default().fg(pal.fg)),
        ]));
        lines.push(Line::from(""));
    }
    lines
}

// ── app state ──────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum InputMode {
    Normal,
    Domain,
}

struct App {
    mode: Mode,
    pal: Palette,
    resolver: TokioResolver,
    domains: Vec<String>,
    dkim_selector: Vec<String>,
    current_domain: usize,
    results: Vec<ScoredAnalysis>,
    scroll: u16,
    selected_tab: usize,
    selected_control: usize,
    last_scan: Option<Instant>,
    input_mode: InputMode,
    input_buf: String,
}

impl App {
    fn new(
        resolver: TokioResolver,
        domains: Vec<String>,
        dkim_selector: Vec<String>,
        covert: bool,
    ) -> Self {
        let mode = if covert { Mode::Covert } else { Mode::Blue };
        let pal = if covert {
            Palette::COVERT
        } else {
            Palette::BLUE
        };
        Self {
            mode,
            pal,
            resolver,
            domains,
            dkim_selector,
            current_domain: 0,
            results: Vec::new(),
            scroll: 0,
            selected_tab: 0,
            selected_control: 0,
            last_scan: None,
            input_mode: InputMode::Normal,
            input_buf: String::new(),
        }
    }
    fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            Mode::Blue => Mode::Covert,
            Mode::Covert => Mode::Blue,
        };
        self.pal = match self.mode {
            Mode::Blue => Palette::BLUE,
            Mode::Covert => Palette::COVERT,
        };
    }
    /// The mode flip changes framing (which consequence string renders), never
    /// facts — both strings come from the shared model.
    fn audience(&self) -> Audience {
        match self.mode {
            Mode::Blue => Audience::BlueTeam,
            Mode::Covert => Audience::RedTeam,
        }
    }
    /// The control the summary cursor points at, in severity order.
    fn selected_report(&self) -> Option<ControlReport> {
        self.current_result()
            .map(|r| by_severity(&truth_chain(r))[self.selected_control.min(7)])
    }
    async fn scan(&mut self) -> Result<()> {
        let domain = &self.domains[self.current_domain];
        self.results = vec![
            analyse_domain_with_selectors(
                &self.resolver,
                domain,
                &self.dkim_selector,
                "cloudflare",
            )
            .await?,
        ];
        self.last_scan = Some(Instant::now());
        self.scroll = 0;
        self.selected_control = 0;
        Ok(())
    }
    fn current_result(&self) -> Option<&ScoredAnalysis> {
        self.results.first()
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
            Constraint::Length(3),
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

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let mode_label = match app.mode {
        Mode::Blue => "BLUE",
        Mode::Covert => "COVERT",
    };
    let domain = app
        .domains
        .get(app.current_domain)
        .map(|d| d.as_str())
        .unwrap_or("—");
    let text = vec![
        Line::from(vec![
            Span::styled(
                "⚡ RESOLUTION SCOPE ",
                Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(mode_label, Style::default().fg(p.warn)),
            Span::styled(
                format!(" [{}/{}] ", app.current_domain + 1, app.domains.len()),
                Style::default().fg(p.muted),
            ),
            Span::styled("│  ", Style::default().fg(p.muted)),
            Span::styled(
                domain,
                Style::default().fg(p.fg).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(
            "1-6:nav  m:mode  j/k:select/scroll  enter:detail  r:rescan  tab:next  q:quit",
            Style::default().fg(p.muted),
        )]),
    ];
    let widget = Paragraph::new(text).block(
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
    let tabs = Tabs::new(titles)
        .select(app.selected_tab)
        .style(Style::default().fg(p.muted))
        .highlight_style(Style::default().fg(p.accent))
        .divider(Span::styled("│", Style::default().fg(p.muted)));
    f.render_widget(tabs, area);
}

fn render_content(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    if let Some(result) = app.current_result() {
        let section_lines = section_for_tab(
            app.selected_tab,
            result,
            p,
            app.audience(),
            app.selected_control,
        );
        let block = Block::default()
            .style(Style::default().bg(p.bg))
            .borders(Borders::NONE);
        let widget = Paragraph::new(section_lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0));
        f.render_widget(widget, area);
    } else {
        let hint = vec![Line::from(Span::styled(
            "Press 'r' to scan, or enter a domain.",
            Style::default().fg(p.muted),
        ))];
        f.render_widget(Paragraph::new(hint).style(Style::default().bg(p.bg)), area);
    }
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    if app.input_mode == InputMode::Domain {
        let prompt = format!(" Domain: {}█", app.input_buf);
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
    let status = match app.last_scan {
        Some(t) => format!(
            "last scan: {:.0}s ago  │  domain {}/{}  │  tab: {}  │  d:add domain",
            t.elapsed().as_secs(),
            app.current_domain + 1,
            app.domains.len(),
            TAB_LABELS[app.selected_tab]
        ),
        None => "no scan yet — press 'r'  |  d:add domain".into(),
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

fn handle_input(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> Result<bool> {
    match code {
        KeyCode::Char('q') => return Ok(false),
        KeyCode::Char('m') => app.toggle_mode(),
        KeyCode::Char('r') => { /* handled in main loop */ }
        // Summary tab: j/k moves the finding cursor. Detail tabs: j/k scrolls.
        KeyCode::Char('j') | KeyCode::Down => {
            if app.selected_tab == 0 {
                app.selected_control = (app.selected_control + 1).min(7);
            } else {
                app.scroll = app.scroll.saturating_add(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if app.selected_tab == 0 {
                app.selected_control = app.selected_control.saturating_sub(1);
            } else {
                app.scroll = app.scroll.saturating_sub(1);
            }
        }
        // Enter on the summary jumps to the selected control's detail tab.
        KeyCode::Enter => {
            if app.selected_tab == 0 {
                if let Some(rep) = app.selected_report() {
                    app.selected_tab = tab_for_control(rep.control);
                    app.scroll = 0;
                }
            }
        }
        KeyCode::Tab => {
            if modifiers.contains(KeyModifiers::SHIFT) {
                app.prev_domain();
            } else {
                app.next_domain();
            }
        }
        KeyCode::Char('d') => {
            app.input_mode = InputMode::Domain;
            app.input_buf.clear();
        }
        KeyCode::Char(c) if c.is_ascii_digit() => {
            if let Some(n) = c.to_digit(10) {
                if (1..=6).contains(&n) {
                    app.selected_tab = n as usize - 1;
                }
            }
        }
        _ => {}
    }
    Ok(true)
}

fn handle_input_mode(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter => {
            let new_domain = app.input_buf.trim().to_string();
            if !new_domain.is_empty() {
                app.domains.push(new_domain);
                app.current_domain = app.domains.len() - 1;
            }
            app.input_mode = InputMode::Normal;
            app.input_buf.clear();
        }
        KeyCode::Esc => {
            app.input_mode = InputMode::Normal;
            app.input_buf.clear();
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => {
            app.input_buf.push(c);
        }
        _ => {}
    }
}

// ── entry point (invoked by the `tui` subcommand) ──────────────────

/// Run the interactive dashboard. The resolver and domains are provided by
/// main.rs; this module owns the terminal session (raw mode, alternate
/// screen, event loop) and the renderers above.
pub async fn run(
    resolver: TokioResolver,
    domains: Vec<String>,
    dkim_selector: Vec<String>,
    covert: bool,
) -> Result<()> {
    let mut app = App::new(resolver, domains, dkim_selector, covert);
    app.scan().await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let res = loop {
        terminal.draw(|f| render_ui(f, &app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                if app.input_mode != InputMode::Normal {
                    handle_input_mode(&mut app, key.code);
                    if app.input_mode == InputMode::Normal {
                        app.scan().await?;
                    }
                    continue;
                }
                if !handle_input(&mut app, key.code, key.modifiers)? {
                    break Ok(());
                }
                // Rescan on 'r' AND on domain switch — Tab without a rescan
                // rendered the previous domain's verdicts under the new
                // domain's name (adversarial panel, 2026-08-19).
                if key.code == KeyCode::Char('r') || key.code == KeyCode::Tab {
                    app.scan().await?;
                }
            }
        }
    };

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    res
}
