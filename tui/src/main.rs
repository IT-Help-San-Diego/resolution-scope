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
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
use ratatui::{Frame, Terminal};

use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::analysis::DnssecDisposition;
use resolution_scope_engine::report::render_text;
use resolution_scope_engine::ScoredAnalysis;
use resolution_scope_engine::TriState;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

// ── CLI ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "rs", about = "Resolution Scope — DNS security analysis terminal")]
struct Args {
    #[arg(short, long)]
    domains: Vec<String>,
    #[arg(short, long)]
    covert: bool,
    #[arg(short = 't', long)]
    text: bool,
}

// ── palette ────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Mode { Blue, Covert }

#[derive(Clone, Copy)]
struct Palette {
    bg: Color, fg: Color, accent: Color, warn: Color, fail: Color,
    pass: Color, muted: Color, border: Color, highlight: Color,
    header_bg: Color, header_fg: Color,
}

impl Palette {
    const BLUE: Self = Self {
        bg: Color::Rgb(10, 10, 10), fg: Color::Rgb(224, 224, 224),
        accent: Color::Rgb(64, 160, 255), warn: Color::Rgb(255, 180, 40),
        fail: Color::Rgb(255, 70, 70), pass: Color::Rgb(70, 200, 100),
        muted: Color::Rgb(100, 100, 100), border: Color::Rgb(50, 50, 55),
        highlight: Color::Rgb(40, 40, 48), header_bg: Color::Rgb(30, 30, 38),
        header_fg: Color::Rgb(180, 200, 220),
    };
    const COVERT: Self = Self {
        bg: Color::Rgb(8, 6, 4), fg: Color::Rgb(200, 140, 80),
        accent: Color::Rgb(220, 60, 30), warn: Color::Rgb(200, 120, 20),
        fail: Color::Rgb(240, 40, 20), pass: Color::Rgb(40, 160, 60),
        muted: Color::Rgb(60, 40, 20), border: Color::Rgb(40, 25, 15),
        highlight: Color::Rgb(30, 18, 10), header_bg: Color::Rgb(20, 12, 8),
        header_fg: Color::Rgb(200, 140, 80),
    };
}

// ── navigation tabs ────────────────────────────────────────────────

const TAB_LABELS: &[&str] = &[
    "1:Summary", "2:DNSSEC", "3:DANE", "4:SPF/DMARC", "5:MTA-STS", "6:CAA/CDS",
];

fn section_for_tab(tab: usize, result: &ScoredAnalysis, pal: Palette) -> Vec<Line<'static>> {
    match tab {
        0 => render_summary(result, pal),
        1 => render_dnssec(result, pal),
        2 => render_dane(result, pal),
        3 => render_email_auth(result, pal),
        4 => render_mta_sts(result, pal),
        5 => render_caa_cds(result, pal),
        _ => vec![Line::from("—")],
    }
}

// ── section renderers ──────────────────────────────────────────────

fn state_icon(s: TriState, pal: Palette) -> (&'static str, Color) {
    match s {
        TriState::Present => ("PASS", pal.pass),
        TriState::Absent => ("FAIL", pal.fail),
        TriState::Indet => (" ? ", pal.warn),
        TriState::NotApplicable => ("N/A", pal.muted),
    }
}

fn render_summary(r: &ScoredAnalysis, pal: Palette) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled("══ Summary ══", Style::default().fg(pal.accent).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    let controls = [
        ("DNSSEC", r.dnssec_chain),
        ("SPF", r.spf),
        ("DKIM", r.dkim),
        ("DMARC", r.dmarc),
        ("DANE", r.dane),
        ("MTA-STS", r.mta_sts),
        ("CAA", r.caa),
        ("CDS/CDNSKEY", r.cds_cdnskey),
    ];
    for (name, state) in &controls {
        let (icon, color) = state_icon(*state, pal);
        lines.push(Line::from(vec![
            Span::styled(format!("  {:>12}  ", name), Style::default().fg(pal.fg)),
            Span::styled(icon, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]));
    }
    lines.push(Line::from(""));
    let present = controls.iter().filter(|(_, s)| *s == TriState::Present).count();
    let total = controls.iter().filter(|(_, s)| *s != TriState::NotApplicable && *s != TriState::Indet).count();
    lines.push(Line::from(Span::styled(
        format!("  Score: {}/{} ({}%)", present, total, if total > 0 { present * 100 / total } else { 0 }),
        Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
    )));
    lines
}

fn render_dnssec(r: &ScoredAnalysis, pal: Palette) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled("══ DNSSEC ══", Style::default().fg(pal.accent).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    let (icon, color) = state_icon(r.dnssec_chain, pal);
    let (label, detail) = match r.dnssec_disposition {
        DnssecDisposition::SignedAndDelegated => ("Signed + Delegated", "Chain validates from root — DNSSEC is fully configured and operational."),
        DnssecDisposition::SignedNotDelegated => ("Island of Security", "Zone is signed (DNSKEY present) but no DS at parent — cannot validate from root. Genuinely signed, not chainable."),
        DnssecDisposition::BrokenChain => ("Broken Chain", "DS present but chain fails validation — wrong DS, expired RRSIG, or misconfigured. Counts as a finding."),
        DnssecDisposition::ChainUnverified => ("Could Not Verify", "DNSKEY present but AD flag absent or resolvers disagreed — cannot confirm or deny. Re-run."),
        DnssecDisposition::Unsigned => ("Unsigned", "No DNSKEY published — the zone is not signed."),
        DnssecDisposition::NoZone => ("No Zone", "NXDOMAIN — the domain does not exist. DNSSEC is not applicable."),
        DnssecDisposition::Unreachable => ("Unreachable", "Lookup failed (timeout/refused). Could not measure — re-run."),
    };
    lines.push(Line::from(vec![
        Span::styled("  Verdict:  ", Style::default().fg(pal.fg)),
        Span::styled(icon, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {}", label), Style::default().fg(pal.accent).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(format!("  {}", detail), Style::default().fg(pal.muted))));
    lines
}

fn render_dane(r: &ScoredAnalysis, pal: Palette) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled("══ DANE ══", Style::default().fg(pal.accent).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    let (icon, color) = state_icon(r.dane, pal);
    lines.push(Line::from(vec![
        Span::styled("  Status: ", Style::default().fg(pal.fg)),
        Span::styled(icon, Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ]));
    let note = match r.dane {
        TriState::NotApplicable => "DANE requires a mail server (MX record) — none found.",
        TriState::Indet => "Could not measure — check TLSA record at _25._tcp.<mx>.",
        TriState::Absent => "No valid TLSA record found for the mail server.",
        TriState::Present => "DANE TLSA record verified for the mail server.",
    };
    lines.push(Line::from(Span::styled(format!("  Note: {}", note), Style::default().fg(pal.muted))));
    lines
}

fn render_email_auth(r: &ScoredAnalysis, pal: Palette) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled("══ SPF / DMARC / DKIM ══", Style::default().fg(pal.accent).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    for (name, state, detail) in &[
        ("SPF", r.spf, "Sender Policy Framework — authorizes sending IPs."),
        ("DKIM", r.dkim, "DomainKeys Identified Mail — cryptographic email signing."),
        ("DMARC", r.dmarc, "Domain-based Message Authentication — policy for SPF/DKIM."),
    ] {
        let (icon, color) = state_icon(*state, pal);
        lines.push(Line::from(vec![
            Span::styled(format!("  {:>6}: ", name), Style::default().fg(pal.fg)),
            Span::styled(icon, Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {}", detail), Style::default().fg(pal.muted)),
        ]));
    }
    lines
}

fn render_mta_sts(r: &ScoredAnalysis, pal: Palette) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled("══ MTA-STS ══", Style::default().fg(pal.accent).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    let (icon, color) = state_icon(r.mta_sts, pal);
    lines.push(Line::from(vec![
        Span::styled("  Status: ", Style::default().fg(pal.fg)),
        Span::styled(icon, Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ]));
    let note = match r.mta_sts {
        TriState::Present => "MTA-STS policy enforced — TLS required for inbound mail.",
        TriState::Absent => "No MTA-STS policy — mail transport may fall back to plaintext.",
        TriState::Indet => "Could not fetch or validate the MTA-STS policy.",
        TriState::NotApplicable => "No mail server (MX) — MTA-STS does not apply.",
    };
    lines.push(Line::from(Span::styled(format!("  Note: {}", note), Style::default().fg(pal.muted))));
    lines
}

fn render_caa_cds(r: &ScoredAnalysis, pal: Palette) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled("══ CAA / CDS / CDNSKEY ══", Style::default().fg(pal.accent).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    for (name, state, detail) in &[
        ("CAA", r.caa, "Certification Authority Authorization — restricts TLS issuers."),
        ("CDS/CDNSKEY", r.cds_cdnskey, "Child DS / CDNSKEY — automates DNSSEC DS updates."),
    ] {
        let (icon, color) = state_icon(*state, pal);
        lines.push(Line::from(vec![
            Span::styled(format!("  {:>11}: ", name), Style::default().fg(pal.fg)),
            Span::styled(icon, Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {}", detail), Style::default().fg(pal.muted)),
        ]));
    }
    lines
}

// ── app state ──────────────────────────────────────────────────────

struct App {
    mode: Mode,
    pal: Palette,
    resolver: TokioResolver,
    domains: Vec<String>,
    current_domain: usize,
    results: Vec<ScoredAnalysis>,
    scroll: u16,
    selected_tab: usize,
    last_scan: Option<Instant>,
}

impl App {
    fn new(resolver: TokioResolver, domains: Vec<String>, covert: bool) -> Self {
        let mode = if covert { Mode::Covert } else { Mode::Blue };
        let pal = if covert { Palette::COVERT } else { Palette::BLUE };
        Self { mode, pal, resolver, domains, current_domain: 0,
            results: Vec::new(), scroll: 0, selected_tab: 0, last_scan: None }
    }
    fn toggle_mode(&mut self) {
        self.mode = match self.mode { Mode::Blue => Mode::Covert, Mode::Covert => Mode::Blue };
        self.pal = match self.mode { Mode::Blue => Palette::BLUE, Mode::Covert => Palette::COVERT };
    }
    async fn scan(&mut self) -> Result<()> {
        let domain = &self.domains[self.current_domain];
        self.results = vec![analyse_domain(&self.resolver, domain).await?];
        self.last_scan = Some(Instant::now());
        self.scroll = 0;
        Ok(())
    }
    fn current_result(&self) -> Option<&ScoredAnalysis> { self.results.first() }
    fn next_domain(&mut self) { self.current_domain = (self.current_domain + 1) % self.domains.len().max(1); }
    fn prev_domain(&mut self) { self.current_domain = (self.current_domain + self.domains.len() - 1) % self.domains.len().max(1); }
}

// ── rendering ──────────────────────────────────────────────────────

fn render_ui(f: &mut Frame, app: &App) {
    let p = app.pal;
    f.render_widget(Block::default().style(Style::default().bg(p.bg)), f.area());

    let main = Layout::default().direction(Direction::Vertical).constraints([
        Constraint::Length(3), Constraint::Length(2), Constraint::Min(0), Constraint::Length(1),
    ]).split(f.area());

    render_header(f, main[0], app);
    render_tabs(f, main[1], app);
    render_content(f, main[2], app);
    render_footer(f, main[3], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let mode_label = match app.mode { Mode::Blue => "BLUE", Mode::Covert => "COVERT" };
    let domain = app.domains.get(app.current_domain).map(|d| d.as_str()).unwrap_or("—");
    let text = vec![
        Line::from(vec![
            Span::styled("⚡ RESOLUTION SCOPE ", Style::default().fg(p.accent).add_modifier(Modifier::BOLD)),
            Span::styled(mode_label, Style::default().fg(p.warn)),
            Span::styled("  │  ", Style::default().fg(p.muted)),
            Span::styled(domain, Style::default().fg(p.fg).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![Span::styled(
            "1-6:nav  m:mode  j/k:scroll  r:rescan  tab:next  q:quit",
            Style::default().fg(p.muted),
        )]),
    ];
    let widget = Paragraph::new(text).block(Block::default().style(Style::default().bg(p.header_bg)).borders(Borders::BOTTOM).border_style(Style::default().fg(p.border)));
    f.render_widget(widget, area);
}

fn render_tabs(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let titles: Vec<Line> = TAB_LABELS.iter().enumerate().map(|(i, t)| {
        let style = if i == app.selected_tab { Style::default().fg(p.accent).add_modifier(Modifier::BOLD) }
        else { Style::default().fg(p.muted) };
        Line::from(Span::styled(*t, style))
    }).collect();
    let tabs = Tabs::new(titles).select(app.selected_tab).style(Style::default().fg(p.muted))
        .highlight_style(Style::default().fg(p.accent))
        .divider(Span::styled("│", Style::default().fg(p.muted)));
    f.render_widget(tabs, area);
}

fn render_content(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    if let Some(result) = app.current_result() {
        let section_lines = section_for_tab(app.selected_tab, result, p);
        let block = Block::default().style(Style::default().bg(p.bg)).borders(Borders::NONE);
        let widget = Paragraph::new(section_lines).block(block).wrap(Wrap { trim: false });
        f.render_widget(widget, area);
    } else {
        let hint = vec![Line::from(Span::styled("Press 'r' to scan, or enter a domain.", Style::default().fg(p.muted)))];
        f.render_widget(Paragraph::new(hint).style(Style::default().bg(p.bg)), area);
    }
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let status = match app.last_scan {
        Some(t) => format!("last scan: {:.0}s ago  │  domain {}/{}  │  tab: {}",
            t.elapsed().as_secs(), app.current_domain + 1, app.domains.len(), TAB_LABELS[app.selected_tab]),
        None => "no scan yet — press 'r'".into(),
    };
    f.render_widget(Paragraph::new(Line::from(Span::styled(status, Style::default().fg(p.muted)))).style(Style::default().bg(p.header_bg)), area);
}

// ── input ──────────────────────────────────────────────────────────

fn handle_input(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> Result<bool> {
    match code {
        KeyCode::Char('q') => return Ok(false),
        KeyCode::Char('m') => app.toggle_mode(),
        KeyCode::Char('r') => { /* handled in main loop */ }
        KeyCode::Char('j') | KeyCode::Down => app.scroll = app.scroll.saturating_add(1),
        KeyCode::Char('k') | KeyCode::Up => app.scroll = app.scroll.saturating_sub(1),
        KeyCode::Tab => {
            if modifiers.contains(KeyModifiers::SHIFT) { app.prev_domain(); }
            else { app.next_domain(); }
        }
        KeyCode::Char(c) if c.is_ascii_digit() => {
            if let Some(n) = c.to_digit(10) {
                if n >= 1 && n <= 6 { app.selected_tab = n as usize - 1; }
            }
        }
        _ => {}
    }
    Ok(true)
}

// ── main ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let domains = if !args.domains.is_empty() { args.domains } else {
        eprintln!("Usage: rs -d example.com [resolutionscope.com ...]");
        std::process::exit(1);
    };

    let mut opts = ResolverOpts::default();
    opts.validate = true;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
        TokioRuntimeProvider::default(),
    ).with_options(opts).build()?;

    if args.text {
        for domain in &domains {
            println!("{}", render_text(&analyse_domain(&resolver, domain).await?));
        }
        return Ok(());
    }

    let mut app = App::new(resolver, domains, args.covert);
    app.scan().await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let res = loop {
        terminal.draw(|f| render_ui(f, &app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                if !handle_input(&mut app, key.code, key.modifiers)? { break Ok(()); }
                if key.code == KeyCode::Char('r') { app.scan().await?; }
            }
        }
    };

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    res
}