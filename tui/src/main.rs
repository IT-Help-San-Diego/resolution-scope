//! Resolution Scope TUI — two-mode terminal DNS analysis dashboard.
//!
//! Two modes, toggled with `m`:
//! - **Covert** (RED-TEAM): scotopic red-on-charcoal, hacker recon look
//! - **Blue** (BLUE-TEAM): regular science/engineering report
//!
//! Keyboard: `1`-`6` jump between report groups. `q` quits. `m` toggles mode.
//! Navigation: `j`/`k` or `↑`/`↓` scroll. `r` re-scans the current domain.

use std::io;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::{Frame, Terminal};

use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::report::render_text;
use resolution_scope_engine::ScoredAnalysis;

use hickory_resolver::TokioResolver;

/// CLI arguments.
#[derive(Parser)]
#[command(name = "rs", about = "Resolution Scope — DNS security analysis terminal")]
struct Args {
    /// Domain(s) to analyze (space-separated)
    domains: Vec<String>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    output: String,

    /// Covert mode (scotopic red palette)
    #[arg(short, long)]
    covert: bool,
}

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
    header_fg: Color,
}

impl Palette {
    const BLUE: Self = Self {
        bg: Color::Rgb(10, 10, 10),
        fg: Color::Rgb(224, 224, 224),
        accent: Color::Rgb(64, 160, 255),
        warn: Color::Rgb(255, 180, 40),
        fail: Color::Rgb(255, 70, 70),
        pass: Color::Rgb(70, 200, 100),
        muted: Color::Rgb(100, 100, 100),
        border: Color::Rgb(50, 50, 55),
        highlight: Color::Rgb(40, 40, 48),
        header_bg: Color::Rgb(30, 30, 38),
        header_fg: Color::Rgb(180, 200, 220),
    };

    const COVERT: Self = Self {
        bg: Color::Rgb(8, 6, 4),
        fg: Color::Rgb(200, 140, 80),
        accent: Color::Rgb(220, 60, 30),
        warn: Color::Rgb(200, 120, 20),
        fail: Color::Rgb(240, 40, 20),
        pass: Color::Rgb(40, 160, 60),
        muted: Color::Rgb(60, 40, 20),
        border: Color::Rgb(40, 25, 15),
        highlight: Color::Rgb(30, 18, 10),
        header_bg: Color::Rgb(20, 12, 8),
        header_fg: Color::Rgb(200, 140, 80),
    };
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
        Self {
            mode,
            pal,
            resolver,
            domains,
            current_domain: 0,
            results: Vec::new(),
            scroll: 0,
            selected_tab: 0,
            last_scan: None,
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

    async fn scan(&mut self) -> Result<()> {
        let domain = &self.domains[self.current_domain];
        let scored = analyse_domain(&self.resolver, domain).await?;
        self.results = vec![scored];
        self.last_scan = Some(Instant::now());
        self.scroll = 0;
        Ok(())
    }

    fn current_result(&self) -> Option<&ScoredAnalysis> {
        self.results.first()
    }
}

// ── Tabs (1-6 navigation groups) ───────────────────────────────────

const TABS: &[&str] = &[
    "1:Summary",
    "2:DNSSEC",
    "3:DANE",
    "4:SPF/DMARC",
    "5:MTA-STS",
    "6:BIMI/CAA",
];

// ── rendering ──────────────────────────────────────────────────────

fn render_ui(f: &mut Frame, app: &App) {
    let p = app.pal;

    // full-screen background
    let bg_block = Block::default().style(Style::default().bg(p.bg));
    f.render_widget(bg_block, f.area());

    // layout: header, tabs, content, footer
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(2),  // tabs
            Constraint::Min(0),     // content
            Constraint::Length(1),  // footer
        ])
        .split(f.area());

    // header
    render_header(f, main[0], app);
    // tabs
    render_tabs(f, main[1], app);
    // content
    render_content(f, main[2], app);
    // footer
    render_footer(f, main[3], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let mode_label = match app.mode {
        Mode::Blue => "BLUE",
        Mode::Covert => "COVERT",
    };
    let domain = app.domains.get(app.current_domain).map(|d| d.as_str()).unwrap_or("—");

    let text = vec![
        Line::from(vec![
            Span::styled("⚡ RESOLUTION SCOPE ", Style::default().fg(p.accent).add_modifier(Modifier::BOLD)),
            Span::styled(mode_label, Style::default().fg(p.warn)),
            Span::styled("  │  ", Style::default().fg(p.muted)),
            Span::styled(domain, Style::default().fg(p.fg).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(
                "1-6:nav  m:mode  j/k:scroll  r:rescan  q:quit",
                Style::default().fg(p.muted),
            ),
        ]),
    ];

    let block = Block::default()
        .style(Style::default().bg(p.header_bg))
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(p.border));
    let widget = Paragraph::new(text).block(block);
    f.render_widget(widget, area);
}

fn render_tabs(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let titles: Vec<Line> = TABS
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
        let report = render_text(result);
        let lines: Vec<Line> = report
            .lines()
            .skip(app.scroll as usize)
            .map(|l| {
                let styled = if l.contains("PASS") || l.contains("✅") {
                    Style::default().fg(p.pass)
                } else if l.contains("FAIL") || l.contains("❌") || l.contains("BROKEN") {
                    Style::default().fg(p.fail)
                } else if l.contains("WARN") || l.contains("⚠") {
                    Style::default().fg(p.warn)
                } else if l.starts_with('#') {
                    Style::default().fg(p.accent).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(p.fg)
                };
                Line::from(Span::styled(l, styled))
            })
            .collect();

        let block = Block::default()
            .style(Style::default().bg(p.bg))
            .borders(Borders::NONE);
        let widget = Paragraph::new(lines).block(block).scroll((0, 0));
        f.render_widget(widget, area);
    } else {
        let hint = vec![
            Line::from(Span::styled(
                "Press 'r' to scan the domain, or enter a domain name.",
                Style::default().fg(p.muted),
            )),
        ];
        let widget = Paragraph::new(hint).style(Style::default().bg(p.bg));
        f.render_widget(widget, area);
    }
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let p = app.pal;
    let status = match app.last_scan {
        Some(t) => format!(
            "last scan: {:.0}s ago  │  {} tests  │  {}",
            t.elapsed().as_secs(),
            app.results.len(),
            app.domains.join(", ")
        ),
        None => "no scan yet — press 'r'".into(),
    };
    let text = Line::from(Span::styled(status, Style::default().fg(p.muted)));
    let widget = Paragraph::new(text).style(Style::default().bg(p.header_bg));
    f.render_widget(widget, area);
}

// ── input handling ─────────────────────────────────────────────────

fn handle_input(app: &mut App, code: KeyCode) -> Result<bool> {
    match code {
        KeyCode::Char('q') => return Ok(false),           // quit
        KeyCode::Char('m') => app.toggle_mode(),           // toggle mode
        KeyCode::Char('r') => {                             // rescan
            // schedule async scan
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.scroll = app.scroll.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.scroll = app.scroll.saturating_sub(1);
        }
        KeyCode::Char(c) if c.is_ascii_digit() => {
            let n = c.to_digit(10).unwrap() as usize;
            if n >= 1 && n <= 6 {
                app.selected_tab = n - 1;
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

    if args.domains.is_empty() {
        eprintln!("Usage: rs <domain> [domain...]");
        eprintln!("  e.g. rs example.com resolutionscope.com");
        std::process::exit(1);
    }

    // Build DNS resolver (Cloudflare UDP, DNSSEC validation on)
    let resolver = {
        use hickory_resolver::config::{ResolverConfig, ResolverOpts};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        let mut opts = ResolverOpts::default();
        opts.validate = true;
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .with_options(opts)
        .build()?
    };

    // Scan on startup
    let mut app = App::new(resolver, args.domains, args.covert);
    app.scan().await?;

    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    // Main loop
    let res = run_app(&mut terminal, &mut app).await;

    // Cleanup
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    res
}

async fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| render_ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                if !handle_input(app, key.code)? {
                    return Ok(());
                }
                // Re-scan on 'r'
                if key.code == KeyCode::Char('r') {
                    app.scan().await?;
                }
            }
        }
    }
}

// crossterm backend
use ratatui::backend::CrosstermBackend;