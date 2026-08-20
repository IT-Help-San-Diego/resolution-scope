//! Resolution Scope — one binary, three verbs.
//!
//! The single user-facing surface. `engine` and `store` stay libraries; the
//! interactive dashboard (folded from the old `tui` crate) is `tui.rs`; every
//! renderer is `render.rs`. One scan, any output — all of it delegating to
//! engine::truth_chain() (the single-producer contract, ARCHITECTURE.md §8).
//!
//!     resolution-scope example.com                # scan + text report (default)
//!     resolution-scope example.com --format html  # static page
//!     resolution-scope example.com --format json  # machine output (Arm 1)
//!     resolution-scope tui                        # interactive dashboard
//!     resolution-scope history example.com        # sealed-history verb

mod render;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use resolution_scope_engine::analysis::analyse_domain_with_selectors;
use resolution_scope_engine::truth_chain::Audience;

#[derive(Parser)]
#[command(
    name = "resolution-scope",
    about = "Resolution Scope — sovereign DNS resolution, measured and sealed",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Domain(s) to scan (repeatable) — the default verb.
    #[arg(short, long, global = true)]
    domains: Vec<String>,

    /// Output format: text, summary, html, json (default text)
    #[arg(short, long, global = true, default_value = "text")]
    format: String,

    /// Consequence framing: blue (defend) or red (assess)
    #[arg(long, global = true, default_value = "blue")]
    audience: String,

    /// DKIM selector(s) to probe in addition to the 81 defaults (repeatable).
    #[arg(long, global = true)]
    dkim_selector: Vec<String>,

    /// Output file path (for html/text; text defaults to stdout)
    #[arg(short, long, global = true)]
    out: Option<String>,

    /// PostgreSQL URL for the sealed-history store (env: RS_STORE_URL).
    #[arg(long, global = true, env = "RS_STORE_URL")]
    store_url: Option<String>,

    /// Start the interactive dashboard in covert (red-team) mode.
    #[arg(long, global = true)]
    covert: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Launch the interactive dashboard (two-mode, terminal).
    Tui,
    /// Show the sealed scan history — reads the store, does NOT scan.
    History,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let audience = match cli.audience.as_str() {
        "blue" => Audience::BlueTeam,
        "red" => Audience::RedTeam,
        other => anyhow::bail!("--audience must be 'blue' or 'red', got {other:?}"),
    };

    // Same resolver for every verb: validating, DNSSEC-capable.
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()?;

    match cli.command {
        Some(Command::Tui) => {
            let domains = require_domains(&cli.domains)?;
            tui::run(resolver, domains, cli.dkim_selector, cli.covert).await
        }
        Some(Command::History) => {
            let url = cli
                .store_url
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("history requires --store-url (or RS_STORE_URL)"))?;
            let domains = require_domains(&cli.domains)?;
            let mut store = resolution_scope_store::Store::connect(url).await?;
            store.migrate().await?;
            for domain in &domains {
                let history = store.scan_history(domain).await?;
                print!("{}", render::render_history(domain, &history));
            }
            Ok(())
        }
        // Default verb: scan + render.
        None => {
            let domains = require_domains(&cli.domains)?;
            let mut analyses = Vec::with_capacity(domains.len());
            for domain in &domains {
                eprintln!("scanning {domain} …");
                analyses.push(
                    analyse_domain_with_selectors(&resolver, domain, &cli.dkim_selector, "cloudflare")
                        .await?,
                );
            }

            match cli.format.as_str() {
                "text" => {
                    let text = render::render_text_report(&analyses);
                    match &cli.out {
                        Some(path) => {
                            std::fs::write(path, &text)?;
                            eprintln!("wrote {path}");
                        }
                        None => println!("{text}"),
                    }
                }
                "summary" => {
                    let summary = render::render_summary(&analyses, audience);
                    match &cli.out {
                        Some(path) => {
                            std::fs::write(path, &summary)?;
                            eprintln!("wrote {path}");
                        }
                        None => println!("{summary}"),
                    }
                }
                "html" => {
                    let html = render::render_html_page(&analyses, audience);
                    let path = cli.out.unwrap_or_else(|| "report.html".to_string());
                    std::fs::write(&path, html)?;
                    eprintln!("wrote {path}");
                }
                "json" => {
                    let json = render::render_json(&analyses);
                    match &cli.out {
                        Some(path) => {
                            std::fs::write(path, &json)?;
                            eprintln!("wrote {path}");
                        }
                        None => print!("{json}"),
                    }
                }
                other => {
                    anyhow::bail!("--format must be 'text', 'summary', 'html', or 'json', got {other:?}")
                }
            }

            // Sealed history: when a store is configured, persist every verdict
            // with a store-computed seal and echo the citable row id + prefix.
            if let Some(url) = &cli.store_url {
                let mut store = resolution_scope_store::Store::connect(url).await?;
                store.migrate().await?;
                for a in &analyses {
                    let id = store.record_scan(a).await?;
                    let seal = resolution_scope_engine::seal::seal(a);
                    eprintln!("stored {} as scan #{id} (seal {}…)", a.domain, &seal[..16]);
                }
            }

            Ok(())
        }
    }
}

fn require_domains(domains: &[String]) -> Result<Vec<String>> {
    if domains.is_empty() {
        anyhow::bail!("at least one domain is required (e.g. `resolution-scope example.com`)");
    }
    Ok(domains.to_vec())
}
