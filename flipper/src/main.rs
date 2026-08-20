//! Resolution Scope flipper — scan once, render in any surface.
//!
//! The third and final surface: it runs the SAME engine scan as the TUI and
//! the web renderer, then outputs in the chosen format. The user switches
//! surfaces without re-scanning — the `ScoredAnalysis` is produced once and
//! fed to whichever renderer the flag selects.
//!
//!     rs-flip -d example.com --format tui    # terminal summary
//!     rs-flip -d example.com --format text   # plain text report
//!     rs-flip -d example.com --format html   # static HTML page
//!     rs-flip -d example.com --format all    # all three to stdout/files
//!
//! All three renderers consume truth_chain() — one verdict assembly path.

mod render;

use anyhow::Result;
use clap::Parser;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use resolution_scope_engine::analysis::analyse_domain_with_selectors;
use resolution_scope_engine::truth_chain::Audience;

#[derive(Parser)]
#[command(
    name = "rs-flip",
    about = "Resolution Scope — scan once, flip between terminal/text/web"
)]
struct Args {
    /// Domain(s) to scan (repeatable)
    #[arg(short, long, required = true)]
    domains: Vec<String>,

    /// Output format: tui (terminal summary), text (plain report), html (web
    /// page), or all (all three)
    #[arg(short, long, default_value = "tui")]
    format: String,

    /// Consequence framing: blue (defend) or red (assess)
    #[arg(long, default_value = "blue")]
    audience: String,

    /// DKIM selector(s) to probe in addition to the 81 defaults (repeatable).
    /// A known selector yields a definitive Verified/KeyMismatch instead of
    /// the sweep's "absence NOT proven".
    #[arg(long)]
    dkim_selector: Vec<String>,

    /// Output file path (for html/text; tui always goes to stdout)
    #[arg(short, long)]
    out: Option<String>,

    /// PostgreSQL URL for the sealed-history store (env: RS_STORE_URL).
    /// When set, every scan is persisted sealed — the store computes the
    /// seal itself from the verdict; nothing here can alter it.
    #[arg(long, env = "RS_STORE_URL")]
    store_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let audience = match args.audience.as_str() {
        "blue" => Audience::BlueTeam,
        "red" => Audience::RedTeam,
        other => anyhow::bail!("--audience must be 'blue' or 'red', got {other:?}"),
    };

    // Same resolver as TUI and web: validating, DNSSEC-capable.
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()?;

    // Scan once — the ScoredAnalysis feeds every renderer.
    let mut analyses = Vec::with_capacity(args.domains.len());
    for domain in &args.domains {
        eprintln!("scanning {domain} …");
        analyses.push(analyse_domain_with_selectors(&resolver, domain, &args.dkim_selector).await?);
    }

    match args.format.as_str() {
        "tui" => {
            // Terminal summary: worst-first findings list + score.
            let summary = render::render_tui_summary(&analyses, audience);
            println!("{summary}");
        }
        "text" => {
            let text = render::render_text_report(&analyses);
            match &args.out {
                Some(path) => {
                    std::fs::write(path, &text)?;
                    eprintln!("wrote {path}");
                }
                None => println!("{text}"),
            }
        }
        "html" => {
            let html = render::render_html_page(&analyses, audience);
            let path = args.out.unwrap_or_else(|| "report.html".to_string());
            std::fs::write(&path, html)?;
            eprintln!("wrote {path}");
        }
        "all" => {
            // Terminal summary to stdout.
            let summary = render::render_tui_summary(&analyses, audience);
            println!("{summary}");

            // Text report to file if --out, else stdout after a separator.
            let text = render::render_text_report(&analyses);
            if let Some(path) = &args.out {
                let text_path = format!("{path}.txt");
                std::fs::write(&text_path, &text)?;
                eprintln!("wrote {text_path}");
            } else {
                println!("\n--- TEXT REPORT ---\n{text}");
            }

            // HTML page to file.
            let html = render::render_html_page(&analyses, audience);
            let html_path = args
                .out
                .as_deref()
                .map(|p| format!("{p}.html"))
                .unwrap_or_else(|| "report.html".to_string());
            std::fs::write(&html_path, html)?;
            eprintln!("wrote {html_path}");
        }
        other => anyhow::bail!("--format must be 'tui', 'text', 'html', or 'all', got {other:?}"),
    }

    // Sealed history: when a store is configured, every verdict is persisted
    // with a store-computed seal (never caller-supplied) and the row id +
    // seal prefix are echoed so the run is citable.
    if let Some(url) = &args.store_url {
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
