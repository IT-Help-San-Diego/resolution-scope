//! Resolution Scope web renderer v0 — one static report page, real engine
//! output, zero copied RFC/verdict logic.
//!
//! The second consumer of engine::truth_chain (the TUI is the first): it
//! proves the single-producer contract works outside the terminal before the
//! flipper adds surface-switching. Scans the given domains through the same
//! engine the TUI uses and writes one self-contained HTML page.
//!
//!     rs-web -d example.com -d resolutionscope.com -o report.html
//!     rs-web -d example.com --audience red

mod render;

use anyhow::Result;
use clap::Parser;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::truth_chain::Audience;

#[derive(Parser)]
#[command(
    name = "rs-web",
    about = "Resolution Scope — static web report from the truth-chain model"
)]
struct Args {
    /// Domain(s) to scan (repeatable)
    #[arg(short, long, required = true)]
    domains: Vec<String>,
    /// Output file path
    #[arg(short, long, default_value = "report.html")]
    out: String,
    /// Consequence framing: blue (defend) or red (assess)
    #[arg(long, default_value = "blue")]
    audience: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let audience = match args.audience.as_str() {
        "blue" => Audience::BlueTeam,
        "red" => Audience::RedTeam,
        other => anyhow::bail!("--audience must be 'blue' or 'red', got {other:?}"),
    };

    // Same resolver construction as the TUI: validating, DNSSEC-capable.
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()?;

    let mut analyses = Vec::with_capacity(args.domains.len());
    for domain in &args.domains {
        eprintln!("scanning {domain} …");
        analyses.push(analyse_domain(&resolver, domain).await?);
    }

    let page = render::render_page(&analyses, audience);
    std::fs::write(&args.out, page)?;
    eprintln!("wrote {}", args.out);
    Ok(())
}
