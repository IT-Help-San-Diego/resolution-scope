// =============================================================================
// resolution-scope-engine — main.rs
// =============================================================================
//
// Entry point for the `dns-sovereign` binary.
//
// Architecture note (seL4 boundary):
//   tokio and hickory-dns run HERE — in the query engine process that lives
//   OUTSIDE the seL4 compartment boundary.  This binary must never be linked
//   into an seL4 compartment image.  See:
//   docs/ARCHITECTURE.md §1
//
// DNSSEC guard:
//   The compile_error! guard in lib.rs fires before this file is compiled if
//   dnssec-ring is absent, so there is no need to repeat it here.
//

use anyhow::Result;
use tracing::info;

// Pull in the library crate (same Cargo package, different compilation unit).
// (analyse_domain is reached via resolution_scope_engine::analysis::analyse_domain.)

// =============================================================================
// Async runtime — OUTSIDE seL4 compartment (see architecture note above)
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // ── Observability ──────────────────────────────────────────────────────
    //
    // RUST_LOG controls verbosity, e.g.:
    //   RUST_LOG=resolution_scope_engine=debug,hickory_resolver=warn  cargo run
    //
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "resolution-scope-engine starting"
    );

    // ── DNS resolver with DNSSEC-ring ──────────────────────────────────────
    //
    // ResolverConfig::default() + ResolverOpts with validate = true ensures
    // hickory performs DNSSEC chain validation on every response.
    // The dnssec-ring feature gate (Cargo.toml) must be active; the
    // compile_error! in lib.rs guarantees it is.
    //
    let resolver = build_resolver().await?;

    // ── CLI: one or more domains, optional --json for machine output ────────
    //   resolution-scope-engine example.com cloudflare.com
    //   resolution-scope-engine --json example.com
    // Default (no --json) prints the human report (report::render_text).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let domains: Vec<String> = args.into_iter().filter(|a| a != "--json").collect();
    let domains = if domains.is_empty() {
        vec!["example.com".to_string()]
    } else {
        domains
    };

    for domain in &domains {
        info!(domain = %domain, "running analysis");
        let result = resolution_scope_engine::analysis::analyse_domain(&resolver, domain).await?;
        if json {
            // One JSON object per line — machine-consumable, no trailing newline noise.
            println!("{}", serde_json::to_string(&result)?);
        } else {
            print!("{}", resolution_scope_engine::report::render_text(&result));
        }
    }

    info!("done");
    Ok(())
}

// =============================================================================
// Resolver construction
// =============================================================================

async fn build_resolver() -> Result<hickory_resolver::TokioResolver> {
    use hickory_resolver::{
        config::{ResolverConfig, ResolverOpts},
        TokioResolver,
    };

    let mut opts = ResolverOpts::default();

    // DNSSEC chain validation — the reason dnssec-ring must be compiled in.
    opts.validate = true;

    // Do not use the system stub resolver; use a known recursive resolver so
    // DNSSEC validation is not silently bypassed by a non-validating upstream.
    let resolver = TokioResolver::builder_with_config(
        // NOTE: DoT (ResolverConfig::tls) fails at hickory 0.26.1 with
        // "no connections available" — the TLS connection path never reaches
        // the handshake (connections die at selection). Reproduced with
        // RUST_LOG trace 2026-08-18; UDP+TCP works. Transport nicety, not a
        // verdict-correctness question — file upstream, use udp_and_tcp here.
        ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
        hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()?;

    info!("resolver constructed (DNSSEC validate=true, DoT/Cloudflare)");
    Ok(resolver)
}
