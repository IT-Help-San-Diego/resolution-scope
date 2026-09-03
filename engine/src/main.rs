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
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use tracing::info;

// Pull in the library crate (same Cargo package, different compilation unit).
// (analyse_domain is reached via resolution_scope_engine::analysis::analyse_domain.)

/// What the command line (and `RS_RESOLVER`) asked for.
#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    json: bool,
    choice: ResolverChoice,
    domains: Vec<String>,
}

/// Pure: the argument grammar. `--resolver` (either spelling) wins over
/// `RS_RESOLVER`; the environment is consulted ONLY when no flag was typed.
/// The old guard compared the parsed choice to the default, so a typed
/// `--resolver cloudflare` under `RS_RESOLVER=tls://quad9` was silently
/// overridden and the seal carried `quad9/tls` — not what the operator
/// typed. `env_resolver` is a parameter, not a `std::env` read, so the
/// tests exercise both controls without touching the process environment.
fn parse_invocation(args: Vec<String>, env_resolver: Option<&str>) -> Result<Invocation> {
    let mut json = false;
    let mut choice = ResolverChoice::default();
    let mut flag_given = false;
    let mut domains: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--resolver" => {
                let Some(value) = it.next() else {
                    anyhow::bail!("--resolver needs a value: cloudflare | quad9 | google | dns4eu | opendns | system | an address, optionally behind tcp://, tls://, https://, quic://, h3://");
                };
                choice = value
                    .parse::<ResolverChoice>()
                    .map_err(|e| anyhow::anyhow!("--resolver {value}: {e}"))?;
                flag_given = true;
            }
            other => match other.strip_prefix("--resolver=") {
                Some(value) => {
                    choice = value
                        .parse::<ResolverChoice>()
                        .map_err(|e| anyhow::anyhow!("--resolver {value}: {e}"))?;
                    flag_given = true;
                }
                None => domains.push(other.to_string()),
            },
        }
    }
    if let Some(env) = env_resolver {
        if !env.is_empty() && !flag_given {
            choice = env
                .parse::<ResolverChoice>()
                .map_err(|e| anyhow::anyhow!("RS_RESOLVER={env}: {e}"))?;
        }
    }
    let domains = if domains.is_empty() {
        vec!["example.com".to_string()]
    } else {
        domains
    };
    Ok(Invocation {
        json,
        choice,
        domains,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Both controls for the flag-over-environment rule, without mutating
    /// the process environment (tests run in parallel).
    ///
    /// NEGATIVE (the defect): the operator types the DEFAULT, `cloudflare`,
    /// and the environment says quad9 — the typed word must stand. Mutant:
    /// restore `choice == ResolverChoice::default()` as the guard in place
    /// of `!flag_given` → the first assertion reads "quad9" and fails.
    /// POSITIVE: no flag → the environment is honoured, or refused with
    /// the fix named; an empty env is no env.
    #[test]
    fn a_typed_default_is_not_overridden_by_the_environment() {
        let i = parse_invocation(
            args(&["--resolver", "cloudflare", "example.com"]),
            Some("quad9"),
        )
        .unwrap();
        assert_eq!(i.choice.identity(), "cloudflare");
        let i = parse_invocation(args(&["--resolver=cloudflare"]), Some("tls://quad9")).unwrap();
        assert_eq!(i.choice.identity(), "cloudflare");
        // A typed non-default beats the env too.
        let i = parse_invocation(args(&["--resolver", "google"]), Some("quad9")).unwrap();
        assert_eq!(i.choice.identity(), "google");
        // The env is not even parsed when a flag was typed.
        let i = parse_invocation(args(&["--resolver", "cloudflare"]), Some("bogus!")).unwrap();
        assert_eq!(i.choice.identity(), "cloudflare");
        // Positive: no flag → the environment is honoured, or refused.
        let i = parse_invocation(args(&["example.com"]), Some("quad9")).unwrap();
        assert_eq!(i.choice.identity(), "quad9");
        let i = parse_invocation(args(&[]), Some("tls://quad9")).unwrap();
        assert_eq!(i.choice.identity(), "quad9/tls");
        let err = parse_invocation(args(&[]), Some("bogus!")).unwrap_err();
        assert!(err.to_string().starts_with("RS_RESOLVER=bogus!: "), "{err}");
        // Empty env is no env; no env is the default.
        let i = parse_invocation(args(&[]), Some("")).unwrap();
        assert_eq!(i.choice, ResolverChoice::default());
        let i = parse_invocation(args(&[]), None).unwrap();
        assert_eq!(i.choice, ResolverChoice::default());
    }

    #[test]
    fn domains_and_json_parse() {
        let i = parse_invocation(args(&["--json", "a.test", "b.test"]), None).unwrap();
        assert!(i.json);
        assert_eq!(i.domains, ["a.test", "b.test"]);
        assert_eq!(i.choice, ResolverChoice::default());
        let i = parse_invocation(args(&[]), None).unwrap();
        assert_eq!(i.domains, ["example.com"]);
        assert!(!i.json);
        assert!(parse_invocation(args(&["--resolver"]), None).is_err());
        assert!(parse_invocation(args(&["--resolver", "nine"]), None).is_err());
    }
}

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

    // ── CLI: one or more domains, --json for machine output, --resolver ─────
    //   resolution-scope-engine example.com cloudflare.com
    //   resolution-scope-engine --json example.com
    //   resolution-scope-engine --resolver tls://quad9 example.com
    // Default (no --json) prints the human report (report::render_text).
    // `RS_RESOLVER` applies only when no `--resolver` was typed.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Invocation {
        json,
        choice,
        domains,
    } = parse_invocation(args, std::env::var("RS_RESOLVER").ok().as_deref())?;

    // ── The vantage: the choice, the resolver built from it, its ledger ─────
    //
    // DNSSEC chain validation is on for every choice (`ResolverChoice::options`
    // sets validate = true; the dnssec-ring guard in lib.rs makes it real).
    // The vantage seals `choice.identity()` — the engine binary once sealed
    // the literal "default" here for the resolver the CLI sealed as
    // "cloudflare"; it now seals "cloudflare" for the vantage it always
    // measured (Science, two-gaps-closed-and-the-vantage-collision.md).
    //
    // The 2026-08-18 "DoT fails with no connections available" note that
    // lived here was our own feature omission: hickory-net builds an EMPTY
    // TLS root store unless `webpki-roots` is on (src/tls.rs client_config),
    // so every 853 handshake failed UnknownIssuer and the pool reported only
    // NoConnections. engine/Cargo.toml `tls-roots` + the lib.rs guard close it.
    if let Some(w) = choice.private_address_warning() {
        eprintln!("{w}");
    }
    let vantage = Vantage::build(choice)?;
    info!(vantage = %vantage.choice().gloss(), "resolver constructed (DNSSEC validate=true)");

    // Both controls, once, before any seal. A refusal seals nothing: exit 3.
    let receipt = match vantage.preflight().await {
        Ok(r) => r,
        Err(refusal) => {
            eprintln!(
                "vantage refused: {} — {refusal}. Nothing was sealed.",
                vantage.identity()
            );
            std::process::exit(3);
        }
    };
    info!(
        identity = %receipt.identity,
        mode = ?receipt.mode,
        positive = %receipt.positive.1,
        negative = %receipt.negative.1,
        at = %receipt.at_utc,
        "preflight passed"
    );

    for domain in &domains {
        info!(domain = %domain, "running analysis");
        let result = resolution_scope_engine::analysis::analyse_domain(&vantage, domain).await?;
        if json {
            // One JSON object per line — machine-consumable, no trailing newline noise.
            println!("{}", serde_json::to_string(&result)?);
        } else {
            print!("{}", resolution_scope_engine::report::render_text(&result));
        }
        let wire = vantage.ledger().drain();
        info!(
            domain = %domain,
            datagrams = wire.datagrams_sent,
            tcp_connections = wire.tcp_connects,
            quic_sockets = wire.quic_sockets,
            destinations = ?wire.destinations(),
            "egress, counted at the socket"
        );
    }

    info!("done");
    Ok(())
}
