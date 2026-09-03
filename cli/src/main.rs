//! Resolution Scope — one binary, three verbs.
//!
//! The single user-facing surface. `engine` and `store` stay libraries; the
//! interactive dashboard is `tui.rs`; every renderer is `render.rs`; the input
//! boundary is `input.rs`. One scan, any output — all of it delegating to
//! engine::truth_chain() (the single-producer contract, ARCHITECTURE.md §8).
//!
//!     resolution-scope example.com                 # measure + report (default verb)
//!     resolution-scope example.com --format html   # static page, seal included
//!     resolution-scope example.com --format json   # machine output (Arm 1) + seal
//!     resolution-scope example.com --format text   # the engine's own minimal render
//!     resolution-scope tui example.com             # interactive dashboard
//!     resolution-scope history example.com         # sealed-history verb (store)
//!
//! Flags are validated at parse time (clap value enums), and every domain
//! passes `input::canonical_domain` BEFORE any network: a pasted URL or an
//! empty `$VAR` is refused with the fix named, never scanned into eight
//! "transient — re-run" rows.

mod input;
mod tui;
mod wire;

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::str::FromStr;

use resolution_scope_engine::analysis::analyse_domain_with_receipts;
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use resolution_scope_engine::truth_chain::Audience;
use resolution_scope_render as render;

/// The `--resolver` help. The first paragraph is the `-h` short help; the
/// rest is `--help`. One line serves the office person and the DNS engineer
/// without condescending to either; every claim is checkable with tcpdump.
const RESOLVER_HELP: &str = "\
Which resolver answers, and how the questions travel. Sealed as the vantage.

The same domain measured through two resolvers is two measurements; they never
seal alike. Whatever a report prints after \"resolver\" is a valid value here —
pass it back to repeat the measurement. Whatever you choose, DNSSEC is
validated on this machine against the root keys; the resolver's word is never
taken for it. Before the first scan two control lookups prove the vantage can
validate at all (the root DNSKEY must come back Secure, dnssec-failed.org must
be refused). If they fail, nothing is sealed. There is no way to skip that
check: skipping would be a silent downgrade.

  cloudflare (default) | quad9 | google | dns4eu | opendns
      a public resolver by name — Cloudflare (1.1.1.1), Quad9 (9.9.9.9),
      Google (8.8.8.8), DNS4EU (86.54.11.100, unfiltered), OpenDNS (208.67.222.222)
  system
      the resolver this machine already uses. On macOS that is the GLOBAL
      resolver only (the first block of scutil --dns): a VPN's per-domain or
      scoped resolvers are not read and never asked — a name your VPN would
      answer privately goes to the global resolver instead. Linux:
      /etc/resolv.conf. Sealed as the word \"system\": its address changes with
      every network, the instrument may use any of the addresses listed, and
      the addresses actually sent to are printed beside the seal, never in it.
  9.9.9.9 | 9.9.9.9#5353 | [2620:fe::fe]
      a resolver by address. A private address (192.168.x.x, 10.x, 127.x) is
      sealed as typed and printed on any report you share — you are warned.

Put a transport in front to encrypt the questions in transit:
  tls://quad9                   DNS over TLS   — TCP 853, certificate checked
  https://quad9                 DNS over HTTPS — TCP 443, certificate checked
  quic://quad9                  DNS over QUIC  — UDP 853 (when measured 2026-09-03 only Quad9 answered)
  h3://cloudflare               DNS over HTTP/3 — UDP 443 (when measured 2026-09-03 Cloudflare and Google answered)
  tcp://quad9                   plain DNS, TCP 53 only
  tls://9.9.9.9/dns.quad9.net   an address plus the name on its certificate

No transport = plain DNS on port 53: every name you scan is readable on the
wire between this machine and the resolver. \"system\" is always plain. An
encrypted transport hides the names from the path, not from the resolver — it
always sees them — and the MTA-STS check still names your domain once, in the
TLS handshake to mta-sts.<domain> (SNI). Quad9 (9.9.9.9) blocks domains on its
threat list: a blocked domain reads here as absent (vendor-documented, not
measured by this instrument). Google forwards part of your address (ECS) to
the domain's nameservers; Cloudflare and Quad9 do not; OpenDNS says it does
(vendor documentation, read 2026-09-03). Not offered by this build's library
(hickory 0.26.1): ODoH, DNSCrypt, post-quantum key exchange.";

const ABOUT: &str = "Resolution Scope — a sovereign instrument for measuring DNS resolution: \
what a domain actually publishes, verified against the protocol and sealed so anyone can re-check it.";

const LONG_ABOUT: &str = "\
Resolution Scope measures ten controls on a domain — DNSSEC, SPF, DKIM, DMARC, \
DANE, MTA-STS, TLS-RPT, CAA, CDS/CDNSKEY, CSYNC — through one resolver you \
choose (Cloudflare by default), with DNSSEC validated by the instrument itself, \
and renders the same truth-chain (RFC requirement → measured state → \
consequence) on every surface.

Every verdict carries a SEAL: a SHA3-512 digest over the exact verdict bytes, printed \
beside the verdict so anyone holding the report can re-derive it. The seal is \
tamper-evidence — it proves the verdict you hold is the one that was sealed, nothing more.

Two scores, always together: Coverage (deployed controls over measured controls) and \
Risk-Weighted (the same verdicts weighted by each control's identity, versioned, never \
sealed). Controls that could not be measured, or do not apply, are excluded from both \
and are always shown as such — never guessed.";

const AFTER_HELP: &str = "\
Examples:
  resolution-scope example.com               measure + human report (default)
  resolution-scope example.com --red          red-team framing + scotopic palette
  resolution-scope example.com --format json  machine output | jq .seal
  resolution-scope example.com --format html -o r.html
  resolution-scope example.com --resolver tls://quad9   the same measurement, encrypted in transit
  resolution-scope tui example.com           interactive dashboard
  resolution-scope tui example.com --red     dashboard in red-team mode
  resolution-scope history example.com --store-url postgres://…";

#[derive(Parser)]
#[command(
    name = "resolution-scope",
    about = ABOUT,
    long_about = LONG_ABOUT,
    after_help = AFTER_HELP,
    version,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// The default verb: measure + report.
    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Args, Debug, Clone)]
struct ScanArgs {
    /// Domain(s) to measure, e.g. `example.com` (repeatable).
    #[arg(value_name = "DOMAIN")]
    domains: Vec<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Report)]
    format: Format,

    /// Blue-team framing: defend — what it costs you, what to do. (Default.)
    #[arg(long, group = "framing")]
    blue: bool,

    /// Red-team framing: assess — what it exposes during an authorised
    /// assessment. The scotopic red-on-charcoal palette.
    #[arg(long, group = "framing")]
    red: bool,

    /// DKIM selector(s) to probe ahead of the 81 defaults (repeatable). The
    /// `s=` tag of any outbound DKIM-Signature header is the selector.
    #[arg(long = "dkim", value_name = "SELECTOR")]
    dkim_selector: Vec<String>,

    #[arg(long, env = "RS_RESOLVER", value_name = "RESOLVER", default_value = "cloudflare", value_parser = ResolverChoice::from_str, help = RESOLVER_HELP.lines().next().unwrap(), long_help = RESOLVER_HELP)]
    resolver: ResolverChoice,

    /// Write the report here instead of stdout (html defaults to report.html).
    #[arg(short, long, value_name = "PATH")]
    out: Option<String>,

    /// PostgreSQL URL of the sealed-history store; when set, every verdict is
    /// recorded with a store-computed seal.
    #[arg(long, env = "RS_STORE_URL", value_name = "URL")]
    store_url: Option<String>,

    /// Null scan: measure but keep nothing. Persistence is the DEFAULT (§3a —
    /// a scan is a sealed fact, and you don't silently discard a scientist's
    /// data); this is the one explicit, irreversible opt-out, mirroring the
    /// website's "null scan".
    #[arg(long)]
    discard: bool,
}

#[derive(Args, Debug, Clone)]
struct TuiArgs {
    /// Domain(s) to measure (repeatable); Tab cycles between them.
    #[arg(value_name = "DOMAIN")]
    domains: Vec<String>,

    /// Blue-team framing: defend — what it costs you, what to do. (Default.)
    /// Press `m` to flip live — palette and framing together.
    #[arg(long, group = "framing")]
    blue: bool,

    /// Red-team framing: assess — what it exposes during an authorised
    /// assessment. The scotopic red-on-charcoal palette. Press `m` to flip
    /// live — palette and framing together.
    #[arg(long, group = "framing")]
    red: bool,

    /// DKIM selector(s) to probe ahead of the 81 defaults (repeatable).
    #[arg(long = "dkim", value_name = "SELECTOR")]
    dkim_selector: Vec<String>,

    #[arg(long, env = "RS_RESOLVER", value_name = "RESOLVER", default_value = "cloudflare", value_parser = ResolverChoice::from_str, help = RESOLVER_HELP.lines().next().unwrap(), long_help = RESOLVER_HELP)]
    resolver: ResolverChoice,
}

#[derive(Args, Debug, Clone)]
struct HistoryArgs {
    /// Domain(s) whose sealed history to list (repeatable).
    #[arg(value_name = "DOMAIN")]
    domains: Vec<String>,

    /// PostgreSQL URL of the sealed-history store.
    #[arg(long, env = "RS_STORE_URL", value_name = "URL")]
    store_url: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Interactive dashboard — measures, then keeps the truth-chain live.
    Tui(TuiArgs),
    /// Sealed scan history — reads the store and re-checks every seal. Does NOT scan.
    History(HistoryArgs),
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Human report: findings in tiers, both scores, seal + re-derive block.
    Report,
    /// Compact at-a-glance listing (no RFC layer, no re-derive block).
    Summary,
    /// Static HTML page, seal included.
    Html,
    /// Machine output: the engine's verdict object plus seal and scores.
    Json,
    /// The engine's own minimal render (the compartment's proof surface).
    Text,
}

/// Build the vantage for a choice and run the preflight: the private-address
/// warning, then both controls. A refusal prints the fix and exits 3 —
/// nothing sealed, nothing stored. Same for every scanning verb.
async fn vantage_for(
    choice: ResolverChoice,
) -> Result<(
    Arc<Vantage>,
    resolution_scope_engine::preflight::VantageReceipt,
)> {
    if let Some(w) = choice.private_address_warning() {
        eprintln!("{w}");
    }
    let vantage =
        Vantage::build(choice.clone()).map_err(|e| anyhow::anyhow!("vantage refused: {e}"))?;
    match vantage.preflight().await {
        Ok(receipt) => {
            eprint!("{}", wire::vantage_line(&receipt, &choice));
            Ok((Arc::new(vantage), receipt))
        }
        Err(refusal) => {
            eprint!("{}", wire::refusal(&refusal, &choice));
            std::process::exit(3); // exit 3 = vantage refused (2 = corpus-excluded, 1 = scan error)
        }
    }
}

/// The verb names. A DOMAIN equal to one of these is a mis-ordered
/// invocation (`resolution-scope example.com history`), never a zone to
/// measure — clap stops recognising verbs once a root argument has been
/// seen, so this boundary catches it before 14s of NXDOMAIN probing (or,
/// with a store, a sealed row for a domain named "history").
const VERBS: [&str; 3] = ["tui", "history", "help"];

/// Canonicalise the positional domain list through the input boundary.
/// Empty → a usage error naming the form.
fn domains_from(domains: &[String]) -> Result<Vec<String>> {
    if domains.is_empty() {
        anyhow::bail!("at least one domain is required (e.g. `resolution-scope example.com`)");
    }
    let is_verb = |d: &String| VERBS.contains(&d.to_ascii_lowercase().as_str());
    if let Some(verb) = domains.iter().find(|d| is_verb(d)) {
        let example = domains
            .iter()
            .find(|d| !is_verb(d))
            .map(String::as_str)
            .unwrap_or("example.com");
        anyhow::bail!(
            "{verb:?} is a verb, not a domain — the verb goes first: `resolution-scope {verb} {example}`"
        );
    }
    Ok(input::canonical_domains(domains)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Tui(args)) => {
            let domains = domains_from(&args.domains)?;
            let audience = if args.red {
                Audience::RedTeam
            } else {
                Audience::BlueTeam
            };
            let (vantage, receipt) = vantage_for(args.resolver).await?;
            tui::run(vantage, receipt, domains, args.dkim_selector, audience).await
        }
        Some(Command::History(args)) => {
            let url = args
                .store_url
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("history requires --store-url (or RS_STORE_URL)"))?;
            let domains = domains_from(&args.domains)?;
            // A read verb does not migrate: it must work under a read-only
            // database role, and "does NOT scan" should also mean "does not
            // write". An uninitialised store reads back as an error that
            // names the fix.
            let store = resolution_scope_store::Store::connect(url).await?;
            for domain in &domains {
                let history = match store.scan_history(domain).await {
                    Ok(h) => h,
                    Err(e) if e.to_string().contains("does not exist") => {
                        return Err(e).with_context(|| {
                            format!(
                                "reading history for {domain}: the store has no schema yet — \
                                 run one scan with --store-url first to initialise it"
                            )
                        });
                    }
                    Err(e) => {
                        return Err(e).with_context(|| format!("reading history for {domain}"))
                    }
                };
                print!("{}", render::render_history(domain, &history));
            }
            Ok(())
        }
        // Default verb: measure + render.
        None => scan(cli.scan).await,
    }
}

async fn scan(args: ScanArgs) -> Result<()> {
    let domains = domains_from(&args.domains)?;
    let audience: Audience = if args.red {
        Audience::RedTeam
    } else {
        Audience::BlueTeam
    };
    let (vantage, _receipt) = vantage_for(args.resolver.clone()).await?;
    let choice = vantage.choice().clone();
    let store_dsn = resolve_store_dsn(args.store_url.as_deref(), args.discard);

    let mut analyses = Vec::with_capacity(domains.len());
    // Layer-4 receipts, one Vec per domain, index-paired with `analyses`.
    // Kept OUTSIDE ScoredAnalysis: receipts are beside-the-seal provenance
    // (R-B) and must never ride the sealed struct.
    let mut all_receipts = Vec::with_capacity(domains.len());
    // Raw records captured at classification — also BESIDE the seal (R-B),
    // one Vec per domain, index-paired with `analyses`.
    let mut all_records = Vec::with_capacity(domains.len());
    for domain in &domains {
        // Corpus exclusion guard — the FIRST check, before any resolution,
        // scoring, store write, or seal (anti-badge-cheat: a fixture that
        // could count as a discovery is manufactured evidence). Both PQ
        // windows carry this in their signed TXT; this makes it mechanical
        // for every surface that reaches the engine.
        if resolution_scope_engine::corpus_filter::is_corpus_excluded(domain) {
            eprintln!(
                "info: {domain} is excluded from corpus statistics (labeled experimental fixture; corpus-excluded=YES in its signed TXT)"
            );
            eprintln!("      scanned by other instruments, never counted by this one");
            std::process::exit(2); // exit 2 = excluded (distinct from scan error 1)
        }
        // Real progress only: what is being measured, from where, and how
        // long it took. Per-control progress needs an engine hook (the
        // scorers run inside one call); until then the instrument says what
        // it is doing and reports the measured elapsed time — never a fake
        // percentage.
        eprintln!(
            "{}",
            wire::progress_line(
                domain,
                &choice,
                resolution_scope_engine::truth_chain::ControlId::ALL.len()
            )
        );
        let started = Instant::now();
        let (a, receipts, records) =
            analyse_domain_with_receipts(&vantage, domain, &args.dkim_selector).await?;
        eprintln!(
            "measured {domain} in {:.1}s — seal {}… ({} receipts, {} records)",
            started.elapsed().as_secs_f64(),
            &resolution_scope_engine::seal::seal(&a)[..16],
            receipts.len(),
            records.len()
        );
        // The wire block: what left this machine for THIS domain, counted at
        // the socket. Drained per domain so every block is exact.
        let snapshot = vantage.ledger().drain();
        let facts = wire::WireFacts {
            domain,
            mta_sts_hint_absent: a.mta_sts_disposition
                == resolution_scope_engine::MtaStsDisposition::RecordAbsent,
            answered: receipts.iter().any(|r| r.answer_count > 0),
            store_url: store_dsn.as_deref(),
        };
        eprint!("{}", wire::render(&snapshot, &choice, &facts));
        analyses.push(a);
        all_receipts.push(receipts);
        all_records.push(records);
    }

    let (body, default_path): (String, Option<&str>) = match args.format {
        Format::Report => (render::render_report(&analyses, audience), None),
        Format::Summary => (render::render_summary(&analyses, audience), None),
        Format::Text => (render::render_text_report(&analyses), None),
        Format::Json => (render::render_json(&analyses), None),
        Format::Html => (
            render::render_html_page(&analyses, audience),
            Some("report.html"),
        ),
    };

    match args.out.as_deref().or(default_path) {
        Some(path) => {
            std::fs::write(path, &body).with_context(|| format!("writing {path}"))?;
            eprintln!("wrote {path}");
        }
        None => print!("{body}"),
    }

    // Persist-by-default (§3a, Carey): a scan is a sealed fact — it persists
    // unless the operator explicitly says --discard. Resolution order:
    //   --discard → no store (null scan)
    //   --store-url / RS_STORE_URL → that DSN
    //   default → postgres://localhost:<RS_DB_PORT>/resolution_scope
    //   unreachable → refuse-and-instruct, never silently drop the data.
    match store_dsn {
        None => eprintln!(
            "discarded {} verdict(s) — --discard (null scan)",
            analyses.len()
        ),
        Some(url) => {
            match resolution_scope_store::Store::connect(&url).await {
                Ok(mut store) => {
                    store.migrate().await?;
                    for (a, receipts, records) in analyses
                        .iter()
                        .zip(all_receipts.iter())
                        .zip(all_records.iter())
                        .map(|((a, r), rec)| (a, r, rec))
                    {
                        let id = store.record_scan(a, receipts, records).await?;
                        let seal = resolution_scope_engine::seal::seal(a);
                        eprintln!(
                            "stored {} as scan #{id} (+{} receipts, +{} records, seal {}…)",
                            a.domain,
                            receipts.len(),
                            records.len(),
                            &seal[..16]
                        );
                    }
                }
                Err(e) => {
                    // Refuse-and-instruct: the tool won't silently discard the
                    // work. The DSN is redacted — a credential is never echoed.
                    let shown = redact_dsn(&url);
                    anyhow::bail!(
                        "no store reachable at {shown}: {e}\n\n\
                         resolution-scope persists every scan by default — your data, on your machine, yours.\n\
                         To bootstrap the local store:\n\n\
                         \x20   docker compose up -d   # starts local Postgres for resolution-scope\n\n\
                         Or set RS_STORE_URL to point at an existing Postgres.\n\
                         Or pass --discard to run a null scan (measure but keep nothing)."
                    );
                }
            }
        }
    }

    Ok(())
}

/// Resolve the store DSN from the flags + env, per the §3a resolution order.
/// Returns `None` when `--discard` (null scan). The default is the local
/// compose store; `RS_DB_PORT` matches the compose publish so the two never
/// drift (port doctrine).
fn resolve_store_dsn(store_url: Option<&str>, discard: bool) -> Option<String> {
    if discard {
        return None;
    }
    if let Some(u) = store_url {
        return Some(u.to_string());
    }
    let port = std::env::var("RS_DB_PORT").unwrap_or_else(|_| "5435".to_string());
    Some(format!(
        "postgres://resolution_scope:resolution_scope_local@localhost:{port}/resolution_scope"
    ))
}

/// Redact the password from a postgres URL for safe display in an error
/// message. A DSN is a credential; it must never be echoed verbatim.
fn redact_dsn(url: &str) -> String {
    match url.find("://") {
        Some(scheme_end) => {
            let after = &url[scheme_end + 3..];
            match after.find('@') {
                Some(at) => {
                    let auth = &after[..at];
                    if auth.contains(':') {
                        // There is a password → redact it.
                        let user = auth.split(':').next().unwrap_or("");
                        format!("{}://{}:***{}", &url[..scheme_end], user, &after[at..])
                    } else {
                        // No password → nothing to redact.
                        url.to_string()
                    }
                }
                None => url.to_string(),
            }
        }
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// `Cli` carries no Debug (clap's Parser does not need it); take the error.
    fn refused(args: &[&str]) -> String {
        match Cli::try_parse_from(args) {
            Ok(_) => panic!("{args:?} should be refused"),
            Err(e) => e.to_string(),
        }
    }

    /// clap's own consistency check: conflicting or mis-declared arguments
    /// panic here instead of at the first user's keyboard.
    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    /// The documented invocation must parse — `resolution-scope example.com`
    /// was rejected as an "unrecognized subcommand" on 2026-08-23 while every
    /// doc (and the tool's own error message) recommended exactly that form.
    #[test]
    fn positional_domain_is_the_default_verb() {
        let cli = Cli::try_parse_from(["resolution-scope", "example.com"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.scan.domains, vec!["example.com"]);
        assert_eq!(cli.scan.format, Format::Report);
    }

    #[test]
    fn format_and_framing_are_validated_at_parse_time() {
        // Before: `-f yaml` scanned the domain and THEN errored.
        assert!(Cli::try_parse_from(["resolution-scope", "x.com", "-f", "yaml"]).is_err());
        // --blue and --red are the allowed framing flags.
        let ok = Cli::try_parse_from(["resolution-scope", "x.com", "-f", "json", "--red"]).unwrap();
        assert_eq!(ok.scan.format, Format::Json);
        assert!(ok.scan.red);
    }

    #[test]
    fn verbs_own_their_flags() {
        // tui has no --format; the scan verb has no tui-only flags.
        assert!(
            Cli::try_parse_from(["resolution-scope", "tui", "x.com", "--format", "html"]).is_err()
        );
        // --red is valid on both scan and tui.
        let tui = Cli::try_parse_from(["resolution-scope", "tui", "x.com", "--red"]).unwrap();
        assert!(matches!(
            tui.command,
            Some(Command::Tui(TuiArgs { red: true, .. }))
        ));
        let scan = Cli::try_parse_from(["resolution-scope", "x.com", "--red"]).unwrap();
        assert!(scan.scan.red);
    }

    /// `resolution-scope example.com history` must not measure a domain
    /// called "history" (clap hands the verb to the DOMAIN list once a root
    /// argument has been seen).
    #[test]
    fn a_verb_after_a_domain_is_refused_with_the_right_order_named() {
        let cli = Cli::try_parse_from(["resolution-scope", "example.com", "history"]).unwrap();
        assert!(cli.command.is_none(), "clap parses it as two domains");
        let err = domains_from(&cli.scan.domains).unwrap_err();
        assert!(
            err.to_string()
                .contains("`resolution-scope history example.com`"),
            "{err}"
        );
        let err = domains_from(&["TUI".to_string()]).unwrap_err();
        assert!(err
            .to_string()
            .contains("`resolution-scope TUI example.com`"));
    }

    /// K1 — `--resolver` parses on both scanning verbs and not on `history`.
    #[test]
    fn resolver_flag_parses_on_scan_and_tui() {
        let scan = Cli::try_parse_from(["resolution-scope", "x.com", "--resolver", "tls://quad9"])
            .unwrap();
        assert_eq!(scan.scan.resolver.identity(), "quad9/tls");
        let tui = Cli::try_parse_from(["resolution-scope", "tui", "x.com", "--resolver", "quad9"])
            .unwrap();
        match tui.command {
            Some(Command::Tui(t)) => assert_eq!(t.resolver.identity(), "quad9"),
            _ => panic!("tui verb"),
        }
        assert!(Cli::try_parse_from([
            "resolution-scope",
            "history",
            "x.com",
            "--resolver",
            "quad9"
        ])
        .is_err());
    }

    /// K2 — the default is Cloudflare over plain 53, identity "cloudflare".
    #[test]
    fn resolver_flag_default_is_cloudflare_plain() {
        let cli = Cli::try_parse_from(["resolution-scope", "x.com"]).unwrap();
        assert_eq!(cli.scan.resolver, ResolverChoice::default());
        assert_eq!(cli.scan.resolver.identity(), "cloudflare");
    }

    /// K3 — refusals happen at parse time, before any network, with the fix
    /// named (like `-f yaml`).
    #[test]
    fn resolver_flag_refuses_hostnames_and_reserved_words_with_the_fix_named() {
        let err = refused(&[
            "resolution-scope",
            "x.com",
            "--resolver",
            "tls://dns.quad9.net",
        ]);
        assert!(err.contains("tls://9.9.9.9/dns.quad9.net"), "{err}");
        let err = refused(&["resolution-scope", "x.com", "--resolver", "default"]);
        assert!(err.contains("spelled `cloudflare`"), "{err}");
        let err = refused(&["resolution-scope", "x.com", "--resolver", "tls://system"]);
        assert!(err.contains("tls://quad9"), "{err}");
    }

    /// K4 — `RS_RESOLVER` is honoured (the `RS_STORE_URL` pattern) on both
    /// scanning verbs, and an explicit flag wins over it. The environment is
    /// not mutated (tests run in parallel); clap's declaration is asserted,
    /// and the precedence is exercised by parsing with the flag present.
    #[test]
    fn resolver_flag_reads_rs_resolver_env() {
        let cmd = Cli::command();
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_id() == "resolver")
            .expect("--resolver on the scan verb");
        assert_eq!(arg.get_env().and_then(|e| e.to_str()), Some("RS_RESOLVER"));
        let tui = cmd.find_subcommand("tui").unwrap();
        let arg = tui
            .get_arguments()
            .find(|a| a.get_id() == "resolver")
            .expect("--resolver on the tui verb");
        assert_eq!(arg.get_env().and_then(|e| e.to_str()), Some("RS_RESOLVER"));
        assert!(cmd
            .find_subcommand("history")
            .unwrap()
            .get_arguments()
            .all(|a| a.get_id() != "resolver"));
        // The flag wins over any environment.
        let cli =
            Cli::try_parse_from(["resolution-scope", "x.com", "--resolver", "quad9"]).unwrap();
        assert_eq!(cli.scan.resolver.identity(), "quad9");
    }

    #[test]
    fn domains_pass_the_input_boundary() {
        let got = domains_from(&["EXAMPLE.COM.".to_string()]).unwrap();
        assert_eq!(got, ["example.com"]);
        let err = domains_from(&["https://example.com/".to_string()]).unwrap_err();
        assert!(err.to_string().contains("bare domain name"));
        let err = domains_from(&[]).unwrap_err();
        assert!(err.to_string().contains("resolution-scope example.com"));
    }

    /// §3a resolution order: --discard → None; explicit URL wins; default is
    /// the local compose store keyed to RS_DB_PORT (default 5435).
    #[test]
    fn resolve_store_dsn_respects_resolution_order() {
        // --discard is a null scan even when a URL is also given.
        assert_eq!(resolve_store_dsn(None, true), None);
        assert_eq!(resolve_store_dsn(Some("postgres://x"), true), None);

        // An explicit store URL wins over the default.
        assert_eq!(
            resolve_store_dsn(Some("postgres://u:p@h/db"), false).as_deref(),
            Some("postgres://u:p@h/db")
        );

        // The default is the compose store, creds matching the compose fixture.
        let dsn = resolve_store_dsn(None, false).unwrap();
        assert!(
            dsn.starts_with("postgres://resolution_scope:resolution_scope_local@localhost:"),
            "{dsn}"
        );
        assert!(dsn.ends_with("/resolution_scope"), "{dsn}");
    }

    #[test]
    fn redact_dsn_masks_password_only() {
        assert_eq!(
            redact_dsn("postgres://user:hunter2@host:5432/db"),
            "postgres://user:***@host:5432/db"
        );
        // No password → unchanged.
        assert_eq!(
            redact_dsn("postgres://user@host/db"),
            "postgres://user@host/db"
        );
        // No scheme → unchanged.
        assert_eq!(redact_dsn("localhost:5432"), "localhost:5432");
    }
}
