// authorities_probe.rs — step-one probe (gate a) for the receipt column.
//
// The question, asked BEFORE the Layer-4 refactor rather than after it
// (Science's ordering directive, 2026-08-25): does hickory-resolver 0.26.1
// actually POPULATE `NoRecords.authorities` on a validated negative answer?
//
// The struct field EXISTS (verified at vendored source: `authorities:
// Option<Arc<[Record]>>` with its own "important to preserve for DNSSEC
// validation" doc). That is NECESSARY, not SUFFICIENT — nothing has yet
// proven it arrives NON-EMPTY in practice. If it comes back None, threading
// receipts through ten async scorers produces ten call sites that all record
// None, and the defect surfaces after the expensive refactor.
//
// Three arms, one nonexistent name each — the exact specimens the denial-class
// table already names:
//   example.com        Cloudflare compact denial WITH the TYPE128 sentinel
//   microsoft.com      honest NXDOMAIN (conventional)
//   resolutionscope.com  Route53 compact denial WITHOUT the sentinel (class c)
//
// SECOND QUESTION (Science, 2026-08-25): hickory's IN-PROCESS CACHE (on by
// default, cache_size=8192) is the path a production RESCAN hits. Does a
// SECOND lookup of the SAME name return a shrunken authority section — i.e.
// is the grade a function of scan order rather than of the zone? The probe
// now looks each name up twice and reports the authority count both times.
//
// Run:  cargo run --example authorities_probe  (from engine/)
//
// This is a PROBE, not a test — it needs live DNS and is deliberately not in
// the `#[test]` harness (a network test that silently skips is a check that
// cannot fail). It prints the raw wire facts so the evidence is inspectable.

use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::TokioResolver;
use resolution_scope_engine::denial_proof::extract_denial_proof;

/// One lookup of a (nonexistent) name: report rcode, authority count, and the
/// grade the classifier would emit from those authorities.
fn report(domain: &str, call: usize, e: &NetError) {
    let (rcode, authorities, proof) = match e {
        NetError::Dns(DnsError::NoRecordsFound(nr)) => {
            let auth_slice: &[hickory_proto::rr::Record] = nr.authorities.as_deref().unwrap_or(&[]);
            (
                format!("{:?}", nr.response_code),
                auth_slice.len(),
                extract_denial_proof(auth_slice),
            )
        }
        other => (
            format!("{other:?}"),
            0,
            resolution_scope_engine::denial_proof::DenialProof::None,
        ),
    };
    println!(
        "[{domain}] call#{call} rcode={rcode}  authorities_present={authorities}  denial_proof={proof:?}"
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()?;

    for domain in ["example.com", "microsoft.com", "resolutionscope.com"] {
        // A name that cannot exist, under a zone that does: the probe target.
        let qname: Name = format!("_receipt-probe-{}.{}.", std::process::id(), domain).parse()?;

        // Two looks at the SAME name — the second exercises the in-process
        // cache. If the authority count shrinks on call#2, the grade is a
        // function of scan order, not of the zone.
        for call in [1usize, 2] {
            match resolver.lookup(qname.clone(), RecordType::A).await {
                Ok(resp) => {
                    println!(
                        "[{domain}] call#{call} OK ({} answers) — no NoRecords path",
                        resp.answers().len()
                    );
                }
                Err(e) => report(domain, call, &e),
            }
        }
    }
    Ok(())
}
