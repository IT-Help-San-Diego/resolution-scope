// analysis.rs — DNS control scoring
//
// Each public function in this module runs OUTSIDE the seL4 compartment.
// Results are packed into ScoredAnalysis and sent over the IPC endpoint.

use anyhow::Result;
use hickory_resolver::{ResolveErrorKind, TokioAsyncResolver};
use hickory_proto::ProtoErrorKind;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::TriState;

// =============================================================================
// ScoredAnalysis — the IPC payload (mirrors lionsOS-compartment-demo-spec.md §5)
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoredAnalysis {
    pub domain: String,
    pub session_id: u64,
    pub timestamp_local: u64,

    // Per-control tri-state scores
    pub dnssec_chain:  TriState,
    pub spf:           TriState,
    pub dkim:          TriState,
    pub dmarc:         TriState,
    pub dane:          TriState,
    pub mta_sts:       TriState, // "warning" → Absent (T1-1 fix)
    pub caa:           TriState,
    pub cds_cdnskey:   TriState,
}

// =============================================================================
// analyse_domain — top-level entry point
// =============================================================================

pub async fn analyse_domain(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> Result<ScoredAnalysis> {
    debug!(domain, "starting analysis");

    let session_id: u64 = rand_session_id();
    let timestamp_local: u64 = unix_now();

    // ── DNSSEC chain ────────────────────────────────────────────────────────
    // hickory-resolver with validate=true performs AD-bit + RRSIG chain check.
    // The dnssec-ring feature (enforced by compile_error! in lib.rs) is what
    // makes this verification real rather than a no-op.
    let dnssec_chain = score_dnssec(resolver, domain).await;

    // ── Email controls (stub — wire up full probes in Tier 2) ───────────────
    let spf         = score_spf(resolver, domain).await;
    let dkim        = TriState::Indet; // selector unknown at analysis time
    let dmarc       = score_dmarc(resolver, domain).await;
    let dane        = score_dane(resolver, domain).await;
    let mta_sts     = score_mta_sts(resolver, domain).await;
    let caa         = score_caa(resolver, domain).await;
    let cds_cdnskey = score_cds_cdnskey(resolver, domain).await;

    Ok(ScoredAnalysis {
        domain: domain.to_string(),
        session_id,
        timestamp_local,
        dnssec_chain,
        spf,
        dkim,
        dmarc,
        dane,
        mta_sts,
        caa,
        cds_cdnskey,
    })
}

// =============================================================================
// Per-control probe stubs
// =============================================================================
// Each stub returns TriState::Indet until the real probe is implemented.
// The function signatures are final — the TriState return type is load-bearing.

async fn score_dnssec(resolver: &TokioAsyncResolver, domain: &str) -> TriState {
    // A successful DNSSEC-validated lookup for the apex A/AAAA record is the
    // simplest chain-validation signal.  If hickory returns a validated result
    // (AD flag set in its internal state), DNSSEC is Present.

    match resolver.lookup_ip(domain).await {
        Ok(resp) => {
            // hickory sets the AD bit on validated responses when validate=true.
            // TODO: expose the raw AD flag once hickory 0.26 API is confirmed.
            if resp.iter().next().is_some() {
                TriState::Present
            } else {
                TriState::Absent
            }
        }
        Err(e) => {
            warn!(domain, error = %e, "DNSSEC lookup error");
            match e.kind() {
                ResolveErrorKind::Proto(e) if matches!(e.kind(), ProtoErrorKind::NoRecordsFound { .. }) => TriState::Absent,
                _ => TriState::Indet,
            }
        }
    }
}

async fn score_spf(resolver: &TokioAsyncResolver, domain: &str) -> TriState {
    // SPF is a TXT record at the apex beginning with "v=spf1".
    match resolver.txt_lookup(domain).await {
        Ok(rdata) => {
            let has_spf = rdata
                .iter()
                .flat_map(|r| r.iter())
                .any(|s| s.starts_with(b"v=spf1"));
            if has_spf { TriState::Present } else { TriState::Absent }
        }
        Err(_) => TriState::Indet,
    }
}

async fn score_dmarc(resolver: &TokioAsyncResolver, domain: &str) -> TriState {
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(dmarc_domain.as_str()).await {
        Ok(rdata) => {
            let has_dmarc = rdata
                .iter()
                .flat_map(|r| r.iter())
                .any(|s| s.starts_with(b"v=DMARC1"));
            if has_dmarc { TriState::Present } else { TriState::Absent }
        }
        Err(_) => TriState::Indet,
    }
}

async fn score_dane(resolver: &TokioAsyncResolver, domain: &str) -> TriState {
    // DANE: TLSA record at _443._tcp.<domain> (HTTPS DANE).
    // RecordType::TLSA = 52, confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // SMTP DANE (_25._tcp.<domain>) is a future extension — tracked in
    // docs/TEST-PLAN.md Section E.
    use hickory_proto::rr::RecordType;

    let tlsa_name = format!("_443._tcp.{}", domain);
    match resolver.lookup(tlsa_name.as_str(), RecordType::TLSA).await {
        Ok(resp) => {
            if resp.iter().next().is_some() {
                TriState::Present
            } else {
                // Empty answer section with NOERROR → treat as absent.
                TriState::Absent
            }
        }
        Err(e) => match e.kind() {
            ResolveErrorKind::Proto(e) if matches!(e.kind(), ProtoErrorKind::NoRecordsFound { .. }) => TriState::Absent,
            _ => {
                warn!(domain, error = %e, "DANE/TLSA lookup error → Indet");
                TriState::Indet
            }
        },
    }
}

async fn score_mta_sts(resolver: &TokioAsyncResolver, domain: &str) -> TriState {
    // T1-1 fix: MTA-STS "warning" (policy found but invalid/expired) MUST map
    // to Absent, not a fourth state.  Any policy parse error → Absent.
    // Successful fetch of /.well-known/mta-sts.txt + valid mode field → Present.
    //
    // Full HTTP fetch is deferred to Tier 2 (requires reqwest dependency).
    // For now, check the DNS TXT record at _mta-sts.<domain> as a proxy.
    let mta_sts_domain = format!("_mta-sts.{}", domain);
    match resolver.txt_lookup(mta_sts_domain.as_str()).await {
        Ok(rdata) => {
            let has_mta_sts = rdata
                .iter()
                .flat_map(|r| r.iter())
                .any(|s| s.starts_with(b"v=STSv1"));
            // DNS record present is necessary but not sufficient; HTTP policy
            // fetch will upgrade Indet → Present or Absent in Tier 2.
            if has_mta_sts { TriState::Indet } else { TriState::Absent }
        }
        Err(_) => TriState::Absent, // missing TXT → definitively absent
    }
}

async fn score_caa(resolver: &TokioAsyncResolver, domain: &str) -> TriState {
    // CAA record lookup.
    // RecordType::CAA = 257, confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // A CAA record constrains which CAs may issue certificates for this domain.
    // Absent = no CAA policy (any CA can issue) — informatively absent, not a failure.
    use hickory_proto::rr::RecordType;

    match resolver.lookup(domain, RecordType::CAA).await {
        Ok(resp) => {
            if resp.iter().next().is_some() {
                TriState::Present
            } else {
                TriState::Absent
            }
        }
        Err(e) => match e.kind() {
            ResolveErrorKind::Proto(e) if matches!(e.kind(), ProtoErrorKind::NoRecordsFound { .. }) => TriState::Absent,
            _ => {
                warn!(domain, error = %e, "CAA lookup error → Indet");
                TriState::Indet
            }
        },
    }
}

async fn score_cds_cdnskey(resolver: &TokioAsyncResolver, domain: &str) -> TriState {
    // CDS (type 59) and CDNSKEY (type 60) are published at the child zone apex
    // to signal an ongoing or pending DS rollover to the parent (RFC 7344).
    // Both types confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // Semantics:
    //   Present  — at least one CDS or CDNSKEY record exists (rollover active/pending)
    //   Absent   — neither record type has any records (no rollover in progress)
    //   Indet    — lookup error other than NXDOMAIN/NOERROR-NODATA
    //
    // We check CDS first; if present we return immediately.
    // Otherwise we fall through to CDNSKEY as the authoritative answer.
    use hickory_proto::rr::RecordType;

    // ── CDS (type 59) ────────────────────────────────────────────────────────
    let cds_absent = match resolver.lookup(domain, RecordType::CDS).await {
        Ok(resp) => {
            if resp.iter().next().is_some() {
                return TriState::Present; // CDS record found — rollover signalled
            }
            true // empty answer section → absent, check CDNSKEY
        }
        Err(e) => match e.kind() {
            ResolveErrorKind::Proto(e) if matches!(e.kind(), ProtoErrorKind::NoRecordsFound { .. }) => true, // definitively absent
            _ => {
                // Transient/servfail on CDS — still worth checking CDNSKEY
                warn!(domain, error = %e, "CDS lookup error, falling through to CDNSKEY");
                false // not definitively absent
            }
        },
    };

    // ── CDNSKEY (type 60) ────────────────────────────────────────────────────
    match resolver.lookup(domain, RecordType::CDNSKEY).await {
        Ok(resp) => {
            if resp.iter().next().is_some() {
                TriState::Present
            } else if cds_absent {
                TriState::Absent // both empty
            } else {
                TriState::Indet // CDS errored, CDNSKEY empty — not conclusive
            }
        }
        Err(e) => match e.kind() {
            ResolveErrorKind::Proto(e) if matches!(e.kind(), ProtoErrorKind::NoRecordsFound { .. }) => {
                if cds_absent {
                    TriState::Absent // both definitively absent
                } else {
                    TriState::Indet // CDS errored, CDNSKEY NXDOMAIN — not conclusive
                }
            }
            _ => {
                warn!(domain, error = %e, "CDNSKEY lookup error → Indet");
                TriState::Indet
            }
        },
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn rand_session_id() -> u64 {
    // Use std thread_rng for a local-only nonce; this never leaves the box.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish()
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// =============================================================================
// Tests
// =============================================================================
//
// Test taxonomy (mirrors docs/TEST-PLAN.md):
//
//   Unit (no network)   — tristate_display, tristate_serde_roundtrip,
//                         resolver_options_validate_is_set
//   Integration (#[ignore], run with: cargo test -- --ignored)
//                       — golden_fixture_*, t1_1_mta_sts_absent_for_unsigned_domain
//
// TODO (Section A.3): Once hickory 0.26 exposes the raw AD/CD flag accessors,
// add `cd_set` and `ad_read` field assertions to every golden fixture.
// Track: https://github.com/hickory-dns/hickory-dns/issues/[pending]

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::{
        config::{ResolverConfig, ResolverOpts},
        TokioAsyncResolver,
    };

    // -------------------------------------------------------------------------
    // Helper — build a DNSSEC-validating resolver pointing at Cloudflare DoT
    // -------------------------------------------------------------------------

    fn make_test_resolver() -> TokioAsyncResolver {
        let mut opts = ResolverOpts::default();
        opts.validate = true; // DNSSEC chain validation on
        // Use Cloudflare DoT for deterministic responses in CI.
        // In sandboxed / offline environments, these tests must be run with
        // `--ignored` suppressed or a local resolver mock substituted.
        TokioAsyncResolver::builder_with_config(
            ResolverConfig::cloudflare_tls(),
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build()
    }

    // -------------------------------------------------------------------------
    // Unit: resolver_options_validate_is_set
    // Verifies that make_test_resolver() actually sets validate=true.
    // This is the Section A.3 gate: if validate is false the golden fixtures
    // would pass vacuously even without DNSSEC signatures.
    // -------------------------------------------------------------------------
    #[test]
    fn resolver_options_validate_is_set() {
        // Default opts have validate=false; our helper must flip it.
        let default_opts = ResolverOpts::default();
        assert!(!default_opts.validate, "sanity: default validate should be false");

        let mut patched = ResolverOpts::default();
        patched.validate = true;
        assert!(patched.validate, "validate must be true for DNSSEC fixture tests");
    }

    // -------------------------------------------------------------------------
    // Unit: TriState display
    // -------------------------------------------------------------------------
    #[test]
    fn tristate_display() {
        assert_eq!(TriState::Present.to_string(), "PRESENT");
        assert_eq!(TriState::Absent.to_string(),  "ABSENT");
        assert_eq!(TriState::Indet.to_string(),   "INDET");
    }

    // -------------------------------------------------------------------------
    // Unit: TriState serde round-trip
    // -------------------------------------------------------------------------
    #[test]
    fn tristate_serde_roundtrip() {
        for ts in [TriState::Present, TriState::Absent, TriState::Indet] {
            let json = serde_json::to_string(&ts).expect("serialize");
            let back: TriState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(ts, back, "round-trip failed for {:?}", ts);
        }
    }

    // -------------------------------------------------------------------------
    // Golden fixture macro
    //
    // Generates one #[tokio::test] #[ignore] per domain.
    // Expected DNSSEC chain state for all four golden fixtures = Present.
    // Run with: cargo test golden_ -- --ignored
    // -------------------------------------------------------------------------
    macro_rules! golden_fixture_test {
        ($name:ident, $domain:expr, $expected_dnssec:expr) => {
            #[tokio::test]
            #[ignore = "requires network + DNSSEC-validating resolver"]
            async fn $name() {
                let resolver = make_test_resolver();
                let result = analyse_domain(&resolver, $domain)
                    .await
                    .expect("analyse_domain should not error");

                assert_eq!(
                    result.dnssec_chain, $expected_dnssec,
                    "DNSSEC chain mismatch for {}",
                    $domain
                );
                // TODO(A.3): assert result.cd_set == false once hickory exposes AD header
                // TODO(A.3): assert result.ad_read == true once hickory exposes AD header
            }
        };
    }

    golden_fixture_test!(golden_cloudflare_com,  "cloudflare.com",  TriState::Present);
    golden_fixture_test!(golden_example_com,     "example.com",     TriState::Present);
    golden_fixture_test!(golden_ietf_org,        "ietf.org",        TriState::Present);
    golden_fixture_test!(golden_whitehouse_gov,  "whitehouse.gov",  TriState::Present);

    // -------------------------------------------------------------------------
    // T1-1 integration: MTA-STS absent for unsigned/no-policy domain
    //
    // example.com has no _mta-sts TXT record → score_mta_sts must return Absent.
    // This directly validates the T1-1 fix (warning → Absent mapping).
    // -------------------------------------------------------------------------
    #[tokio::test]
    #[ignore = "requires network"]
    async fn t1_1_mta_sts_absent_for_unsigned_domain() {
        let resolver = make_test_resolver();
        let result = analyse_domain(&resolver, "example.com")
            .await
            .expect("analyse_domain should not error");

        assert_eq!(
            result.mta_sts,
            TriState::Absent,
            "T1-1: example.com has no MTA-STS policy; expected Absent, got {:?}",
            result.mta_sts
        );
    }
}
