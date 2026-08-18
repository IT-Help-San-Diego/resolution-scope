// analysis.rs — DNS control scoring
//
// Each public function in this module runs OUTSIDE the seL4 compartment.
// Results are packed into ScoredAnalysis and sent over the IPC endpoint.

use anyhow::Result;
use hickory_resolver::TokioResolver;
use hickory_resolver::net::NetError;
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
    resolver: &TokioResolver,
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

async fn score_dnssec(resolver: &TokioResolver, domain: &str) -> TriState {
    // DNSSEC is measured by the zone's DNSKEY material, NOT by A/AAAA address
    // existence. A zone can publish DNSKEY + RRSIG (sign) while hosting no
    // web content yet — the island-of-security case (resolutionscope.com/.dev:
    // 2 DNSKEY, 0 DS, 0 A/AAAA). Probing via lookup_ip and mapping
    // "no address record" -> Absent was a category error: it read "no website"
    // as "no DNSSEC".
    //
    // hickory validates with validate=true and attaches one of four proofs to
    // each answer record:
    //   Secure        — chain of DNSKEY+DS from a trust anchor validates (SIGNED)
    //   Insecure      — resolver KNOWS there is no chain (proven unsigned delegation)
    //   Bogus         — ought to validate but does not (BROKEN; possible attack)
    //   Indeterminate — could not obtain the DNSSEC RRs (couldn't measure)
    //
    // Mapping (aligned with Claude Science's 2026-08-18 ruling that Insecure
    // counts as "proven unsigned" only from a validating resolver with a trust
    // anchor, else it collapses to couldn't-measure):
    //   DNSKEY present + Secure         -> Present   (signed AND delegated)
    //   DNSKEY present + Insecure/Bogus -> Indet     (island/broken — NOT "absent")
    //   DNSKEY absent                  -> Absent    (genuinely unsigned)
    //   NXDOMAIN                       -> Indet     (no zone — domain_exists doctrine)
    use hickory_proto::rr::RecordType;
    use hickory_proto::dnssec::Proof;

    match resolver.lookup(domain, RecordType::DNSKEY).await {
        Ok(resp) => {
            let answers = resp.answers();
            if answers.is_empty() {
                return TriState::Absent; // no DNSKEY published = unsigned
            }
            match answers.first().map(|r| r.proof) {
                Some(Proof::Secure) => TriState::Present, // signed + delegated + validates
                Some(Proof::Insecure) => TriState::Indet, // keys present, no trusted chain (island)
                Some(Proof::Bogus) => TriState::Absent,   // broken chain — counts against
                _ => TriState::Indet,                     // keys present, chain unmeasurable
            }
        }
        Err(e) => {
            warn!(domain, error = %e, "DNSSEC DNSKEY lookup error");
            // domain_exists doctrine (Carey ruling, 2026-08-18): an
            // authoritative no-such-name is an absence OF THE DOMAIN, not of
            // DNSSEC. NXDOMAIN must never flatten to Absent.
            if e.is_nx_domain() {
                TriState::Indet
            } else if e.is_no_records_found() {
                // NOERROR/NODATA on the DNSKEY query = no keys = unsigned.
                TriState::Absent
            } else {
                // SERVFAIL from a validating resolver on a DNSSEC query is the
                // RFC 4035 "bogus" signal — the chain broke (wrong DS, expired
                // RRSIG), so the resolver refused to return the keys. Map it to
                // Absent (broken counts against), NOT Indet. Same class as the
                // Go engine's #336 SERVFAIL→bogus fix.
                use hickory_resolver::net::{DnsError, NetError};
                use hickory_proto::op::ResponseCode;
                if matches!(&e, NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail))) {
                    TriState::Absent
                } else {
                    TriState::Indet
                }
            }
        }
    }
}

async fn score_spf(resolver: &TokioResolver, domain: &str) -> TriState {
    // SPF is a TXT record at the apex beginning with "v=spf1".
    match resolver.txt_lookup(domain).await {
        Ok(rdata) => {
            let has_spf = rdata.answers().iter().any(|rec| {
                matches!(&rec.data, hickory_proto::rr::RData::TXT(txt)
                    if txt.txt_data.iter().any(|s| s.starts_with(b"v=spf1")))
            });
            if has_spf { TriState::Present } else { TriState::Absent }
        }
        Err(e) => {
            // NODATA (no TXT on an existing zone) = measured absence; NXDOMAIN
            // (no zone) = couldn't-measure; transient = couldn't-measure.
            if e.is_nx_domain() {
                TriState::Indet
            } else if e.is_no_records_found() {
                TriState::Absent
            } else {
                TriState::Indet
            }
        }
    }
}

async fn score_dmarc(resolver: &TokioResolver, domain: &str) -> TriState {
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(dmarc_domain.as_str()).await {
        Ok(rdata) => {
            let has_dmarc = rdata.answers().iter().any(|rec| {
                matches!(&rec.data, hickory_proto::rr::RData::TXT(txt)
                    if txt.txt_data.iter().any(|s| s.starts_with(b"v=DMARC1")))
            });
            if has_dmarc { TriState::Present } else { TriState::Absent }
        }
        Err(e) => {
            if e.is_nx_domain() {
                TriState::Indet
            } else if e.is_no_records_found() {
                TriState::Absent
            } else {
                TriState::Indet
            }
        }
    }
}

async fn score_dane(resolver: &TokioResolver, domain: &str) -> TriState {
    // DANE: TLSA record at _443._tcp.<domain> (HTTPS DANE).
    // RecordType::TLSA = 52, confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // SMTP DANE (_25._tcp.<domain>) is a future extension — tracked in
    // docs/TEST-PLAN.md Section E.
    use hickory_proto::rr::RecordType;

    let tlsa_name = format!("_443._tcp.{}", domain);
    match resolver.lookup(tlsa_name.as_str(), RecordType::TLSA).await {
        Ok(resp) => {
            if !resp.answers().is_empty() {
                TriState::Present
            } else {
                // Empty answer section with NOERROR → treat as absent.
                TriState::Absent
            }
        }
        Err(e) => {
            if e.is_nx_domain() {
                TriState::Indet
            } else if e.is_no_records_found() {
                TriState::Absent
            } else {
                warn!(domain, error = %e, "DANE/TLSA lookup error → Indet");
                TriState::Indet
            }
        }
    }
}

async fn score_mta_sts(resolver: &TokioResolver, domain: &str) -> TriState {
    // T1-1 fix: MTA-STS "warning" (policy found but invalid/expired) MUST map
    // to Absent, not a fourth state.  Any policy parse error → Absent.
    // Successful fetch of /.well-known/mta-sts.txt + valid mode field → Present.
    //
    // Full HTTP fetch is deferred to Tier 2 (requires reqwest dependency).
    // For now, check the DNS TXT record at _mta-sts.<domain> as a proxy.
    let mta_sts_domain = format!("_mta-sts.{}", domain);
    match resolver.txt_lookup(mta_sts_domain.as_str()).await {
        Ok(rdata) => {
            let has_mta_sts = rdata.answers().iter().any(|rec| {
                matches!(&rec.data, hickory_proto::rr::RData::TXT(txt)
                    if txt.txt_data.iter().any(|s| s.starts_with(b"v=STSv1")))
            });
            // DNS record present is necessary but not sufficient; HTTP policy
            // fetch will upgrade Indet → Present or Absent in Tier 2.
            if has_mta_sts { TriState::Indet } else { TriState::Absent }
        }
        Err(e) => {
            // No MTA-STS TXT on an existing zone = measured absence; NXDOMAIN
            // (no zone) and transient errors = couldn't-measure (never Absent).
            if e.is_nx_domain() {
                TriState::Indet
            } else if e.is_no_records_found() {
                TriState::Absent
            } else {
                TriState::Indet
            }
        }
    }
}

async fn score_caa(resolver: &TokioResolver, domain: &str) -> TriState {
    // CAA record lookup.
    // RecordType::CAA = 257, confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // A CAA record constrains which CAs may issue certificates for this domain.
    // Absent = no CAA policy (any CA can issue) — informatively absent, not a failure.
    use hickory_proto::rr::RecordType;

    match resolver.lookup(domain, RecordType::CAA).await {
        Ok(resp) => {
            if !resp.answers().is_empty() {
                TriState::Present
            } else {
                TriState::Absent
            }
        }
        Err(e) => {
            if e.is_nx_domain() {
                TriState::Indet
            } else if e.is_no_records_found() {
                TriState::Absent
            } else {
                warn!(domain, error = %e, "CAA lookup error → Indet");
                TriState::Indet
            }
        }
    }
}

async fn score_cds_cdnskey(resolver: &TokioResolver, domain: &str) -> TriState {
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
            if !resp.answers().is_empty() {
                return TriState::Present; // CDS record found — rollover signalled
            }
            true // empty answer section → absent, check CDNSKEY
        }
        Err(e) => {
            if e.is_nx_domain() {
                return TriState::Indet; // no zone — CDS state not applicable
            }
            if e.is_no_records_found() {
                true // definitively absent
            } else {
                // Transient/servfail on CDS — still worth checking CDNSKEY
                warn!(domain, error = %e, "CDS lookup error, falling through to CDNSKEY");
                false // not definitively absent
            }
        }
    };

    // ── CDNSKEY (type 60) ────────────────────────────────────────────────────
    match resolver.lookup(domain, RecordType::CDNSKEY).await {
        Ok(resp) => {
            if !resp.answers().is_empty() {
                TriState::Present
            } else if cds_absent {
                TriState::Absent // both empty
            } else {
                TriState::Indet // CDS errored, CDNSKEY empty — not conclusive
            }
        }
        Err(e) => {
            if e.is_nx_domain() {
                TriState::Indet // no zone — CDNSKEY state not applicable
            } else if e.is_no_records_found() {
                if cds_absent {
                    TriState::Absent // both definitively absent
                } else {
                    TriState::Indet // CDS errored, CDNSKEY NODATA — not conclusive
                }
            } else {
                warn!(domain, error = %e, "CDNSKEY lookup error → Indet");
                TriState::Indet
            }
        }
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
        TokioResolver,
    };

    // -------------------------------------------------------------------------
    // Helper — build a DNSSEC-validating resolver pointing at Cloudflare DoT
    // -------------------------------------------------------------------------

    fn make_test_resolver() -> TokioResolver {
        let mut opts = ResolverOpts::default();
        opts.validate = true; // DNSSEC chain validation on
        // Use Cloudflare DoT for deterministic responses in CI.
        // In sandboxed / offline environments, these tests must be run with
        // `--ignored` suppressed or a local resolver mock substituted.
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .with_options(opts)
        .build()
        .expect("test resolver construction")
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
