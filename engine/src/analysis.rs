// analysis.rs — DNS control scoring
//
// Each public function in this module runs OUTSIDE the seL4 compartment.
// Results are packed into ScoredAnalysis and sent over the IPC endpoint.

use anyhow::Result;
use hickory_resolver::net::NetError;
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::TriState;

// =============================================================================
// ScoredAnalysis — the IPC payload (mirrors lionsOS-compartment-demo-spec.md §5)
// =============================================================================

// =============================================================================
// DnssecDisposition — the full DNSSEC decision, richer than the TriState
// =============================================================================
//
// score_dnssec collapses DNSSEC to a TriState for the tally, but the *reason*
// matters: "signed but not delegated" (island of security) is a different fact
// from "couldn't measure" or "broken chain". Claude Science's 2026-08-18
// ruling requires the engine to preserve this so a report can explain WHY a
// domain is Indet — e.g. .dev (Insecure proof = proven signed-but-not-delegated)
// vs a domain whose DNSSEC RRs couldn't be fetched (Indeterminate proof).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnssecDisposition {
    /// DNSKEY present + Secure proof — signed AND delegated, chain validates.
    SignedAndDelegated,
    /// DNSKEY present + Insecure proof — resolver KNOWS there is no chain
    /// (proven signed-but-not-delegated; the island-of-security case).
    SignedNotDelegated,
    /// DNSKEY present + Bogus proof — ought to validate but does not
    /// (wrong DS / expired RRSIG). Broken — counts against.
    BrokenChain,
    /// DNSKEY present + Indeterminate proof — could not obtain the DNSSEC RRs
    /// (unauthenticated). Couldn't-measure, not "absent".
    ChainUnverified,
    /// No DNSKEY published at the apex — genuinely unsigned.
    Unsigned,
    /// NXDOMAIN — no zone, so DNSSEC is not applicable (domain_exists doctrine).
    NoZone,
    /// Transient lookup error (timeout/refused) — couldn't measure.
    Unreachable,
}

impl DnssecDisposition {
    /// Collapse to the tri-state used by the tally and score denominator.
    pub fn chain(self) -> TriState {
        match self {
            DnssecDisposition::SignedAndDelegated => TriState::Present,
            DnssecDisposition::SignedNotDelegated => TriState::Indet,
            DnssecDisposition::BrokenChain => TriState::Absent,
            DnssecDisposition::ChainUnverified => TriState::Indet,
            DnssecDisposition::Unsigned => TriState::Absent,
            DnssecDisposition::NoZone => TriState::Indet,
            DnssecDisposition::Unreachable => TriState::Indet,
        }
    }
}

impl std::fmt::Display for DnssecDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnssecDisposition::SignedAndDelegated => write!(f, "signed-and-delegated"),
            DnssecDisposition::SignedNotDelegated => {
                write!(f, "signed-but-not-delegated (island of security)")
            }
            DnssecDisposition::BrokenChain => write!(f, "broken-chain (bogus)"),
            DnssecDisposition::ChainUnverified => {
                write!(f, "chain-unverified (couldn't obtain DNSSEC RRs)")
            }
            DnssecDisposition::Unsigned => write!(f, "unsigned (no DNSKEY)"),
            DnssecDisposition::NoZone => write!(f, "no-zone (NXDOMAIN)"),
            DnssecDisposition::Unreachable => write!(f, "unreachable (transient lookup error)"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoredAnalysis {
    pub domain: String,
    pub session_id: u64,
    pub timestamp_local: u64,

    // Per-control tri-state scores
    pub dnssec_chain: TriState,
    pub dnssec_disposition: DnssecDisposition,
    pub spf: TriState,
    pub dkim: TriState,
    pub dmarc: TriState,
    pub dane: TriState,
    pub mta_sts: TriState, // "warning" → Absent (T1-1 fix)
    pub caa: TriState,
    pub cds_cdnskey: TriState,
}

// =============================================================================
// analyse_domain — top-level entry point
// =============================================================================

pub async fn analyse_domain(resolver: &TokioResolver, domain: &str) -> Result<ScoredAnalysis> {
    debug!(domain, "starting analysis");

    let session_id: u64 = rand_session_id();
    let timestamp_local: u64 = unix_now();

    // ── DNSSEC chain ────────────────────────────────────────────────────────
    // hickory-resolver with validate=true performs AD-bit + RRSIG chain check.
    // The dnssec-ring feature (enforced by compile_error! in lib.rs) is what
    // makes this verification real rather than a no-op.
    let dnssec_disposition = score_dnssec(resolver, domain).await;
    let dnssec_chain = dnssec_disposition.chain();

    // ── Email controls (stub — wire up full probes in Tier 2) ───────────────
    let spf = score_spf(resolver, domain).await;
    let dkim = TriState::Indet; // selector unknown at analysis time
    let dmarc = score_dmarc(resolver, domain).await;
    let dane = score_dane(resolver, domain).await;
    let mta_sts = score_mta_sts(resolver, domain).await;
    let caa = score_caa(resolver, domain).await;
    let cds_cdnskey = score_cds_cdnskey(resolver, domain).await;

    Ok(ScoredAnalysis {
        domain: domain.to_string(),
        session_id,
        timestamp_local,
        dnssec_chain,
        dnssec_disposition,
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

// =============================================================================
// Verdict mapping — pure, unit-testable
// =============================================================================
//
// Every scored control's Err path reduces to the same three-way decision:
//   NXDOMAIN       -> Indet   (no zone — domain_exists doctrine: `Absent` is
//                              a claim about a zone's configuration, and there
//                              is no zone)
//   NoRecordsFound -> Absent  (NODATA on an existing zone = measured absence)
//   else           -> Indet   (transient / couldn't measure)
//
// Extracted from the per-arm Err branches so the boundary is a single,
// unit-tested decision rather than six hand-copied blocks. The DNSSEC arm
// adds one extra case (SERVFAIL -> Absent = broken chain) below.

/// Map a record-presence lookup error to a tri-state verdict.
fn record_absence_verdict(e: &NetError) -> TriState {
    // NODATA (no record on an existing zone) = measured absence -> Absent.
    // NXDOMAIN (no zone) and transient errors = couldn't measure -> Indet.
    // (is_nx_domain() is a subset of is_no_records_found(): NXDOMAIN arrives as
    //  NoRecordsFound with an NXDomain response code, so the !is_nx_domain()
    //  guard separates "no zone" from "no record".)
    if e.is_no_records_found() && !e.is_nx_domain() {
        TriState::Absent
    } else {
        TriState::Indet
    }
}

/// Map a DNSSEC DNSKEY lookup error to its full disposition.
/// Rich sibling of `record_absence_verdict`: instead of collapsing to the
/// tri-state it preserves WHY — NXDOMAIN is NoZone, NODATA is Unsigned,
/// SERVFAIL is BrokenChain (RFC 4035 "bogus"), anything else is Unreachable.
/// Same class as the Go engine's #336 fix (broken chain must not read as
/// "couldn't measure").
fn dnssec_disposition_err(e: &NetError) -> DnssecDisposition {
    use hickory_proto::op::ResponseCode;
    use hickory_resolver::net::DnsError;
    if e.is_nx_domain() {
        DnssecDisposition::NoZone
    } else if e.is_no_records_found() {
        DnssecDisposition::Unsigned
    } else if matches!(
        e,
        NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail))
    ) {
        DnssecDisposition::BrokenChain
    } else {
        DnssecDisposition::Unreachable
    }
}

async fn score_dnssec(resolver: &TokioResolver, domain: &str) -> DnssecDisposition {
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
    // We return the full DnssecDisposition (not just the TriState) so the
    // report can explain WHY — the collapse to Present/Absent/Indet happens in
    // `chain()`. Aligned with Claude Science's 2026-08-18 ruling: Insecure
    // counts as "proven unsigned" only from a validating resolver with a trust
    // anchor; Indeterminate is genuinely "couldn't measure", never "absent".
    use hickory_proto::dnssec::Proof;
    use hickory_proto::rr::RecordType;

    match resolver.lookup(domain, RecordType::DNSKEY).await {
        Ok(resp) => {
            let answers = resp.answers();
            if answers.is_empty() {
                return DnssecDisposition::Unsigned; // no DNSKEY published = unsigned
            }
            match answers.first().map(|r| r.proof) {
                Some(Proof::Secure) => DnssecDisposition::SignedAndDelegated,
                Some(Proof::Insecure) => DnssecDisposition::SignedNotDelegated, // island
                Some(Proof::Bogus) => DnssecDisposition::BrokenChain, // broken — counts against
                _ => DnssecDisposition::ChainUnverified, // keys present, chain unmeasurable
            }
        }
        Err(e) => {
            warn!(domain, error = %e, "DNSSEC DNSKEY lookup error");
            dnssec_disposition_err(&e)
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
            if has_spf {
                TriState::Present
            } else {
                TriState::Absent
            }
        }
        Err(e) => {
            // NODATA (no TXT on an existing zone) = measured absence; NXDOMAIN
            // (no zone) = couldn't-measure; transient = couldn't-measure.
            record_absence_verdict(&e)
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
            if has_dmarc {
                TriState::Present
            } else {
                TriState::Absent
            }
        }
        Err(e) => record_absence_verdict(&e),
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
            warn!(domain, error = %e, "DANE/TLSA lookup error");
            record_absence_verdict(&e)
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
            if has_mta_sts {
                TriState::Indet
            } else {
                TriState::Absent
            }
        }
        Err(e) => {
            // No MTA-STS TXT on an existing zone = measured absence; NXDOMAIN
            // (no zone) and transient errors = couldn't-measure (never Absent).
            record_absence_verdict(&e)
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
            warn!(domain, error = %e, "CAA lookup error");
            record_absence_verdict(&e)
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
        assert!(
            !default_opts.validate,
            "sanity: default validate should be false"
        );

        let mut patched = ResolverOpts::default();
        patched.validate = true;
        assert!(
            patched.validate,
            "validate must be true for DNSSEC fixture tests"
        );
    }

    // -------------------------------------------------------------------------
    // Unit: TriState display
    // -------------------------------------------------------------------------
    #[test]
    fn tristate_display() {
        assert_eq!(TriState::Present.to_string(), "PRESENT");
        assert_eq!(TriState::Absent.to_string(), "ABSENT");
        assert_eq!(TriState::Indet.to_string(), "INDET");
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

    golden_fixture_test!(golden_cloudflare_com, "cloudflare.com", TriState::Present);
    golden_fixture_test!(golden_example_com, "example.com", TriState::Present);
    golden_fixture_test!(golden_ietf_org, "ietf.org", TriState::Present);
    golden_fixture_test!(golden_whitehouse_gov, "whitehouse.gov", TriState::Present);

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

    // -------------------------------------------------------------------------
    // Verdict-mapping unit tests (pure, no network)
    //
    // These pin the tri-state boundary that was hand-copied across six arms
    // before extraction. Each arm's Err path reduces to: NXDOMAIN -> Indet,
    // NODATA -> Absent, else -> Indet; DNSSEC additionally maps SERVFAIL ->
    // Absent (broken chain). Regression protection for the 2026-08-18 fixes.
    // -------------------------------------------------------------------------

    fn no_records_err(code: hickory_proto::op::ResponseCode) -> NetError {
        use hickory_proto::op::Query;
        use hickory_proto::rr::{Name, RecordType};
        use hickory_resolver::net::{DnsError, NoRecords};
        let q = Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::DNSKEY,
        );
        let nr = NoRecords::new(Box::new(q), code);
        NetError::Dns(DnsError::NoRecordsFound(nr))
    }

    fn servfail_err() -> NetError {
        use hickory_proto::op::ResponseCode;
        use hickory_resolver::net::DnsError;
        NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail))
    }

    #[test]
    fn record_absence_nxdomain_is_indet() {
        // no zone -> couldn't measure, NEVER Absent (domain_exists doctrine)
        assert_eq!(
            record_absence_verdict(&no_records_err(hickory_proto::op::ResponseCode::NXDomain)),
            TriState::Indet
        );
    }

    #[test]
    fn record_absence_nodata_is_absent() {
        // NODATA on an existing zone = measured absence
        assert_eq!(
            record_absence_verdict(&no_records_err(hickory_proto::op::ResponseCode::NoError)),
            TriState::Absent
        );
    }

    #[test]
    fn record_absence_servfail_is_indet() {
        // transient SERVFAIL = couldn't measure (NOT a DNSSEC verdict here)
        assert_eq!(record_absence_verdict(&servfail_err()), TriState::Indet);
    }

    #[test]
    fn dnssec_nxdomain_is_nozone() {
        // no zone -> DNSSEC not applicable; collapses to Indet (never Absent).
        let d = dnssec_disposition_err(&no_records_err(hickory_proto::op::ResponseCode::NXDomain));
        assert_eq!(d, DnssecDisposition::NoZone);
        assert_eq!(d.chain(), TriState::Indet);
    }

    #[test]
    fn dnssec_nodata_is_unsigned() {
        // no DNSKEY = unsigned; collapses to Absent (counts in denominator).
        let d = dnssec_disposition_err(&no_records_err(hickory_proto::op::ResponseCode::NoError));
        assert_eq!(d, DnssecDisposition::Unsigned);
        assert_eq!(d.chain(), TriState::Absent);
    }

    #[test]
    fn dnssec_servfail_is_broken() {
        // RFC 4035 bogus: validating resolver SERVFAILs on a broken chain.
        // This is the one case where the DNSSEC err mapping differs from
        // record_absence_verdict — broken counts against (Absent), not Indet.
        let d = dnssec_disposition_err(&servfail_err());
        assert_eq!(d, DnssecDisposition::BrokenChain);
        assert_eq!(d.chain(), TriState::Absent);
    }

    #[test]
    fn disposition_chain_mapping() {
        // The full disposition collapses to the tri-state the tally uses.
        assert_eq!(
            DnssecDisposition::SignedAndDelegated.chain(),
            TriState::Present
        );
        assert_eq!(
            DnssecDisposition::SignedNotDelegated.chain(),
            TriState::Indet
        );
        assert_eq!(DnssecDisposition::BrokenChain.chain(), TriState::Absent);
        assert_eq!(DnssecDisposition::ChainUnverified.chain(), TriState::Indet);
        assert_eq!(DnssecDisposition::Unsigned.chain(), TriState::Absent);
        assert_eq!(DnssecDisposition::NoZone.chain(), TriState::Indet);
        assert_eq!(DnssecDisposition::Unreachable.chain(), TriState::Indet);
    }

    #[test]
    fn dnssec_disposition_serde_roundtrip() {
        // The disposition crosses the IPC boundary as JSON — it must round-trip.
        for d in [
            DnssecDisposition::SignedAndDelegated,
            DnssecDisposition::SignedNotDelegated,
            DnssecDisposition::BrokenChain,
            DnssecDisposition::ChainUnverified,
            DnssecDisposition::Unsigned,
            DnssecDisposition::NoZone,
            DnssecDisposition::Unreachable,
        ] {
            let json = serde_json::to_string(&d).expect("serialize");
            let back: DnssecDisposition = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(d, back, "round-trip failed for {:?}", d);
        }
    }
}
