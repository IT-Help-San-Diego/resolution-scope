//! T2 — the default vantage's seal is byte-frozen.
//!
//! The 128-hex literal below was MINTED BY EXECUTION on the base commit
//! (b4e2a77, 2026-09-03T06:1xZ) BEFORE the refactor: a fixture sealed with
//! the identity literal "cloudflare", version "0.0.0-kat", under SEAL_SCHEME.
//! After the refactor the identity comes from `ResolverChoice::default()
//! .identity()` — if that ever drifts from "cloudflare", or the preimage
//! header moves, this literal stops matching. Re-pin ONLY on a deliberate
//! scheme bump (which mints a new KAT alongside).

use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use resolution_scope_engine::seal::{canonical_input, seal_versioned_under_scheme, SEAL_SCHEME};
use resolution_scope_engine::{
    CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
    DmarcDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition, TlsRptDisposition,
    TriState,
};

/// Minted on b4e2a77 with `resolver_identity: "cloudflare"` (the literal).
const DEFAULT_VANTAGE_KAT: &str = "d3a361cb5137e123d2056191f2c7bf9d5960433a2d86b48eac224243cb486013\
                                   b849c553c3b88ee1b7957bd572a6c5acbce78d3c4fd53fd456c528b4875cb9f8";

fn fixture(identity: String) -> ScoredAnalysis {
    ScoredAnalysis {
        domain: "example.com".to_string(),
        session_id: 0xdead_beef,
        timestamp_local: 1_700_000_000,
        resolver_identity: identity,
        dnssec_chain: TriState::Present,
        dnssec_disposition:
            resolution_scope_engine::analysis::DnssecDisposition::SignedAndDelegated,
        spf: TriState::Present,
        spf_disposition: SpfDisposition::HardFail,
        dkim: TriState::Absent,
        dkim_disposition: DkimDisposition::NotFoundDefaults,
        dmarc: TriState::Indet,
        dmarc_disposition: DmarcDisposition::TransientError,
        dane: TriState::Indet,
        dane_disposition: DaneDisposition::TransientError,
        tlsa_zone: resolution_scope_engine::analysis::TlsaZone::ZoneUnmeasured,
        mta_sts: TriState::Present,
        mta_sts_disposition: MtaStsDisposition::Enforced,
        caa: TriState::Indet,
        caa_disposition: CaaDisposition::NoZone,
        cds_cdnskey: TriState::Indet,
        cds_disposition: CdsDisposition::NoZone,
        tls_rpt: TriState::Absent,
        tls_rpt_disposition: TlsRptDisposition::RecordAbsent,
        csync: TriState::Absent,
        csync_disposition: CsyncDisposition::RecordAbsent,
    }
}

#[test]
fn default_vantage_seal_kat_is_byte_frozen() {
    // The identity is taken from the PRODUCER, not spelled here.
    let identity = ResolverChoice::default().identity();
    let a = fixture(identity);
    assert_eq!(
        seal_versioned_under_scheme(&a, "0.0.0-kat", SEAL_SCHEME),
        DEFAULT_VANTAGE_KAT,
        "the default vantage's seal moved: either the identity is no longer the literal \
         \"cloudflare\" or the preimage header changed"
    );
    assert!(
        canonical_input(&a, "0.0.0-kat")
            .starts_with("resolution-scope-sha3-512-v5\nexample.com\n0.0.0-kat\ncloudflare\n"),
        "preimage line 4 must be the literal `cloudflare` for the default run"
    );
}

/// The built vantage seals the same bytes as the choice (no second producer).
#[test]
fn built_default_vantage_identity_is_cloudflare() {
    let v = Vantage::build(ResolverChoice::default()).expect("offline construction");
    assert_eq!(v.identity(), "cloudflare");
    assert_eq!(v.choice().identity(), v.identity());
}

/// Negative control: a different choice seals differently over the same
/// verdict (the existing `seal_changes_when_resolver_identity_changes`
/// property, restated through the producer).
#[test]
fn another_choice_moves_the_seal() {
    let other: ResolverChoice = "tls://cloudflare".parse().unwrap();
    assert_ne!(
        seal_versioned_under_scheme(&fixture(other.identity()), "0.0.0-kat", SEAL_SCHEME),
        DEFAULT_VANTAGE_KAT
    );
}
