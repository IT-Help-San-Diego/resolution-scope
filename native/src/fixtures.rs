// fixtures.rs — the canonical demo verdict (single producer)
//
// This is the ONE place the demo `ScoredAnalysis` lives. It is the exact
// fixture the golden-seal test pins: `seal_versioned(&demo_verdict(), "0.1.0")`
// must equal the golden value recorded in seal.rs (computed from the ENGINE on
// 2026-08-22). Every consumer — the bare-metal `[[bin]]` (main_native.rs), the
// seal tests, and the FFI tests — uses this one function, so a single edit here
// is caught by the golden test if it drifts. (Previously the fixture was copied
// into both main_native.rs and the seal.rs test module — a hand-maintained
// mirror that the golden test made merely *detectable*, not impossible.)
//
// It is a DEMO fixture, not an API: it stands in for "a ScoredAnalysis received
// over the IPC channel" until the receive path is wired. It deliberately
// exercises every TriState variant and all 8 distinct dispositions.

use resolution_scope_types::{
    CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
    DnssecDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition, TriState,
};

pub fn demo_verdict() -> ScoredAnalysis {
    ScoredAnalysis {
        domain: "example.com".into(),
        session_id: 1,
        timestamp_local: 1_700_000_000,
        resolver_identity: "default".into(),
        dnssec_chain: TriState::Present,
        dnssec_disposition: DnssecDisposition::SignedAndDelegated,
        spf: TriState::Present,
        spf_disposition: SpfDisposition::SoftFail,
        dkim: TriState::Absent,
        dkim_disposition: DkimDisposition::NotFoundDefaults,
        dmarc: TriState::Present,
        dmarc_disposition: DmarcDisposition::Reject,
        dane: TriState::NotApplicable,
        dane_disposition: DaneDisposition::NoMail,
        mta_sts: TriState::Present,
        mta_sts_disposition: MtaStsDisposition::Enforced,
        caa: TriState::Absent,
        caa_disposition: CaaDisposition::NotConfigured,
        cds_cdnskey: TriState::Absent,
        cds_disposition: CdsDisposition::NotPublished,
    }
}
