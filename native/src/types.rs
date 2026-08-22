// types.rs — the IPC payload types (MIRROR of the engine's type section)
//
// The native compartment is the report/store receiver: it deserializes a
// ScoredAnalysis produced by the std engine (Phase 1) and re-derives the
// verdict seal. Every enum VARIANT NAME here is load-bearing — the seal binds
// the Debug representation (`{:?}`), which is the variant name — so these
// definitions are byte-identical to engine/src/analysis.rs's type section.
// Drift is caught by the golden-seal test in seal.rs.
//
// MIRROR NOTICE — this is a temporary thin copy, documented as the established
// spike pattern. The correct long-term architecture is a shared no_std "types"
// crate that both engine/ and native/ depend on (single-producer rule — a
// hand-kept mirror WILL drift). That extraction is the follow-up and requires
// updating scripts/check-citation-boundary.sh too, because the citation-bearing
// truth_chain.rs would move out of engine/ alongside these types.
//
// Under Option B the `chain()` collapse and `Display` impls are NOT needed here
// (the seal reads the disposition directly, and the full truth_chain renderer
// is deferred) — so this mirror carries only what the seal contract requires:
// the exact variant names + the ScoredAnalysis field layout + serde derives.

use crate::tristate::TriState;
use alloc::string::String;
use serde::{Deserialize, Serialize};

// =============================================================================
// DnssecDisposition — the full DNSSEC decision
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnssecDisposition {
    SignedAndDelegated,
    SignedNotDelegated,
    BrokenChain,
    ChainUnverified,
    Unsigned,
    NoZone,
    Unreachable,
}

// =============================================================================
// DkimDisposition — DKIM verification detail
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkimDisposition {
    Verified,
    NotFoundDefaults,
    NotProbed,
    NoMailDomain,
    TransientError,
    KeyMismatch,
    Revoked,
    Wildcard,
}

// =============================================================================
// MtaStsDisposition — MTA-STS policy detail
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MtaStsDisposition {
    Enforced,
    RecordAbsent,
    NoZone,
    TransientError,
    NotEnforced,
    PolicyInvalid,
}

// =============================================================================
// DaneDisposition — DANE (SMTP TLSA) verification detail
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaneDisposition {
    TlsaPublished,
    Verified,
    Mismatch,
    NotConfigured,
    NoMx,
    NoMail,
    TransientError,
    DnssecRequired,
}

// =============================================================================
// SpfDisposition — SPF policy detail
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpfDisposition {
    HardFail, // -all — enforced
    SoftFail, // ~all — deployed but not enforced
    OtherPolicy,
    NotConfigured,
    NoMail,
    TransientError,
}

// =============================================================================
// DmarcDisposition — DMARC policy detail
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmarcDisposition {
    Reject,     // p=reject
    Quarantine, // p=quarantine
    Monitor,    // p=none
    InvalidPolicy,
    NotConfigured,
    NoMail,
    TransientError,
}

// =============================================================================
// CaaDisposition — CAA record detail
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaaDisposition {
    FullyRestricted,         // issue ";"
    Configured,              // issue restriction present
    WildcardFullyRestricted, // issuewild ";"
    NotConfigured,
    NoZone,
    TransientError,
}

// =============================================================================
// CdsDisposition — CDS/CDNSKEY detail (DNSSEC DS automation)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdsDisposition {
    Published,
    DeletionRequested, // null CDS (algorithm 0) — DS removal signaled
    NotPublished,
    NoZone,
    TransientError,
}

// =============================================================================
// ScoredAnalysis — the IPC payload (spec §5)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredAnalysis {
    pub domain: String,
    pub session_id: u64,
    pub timestamp_local: u64,
    /// Which resolver (vantage) produced this measurement — enters the seal.
    pub resolver_identity: String,

    pub dnssec_chain: TriState,
    pub dnssec_disposition: DnssecDisposition,
    pub spf: TriState,
    pub spf_disposition: SpfDisposition,
    pub dkim: TriState,
    pub dkim_disposition: DkimDisposition,
    pub dmarc: TriState,
    pub dmarc_disposition: DmarcDisposition,
    pub dane: TriState,
    pub dane_disposition: DaneDisposition,
    pub mta_sts: TriState,
    pub mta_sts_disposition: MtaStsDisposition,
    pub caa: TriState,
    pub caa_disposition: CaaDisposition,
    pub cds_cdnskey: TriState,
    pub cds_disposition: CdsDisposition,
}
