// dispositions.rs — the eight per-control disposition enums + the IPC payload
//
// Extracted from engine/src/analysis.rs (the former single location) into this
// shared crate so the engine (std) and the native store compartment (no_std)
// compile against ONE definition. The enum VARIANT NAMES are load-bearing
// twice over: serde writes them verbatim into stored verdict JSON, and the
// verdict seal hashes each variant's SealSpelling (seal_spelling.rs —
// hand-pinned literals, today identical to the variant names; no longer the
// derived `Debug` output, whose stability Rust disclaims). A rename is a
// seal-scheme event — which is exactly why the definition must not be
// duplicated anywhere.
//
// The RFC citations in the doc comments below are layer-1 facts of the
// disposition semantics; they move WITH the type so the semantics and their
// authority stay colocated. check-citation-boundary.sh treats this crate (like
// engine/) as a licensed citation producer.

use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::tristate::TriState;

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
            DnssecDisposition::SignedNotDelegated => TriState::Absent,
            DnssecDisposition::BrokenChain => TriState::Absent,
            DnssecDisposition::ChainUnverified => TriState::Indet,
            DnssecDisposition::Unsigned => TriState::Absent,
            DnssecDisposition::NoZone => TriState::Indet,
            DnssecDisposition::Unreachable => TriState::Indet,
        }
    }
}

impl core::fmt::Display for DnssecDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
// =============================================================================
// DkimDisposition — DKIM verification detail
// =============================================================================
//
// Carey's rule: "not found with the 81 defaults" and "absent" must never be
// the same value. The Go engine defaults to DKIMInconclusive (zero value). This
// enum makes that distinction structural — following the DnssecDisposition
// pattern (one enum per control, chain() to TriState at presentation).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkimDisposition {
    /// Selector resolved, key verified — DKIM is configured and operational.
    Verified,
    /// 81 default selectors probed, none matched — NOT evidence of absence.
    /// Provide a selector (s= tag in DKIM-Signature header) to verify.
    /// Only the prober may emit this: it is a claim that the sweep RAN.
    NotFoundDefaults,
    /// The selector sweep has not run (probe not yet wired in). Distinct from
    /// NotFoundDefaults, which claims 81 probes happened — emitting that
    /// without probing would be a fabricated measurement.
    NotProbed,
    /// No mail server — DKIM is not applicable.
    NoMailDomain,
    /// Lookup failed (SERVFAIL/timeout) — could not measure.
    TransientError,
    /// Selector resolved but key validation failed.
    KeyMismatch,
    /// Selector resolves to an EMPTY p= — the key is revoked (RFC 6376 §3.6.1),
    /// a deliberate withdrawal, not a misconfiguration. Collapses to Absent
    /// (no signature verifies) at a lower severity than KeyMismatch.
    Revoked,
    /// A nonexistent selector name resolved to TXT — the domain publishes a
    /// wildcard `*._domainkey`, so the 81-selector sweep proves nothing.
    /// Collapses to Indet (honest uncertainty), not a key verdict.
    Wildcard,
}

impl DkimDisposition {
    pub fn chain(self) -> TriState {
        match self {
            DkimDisposition::Verified => TriState::Present,
            DkimDisposition::NotFoundDefaults => TriState::Indet,
            DkimDisposition::NotProbed => TriState::Indet,
            DkimDisposition::NoMailDomain => TriState::NotApplicable,
            DkimDisposition::TransientError => TriState::Indet,
            DkimDisposition::KeyMismatch => TriState::Absent,
            DkimDisposition::Revoked => TriState::Absent,
            DkimDisposition::Wildcard => TriState::Indet,
        }
    }
}

impl core::fmt::Display for DkimDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DkimDisposition::Verified => write!(f, "verified"),
            DkimDisposition::NotFoundDefaults => write!(f, "not-found-with-81-defaults"),
            DkimDisposition::NotProbed => write!(f, "not-probed (no selector available)"),
            DkimDisposition::NoMailDomain => write!(f, "no-mail-domain"),
            DkimDisposition::TransientError => write!(f, "transient-error"),
            DkimDisposition::KeyMismatch => write!(f, "key-mismatch"),
            DkimDisposition::Revoked => write!(f, "key-revoked"),
            DkimDisposition::Wildcard => write!(f, "wildcard"),
        }
    }
}

// =============================================================================
// MtaStsDisposition — MTA-STS policy detail
// =============================================================================
//
// The SOA disambiguation (record_absence_verdict) computes which zone answered
// an NXDOMAIN and then throws it away at the TriState boundary. This enum
// preserves that distinction — following the DnssecDisposition/DkimDisposition
// pattern.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MtaStsDisposition {
    /// Policy fetched and valid — MTA-STS is configured and enforced.
    Enforced,
    /// Zone exists but no MTA-STS record — the domain could configure it but
    /// has not. Distinguished from NoZone by the SOA disambiguation.
    RecordAbsent,
    /// NXDOMAIN on _mta-sts — the domain does not exist (SOA is parent/TLD).
    NoZone,
    /// The DISCOVERY lookup errored (SERVFAIL/timeout) — nothing measured.
    /// Never emitted once the hint is confirmed present: a hint without a
    /// servable policy is PolicyInvalid (measured), not this.
    TransientError,
    /// Policy fetched and VALID but mode is "none" or "testing" — deployed,
    /// not enforcing (§8: scores Present, deployment not protection).
    NotEnforced,
    /// The hint TXT exists but the HTTPS policy is missing, unfetchable, or
    /// invalid — T1-1 doctrine: an advertised policy that cannot be served is
    /// a MEASURED absence, never "couldn't measure".
    PolicyInvalid,
}

impl MtaStsDisposition {
    pub fn chain(self) -> TriState {
        match self {
            MtaStsDisposition::Enforced => TriState::Present,
            MtaStsDisposition::RecordAbsent => TriState::Absent,
            MtaStsDisposition::NoZone => TriState::Indet,
            MtaStsDisposition::TransientError => TriState::Indet,
            MtaStsDisposition::NotEnforced => TriState::Present,
            MtaStsDisposition::PolicyInvalid => TriState::Absent,
        }
    }
}

impl core::fmt::Display for MtaStsDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MtaStsDisposition::Enforced => write!(f, "enforced"),
            MtaStsDisposition::RecordAbsent => write!(f, "record-absent"),
            MtaStsDisposition::NoZone => write!(f, "no-zone"),
            MtaStsDisposition::TransientError => write!(f, "transient-error"),
            MtaStsDisposition::NotEnforced => write!(f, "not-enforced"),
            MtaStsDisposition::PolicyInvalid => {
                write!(f, "policy-invalid (hint without a servable policy)")
            }
        }
    }
}

// =============================================================================
// DaneDisposition — DANE (SMTP TLSA) verification detail
// =============================================================================
//
// The null-MX NotApplicable vs absent distinction is the one remaining
// scope-diff from the 39/1/0 differential.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaneDisposition {
    /// TLSA records are PUBLISHED at _25._tcp.<mx>. Publication is the only
    /// fact this pass measures — the certificate match is not checked. This is
    /// what the presence probe emits; claiming more would be a fabricated
    /// measurement (the DKIM NotProbed lesson).
    TlsaPublished,
    /// RESERVED for the SMTP certificate prober (connect, fetch cert, compare
    /// digests). No current emission site — TLSA presence alone must emit
    /// TlsaPublished, never this.
    Verified,
    /// RESERVED for the SMTP certificate prober. No current emission site.
    Mismatch,
    NotConfigured, // MX exists (non-null), no TLSA on any MX host
    /// Zone exists but publishes NO MX at all (NODATA). Mail is unroutable
    /// yet the domain can still be spoofed FROM — a measured absence, distinct
    /// from the null-MX declaration below.
    NoMx,
    NoMail,         // null MX (RFC 7505) — explicit "accepts no mail"
    TransientError, // SERVFAIL/timeout
    DnssecRequired, // DANE requires DNSSEC (RFC 7672 §1.3.2)
}

impl DaneDisposition {
    pub fn chain(self) -> TriState {
        match self {
            DaneDisposition::TlsaPublished => TriState::Present,
            DaneDisposition::Verified => TriState::Present,
            DaneDisposition::Mismatch => TriState::Absent,
            DaneDisposition::NotConfigured => TriState::Absent,
            DaneDisposition::NoMx => TriState::Absent,
            DaneDisposition::NoMail => TriState::NotApplicable,
            DaneDisposition::TransientError => TriState::Indet,
            // NOT Indet. The gate that emits this (dane_host_zone_requires_dnssec)
            // fires ONLY on Unsigned/NoZone — both MEASURED — and deliberately
            // passes Unreachable/ChainUnverified through to the TLSA loop so a
            // genuine couldn't-measure reports itself. So this is a measured
            // structural unavailability, not a gap in our knowledge: we queried
            // the MX host's zone, found no DNSKEY, and concluded DANE cannot be
            // trusted here (RFC 7672 §1.3.2). Rendering "?" told the reader we
            // failed to determine something the DNSSEC row two lines up already
            // determined. Absent is also wrong — it attributes the DNSSEC
            // failure to DANE and counts one deficiency twice.
            DaneDisposition::DnssecRequired => TriState::NotApplicable,
        }
    }
}

impl core::fmt::Display for DaneDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DaneDisposition::TlsaPublished => write!(f, "tlsa-published (match not verified)"),
            DaneDisposition::Verified => write!(f, "verified"),
            DaneDisposition::Mismatch => write!(f, "mismatch"),
            DaneDisposition::NotConfigured => write!(f, "not-configured"),
            DaneDisposition::NoMx => write!(f, "no-mx (zone has no mail routing)"),
            DaneDisposition::NoMail => write!(f, "no-mail (null MX)"),
            DaneDisposition::TransientError => write!(f, "transient-error"),
            DaneDisposition::DnssecRequired => write!(f, "dnssec-required"),
        }
    }
}

// =============================================================================
// SpfDisposition — SPF policy detail
// =============================================================================
//
// ~all (softfail) is deployed-but-not-enforcing — a different claim from
// absent (no SPF at all) or -all (hardfail). Same shape as MtaStsDisposition.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpfDisposition {
    HardFail, // -all — SPF enforced
    SoftFail, // ~all — deployed but not enforced
    /// Record present but the terminal qualifier is ?all, or there is no `all`
    /// mechanism at all (bare redirect=). Neutral: asserts nothing against
    /// unauthorized senders. RFC 7208 §8.2 — neutral is treated exactly like
    /// none. Measured as deployed with no negative assertion — NEVER report
    /// this as HardFail: the -all was measured to be absent.
    OtherPolicy,
    /// +all — an explicit statement that ANY host is authorized to inject mail
    /// with this identity. RFC 7208 §2.6.3 / §8.3: a pass means the domain
    /// "can now, in the sense of reputation, be considered responsible for
    /// sending the message." It authorizes the entire internet, so it provides
    /// no selective authorization — functionally identical to no record. The
    /// one disposition that makes forgery SUCCEED rather than go unblocked.
    PositiveAll,
    NotConfigured, // no SPF record
    NoMail,        // null MX — SPF not applicable
    TransientError,
}

impl SpfDisposition {
    pub fn chain(self) -> TriState {
        match self {
            SpfDisposition::HardFail => TriState::Present,
            SpfDisposition::SoftFail => TriState::Present,
            SpfDisposition::OtherPolicy => TriState::Present,
            SpfDisposition::PositiveAll => TriState::Absent,
            SpfDisposition::NotConfigured => TriState::Absent,
            SpfDisposition::NoMail => TriState::NotApplicable,
            SpfDisposition::TransientError => TriState::Indet,
        }
    }
}

impl core::fmt::Display for SpfDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpfDisposition::HardFail => write!(f, "hardfail (-all)"),
            SpfDisposition::SoftFail => write!(f, "softfail (~all)"),
            SpfDisposition::OtherPolicy => write!(f, "other-policy (no -all/~all terminal)"),
            SpfDisposition::PositiveAll => write!(f, "authorizes-all (+all)"),
            SpfDisposition::NotConfigured => write!(f, "not-configured"),
            SpfDisposition::NoMail => write!(f, "no-mail"),
            SpfDisposition::TransientError => write!(f, "transient-error"),
        }
    }
}

// =============================================================================
// DmarcDisposition — DMARC policy detail
// =============================================================================
//
// p=none is deployed-but-not-enforcing — a different claim from absent
// or p=reject. Same shape as MtaStsDisposition::NotEnforced.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmarcDisposition {
    Reject,     // p=reject — DMARC enforced
    Quarantine, // p=quarantine — intermediate enforcement
    Monitor,    // p=none — deployed but not enforced
    /// Record present but the REQUIRED p= tag is missing or unrecognized
    /// (RFC 9989, which obsoletes RFC 7489: p is mandatory). Receivers ignore
    /// an invalid record — this is measured invalidity, NEVER to be reported
    /// as any real policy.
    InvalidPolicy,
    NotConfigured, // no DMARC record
    NoMail,        // null MX — DMARC not applicable
    TransientError,
}

impl DmarcDisposition {
    pub fn chain(self) -> TriState {
        match self {
            DmarcDisposition::Reject => TriState::Present,
            DmarcDisposition::Quarantine => TriState::Present,
            DmarcDisposition::Monitor => TriState::Present,
            // Missing-or-invalid is the TriState Absent doctrine verbatim: an
            // invalid record gives receivers exactly as much as no record.
            DmarcDisposition::InvalidPolicy => TriState::Absent,
            DmarcDisposition::NotConfigured => TriState::Absent,
            DmarcDisposition::NoMail => TriState::NotApplicable,
            DmarcDisposition::TransientError => TriState::Indet,
        }
    }
}

impl core::fmt::Display for DmarcDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DmarcDisposition::Reject => write!(f, "reject (p=reject)"),
            DmarcDisposition::Quarantine => write!(f, "quarantine (p=quarantine)"),
            DmarcDisposition::Monitor => write!(f, "monitor (p=none)"),
            DmarcDisposition::InvalidPolicy => {
                write!(f, "invalid-policy (p= missing or unrecognized)")
            }
            DmarcDisposition::NotConfigured => write!(f, "not-configured"),
            DmarcDisposition::NoMail => write!(f, "no-mail"),
            DmarcDisposition::TransientError => write!(f, "transient-error"),
        }
    }
}

// =============================================================================
// CaaDisposition — CAA record detail
// =============================================================================
//
// CAA is a presence signal (which CAs may issue). The disposition captures
// configured vs not-configured vs couldn't-measure (SOA disambiguation).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaaDisposition {
    /// `issue ";"` — no CA may issue ANY certificate for this domain
    /// (RFC 8659 §4.2). The strongest CAA state: issuance is affirmatively
    /// prohibited outright, not delegated to a list.
    FullyRestricted,
    Configured, // CAA record present (issue restriction)
    /// `issuewild ";"` — no CA may issue a wildcard certificate for this
    /// domain (RFC 8659 §4.3). A distinct, more restrictive state than a
    /// named-CA `issue` restriction: wildcard issuance is affirmatively
    /// prohibited rather than delegated to a list.
    WildcardFullyRestricted,
    NotConfigured, // zone exists, no CAA
    NoZone,        // NXDOMAIN — domain missing
    TransientError,
}

impl CaaDisposition {
    pub fn chain(self) -> TriState {
        match self {
            CaaDisposition::FullyRestricted => TriState::Present,
            CaaDisposition::Configured => TriState::Present,
            CaaDisposition::WildcardFullyRestricted => TriState::Present,
            CaaDisposition::NotConfigured => TriState::Absent,
            CaaDisposition::NoZone => TriState::Indet,
            CaaDisposition::TransientError => TriState::Indet,
        }
    }
}

impl core::fmt::Display for CaaDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CaaDisposition::FullyRestricted => write!(f, "fully-restricted (issue ;)"),
            CaaDisposition::Configured => write!(f, "configured"),
            CaaDisposition::WildcardFullyRestricted => {
                write!(f, "wildcard-fully-restricted (issuewild ;)")
            }
            CaaDisposition::NotConfigured => write!(f, "not-configured"),
            CaaDisposition::NoZone => write!(f, "no-zone"),
            CaaDisposition::TransientError => write!(f, "transient-error"),
        }
    }
}

// =============================================================================
// CdsDisposition — CDS/CDNSKEY detail (DNSSEC DS automation)
// =============================================================================
//
// CDS/CDNSKEY signal whether the child publishes a DS-update hint for the
// parent. Presence is a measured fact; absence under an existing zone is a
// different claim from no-zone.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdsDisposition {
    Published, // CDS or CDNSKEY present
    /// Null CDS/CDNSKEY (algorithm 0) — the operator has signaled "remove my
    /// DS records", i.e. deliberate DNSSEC decommissioning (RFC 8078 §4).
    /// Present-but-negative: the record exists, and its value requests the
    /// parent delete the DS RRset. Measured presence, NOT the same as absence.
    DeletionRequested,
    NotPublished, // zone exists, no CDS/CDNSKEY
    NoZone,       // NXDOMAIN — domain missing
    TransientError,
}

impl CdsDisposition {
    pub fn chain(self) -> TriState {
        match self {
            CdsDisposition::Published => TriState::Present,
            CdsDisposition::DeletionRequested => TriState::Present,
            CdsDisposition::NotPublished => TriState::Absent,
            CdsDisposition::NoZone => TriState::Indet,
            CdsDisposition::TransientError => TriState::Indet,
        }
    }
}

impl core::fmt::Display for CdsDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CdsDisposition::Published => write!(f, "published"),
            CdsDisposition::DeletionRequested => {
                write!(f, "deletion-requested (null CDS — DS removal signaled)")
            }
            CdsDisposition::NotPublished => write!(f, "not-published"),
            CdsDisposition::NoZone => write!(f, "no-zone"),
            CdsDisposition::TransientError => write!(f, "transient-error"),
        }
    }
}

// =============================================================================
// TlsaZone — where the MX host lives, relative to the scanned domain's zone
// =============================================================================
//
// The DANE attribution field — a MEASUREMENT, never a verdict (the
// "provider-gated" disposition was retracted: it asserted an ownership
// relationship DNS cannot observe). The only observable is the SOA zone-cut
// relationship: does the MX host's zone apex equal, descend from, or lie
// outside the scanned domain's zone apex? Read directly from the zone cut
// (no PSL) — RFC 7672 §2.2.3 puts the TLSA key `_25._tcp.<mx-host>` in the MX
// host's zone by delegation, so the zone cut answers "who must publish for
// DANE to work?"
//
// Sealed (SEAL_SCHEME v3): it is a primary DNS measurement that changes the
// verdict's attribution, so two verdicts that differ only here must not seal
// identically (dhs.gov vs cia.gov both read dane=NotConfigured, but one is the
// operator's gap and the other the owner's).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsaZone {
    /// MX host lives in the scanned domain's own zone (apex equal) — self-operated.
    SameZone,
    /// MX host in a subdomain-zone of the scanned domain — still owner-controlled
    /// (e.g. amazon.com -> amazon-smtp.amazon.com).
    DescendantZone,
    /// MX host in a zone that is NOT a descendant of the scanned domain —
    /// someone else's infrastructure (e.g. microsoft.com -> protection.outlook.com).
    ForeignZone,
    /// Couldn't walk the zone cut (SOA unresolvable) — honest non-classification.
    ZoneUnmeasured,
    /// No MX host exists to classify (no MX records, or null-MX "no mail").
    NoMxHost,
}

impl core::fmt::Display for TlsaZone {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlsaZone::SameZone => write!(f, "same-zone"),
            TlsaZone::DescendantZone => write!(f, "descendant-zone"),
            TlsaZone::ForeignZone => write!(f, "foreign-zone"),
            TlsaZone::ZoneUnmeasured => write!(f, "zone-unmeasured"),
            TlsaZone::NoMxHost => write!(f, "no-mx-host"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoredAnalysis {
    pub domain: String,
    pub session_id: u64,
    pub timestamp_local: u64,
    /// Which resolver (vantage) produced this measurement — the observer's
    /// identity, not the target's. Two scans from different resolvers are
    /// different measurements even if their verdicts coincide (the
    /// observation-conditions rule), so this enters the seal. Populated by
    /// the caller (the flipper/TUI know their own resolver config).
    pub resolver_identity: String,

    // Per-control tri-state scores
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
    /// Where the MX host lives relative to this domain's zone (DANE attribution
    /// field — a measurement, sealed; see TlsaZone).
    pub tlsa_zone: TlsaZone,
    pub mta_sts: TriState,
    pub mta_sts_disposition: MtaStsDisposition, // "warning" → Absent (T1-1 fix)
    pub caa: TriState,
    pub caa_disposition: CaaDisposition,
    pub cds_cdnskey: TriState,
    pub cds_disposition: CdsDisposition,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec::Vec};

    /// Serde writes the variant NAMES verbatim into stored JSON, and the seal
    /// spellings (seal_spelling.rs, pinned separately) today equal them too —
    /// so this test guards the JSON vocabulary. Pin the exact ordered
    /// variant-name sets so a rename fails loudly here rather than silently
    /// changing what every existing seal means.
    #[test]
    fn disposition_variant_names_are_stable() {
        fn names<T: core::fmt::Debug>(all: &[T]) -> Vec<String> {
            all.iter().map(|v| format!("{v:?}")).collect()
        }
        assert_eq!(
            names(&[
                DnssecDisposition::SignedAndDelegated,
                DnssecDisposition::SignedNotDelegated,
                DnssecDisposition::BrokenChain,
                DnssecDisposition::ChainUnverified,
                DnssecDisposition::Unsigned,
                DnssecDisposition::NoZone,
                DnssecDisposition::Unreachable,
            ]),
            [
                "SignedAndDelegated",
                "SignedNotDelegated",
                "BrokenChain",
                "ChainUnverified",
                "Unsigned",
                "NoZone",
                "Unreachable"
            ]
        );
        assert_eq!(
            names(&[
                DkimDisposition::Verified,
                DkimDisposition::NotFoundDefaults,
                DkimDisposition::NotProbed,
                DkimDisposition::NoMailDomain,
                DkimDisposition::TransientError,
                DkimDisposition::KeyMismatch,
                DkimDisposition::Revoked,
                DkimDisposition::Wildcard,
            ]),
            [
                "Verified",
                "NotFoundDefaults",
                "NotProbed",
                "NoMailDomain",
                "TransientError",
                "KeyMismatch",
                "Revoked",
                "Wildcard"
            ]
        );
        assert_eq!(
            names(&[
                DaneDisposition::TlsaPublished,
                DaneDisposition::Verified,
                DaneDisposition::Mismatch,
                DaneDisposition::NotConfigured,
                DaneDisposition::NoMx,
                DaneDisposition::NoMail,
                DaneDisposition::TransientError,
                DaneDisposition::DnssecRequired,
            ]),
            [
                "TlsaPublished",
                "Verified",
                "Mismatch",
                "NotConfigured",
                "NoMx",
                "NoMail",
                "TransientError",
                "DnssecRequired"
            ]
        );
        assert_eq!(
            names(&[
                TlsaZone::SameZone,
                TlsaZone::DescendantZone,
                TlsaZone::ForeignZone,
                TlsaZone::ZoneUnmeasured,
                TlsaZone::NoMxHost,
            ]),
            [
                "SameZone",
                "DescendantZone",
                "ForeignZone",
                "ZoneUnmeasured",
                "NoMxHost"
            ]
        );
        // SPF — previously unpinned; the fork's rename proposal (PositiveAll →
        // PassAll, OtherPolicy → Neutral) makes this load-bearing: a rename
        // MUST fail here loudly rather than silently change what every seal
        // means. Pinned to the CURRENT shipped names.
        assert_eq!(
            names(&[
                SpfDisposition::HardFail,
                SpfDisposition::SoftFail,
                SpfDisposition::OtherPolicy,
                SpfDisposition::PositiveAll,
                SpfDisposition::NotConfigured,
                SpfDisposition::NoMail,
                SpfDisposition::TransientError,
            ]),
            [
                "HardFail",
                "SoftFail",
                "OtherPolicy",
                "PositiveAll",
                "NotConfigured",
                "NoMail",
                "TransientError"
            ]
        );
        assert_eq!(
            names(&[
                DmarcDisposition::Reject,
                DmarcDisposition::Quarantine,
                DmarcDisposition::Monitor,
                DmarcDisposition::InvalidPolicy,
                DmarcDisposition::NotConfigured,
                DmarcDisposition::NoMail,
                DmarcDisposition::TransientError,
            ]),
            [
                "Reject",
                "Quarantine",
                "Monitor",
                "InvalidPolicy",
                "NotConfigured",
                "NoMail",
                "TransientError"
            ]
        );
        assert_eq!(
            names(&[
                MtaStsDisposition::Enforced,
                MtaStsDisposition::RecordAbsent,
                MtaStsDisposition::NoZone,
                MtaStsDisposition::TransientError,
                MtaStsDisposition::NotEnforced,
                MtaStsDisposition::PolicyInvalid,
            ]),
            [
                "Enforced",
                "RecordAbsent",
                "NoZone",
                "TransientError",
                "NotEnforced",
                "PolicyInvalid"
            ]
        );
        assert_eq!(
            names(&[
                CaaDisposition::FullyRestricted,
                CaaDisposition::Configured,
                CaaDisposition::WildcardFullyRestricted,
                CaaDisposition::NotConfigured,
                CaaDisposition::NoZone,
                CaaDisposition::TransientError,
            ]),
            [
                "FullyRestricted",
                "Configured",
                "WildcardFullyRestricted",
                "NotConfigured",
                "NoZone",
                "TransientError"
            ]
        );
        assert_eq!(
            names(&[
                CdsDisposition::Published,
                CdsDisposition::DeletionRequested,
                CdsDisposition::NotPublished,
                CdsDisposition::NoZone,
                CdsDisposition::TransientError,
            ]),
            [
                "Published",
                "DeletionRequested",
                "NotPublished",
                "NoZone",
                "TransientError"
            ]
        );
    }

    /// chain() is the single collapse point (disposition -> TriState). The
    /// engine derives every score through it, never hand-paired.
    #[test]
    fn chain_collapses_correctly() {
        assert_eq!(
            DnssecDisposition::SignedAndDelegated.chain(),
            TriState::Present
        );
        assert_eq!(DnssecDisposition::BrokenChain.chain(), TriState::Absent);
        assert_eq!(DnssecDisposition::NoZone.chain(), TriState::Indet);
        assert_eq!(DaneDisposition::NoMail.chain(), TriState::NotApplicable);
        assert_eq!(SpfDisposition::SoftFail.chain(), TriState::Present);
    }
}
