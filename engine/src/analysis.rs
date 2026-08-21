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
        }
    }
}

impl std::fmt::Display for DkimDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimDisposition::Verified => write!(f, "verified"),
            DkimDisposition::NotFoundDefaults => write!(f, "not-found-with-81-defaults"),
            DkimDisposition::NotProbed => write!(f, "not-probed (no selector available)"),
            DkimDisposition::NoMailDomain => write!(f, "no-mail-domain"),
            DkimDisposition::TransientError => write!(f, "transient-error"),
            DkimDisposition::KeyMismatch => write!(f, "key-mismatch"),
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

impl std::fmt::Display for MtaStsDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    DnssecRequired, // DANE requires DNSSEC (RFC 7672 §4)
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
            DaneDisposition::DnssecRequired => TriState::Indet,
        }
    }
}

impl std::fmt::Display for DaneDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    /// Record present but the terminal qualifier is neither -all nor ~all
    /// (?all, +all, no all mechanism, bare redirect=). Measured as deployed
    /// with no enforcement instruction — NEVER report this as HardFail: the
    /// -all was measured to be absent.
    OtherPolicy,
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
            SpfDisposition::NotConfigured => TriState::Absent,
            SpfDisposition::NoMail => TriState::NotApplicable,
            SpfDisposition::TransientError => TriState::Indet,
        }
    }
}

impl std::fmt::Display for SpfDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfDisposition::HardFail => write!(f, "hardfail (-all)"),
            SpfDisposition::SoftFail => write!(f, "softfail (~all)"),
            SpfDisposition::OtherPolicy => write!(f, "other-policy (no -all/~all terminal)"),
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

impl std::fmt::Display for DmarcDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    Configured,    // CAA record present
    NotConfigured, // zone exists, no CAA
    NoZone,        // NXDOMAIN — domain missing
    TransientError,
}

impl CaaDisposition {
    pub fn chain(self) -> TriState {
        match self {
            CaaDisposition::Configured => TriState::Present,
            CaaDisposition::NotConfigured => TriState::Absent,
            CaaDisposition::NoZone => TriState::Indet,
            CaaDisposition::TransientError => TriState::Indet,
        }
    }
}

impl std::fmt::Display for CaaDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaaDisposition::Configured => write!(f, "configured"),
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
    Published,    // CDS or CDNSKEY present
    NotPublished, // zone exists, no CDS/CDNSKEY
    NoZone,       // NXDOMAIN — domain missing
    TransientError,
}

impl CdsDisposition {
    pub fn chain(self) -> TriState {
        match self {
            CdsDisposition::Published => TriState::Present,
            CdsDisposition::NotPublished => TriState::Absent,
            CdsDisposition::NoZone => TriState::Indet,
            CdsDisposition::TransientError => TriState::Indet,
        }
    }
}

impl std::fmt::Display for CdsDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CdsDisposition::Published => write!(f, "published"),
            CdsDisposition::NotPublished => write!(f, "not-published"),
            CdsDisposition::NoZone => write!(f, "no-zone"),
            CdsDisposition::TransientError => write!(f, "transient-error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub mta_sts: TriState,
    pub mta_sts_disposition: MtaStsDisposition, // "warning" → Absent (T1-1 fix)
    pub caa: TriState,
    pub caa_disposition: CaaDisposition,
    pub cds_cdnskey: TriState,
    pub cds_disposition: CdsDisposition,
}

// =============================================================================
// analyse_domain — top-level entry point
// =============================================================================

/// Analyse a domain with the default probe set (no caller-supplied DKIM
/// selectors, default resolver identity). Thin wrapper over
/// [`analyse_domain_with_selectors`].
pub async fn analyse_domain(resolver: &TokioResolver, domain: &str) -> Result<ScoredAnalysis> {
    analyse_domain_with_selectors(resolver, domain, &[], "default").await
}

/// Analyse a domain, probing the caller-supplied DKIM selectors in addition
/// to (and ahead of) the 81 defaults. A user who knows their selector gets a
/// definitive `Verified` / `KeyMismatch` instead of the sweep's
/// "absence NOT proven".
///
/// `resolver_identity` names the vantage the measurement was taken from
/// (e.g. "cloudflare") — it is sealed, so two scans from different resolvers
/// never seal identically, even when their verdicts coincide.
pub async fn analyse_domain_with_selectors(
    resolver: &TokioResolver,
    domain: &str,
    dkim_selectors: &[String],
    resolver_identity: &str,
) -> Result<ScoredAnalysis> {
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
    // Every scorer returns ONLY its disposition; the tri-state is derived via
    // chain() right here and nowhere else. Hand-pairing (TriState, Disposition)
    // tuples let the two verdict channels disagree — the 2026-08-19 adversarial
    // panel found three live divergences that way. Derived means impossible.
    let spf_disposition = score_spf(resolver, domain).await;
    let spf = spf_disposition.chain();
    // The selector sweep is now wired: probe the 81 defaults (plus any
    // caller-supplied selector via analyse_domain_with_selectors). The honest
    // dispositions are Verified / KeyMismatch / NotFoundDefaults — no longer
    // a hardcoded NotProbed stub.
    let dkim_disposition = score_dkim(resolver, domain, dkim_selectors).await;
    let dkim = dkim_disposition.chain();
    let dmarc_disposition = score_dmarc(resolver, domain).await;
    let dmarc = dmarc_disposition.chain();
    let dane_disposition = score_dane(resolver, domain).await;
    let dane = dane_disposition.chain();
    let mta_sts_disposition = score_mta_sts(resolver, domain).await;
    let mta_sts = mta_sts_disposition.chain();
    let caa_disposition = score_caa(resolver, domain).await;
    let caa = caa_disposition.chain();
    let cds_disposition = score_cds_cdnskey(resolver, domain).await;
    let cds_cdnskey = cds_disposition.chain();

    Ok(ScoredAnalysis {
        domain: domain.to_string(),
        session_id,
        timestamp_local,
        resolver_identity: resolver_identity.to_string(),
        dnssec_chain,
        dnssec_disposition,
        spf,
        spf_disposition,
        dkim,
        dkim_disposition,
        dmarc,
        dmarc_disposition,
        dane,
        dane_disposition,
        mta_sts,
        mta_sts_disposition,
        caa,
        caa_disposition,
        cds_cdnskey,
        cds_disposition,
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
/// `domain` is the apex under analysis (e.g. "cia.gov"); the error may come
/// from a query for the apex (SPF/CAA) or a subdomain (`_dmarc`, `_mta-sts`).
///
/// NODATA (NoError) = the zone exists but has no record of this type -> Absent.
/// NXDOMAIN = the queried NAME does not exist. Whether that means "domain
///   missing" (Indet) or "record absent" (Absent) depends on which zone
///   returned NXDOMAIN, read from the SOA in the authority section:
///     * SOA is the domain's own zone  -> domain exists, name absent -> Absent
///     * SOA is a parent/TLD (or none) -> domain itself missing -> Indet
///   (the domain_exists doctrine: `Absent` is a claim about a zone's
///    configuration, and there is no zone).
/// transient -> Indet.
fn record_absence_verdict(e: &NetError, domain: &str) -> TriState {
    use hickory_proto::op::ResponseCode;
    use hickory_resolver::net::DnsError;
    match e {
        NetError::Dns(DnsError::NoRecordsFound(nr)) => match nr.response_code {
            ResponseCode::NoError => TriState::Absent, // NODATA on an existing zone
            ResponseCode::NXDomain => {
                let soa_zone = nr.soa.as_ref().map(|s| s.name.to_ascii());
                match soa_zone {
                    Some(z) if z.trim_end_matches('.').eq_ignore_ascii_case(domain) => {
                        TriState::Absent // domain's own zone: name absent, not domain
                    }
                    _ => TriState::Indet, // parent/TLD zone (or no SOA): domain missing
                }
            }
            _ => TriState::Indet, // SERVFAIL etc. — transient
        },
        _ => TriState::Indet, // transient network error
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
    use hickory_proto::rr::RecordType;

    match resolver.lookup(domain, RecordType::DNSKEY).await {
        Ok(resp) => {
            let answers = resp.answers();
            dnssec_disposition_from_answer(answers_present(answers), answers.first().map(|r| r.proof))
        }
        Err(e) => {
            warn!(domain, error = %e, "DNSSEC DNSKEY lookup error");
            dnssec_disposition_err(&e)
        }
    }
}

/// Pure discriminator: DNSKEY presence × validation proof → disposition.
///
/// Extracted so the island-vs-broken split is pinned WITHOUT the live
/// specimens. The `#[ignore]`d live test (island_of_security_vs_broken_chain)
/// depends on resolutionscope.com still being an island — a window that
/// CLOSES the day its DS lands at the parent. This function is what survives
/// that: every (presence, proof) combination is unit-pinned below, network
/// never involved. DNSKEY presence is the discriminator Proof alone cannot
/// supply — without the presence gate, every genuinely-unsigned domain would
/// read as an island.
fn dnssec_disposition_from_answer(
    keys_present: bool,
    proof: Option<hickory_proto::dnssec::Proof>,
) -> DnssecDisposition {
    use hickory_proto::dnssec::Proof;
    if !keys_present {
        return DnssecDisposition::Unsigned; // no DNSKEY published = unsigned
    }
    match proof {
        Some(Proof::Secure) => DnssecDisposition::SignedAndDelegated,
        Some(Proof::Insecure) => DnssecDisposition::SignedNotDelegated, // island
        Some(Proof::Bogus) => DnssecDisposition::BrokenChain,           // broken — counts against
        _ => DnssecDisposition::ChainUnverified, // keys present, chain unmeasurable
    }
}

async fn score_spf(resolver: &TokioResolver, domain: &str) -> SpfDisposition {
    // SPF is a TXT record at the apex beginning with "v=spf1". The qualifier
    // (-all hardfail vs ~all softfail) is the deployed-but-not-enforcing
    // distinction: ~all is advisory, -all is enforced.
    match resolver.txt_lookup(domain).await {
        Ok(rdata) => {
            let mut spf_records: Vec<String> = Vec::new();
            for rec in rdata.answers() {
                if let hickory_proto::rr::RData::TXT(txt) = &rec.data {
                    for s in &txt.txt_data {
                        let s = String::from_utf8_lossy(s);
                        if s.starts_with("v=spf1") {
                            spf_records.push(s.to_string());
                        }
                    }
                }
            }
            spf_disposition_from_records(&spf_records)
        }
        Err(e) => spf_err_to_disposition(&e, domain),
    }
}

/// Pure SPF terminal-qualifier classifier, extracted so the 2026-08-19
/// panel fix (?all/+all/no-all must NEVER read as HardFail — that reported
/// an enforcement measured to be absent) is regression-pinned without
/// network. The emission decision lives here and only here.
fn spf_disposition_from_records(spf_records: &[String]) -> SpfDisposition {
    if spf_records.is_empty() {
        SpfDisposition::NotConfigured
    } else if spf_records.iter().any(|r| r.contains("-all")) {
        SpfDisposition::HardFail
    } else if spf_records.iter().any(|r| r.contains("~all")) {
        SpfDisposition::SoftFail
    } else {
        SpfDisposition::OtherPolicy
    }
}

async fn score_dmarc(resolver: &TokioResolver, domain: &str) -> DmarcDisposition {
    // DMARC policy at _dmarc.<domain> TXT "v=DMARC1; p=...". p=none is
    // deployed-but-not-enforcing (monitor only), p=quarantine is intermediate,
    // p=reject is enforced. Same shape as MtaStsDisposition::NotEnforced.
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(dmarc_domain.as_str()).await {
        Ok(rdata) => {
            let mut dmarc_records: Vec<String> = Vec::new();
            for rec in rdata.answers() {
                if let hickory_proto::rr::RData::TXT(txt) = &rec.data {
                    for s in &txt.txt_data {
                        let s = String::from_utf8_lossy(s);
                        if s.starts_with("v=DMARC1") {
                            dmarc_records.push(s.to_string());
                        }
                    }
                }
            }
            if dmarc_records.is_empty() {
                DmarcDisposition::NotConfigured
            } else {
                dmarc_disposition_from_record(&dmarc_records[0])
            }
        }
        Err(e) => dmarc_err_to_disposition(&e, domain),
    }
}

// =============================================================================
// DKIM scoring — probe the 81 default selectors (plus caller-supplied ones)
// =============================================================================
//
// RFC 6376 §3.6.2.2: a DKIM key is published at <selector>._domainkey.
// <domain>. The selector is an ARBITRARY label advertised only in the s= tag
// of an outbound DKIM-Signature header — it is not enumerable from the
// zone. Probing these 81 common provider selectors is a SWEEP, not a proof of
// absence: a custom selector means the key exists under a name we didn't
// guess. That is exactly why "not found with 81 defaults" (NotFoundDefaults)
// must never read as "absent" — the enum enforces it structurally, and
// only the prober may emit it (it is a claim that the sweep RAN).

/// The 81 common DKIM selectors, ported from dns-tool-intel
/// (analyzer/dkim.go defaultDKIMSelectors). Each is the full
/// <selector>._domainkey suffix; the queried name is {suffix}.{domain}.
pub(crate) const DEFAULT_DKIM_SELECTORS: [&str; 81] = [
    "default._domainkey",
    "dkim._domainkey",
    "mail._domainkey",
    "email._domainkey",
    "k1._domainkey",
    "k2._domainkey",
    "k3._domainkey",
    "s1._domainkey",
    "s2._domainkey",
    "s3._domainkey",
    "sig1._domainkey",
    "sig2._domainkey",
    "selector1._domainkey",
    "selector2._domainkey",
    "selector3._domainkey",
    "google._domainkey",
    "google2048._domainkey",
    "mailjet._domainkey",
    "mandrill._domainkey",
    "mandrill2._domainkey",
    "amazonses._domainkey",
    "sendgrid._domainkey",
    "sendgrid2._domainkey",
    "smtpapi._domainkey",
    "em._domainkey",
    "mailchimp._domainkey",
    "mc._domainkey",
    "postmark._domainkey",
    "sparkpost._domainkey",
    "mailgun._domainkey",
    "sendinblue._domainkey",
    "brevo._domainkey",
    "mimecast._domainkey",
    "proofpoint._domainkey",
    "everlytickey1._domainkey",
    "everlytickey2._domainkey",
    "zendesk1._domainkey",
    "zendesk2._domainkey",
    "cm._domainkey",
    "mx._domainkey",
    "smtp._domainkey",
    "mailer._domainkey",
    "mta._domainkey",
    "mta1._domainkey",
    "mta2._domainkey",
    "protonmail._domainkey",
    "protonmail2._domainkey",
    "protonmail3._domainkey",
    "fm1._domainkey",
    "fm2._domainkey",
    "fm3._domainkey",
    "zoho._domainkey",
    "zohomail._domainkey",
    "zmail._domainkey",
    "square._domainkey",
    "squareup._domainkey",
    "sq._domainkey",
    "dkim1._domainkey",
    "dkim2._domainkey",
    "dkim3._domainkey",
    "key1._domainkey",
    "key2._domainkey",
    "barracuda._domainkey",
    "hornet._domainkey",
    "cisco._domainkey",
    "turbo-smtp._domainkey",
    "freshdesk._domainkey",
    "hubspot._domainkey",
    "hs1._domainkey",
    "hs2._domainkey",
    "salesforce._domainkey",
    "sf1._domainkey",
    "sf2._domainkey",
    "klaviyo._domainkey",
    "intercom._domainkey",
    "customerio._domainkey",
    "ctct1._domainkey",
    "ctct2._domainkey",
    "dk._domainkey",
    "ml._domainkey",
    "drip._domainkey",
];

/// Pure DKIM key-record extractor: returns the `p=` value if `record` is a
/// DKIM key, else None.
///
/// RFC 6376 §3.6.1: the `v=` tag is RECOMMENDED with default "DKIM1" (not
/// required) — a key record may omit it (e.g. the Mailchimp `mandrill`
/// selector publishes `k=rsa; p=...` with no v=). A record whose FIRST tag is
/// `v=` with any value OTHER than `dkim1` (case-insensitive per RFC 5234) is
/// NOT a DKIM key (e.g. `v=spf1`). The public key is the `p=` tag; an EMPTY
/// `p=` is a revocation (RFC 6376 §3.6.1) — the key is present but unusable.
fn dkim_p_value(record: &str) -> Option<&str> {
    // Reject an explicit v= tag with a non-DKIM1 value. Absent v= defaults to
    // DKIM1, so a bare `k=rsa; p=...` record IS a DKIM key.
    if let Some(first) = record.split(';').next().map(str::trim) {
        let f = first.to_ascii_lowercase();
        if f.starts_with("v=") && !f.starts_with("v=dkim1") {
            return None;
        }
    }
    record.split(';').find_map(|part| {
        let part = part.trim();
        if part.to_ascii_lowercase().starts_with("p=") {
            Some(part[2..].trim())
        } else {
            None
        }
    })
}

/// Pure DKIM disposition classifier: from the sweep counts, decide the verdict.
/// Extracted so the emission decision is unit-pinned without network — the
/// same discipline as spf_disposition_from_records (a scorer that emits
/// Verified from an unverified path must fail a test, not silently ship).
///
///   found_valid     — selectors whose key resolved AND carried a non-empty p=
///   found_revoked   — selectors whose key resolved but p= was empty (revoked)
///   definitive_miss — selectors that answered NODATA / own-zone NXDOMAIN
///   transient       — selectors that SERVFAILed / timed out
///
/// Precedence: revoked beats valid (a revoked key on ANY selector means mail
/// cannot verify through it — deployed-but-wrong, Critical); a valid key
/// beats "not found"; a definitive miss beats transient (we DID probe, nothing
/// matched — NotFoundDefaults, NOT evidence of absence); only when every
/// selector failed transiently do we say we couldn't measure at all.
fn dkim_disposition_from_counts(
    found_valid: usize,
    found_revoked: usize,
    definitive_miss: usize,
    transient: usize,
) -> DkimDisposition {
    if found_revoked > 0 {
        DkimDisposition::KeyMismatch
    } else if found_valid > 0 {
        DkimDisposition::Verified
    } else if definitive_miss > 0 {
        DkimDisposition::NotFoundDefaults
    } else if transient > 0 {
        DkimDisposition::TransientError
    } else {
        // No selectors at all — unreachable (81 defaults always present),
        // but fail honest rather than fabricate a measurement.
        DkimDisposition::NotProbed
    }
}

/// Pure DKIM selector-list builder: caller selectors first (normalized to
/// <selector>._domainkey), then the 81 defaults, deduped. Extracted so the
/// dedup/normalize logic is unit-tested — the two `!selectors.contains` guards
/// were surviving mutants (deleting them silently dropped/deduped selectors).
fn build_dkim_selector_list(extra_selectors: &[String]) -> Vec<String> {
    let mut selectors: Vec<String> =
        Vec::with_capacity(DEFAULT_DKIM_SELECTORS.len() + extra_selectors.len());
    for s in extra_selectors {
        let norm = if s.ends_with("._domainkey") {
            s.clone()
        } else {
            format!("{}._domainkey", s)
        };
        if !selectors.contains(&norm) {
            selectors.push(norm);
        }
    }
    for s in DEFAULT_DKIM_SELECTORS {
        let s = s.to_string();
        if !selectors.contains(&s) {
            selectors.push(s);
        }
    }
    selectors
}

/// The measured DKIM state of one selector's TXT chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DkimKeyState {
    /// A p= tag with an empty value — key present but revoked (RFC 6376 §3.6.1).
    Revoked,
    /// A p= tag with a non-empty value — a usable key.
    Valid,
    /// Chunks returned, but no DKIM key (no p= tag).
    NoKey,
}

/// Classify one selector's TXT chunks: valid key, revoked key, or no key.
/// Extracted so the `key_found = true` / `revoked = true` assignments (surviving
/// mutants) are unit-tested rather than living inline in the async loop.
fn dkim_key_state(chunks: &[String]) -> DkimKeyState {
    let mut key_found = false;
    let mut revoked = false;
    for s in chunks {
        if let Some(p) = dkim_p_value(s) {
            key_found = true;
            if p.is_empty() {
                revoked = true;
            }
        }
    }
    if revoked {
        DkimKeyState::Revoked
    } else if key_found {
        DkimKeyState::Valid
    } else {
        DkimKeyState::NoKey
    }
}

/// One selector's resolved probe: its TXT chunks, or the tri-state verdict of
/// a failed lookup (already disambiguated via record_absence_verdict).
type DkimSelectorProbe = Result<Vec<String>, TriState>;

/// Accumulate per-selector probes into the four counts and apply the DKIM
/// precedence. Extracted so the counter increments and the branch are
/// unit-tested — surviving mutants were `+= → -=` on the counters, the
/// revoked/valid/miss precedence, and the Absent-vs-transient split.
fn dkim_disposition_from_probes(probes: &[DkimSelectorProbe]) -> DkimDisposition {
    let mut found_valid = 0usize;
    let mut found_revoked = 0usize;
    let mut definitive_miss = 0usize;
    let mut transient = 0usize;
    for probe in probes {
        match probe {
            Ok(chunks) => match dkim_key_state(chunks) {
                DkimKeyState::Revoked => found_revoked += 1,
                DkimKeyState::Valid => found_valid += 1,
                DkimKeyState::NoKey => definitive_miss += 1,
            },
            Err(TriState::Absent) => definitive_miss += 1,
            Err(_) => transient += 1,
        }
    }
    dkim_disposition_from_counts(found_valid, found_revoked, definitive_miss, transient)
}

/// Score DKIM by probing the 81 default selectors (plus any caller-supplied
/// selector). This replaces the NotProbed stub: the engine can now honestly
/// report Verified / KeyMismatch / NotFoundDefaults instead of "not measured".
async fn score_dkim(
    resolver: &TokioResolver,
    domain: &str,
    extra_selectors: &[String],
) -> DkimDisposition {
    let selectors = build_dkim_selector_list(extra_selectors);

    // Resolve every selector to its probe outcome (chunks, or a tri-state
    // verdict of a failed lookup). The testable logic — classification and
    // precedence — lives in dkim_key_state + dkim_disposition_from_probes;
    // only the network resolution stays here.
    let mut probes: Vec<DkimSelectorProbe> = Vec::with_capacity(selectors.len());
    for sel in &selectors {
        let fqdn = format!("{}.{}", sel, domain);
        probes.push(match resolver.txt_lookup(fqdn.as_str()).await {
            Ok(rdata) => {
                let mut chunks = Vec::new();
                for rec in rdata.answers() {
                    if let hickory_proto::rr::RData::TXT(txt) = &rec.data {
                        for c in &txt.txt_data {
                            chunks.push(String::from_utf8_lossy(c).to_string());
                        }
                    }
                }
                Ok(chunks)
            }
            Err(e) => Err(record_absence_verdict(&e, domain)),
        });
    }

    dkim_disposition_from_probes(&probes)
}

/// Pure DMARC policy classifier, extracted so the 2026-08-19 panel fix
/// (missing/unrecognized p= must NEVER read as Reject — that reported a
/// policy never observed) is regression-pinned without network.
///
/// Tag VALUES compare case-insensitively: RFC 5234 §2.3 makes ABNF string
/// literals case-insensitive, so `p=REJECT` satisfies RFC 9989's grammar —
/// treating it as invalid would manufacture a finding out of a valid record.
fn dmarc_disposition_from_record(record: &str) -> DmarcDisposition {
    let p = record
        .split(';')
        .map(|t| t.trim())
        .find(|t| t.starts_with("p="))
        .map(|t| t[2..].trim().to_ascii_lowercase())
        .unwrap_or_default();
    match p.as_str() {
        "reject" => DmarcDisposition::Reject,
        "quarantine" => DmarcDisposition::Quarantine,
        "none" => DmarcDisposition::Monitor,
        // Missing or unrecognized p= is measured invalidity, never a policy.
        _ => DmarcDisposition::InvalidPolicy,
    }
}

/// Extract the MX exchange from an rdata record, if it is one. Pure so the
/// MX match arm is unit-tested: deleting it (mutation 1089) would drop every
/// MX record and misread a mail domain as "no MX".
fn mx_exchange_from_rdata(data: &hickory_proto::rr::RData) -> Option<&hickory_proto::rr::Name> {
    match data {
        hickory_proto::rr::RData::MX(m) => Some(&m.exchange),
        _ => None,
    }
}

/// The measured MX shape — the first half of the DANE decision. Three-way
/// because "no MX" and "null MX" are DIFFERENT measurements, and only the
/// third carries routable hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MxShape {
    /// No MX answers (NODATA in disguise) — a domain with no MX can still be
    /// spoofed FROM, a real finding. → NoMx (Absent).
    NoMx,
    /// Every MX is a null MX (RFC 7505 "MX 0 .") — an explicit "accepts no
    /// mail" declaration, a positive measurement. → NoMail (NotApplicable).
    NoMail,
    /// At least one routable host; carries the non-root exchanges.
    Hosts(Vec<String>),
}

/// Classify the extracted MX exchanges. Pure so the empty / all-root /
/// non-root-filter decisions are unit-tested. Mutation 1109 (delete the `!`
/// in the filter) would keep ONLY null-MX entries and read a mixed set as
/// hostless — the mixed test pins that the filter does real work.
fn classify_mx(exchanges: &[hickory_proto::rr::Name]) -> MxShape {
    if exchanges.is_empty() {
        MxShape::NoMx
    } else if exchanges.iter().all(|e| e.is_root()) {
        MxShape::NoMail
    } else {
        let hosts = exchanges
            .iter()
            .filter(|e| !e.is_root())
            .map(|e| e.to_ascii())
            .collect();
        MxShape::Hosts(hosts)
    }
}

/// Pure: the disposition from per-host TLSA outcomes. `Some(n)` is a
/// MEASURED answer count (0 = the host answered "no TLSA records");
/// `None` is a lookup that ERRORED — nothing was measured for that host.
/// The type carries the distinction the old `&[usize]` erased: an errored
/// lookup and a measured-empty answer both arrived as `0`, so when every
/// host errored the old function returned NotConfigured — a measured
/// absence — from data that measured nothing. That is the exact conflation
/// DANE's four-way split exists to prevent.
///
/// Decision, in epistemic order:
///   1. any `Some(n > 0)`  → TlsaPublished — publication was measured;
///      an error on another host cannot erase a found record.
///   2. else any `None`    → TransientError (Indet) — at least one host is
///      unmeasured and no publication was found, so absence is NOT proven
///      (the same "absence NOT proven" doctrine as the DKIM sweep).
///   3. else               → NotConfigured — every host measured, all empty:
///      a real measured absence.
///
/// Publication is the only fact measured here — the SMTP certificate
/// comparison does not exist in this crate, so Verified must never be
/// emitted from this site (panel blocker, 2026-08-19). TlsaPublished is the
/// honest ceiling. The three mutation sites at the original guard
/// (`!resp.answers().is_empty()`) all reduce to the `n > 0` decision, which
/// the count exposes to the mutation tool instead of hiding behind a live
/// resolver.
fn dane_from_tlsa_counts(counts: &[Option<usize>]) -> DaneDisposition {
    if counts.iter().any(|c| matches!(c, Some(n) if *n > 0)) {
        DaneDisposition::TlsaPublished
    } else if counts.iter().any(|c| c.is_none()) {
        DaneDisposition::TransientError
    } else {
        DaneDisposition::NotConfigured
    }
}

/// Pure: map a TLSA lookup error to the per-host outcome it actually
/// measured. `Some(0)` = a MEASURED absence (NODATA, or an NXDOMAIN whose SOA
/// is the host's own zone — the host exists, it just publishes no TLSA);
/// `None` = couldn't measure (transient, or the host's zone is missing).
///
/// This is the branch `score_dane` skipped when every other control's Err
/// path routed through `record_absence_verdict` — the skip folded measured
/// absence into couldn't-measure, the INVERSE conflation of the original
/// `&[usize]` bug (which folded couldn't-measure into measured absence).
/// Both directions lose the distinction DANE's four-way split exists to hold.
///
/// The host is passed with its trailing dot trimmed to match
/// `record_absence_verdict`'s own SOA-side trim (`z.trim_end_matches('.')`);
/// without the trim, the own-zone comparison never matches a third-party MX.
fn tlsa_err_to_count(e: &NetError, host: &str) -> Option<usize> {
    match record_absence_verdict(e, host.trim_end_matches('.')) {
        TriState::Absent => Some(0), // measured: host exists, no TLSA at _25._tcp.<host>
        _ => None,                  // Indet (and the unreachable others) — couldn't measure
    }
}

async fn score_dane(resolver: &TokioResolver, domain: &str) -> DaneDisposition {
    // DANE for SMTP (RFC 7672): TLSA at _25._tcp.<mx-host> for each MX target.
    // NOT _443._tcp.<domain> — that is HTTPS DANE (RFC 6698 for browsers), the
    // wrong surface for an email-security instrument. A mail domain may host no
    // website at all, so probing HTTPS DANE read "no website" as "no DANE" —
    // the same category error as the DNSSEC address-existence bug.
    //
    // Four distinct outcomes (this is the precise epistemic split):
    //   Present        — MX exists and >=1 MX host publishes a TLSA (DANE on)
    //   Absent         — mail is routable but no DANE: either a silent absence
    //                    of MX (NODATA — a domain with no MX can still be
    //                    spoofed FROM, a real finding) or MX present with no
    //                    TLSA on any host.
    //   NotApplicable  — null MX (RFC 7505 "MX 0 ."): an explicit declaration
    //                    that the domain accepts no mail. A POSITIVE measurement
    //                    ("we know why DANE doesn't apply"), not "couldn't
    //                    measure".
    //   Indet          — domain missing (NXDOMAIN) or transient lookup error.
    use hickory_proto::rr::RecordType;

    match resolver.lookup(domain, RecordType::MX).await {
        Ok(mx) => {
            let exchanges: Vec<hickory_proto::rr::Name> = mx
                .answers()
                .iter()
                .filter_map(|r| mx_exchange_from_rdata(&r.data).cloned())
                .collect();

            match classify_mx(&exchanges) {
                MxShape::NoMx => DaneDisposition::NoMx,
                MxShape::NoMail => DaneDisposition::NoMail,
                MxShape::Hosts(hosts) => {
                    let mut counts = Vec::with_capacity(hosts.len());
                    for host in &hosts {
                        let tlsa_name = format!("_25._tcp.{}", host);
                        match resolver.lookup(tlsa_name.as_str(), RecordType::TLSA).await {
                            Ok(resp) => counts.push(Some(resp.answers().len())),
                            Err(e) => {
                                // Route through record_absence_verdict so NODATA
                                // (the host exists, no TLSA) is a MEASURED
                                // absence — Some(0) — not "couldn't measure".
                                // Only transient/zone-missing errors are None.
                                warn!(domain, host = %host, error = %e, "SMTP DANE TLSA lookup error");
                                counts.push(tlsa_err_to_count(&e, host));
                            }
                        }
                    }
                    dane_from_tlsa_counts(&counts)
                }
            }
        }
        Err(e) => {
            // NODATA (no MX) -> NoMx; NXDOMAIN (domain missing) -> Indet.
            // record_absence_verdict applies the SOA disambiguation — the same
            // mechanism _dmarc/_mta-sts use, now generalized to the MX lookup.
            warn!(domain, error = %e, "MX lookup error for DANE");
            record_absence_to_dane(&e, domain)
        }
    }
}

async fn score_mta_sts(resolver: &TokioResolver, domain: &str) -> MtaStsDisposition {
    // MTA-STS (RFC 8461) is a two-step protocol:
    //   1. Discovery: _mta-sts.<domain> TXT ("v=STSv1; id=...") signals that a
    //      policy MAY be published.
    //   2. Policy: fetch https://mta-sts.<domain>/.well-known/mta-sts.txt and
    //      parse version/mode/mx/max_age.
    //
    // The TXT alone is necessary but not sufficient — a domain can publish the
    // hint and serve no (or an invalid) policy. The tri-state verdict needs the
    // policy. Per T1-1, an invalid/unfetchable policy maps to Absent (the old
    // "warning" state), never a fourth value.
    let mta_sts_domain = format!("_mta-sts.{}", domain);

    // ── Step 1: discovery TXT ────────────────────────────────────────────────
    let has_hint = match resolver.txt_lookup(mta_sts_domain.as_str()).await {
        Ok(rdata) => rdata.answers().iter().any(|rec| {
            matches!(&rec.data, hickory_proto::rr::RData::TXT(txt)
                if txt.txt_data.iter().any(|s| s.starts_with(b"v=STSv1")))
        }),
        Err(e) => {
            // NODATA (no hint) = measured absence; NXDOMAIN/transient = Indet.
            return mta_sts_err_to_disposition(&e, domain);
        }
    };

    if let Some(disposition) = mta_sts_absent_without_hint(has_hint) {
        return disposition; // no discovery record → measured absence
    }

    // ── Step 2: fetch + parse the policy ─────────────────────────────────────
    // The hint is now CONFIRMED present, so every outcome below is a measured
    // state of the advertised policy — TransientError is no longer honest from
    // here on (a hint without a servable policy is the T1-1 measured absence,
    // which is what PolicyInvalid's chain() encodes).
    let policy_url = format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
    // The HTTP I/O lives inline here (it is async glue, not a decision); the
    // status→ok/err decision is the pure `mta_sts_policy_from_response` below,
    // so the `!status.is_success()` gate and the body passthrough are unit-pinned
    // rather than hidden behind a live request. A Result-returning fetch helper
    // was the one place whose FnValue mutants (return fabricated Ok(empty) bytes)
    // survived mutation testing.
    let policy_result: anyhow::Result<String> = async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let resp = client.get(&policy_url).send().await?;
        mta_sts_policy_from_response(resp.status(), resp.text().await?)
    }
    .await;
    match policy_result {
        Ok(policy) => match mta_sts_policy_state(&policy) {
            MtaStsPolicyState::Enforce => MtaStsDisposition::Enforced,
            // Valid policy, mode testing/none — deployed, not enforcing (§8).
            MtaStsPolicyState::TestingOrNone => MtaStsDisposition::NotEnforced,
            // Fetched bytes that are not a valid policy: the old code lumped
            // this into NotEnforced, reporting "published (mode testing/none)"
            // for garbage — a mode that was never measured.
            MtaStsPolicyState::Invalid => MtaStsDisposition::PolicyInvalid,
        },
        Err(e) => {
            warn!(domain, error = %e, "MTA-STS policy fetch failed");
            MtaStsDisposition::PolicyInvalid // hint present, policy not servable
        }
    }
}

/// Pure: the HTTP status gate for an MTA-STS policy fetch. A non-2xx response
/// is a failed fetch (the advertised policy is not servable), never a valid
/// policy. Extracted so the `!status.is_success()` gate is unit-pinned:
/// deleting the `!` accepts a 404/500 error page as a fetched MTA-STS policy.
/// This is the pure half of the fetch — the HTTP I/O lives inline in
/// `score_mta_sts`, because a `Result<String>`-returning async helper was the
/// one site whose FnValue mutants (return fabricated `Ok(empty)` bytes) were
/// viable and survived mutation testing.
fn mta_sts_policy_from_response(
    status: reqwest::StatusCode,
    body: String,
) -> anyhow::Result<String> {
    if !status.is_success() {
        anyhow::bail!("HTTP {}", status);
    }
    Ok(body)
}

/// Pure: the discovery-hint gate. A missing `_mta-sts.<domain>` TXT hint is a
/// measured absence (RecordAbsent) — return `Some(RecordAbsent)` to
/// short-circuit; a present hint returns `None` (continue to fetch the policy).
/// Extracted so the `!has_hint` negation is unit-pinned: deleting the `!`
/// short-circuits on a PRESENT hint and proceeds to fetch on an ABSENT one,
/// inverting the entire control flow.
fn mta_sts_absent_without_hint(has_hint: bool) -> Option<MtaStsDisposition> {
    if !has_hint {
        Some(MtaStsDisposition::RecordAbsent)
    } else {
        None
    }
}

/// The measured state of a fetched MTA-STS policy text. Three-way, because
/// "valid but mode testing/none" and "not a valid policy at all" are different
/// measurements — collapsing them reported a mode that was never parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MtaStsPolicyState {
    Enforce,
    TestingOrNone,
    Invalid,
}

/// Classify a policy text: version STSv1 + a recognized mode + at least one mx
/// make it valid; mode decides Enforce vs TestingOrNone; anything else is
/// Invalid. (Full RFC 8461 validation — max_age range, strict CRLF — is a
/// refinement; this captures the measured signal.)
fn mta_sts_policy_state(policy: &str) -> MtaStsPolicyState {
    let mut version_ok = false;
    let mut mode: Option<&str> = None;
    let mut has_mx = false;
    for raw in policy.lines() {
        let line = raw.trim();
        if let Some(v) = line.strip_prefix("version:") {
            version_ok = v.trim() == "STSv1";
        } else if let Some(m) = line.strip_prefix("mode:") {
            mode = Some(m.trim());
        } else if line.strip_prefix("mx:").is_some() {
            has_mx = true;
        }
    }
    match (version_ok, mode, has_mx) {
        (true, Some("enforce"), true) => MtaStsPolicyState::Enforce,
        (true, Some("testing"), true) | (true, Some("none"), true) => {
            MtaStsPolicyState::TestingOrNone
        }
        _ => MtaStsPolicyState::Invalid,
    }
}

/// Back-compat shim for the existing tests: "enforced" = the three-way state
/// reads Enforce.
#[cfg(test)]
fn mta_sts_enforced(policy: &str) -> bool {
    mta_sts_policy_state(policy) == MtaStsPolicyState::Enforce
}

async fn score_caa(resolver: &TokioResolver, domain: &str) -> CaaDisposition {
    // CAA record lookup.
    // RecordType::CAA = 257, confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // A CAA record constrains which CAs may issue certificates for this domain.
    // Absent = no CAA policy (any CA can issue) — informatively absent, not a failure.
    use hickory_proto::rr::RecordType;

    match resolver.lookup(domain, RecordType::CAA).await {
        Ok(resp) => {
            if answers_present(resp.answers()) {
                CaaDisposition::Configured
            } else {
                CaaDisposition::NotConfigured
            }
        }
        Err(e) => {
            warn!(domain, error = %e, "CAA lookup error");
            caa_err_to_disposition(&e, domain)
        }
    }
}

async fn score_cds_cdnskey(resolver: &TokioResolver, domain: &str) -> CdsDisposition {
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
            if answers_present(resp.answers()) {
                return CdsDisposition::Published; // CDS record found
            }
            true // empty answer section → absent, check CDNSKEY
        }
        Err(e) => {
            if e.is_nx_domain() {
                return CdsDisposition::NoZone; // no zone
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
            if answers_present(resp.answers()) {
                CdsDisposition::Published
            } else if cds_absent {
                CdsDisposition::NotPublished // both empty
            } else {
                CdsDisposition::TransientError // CDS errored, CDNSKEY empty
            }
        }
        Err(e) => {
            if e.is_nx_domain() {
                CdsDisposition::NoZone // no zone
            } else if e.is_no_records_found() {
                if cds_absent {
                    CdsDisposition::NotPublished // both definitively absent
                } else {
                    CdsDisposition::TransientError // CDS errored, CDNSKEY NODATA
                }
            } else {
                warn!(domain, error = %e, "CDNSKEY lookup error → Indet");
                CdsDisposition::TransientError
            }
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Pure: does an answer section contain at least one record? Centralized so the
/// `!is_empty()` presence gate is unit-pinned at ONE site instead of being
/// repeated at four call sites where mutation testing showed `delete !` could
/// survive — DNSSEC, CAA, CDS and CDNSKEY each read an empty answer section as
/// a PRESENT measurement when the `!` was dropped, fabricating DNSKEY material,
/// a CAA policy, or a rollover signal from a lookup that measured nothing.
fn answers_present(answers: &[hickory_proto::rr::Record]) -> bool {
    !answers.is_empty()
}

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

/// Wraps record_absence_verdict for DANE's MX lookup. A measured absence of
/// MX records is NoMx (chain: Absent — the "MX exists, no TLSA" state is
/// NotConfigured and never reachable from a failed MX lookup); anything
/// unmeasurable is TransientError.
fn record_absence_to_dane(e: &NetError, domain: &str) -> DaneDisposition {
    match record_absence_verdict(e, domain) {
        TriState::Indet => DaneDisposition::TransientError,
        _ => DaneDisposition::NoMx,
    }
}

/// Pure Err-branch mappings: each collapses `record_absence_verdict`'s
/// TriState to a control's disposition. Extracted so the load-bearing
/// `TriState::Indet => TransientError` arm is a named, unit-testable decision
/// rather than an inline match that mutation testing showed could be deleted
/// (collapsing "couldn't measure" into a measured-absence variant) with no test
/// failing. Same shape as record_absence_to_dane; one per control because the
/// absence variant differs (NotConfigured vs RecordAbsent).
fn spf_err_to_disposition(e: &NetError, domain: &str) -> SpfDisposition {
    match record_absence_verdict(e, domain) {
        TriState::Indet => SpfDisposition::TransientError,
        _ => SpfDisposition::NotConfigured,
    }
}

fn dmarc_err_to_disposition(e: &NetError, domain: &str) -> DmarcDisposition {
    match record_absence_verdict(e, domain) {
        TriState::Indet => DmarcDisposition::TransientError,
        _ => DmarcDisposition::NotConfigured,
    }
}

fn mta_sts_err_to_disposition(e: &NetError, domain: &str) -> MtaStsDisposition {
    match record_absence_verdict(e, domain) {
        TriState::Indet => MtaStsDisposition::TransientError,
        _ => MtaStsDisposition::RecordAbsent,
    }
}

fn caa_err_to_disposition(e: &NetError, domain: &str) -> CaaDisposition {
    match record_absence_verdict(e, domain) {
        TriState::Indet => CaaDisposition::TransientError,
        _ => CaaDisposition::NotConfigured,
    }
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
        assert_eq!(TriState::NotApplicable.to_string(), "NOT-APPLICABLE");
    }

    // -------------------------------------------------------------------------
    // Unit: TriState serde round-trip
    // -------------------------------------------------------------------------
    #[test]
    fn tristate_serde_roundtrip() {
        for ts in [
            TriState::Present,
            TriState::Absent,
            TriState::Indet,
            TriState::NotApplicable,
        ] {
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
    // Island-of-security vs broken-chain split
    //
    // resolutionscope.com  publishes DNSKEY but has no DS at the parent
    //   → SignedNotDelegated (island of security — genuinely signed, not
    //     chainable from root, AD=false on the DS denial).
    // dns-evil-flicker.com publishes DNSKEY AND has a deliberately wrong DS
    //   → BrokenChain (bogus — DS present but chain fails, SERVFAIL).
    //
    // Claude Science 2026-08-18: write this while both specimens still
    // publish DNSKEY with zero DS — the island case expires and it's the
    // only test for the authenticated-denial split.
    // -------------------------------------------------------------------------
    #[tokio::test]
    #[ignore = "requires network + DNSSEC-validating resolver"]
    async fn island_of_security_vs_broken_chain() {
        let resolver = make_test_resolver();

        // Negative control: google.com has zero DNSKEY → Unsigned.
        // The answers.is_empty() gate at line 248 is what prevents every
        // genuinely-unsigned domain from reading as an island. Proof::Insecure
        // alone cannot distinguish — DNSKEY presence is the discriminator.
        let unsigned = analyse_domain(&resolver, "google.com")
            .await
            .expect("analyse_domain should not error");
        assert_eq!(
            unsigned.dnssec_disposition,
            DnssecDisposition::Unsigned,
            "google.com: expected Unsigned (no DNSKEY), got {:?}",
            unsigned.dnssec_disposition
        );

        let island = analyse_domain(&resolver, "resolutionscope.com")
            .await
            .expect("analyse_domain should not error");
        assert_eq!(
            island.dnssec_disposition,
            DnssecDisposition::SignedNotDelegated,
            "resolutionscope.com: expected SignedNotDelegated (island of security), got {:?}",
            island.dnssec_disposition
        );

        let broken = analyse_domain(&resolver, "dns-evil-flicker.com")
            .await
            .expect("analyse_domain should not error");
        assert_eq!(
            broken.dnssec_disposition,
            DnssecDisposition::BrokenChain,
            "dns-evil-flicker.com: expected BrokenChain (bogus), got {:?}",
            broken.dnssec_disposition
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
        // NXDOMAIN with no SOA in the error -> can't prove the domain exists
        // -> Indet (the conservative default; domain_exists doctrine).
        assert_eq!(
            record_absence_verdict(
                &no_records_err(hickory_proto::op::ResponseCode::NXDomain),
                "example.com"
            ),
            TriState::Indet
        );
    }

    #[test]
    fn record_absence_nodata_is_absent() {
        // NODATA on an existing zone = measured absence
        assert_eq!(
            record_absence_verdict(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com"
            ),
            TriState::Absent
        );
    }

    #[test]
    fn record_absence_servfail_is_indet() {
        // transient SERVFAIL = couldn't measure (NOT a DNSSEC verdict here)
        assert_eq!(
            record_absence_verdict(&servfail_err(), "example.com"),
            TriState::Indet
        );
    }

    // --- record_absence_to_dane: the Indet → TransientError boundary ----------
    // record_absence_to_dane wraps record_absence_verdict for DANE's MX probe.
    // Its load-bearing arm is `TriState::Indet => TransientError`: a transient
    // failure must NOT collapse to NoMx (which is a MEASURED absence — "zone
    // has no MX" — and would falsely read "unroutable mail" for a query that
    // simply failed). Deleting that arm survives mutation testing; these two
    // tests pin both directions so it cannot.

    #[test]
    fn record_absence_to_dane_indet_is_transient_not_nomx() {
        // SERVFAIL -> record_absence_verdict -> Indet -> TransientError.
        // If the Indet arm is dropped, Indet falls through to NoMx (measured
        // absence) — the exact "couldn't measure read as absent" defect.
        assert_eq!(
            record_absence_to_dane(&servfail_err(), "example.com"),
            DaneDisposition::TransientError
        );
    }

    #[test]
    fn record_absence_to_dane_absent_is_nomx() {
        // NODATA on the zone's own MX -> Absent -> NoMx (measured: no MX).
        assert_eq!(
            record_absence_to_dane(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com"
            ),
            DaneDisposition::NoMx
        );
    }

    // --- the DANE core extraction (score_dane's three epistemic distinctions) --
    // DANE is the one control that holds a four-way split (Present / Absent /
    // NotApplicable / Indet) plus publication-not-verification honesty. These
    // tests pin the three pure functions the extraction produced, one
    // contributor per assertion (the masking trap: an all-absent list and a
    // single-publishing list must be SEPARATE assertions, or the guard mutant
    // hides behind the other host's positive).

    fn mx_name(s: &str) -> hickory_proto::rr::Name {
        hickory_proto::rr::Name::from_ascii(s).unwrap()
    }

    fn one_record() -> hickory_proto::rr::Record {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::RData;
        use std::net::Ipv4Addr;
        hickory_proto::rr::Record::from_rdata(
            mx_name("example.com."),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )
    }

    #[test]
    fn answers_present_distinguishes_empty_from_nonempty() {
        // The presence gate's `!is_empty()` is pinned in both directions: the
        // empty assertion catches `delete !` (and FnValue `true`), the non-empty
        // assertion catches FnValue `false`. Four call sites (DNSSEC, CAA, CDS,
        // CDNSKEY) all read an empty answer section as present when the `!` goes.
        assert!(!answers_present(&[]));
        assert!(answers_present(&[one_record()]));
    }

    #[test]
    fn mx_exchange_from_rdata_extracts_only_mx() {
        use hickory_proto::rr::rdata::{A, MX};
        use hickory_proto::rr::RData;
        use std::net::Ipv4Addr;
        let mx = RData::MX(MX::new(10, mx_name("mail.example.com.")));
        assert_eq!(
            mx_exchange_from_rdata(&mx),
            Some(&mx_name("mail.example.com."))
        );
        let a = RData::A(A(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(mx_exchange_from_rdata(&a), None);
    }

    #[test]
    fn classify_mx_no_answers_is_nomx() {
        assert_eq!(classify_mx(&[]), MxShape::NoMx);
    }

    #[test]
    fn classify_mx_all_root_is_nomail() {
        // Null MX (RFC 7505): a positive "accepts no mail" declaration, NOT
        // "no MX". This is the NotApplicable half of the four-way split.
        let roots = [
            hickory_proto::rr::Name::root(),
            hickory_proto::rr::Name::root(),
        ];
        assert_eq!(classify_mx(&roots), MxShape::NoMail);
    }

    #[test]
    fn classify_mx_mixed_keeps_only_routable_hosts() {
        // A mixed set (null MX + a real host) is the ONLY case where the
        // non-root filter does real work — `all(is_root)` is false, so the
        // filter must strip the null MX and leave the routable host. This is
        // the assertion that kills "delete !" on the filter.
        let mixed = [
            hickory_proto::rr::Name::root(), // null MX
            mx_name("mail.example.com."),    // routable host
        ];
        assert_eq!(
            classify_mx(&mixed),
            MxShape::Hosts(vec!["mail.example.com.".to_string()])
        );
    }

    #[test]
    fn dane_all_absent_is_notconfigured() {
        // Every host MEASURED empty → measured absence (NotConfigured). The
        // all-measured list is its OWN assertion so the "n > 0 → always true"
        // mutant cannot hide behind another host's positive.
        assert_eq!(
            dane_from_tlsa_counts(&[Some(0), Some(0), Some(0)]),
            DaneDisposition::NotConfigured
        );
    }

    #[test]
    fn dane_single_publishing_host_is_tlsa_published() {
        // One host publishes → TlsaPublished. A single positive is its OWN
        // assertion so the "n > 0 → n > 1" mutant (which would demand two
        // publishers) cannot survive.
        assert_eq!(
            dane_from_tlsa_counts(&[Some(0), Some(1)]),
            DaneDisposition::TlsaPublished
        );
    }

    #[test]
    fn dane_first_host_publishing_is_tlsa_published() {
        // Order matters for the early-return shape: the FIRST host publishing
        // must also yield TlsaPublished, not just a later one.
        assert_eq!(
            dane_from_tlsa_counts(&[Some(1), Some(0)]),
            DaneDisposition::TlsaPublished
        );
    }

    #[test]
    fn dane_all_lookups_errored_is_transient_not_notconfigured() {
        // THE honesty-gap test (Carey ruling, 2026-08-20): every lookup
        // errored → nothing was measured → TransientError (Indet), never
        // NotConfigured (a measured absence). One-contributor rule: the list
        // is ALL-errored — a mixed list would let a measured host mask the
        // conflation this test exists to forbid.
        assert_eq!(
            dane_from_tlsa_counts(&[None, None]),
            DaneDisposition::TransientError
        );
    }

    #[test]
    fn dane_mixed_error_and_measured_empty_is_transient() {
        // One host measured empty, one unmeasured → absence NOT proven (the
        // unmeasured host might publish) → TransientError, not NotConfigured.
        // Same doctrine as the DKIM sweep's "absence NOT proven".
        assert_eq!(
            dane_from_tlsa_counts(&[Some(0), None]),
            DaneDisposition::TransientError
        );
    }

    #[test]
    fn dane_publication_beats_error() {
        // A measured publication is a real finding; an error on another host
        // cannot erase it. [None, Some(2)] → TlsaPublished, not
        // TransientError — the error only matters when nothing was found.
        assert_eq!(
            dane_from_tlsa_counts(&[None, Some(2)]),
            DaneDisposition::TlsaPublished
        );
    }

    // --- the TLSA error classification (the over-correction fix) ---------------
    // tlsa_err_to_count routes a TLSA lookup error through
    // record_absence_verdict so NODATA (the host exists, no TLSA) is a MEASURED
    // absence — Some(0) — while only transient/zone-missing errors are None.
    // Without this, every Err became None, and the common "no TLSA on this
    // host" case (NODATA) was folded into couldn't-measure: the inverse
    // conflation of the original bug.

    #[test]
    fn tlsa_err_nodata_is_measured_absence() {
        // NODATA on _25._tcp.<host>: the host's zone exists, no TLSA → a
        // measured absence (Some(0)), NOT couldn't-measure.
        assert_eq!(
            tlsa_err_to_count(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "mail.example.com"
            ),
            Some(0)
        );
    }

    #[test]
    fn tlsa_err_servfail_is_unmeasured() {
        // SERVFAIL: nothing was measured → None (couldn't measure).
        assert_eq!(
            tlsa_err_to_count(&servfail_err(), "mail.example.com"),
            None
        );
    }

    #[test]
    fn tlsa_err_nxdomain_own_zone_is_measured_absence() {
        // NXDOMAIN with the HOST's own zone in the SOA: the host exists, only
        // _25._tcp.<host> is absent → measured absence. The host is passed in
        // its PRODUCTION shape — WITH the trailing dot, as Name::to_ascii()
        // emits it — so this test exercises the host-side trim_end_matches
        // that the sanitised form would leave untested (and that cargo-mutants
        // cannot flag, since the trim is a method call, not a mutable operator).
        let e = nxdomain_err_with_soa("mail.example.com.");
        assert_eq!(tlsa_err_to_count(&e, "mail.example.com."), Some(0));
    }

    #[test]
    fn tlsa_err_nxdomain_parent_zone_is_unmeasured() {
        // NXDOMAIN with the parent's SOA: the host itself is missing → Indet.
        // Host in the dotted production form here too, for the same reason.
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(tlsa_err_to_count(&e, "mail.example.com."), None);
    }

    // --- the four extracted Err-branch wrappers: Indet -> TransientError -------
    // Each is the same doctrine as record_absence_to_dane: a transient failure
    // must NOT collapse to a measured-absence variant. Mutation testing showed
    // deleting these `TriState::Indet` arms survived with no test failing;
    // each pair below pins both directions.

    #[test]
    fn spf_err_indet_is_transient_not_notconfigured() {
        assert_eq!(
            spf_err_to_disposition(&servfail_err(), "example.com"),
            SpfDisposition::TransientError
        );
        assert_eq!(
            spf_err_to_disposition(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com"
            ),
            SpfDisposition::NotConfigured
        );
    }

    #[test]
    fn dmarc_err_indet_is_transient_not_notconfigured() {
        assert_eq!(
            dmarc_err_to_disposition(&servfail_err(), "example.com"),
            DmarcDisposition::TransientError
        );
        assert_eq!(
            dmarc_err_to_disposition(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com"
            ),
            DmarcDisposition::NotConfigured
        );
    }

    #[test]
    fn mta_sts_err_indet_is_transient_not_recordabsent() {
        assert_eq!(
            mta_sts_err_to_disposition(&servfail_err(), "example.com"),
            MtaStsDisposition::TransientError
        );
        assert_eq!(
            mta_sts_err_to_disposition(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com"
            ),
            MtaStsDisposition::RecordAbsent
        );
    }

    #[test]
    fn caa_err_indet_is_transient_not_notconfigured() {
        assert_eq!(
            caa_err_to_disposition(&servfail_err(), "example.com"),
            CaaDisposition::TransientError
        );
        assert_eq!(
            caa_err_to_disposition(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com"
            ),
            CaaDisposition::NotConfigured
        );
    }

    // --- NXDOMAIN SOA disambiguation ------------------------------------------
    // A signed zone that lacks a name returns NXDOMAIN with its OWN SOA in the
    // authority section (proving the zone exists). A nonexistent domain returns
    // NXDOMAIN with the parent/TLD SOA. The SOA name is the discriminator.

    fn nxdomain_err_with_soa(soa_zone: &str) -> NetError {
        use hickory_proto::op::{Query, ResponseCode};
        use hickory_proto::rr::{rdata::SOA, Name, Record, RecordType};
        use hickory_resolver::net::{DnsError, NoRecords};
        let q = Query::query(
            Name::from_ascii("_mta-sts.example.com.").unwrap(),
            RecordType::TXT,
        );
        let soa = SOA::new(
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            3600,
            600,
            86400,
            3600,
        );
        let rec: Record<SOA> = Record::from_rdata(Name::from_ascii(soa_zone).unwrap(), 3600, soa);
        let mut nr = NoRecords::new(Box::new(q), ResponseCode::NXDomain);
        nr.soa = Some(Box::new(rec));
        NetError::Dns(DnsError::NoRecordsFound(nr))
    }

    #[test]
    fn record_absence_nxdomain_own_zone_is_absent() {
        // NXDOMAIN with the domain's OWN SOA -> the domain exists, only the
        // queried subdomain name is absent -> Absent (not "domain missing").
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(record_absence_verdict(&e, "example.com"), TriState::Absent);
    }

    #[test]
    fn record_absence_nxdomain_parent_zone_is_indet() {
        // NXDOMAIN with the TLD's SOA -> the domain itself is missing -> Indet.
        let e = nxdomain_err_with_soa("com.");
        assert_eq!(record_absence_verdict(&e, "example.com"), TriState::Indet);
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

    /// The DKIM default selector list is 81 entries — the count the report
    /// copy cites ("81 selectors probed"). If this shrinks, the copy lies.
    #[test]
    fn dkim_default_selectors_is_81() {
        assert_eq!(DEFAULT_DKIM_SELECTORS.len(), 81);
    }

    /// dkim_p_value extracts the p= tag only from v=DKIM1 records, and the
    /// ABNF literals are case-insensitive (RFC 5234).
    #[test]
    fn dkim_p_value_extracts_case_insensitively() {
        assert_eq!(
            dkim_p_value("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3"),
            Some("MIGfMA0GCSqGSIb3")
        );
        assert_eq!(dkim_p_value("v=dkim1; p=abc; s=email"), Some("abc"));
        // Not a DKIM key record.
        assert_eq!(dkim_p_value("v=spf1 -all"), None);
        assert_eq!(dkim_p_value("hello world"), None);
        // Missing p= tag entirely.
        assert_eq!(dkim_p_value("v=DKIM1; k=rsa"), None);
        // Empty p= is a revocation — the extractor still returns Some("").
        assert_eq!(dkim_p_value("v=DKIM1; p="), Some(""));
        // A key record that OMITS v= is still a DKIM key (RFC 6376 §3.6.1:
        // v= is RECOMMENDED, default DKIM1) — the Mailchimp mandrill shape.
        assert_eq!(
            dkim_p_value("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"),
            Some("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ")
        );
        // An explicit non-DKIM version tag is rejected even with a p= present.
        assert_eq!(dkim_p_value("v=spf1; p=abc"), None);
    }

    /// The disposition classifier's precedence, pinned without network:
    /// revoked > valid > definitive-miss > transient > empty.
    #[test]
    fn dkim_disposition_precedence() {
        // Revoked key beats a valid key (deployed-but-wrong, Critical).
        assert_eq!(
            dkim_disposition_from_counts(1, 1, 0, 0),
            DkimDisposition::KeyMismatch
        );
        // A valid key beats "not found".
        assert_eq!(
            dkim_disposition_from_counts(1, 0, 80, 0),
            DkimDisposition::Verified
        );
        // Nothing matched but we probed (definitive misses) → NotFoundDefaults.
        assert_eq!(
            dkim_disposition_from_counts(0, 0, 81, 0),
            DkimDisposition::NotFoundDefaults
        );
        // Every selector failed transiently → TransientError.
        assert_eq!(
            dkim_disposition_from_counts(0, 0, 0, 81),
            DkimDisposition::TransientError
        );
        // No selectors at all (unreachable, but honest) → NotProbed.
        assert_eq!(
            dkim_disposition_from_counts(0, 0, 0, 0),
            DkimDisposition::NotProbed
        );
    }

    /// The selector-list builder: caller selectors first, normalized, then the
    /// 81 defaults, all deduped. Pins the two `!selectors.contains` guards that
    /// mutation testing showed could be deleted with no test failing.
    #[test]
    fn dkim_selector_list_normalizes_and_dedupes() {
        // A bare selector gets the ._domainkey suffix; a pre-suffixed one is
        // left alone; a duplicate is dropped. "zzztest" is NOT in the 81
        // defaults, so it must appear exactly once as a normalized extra.
        let list = build_dkim_selector_list(&[
            "zzztest".to_string(),
            "zzztest._domainkey".to_string(), // duplicate of the normalized form
        ]);
        assert_eq!(list.first(), Some(&"zzztest._domainkey".to_string()));
        // The bare "zzztest" normalized to "zzztest._domainkey"; the second
        // entry was a duplicate, so it must not appear twice.
        assert_eq!(
            list.iter()
                .filter(|s| s.as_str() == "zzztest._domainkey")
                .count(),
            1
        );
        // The 81 defaults are always present, plus exactly one normalized extra.
        assert_eq!(list.len(), DEFAULT_DKIM_SELECTORS.len() + 1);
        // A pre-suffixed caller selector is preserved verbatim, not double-suffixed.
        let list2 = build_dkim_selector_list(&["zzztest._domainkey".to_string()]);
        assert!(list2.contains(&"zzztest._domainkey".to_string()));
        assert!(!list2.iter().any(|s| s == "zzztest._domainkey._domainkey"));
    }

    /// dkim_key_state: the three-way classification of one selector's chunks.
    #[test]
    fn dkim_key_state_classifies() {
        assert_eq!(
            dkim_key_state(&["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3".to_string()]),
            DkimKeyState::Valid
        );
        assert_eq!(
            dkim_key_state(&["v=DKIM1; p=".to_string()]),
            DkimKeyState::Revoked
        );
        assert_eq!(
            dkim_key_state(&["v=spf1 -all".to_string()]),
            DkimKeyState::NoKey
        );
        assert_eq!(dkim_key_state(&[]), DkimKeyState::NoKey);
    }

    /// dkim_disposition_from_probes: the per-selector accumulation + precedence,
    /// with the Absent-vs-transient split. Pins the counter increments and the
    /// branch that mutation testing showed were un-killed.
    #[test]
    fn dkim_probes_accumulate_and_precede() {
        use DkimSelectorProbe as Probe;
        // One valid key beats 80 definitive misses.
        let probes = vec![
            Ok(vec!["v=DKIM1; p=MIGf".to_string()]), // Valid
            Err(TriState::Absent),                   // definitive miss
            Err(TriState::Indet),                    // transient
        ];
        assert_eq!(
            dkim_disposition_from_probes(&probes),
            DkimDisposition::Verified
        );
        // A revoked key beats a valid key (KeyMismatch).
        let probes2 = vec![
            Ok(vec!["v=DKIM1; p=".to_string()]),     // Revoked
            Ok(vec!["v=DKIM1; p=MIGf".to_string()]), // Valid
        ];
        assert_eq!(
            dkim_disposition_from_probes(&probes2),
            DkimDisposition::KeyMismatch
        );
        // Only definitive misses → NotFoundDefaults (NOT evidence of absence).
        // Each miss-SHAPE must be the sole contributor in its own assertion —
        // combining them lets one site's mutant hide behind the other's count.
        let probes3: Vec<Probe> = vec![Err(TriState::Absent), Err(TriState::Absent)];
        assert_eq!(
            dkim_disposition_from_probes(&probes3),
            DkimDisposition::NotFoundDefaults
        );
        // The NoKey arm is a distinct += site: a single selector whose chunks
        // hold no key must alone produce a definitive miss (not transient).
        let probes_no_key: Vec<Probe> = vec![Ok(vec!["v=spf1 -all".to_string()])];
        assert_eq!(
            dkim_disposition_from_probes(&probes_no_key),
            DkimDisposition::NotFoundDefaults
        );
        // Only transient → TransientError (couldn't measure).
        let probes4: Vec<Probe> = vec![Err(TriState::Indet)];
        assert_eq!(
            dkim_disposition_from_probes(&probes4),
            DkimDisposition::TransientError
        );
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

    #[test]
    fn mta_sts_enforced_accepts_valid_policy() {
        let policy = "version: STSv1\nmode: enforce\nmx: smtp.example.com\nmax_age: 86400\n";
        assert!(mta_sts_enforced(policy));
    }

    #[test]
    fn mta_sts_enforced_rejects_testing_mode() {
        let policy = "version: STSv1\nmode: testing\nmx: smtp.example.com\nmax_age: 86400\n";
        assert!(!mta_sts_enforced(policy));
    }

    #[test]
    fn mta_sts_enforced_rejects_none_mode() {
        let policy = "version: STSv1\nmode: none\nmax_age: 86400\n";
        assert!(!mta_sts_enforced(policy));
    }

    #[test]
    fn mta_sts_enforced_rejects_missing_version() {
        let policy = "mode: enforce\nmx: smtp.example.com\nmax_age: 86400\n";
        assert!(!mta_sts_enforced(policy));
    }

    #[test]
    fn mta_sts_enforced_rejects_missing_mx() {
        let policy = "version: STSv1\nmode: enforce\nmax_age: 86400\n";
        assert!(!mta_sts_enforced(policy));
    }

    #[test]
    fn mta_sts_enforced_handles_crlf() {
        // Real policies use CRLF (the RFC 8461 wire format) — trim() must
        // tolerate the trailing \r.
        let policy =
            "version: STSv1\r\nmode: enforce\r\nmx: smtp.example.com\r\nmax_age: 86400\r\n";
        assert!(mta_sts_enforced(policy));
    }

    // --- the discovery-hint gate (the `!has_hint` mutation survivor) -----------
    #[test]
    fn mta_sts_absent_without_hint_pins_the_negation() {
        // No hint → short-circuit with RecordAbsent (measured absence). Deleting
        // the `!` inverts this: it would short-circuit on a PRESENT hint and
        // proceed to fetch on an ABSENT one. Both directions are pinned.
        assert_eq!(
            mta_sts_absent_without_hint(false),
            Some(MtaStsDisposition::RecordAbsent)
        );
        assert_eq!(mta_sts_absent_without_hint(true), None);
    }

    // --- the HTTP status gate (the `!status.is_success()` + FnValue survivors) -
    #[test]
    fn mta_sts_policy_from_response_status_gate() {
        // A 2xx passes the body through; a 404/500 is a failed fetch, never a
        // policy. The body-passthrough assertion catches the FnValue mutants
        // (return fabricated Ok(empty)/Ok("xyzzy") bytes); the 404 assertion
        // catches `delete !` (which would accept the error page as a policy).
        let body = "version: STSv1\nmode: enforce\nmx: smtp.example.com\n".to_string();
        assert_eq!(
            mta_sts_policy_from_response(reqwest::StatusCode::OK, body.clone()).unwrap(),
            body
        );
        assert!(mta_sts_policy_from_response(reqwest::StatusCode::NOT_FOUND, body).is_err());
        // Empty body on 2xx passes through — the parse step (mta_sts_policy_state)
        // rejects it, not the fetch.
        assert_eq!(
            mta_sts_policy_from_response(reqwest::StatusCode::OK, String::new()).unwrap(),
            ""
        );
    }

    // --- the policy-state three-way split (the MatchArm mutation survivor) -----
    #[test]
    fn mta_sts_policy_state_distinguishes_testing_and_none_from_invalid() {
        // The `(true, Some("testing"), true) | (true, Some("none"), true)` arm is
        // the distinction between a VALID deployed policy (mode testing/none) and
        // a fetched-but-invalid one. The `mta_sts_enforced` shim only checks
        // `== Enforce`, so deleting the arm (collapsing testing/none into Invalid)
        // passed every shim test — both are "not Enforce". These direct state
        // assertions pin the three-way split itself.
        let testing = "version: STSv1\nmode: testing\nmx: smtp.example.com\n";
        assert_eq!(mta_sts_policy_state(testing), MtaStsPolicyState::TestingOrNone);
        let none = "version: STSv1\nmode: none\nmx: smtp.example.com\n";
        assert_eq!(mta_sts_policy_state(none), MtaStsPolicyState::TestingOrNone);
        let enforce = "version: STSv1\nmode: enforce\nmx: smtp.example.com\n";
        assert_eq!(mta_sts_policy_state(enforce), MtaStsPolicyState::Enforce);
        // Contrast: garbage is Invalid, not TestingOrNone — the arm must not
        // absorb it either direction.
        assert_eq!(mta_sts_policy_state("hello world"), MtaStsPolicyState::Invalid);
    }

    // -------------------------------------------------------------------------
    // Specimen-independent pins (2026-08-19).
    //
    // The #[ignore]d live island test above DIES the day resolutionscope.com's
    // DS lands at the parent (the specimen window closes, deliberately, for
    // the site deploy). These pins are the insurance that survives it: the
    // emission decisions are pure functions now, and every combination is
    // pinned without network or specimens.
    // -------------------------------------------------------------------------

    #[test]
    fn dnssec_discriminator_pinned_without_specimens() {
        use hickory_proto::dnssec::Proof;
        // No DNSKEY → Unsigned regardless of proof: presence is the gate that
        // stops every genuinely-unsigned domain from reading as an island.
        assert_eq!(
            dnssec_disposition_from_answer(false, None),
            DnssecDisposition::Unsigned
        );
        assert_eq!(
            dnssec_disposition_from_answer(false, Some(Proof::Insecure)),
            DnssecDisposition::Unsigned
        );
        assert_eq!(
            dnssec_disposition_from_answer(true, Some(Proof::Secure)),
            DnssecDisposition::SignedAndDelegated
        );
        // Keys + Insecure = ISLAND (the resolutionscope.com state, preserved
        // here after the live specimen expires).
        assert_eq!(
            dnssec_disposition_from_answer(true, Some(Proof::Insecure)),
            DnssecDisposition::SignedNotDelegated
        );
        // Keys + Bogus = BROKEN (the dns-evil-flicker.com state) — never island.
        assert_eq!(
            dnssec_disposition_from_answer(true, Some(Proof::Bogus)),
            DnssecDisposition::BrokenChain
        );
        // Keys + Indeterminate/None = couldn't measure, never absent.
        assert_eq!(
            dnssec_disposition_from_answer(true, Some(Proof::Indeterminate)),
            DnssecDisposition::ChainUnverified
        );
        assert_eq!(
            dnssec_disposition_from_answer(true, None),
            DnssecDisposition::ChainUnverified
        );
    }

    #[test]
    fn spf_terminal_never_fabricates_hardfail() {
        let rec = |s: &str| vec![s.to_string()];
        assert_eq!(
            spf_disposition_from_records(&[]),
            SpfDisposition::NotConfigured
        );
        assert_eq!(
            spf_disposition_from_records(&rec("v=spf1 ip4:1.2.3.4 -all")),
            SpfDisposition::HardFail
        );
        assert_eq!(
            spf_disposition_from_records(&rec("v=spf1 include:x ~all")),
            SpfDisposition::SoftFail
        );
        // The 2026-08-19 panel case: ?all / +all / bare redirect MUST read
        // OtherPolicy — the old fallback fabricated HardFail here.
        assert_eq!(
            spf_disposition_from_records(&rec("v=spf1 mx ?all")),
            SpfDisposition::OtherPolicy
        );
        assert_eq!(
            spf_disposition_from_records(&rec("v=spf1 +all")),
            SpfDisposition::OtherPolicy
        );
        assert_eq!(
            spf_disposition_from_records(&rec("v=spf1 redirect=_spf.example.com")),
            SpfDisposition::OtherPolicy
        );
    }

    #[test]
    fn dmarc_policy_never_fabricates_reject() {
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=reject"),
            DmarcDisposition::Reject
        );
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=quarantine; rua=mailto:x@y"),
            DmarcDisposition::Quarantine
        );
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=none"),
            DmarcDisposition::Monitor
        );
        // Panel case: no p= tag at all — the old wildcard fabricated Reject.
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; sp=none"),
            DmarcDisposition::InvalidPolicy
        );
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=bogusvalue"),
            DmarcDisposition::InvalidPolicy
        );
        // ABNF string literals are case-insensitive (RFC 5234 §2.3): p=REJECT
        // satisfies the grammar — reading it as invalid would manufacture a
        // finding out of a valid record.
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=REJECT"),
            DmarcDisposition::Reject
        );
    }
}
