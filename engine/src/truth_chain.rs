// truth_chain.rs — the truth-chain contract (docs/ARCHITECTURE.md §8) as code.
//
// One render model for every surface: terminal, website, flipper. Each control
// carries the three layers the contract names:
//
//   1. RFC requirement    — what the standard demands, including optionality
//   2. Measured state     — the disposition, at full fidelity
//   3. Real-world consequence — what the measured state costs, per audience
//
// This module is the ONLY place dispositions map to presentation facts
// (labels, severities, consequences, tally). A surface that matches on a
// disposition enum to decide what a verdict MEANS is out of contract; surfaces
// own styling and layout, nothing else.
//
// No fake data: every string here describes the measured state and only the
// measured state. A claim like "81 selectors probed" may only appear on a
// variant the prober actually emits after probing (see DkimDisposition::
// NotProbed vs NotFoundDefaults).
//
// Citations are claims too, and their STATUS is part of the claim: layer 1
// says what a standard REQUIRES, so it must cite documents that can require.
// The 2026-08-19 audit's DMARC fix was a category upgrade, not just a
// freshness fix — RFC 7489 was Informational (never normative; it could not
// require anything), while its successor RFC 9989 is Standards Track
// (obsoletes 7489 + 9091, verified at rfc-editor.org). Cite successor-first,
// keep the obsoleted number for reader orientation, and prefer normative
// documents wherever one exists. The citation boundary is build-enforced by
// scripts/check-citation-boundary.sh, which enumerates every non-engine crate
// and scans its src/ in CI (a new renderer crate is covered the day its
// Cargo.toml exists).
//
// Kept alloc-light on purpose (only &'static str + fixed arrays): report.rs
// aims to compile for a no_std seL4 compartment someday, and this module sits
// on that same side of the boundary.

use crate::analysis::{
    CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
    DnssecDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition,
};
use crate::tristate::TriState;
use serde::{Deserialize, Serialize};

// =============================================================================
// ControlId — the eight controls, in canonical (protocol-layer) order
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlId {
    Dnssec,
    Spf,
    Dkim,
    Dmarc,
    Dane,
    MtaSts,
    Caa,
    Cds,
}

impl ControlId {
    pub const ALL: [ControlId; 8] = [
        ControlId::Dnssec,
        ControlId::Spf,
        ControlId::Dkim,
        ControlId::Dmarc,
        ControlId::Dane,
        ControlId::MtaSts,
        ControlId::Caa,
        ControlId::Cds,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ControlId::Dnssec => "DNSSEC",
            ControlId::Spf => "SPF",
            ControlId::Dkim => "DKIM",
            ControlId::Dmarc => "DMARC",
            ControlId::Dane => "DANE",
            ControlId::MtaSts => "MTA-STS",
            ControlId::Caa => "CAA",
            ControlId::Cds => "CDS/CDNSKEY",
        }
    }
}

// =============================================================================
// Severity — consequence-derived, declared worst-first so Ord sorts naturally
// =============================================================================
//
// Sorting a slice of ControlReport by `severity` ascending puts the worst
// finding first — the declaration order IS the display order. Doctrine:
//
//   Critical   — deployed but WRONG (broken chain, key/TLSA mismatch): the
//                control actively asserts something false right now.
//   High       — absent enforcement with a direct spoofing/interception
//                surface (no SPF, no DMARC, no MTA-STS policy, unsigned zone).
//   Medium     — deployed but not enforcing (§8 ruling: scores Present; the
//                enforcement gap is a severity fact, never a presence fact).
//   Low        — hardening absent (CAA, CDS, TLSA) or a precondition gap.
//   Ok         — enforced / verified / configured.
//   Unmeasured — could not measure; NEVER ranked as a finding (a "?" is not
//                a verdict).
//   NotApplicable — no mail domain etc.; excluded from the denominator.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Ok,
    Unmeasured,
    NotApplicable,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Ok => "OK",
            Severity::Unmeasured => "UNMEASURED",
            Severity::NotApplicable => "N/A",
        }
    }
}

// =============================================================================
// Audience — blue-team / red-team framing of the SAME measured consequence
// =============================================================================
//
// The flip changes phrasing, never facts: both strings for a given
// (control, disposition) describe one measured state. Blue reads as "what
// this costs you and what to do"; Red reads as "what this exposes during an
// authorized assessment". A surface passes the audience through; it does not
// edit or synthesize consequence text.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Audience {
    BlueTeam,
    RedTeam,
}

// =============================================================================
// ControlReport — one control's full truth chain
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ControlReport {
    pub control: ControlId,
    /// Layer 1 — the RFC requirement, including optionality.
    pub rfc_requirement: &'static str,
    /// Layer 2 — the measured state at full fidelity (disposition label).
    pub measured: &'static str,
    /// Layer 2 collapsed — presentation tri-state (§8: collapse happens here,
    /// at the model boundary, never upstream in the engine's scoring).
    pub tri: TriState,
    /// Consequence-derived severity for ordering.
    pub severity: Severity,
    consequence_blue: &'static str,
    consequence_red: &'static str,
}

impl ControlReport {
    /// Layer 3 — the real-world consequence of the measured state.
    pub fn consequence(&self, audience: Audience) -> &'static str {
        match audience {
            Audience::BlueTeam => self.consequence_blue,
            Audience::RedTeam => self.consequence_red,
        }
    }
}

// =============================================================================
// Layer 1 — RFC requirements (static per control)
// =============================================================================

fn rfc_requirement(control: ControlId) -> &'static str {
    match control {
        ControlId::Dnssec => {
            "Optional (BCP: RFC 9364). If deployed: DNSKEY at the apex, DS at the \
             parent, and the chain must validate from the root."
        }
        ControlId::Spf => {
            "Optional (RFC 7208). If present: exactly one TXT record starting \
             `v=spf1`, terminating in `-all` (enforce) or `~all` (softfail)."
        }
        ControlId::Dkim => {
            "Optional (RFC 6376). Public key published at \
             <selector>._domainkey.<domain>; the selector is advertised only in \
             outbound mail (DKIM-Signature `s=` tag), not in the zone."
        }
        ControlId::Dmarc => {
            "Optional (RFC 9989, which obsoletes RFC 7489). TXT at \
             _dmarc.<domain> with p=none, p=quarantine, or p=reject; only \
             quarantine and reject enforce."
        }
        ControlId::Dane => {
            "Optional (RFC 7672). TLSA at _25._tcp.<mx-host> for each MX; \
             requires a DNSSEC-signed zone (§4) to mean anything."
        }
        ControlId::MtaSts => {
            "Optional (RFC 8461). TXT at _mta-sts.<domain> plus an HTTPS policy \
             file; only mode:enforce enforces — testing and none do not."
        }
        ControlId::Caa => {
            "Optional (RFC 8659). CAA records name the CAs allowed to issue \
             certificates for the domain; CAs are required to honor them."
        }
        ControlId::Cds => {
            "Optional (RFC 7344). CDS/CDNSKEY at the apex signal automated DS \
             maintenance to the parent zone."
        }
    }
}

// =============================================================================
// Layers 2+3 — per-disposition mapping (the single source of verdict meaning)
// =============================================================================

fn dnssec_report(d: DnssecDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        DnssecDisposition::SignedAndDelegated => (
            "signed + delegated — chain validates from the root",
            Severity::Ok,
            "DNSSEC is fully operational: responses for this zone are cryptographically verifiable end-to-end.",
            "Zone data is signed and validated; forged-response and cache-poisoning plays are cryptographically detectable.",
        ),
        DnssecDisposition::SignedNotDelegated => (
            "island of security — DNSKEY present, no DS at the parent",
            Severity::Medium,
            "The zone signs its data but the parent holds no DS, so no resolver can validate it from the root. Publish the DS at the registrar to complete the chain.",
            "Signatures exist but nothing chains to the root: validating resolvers treat the zone as insecure, so spoofed responses are not rejected on signature grounds.",
        ),
        DnssecDisposition::BrokenChain => (
            "broken chain (bogus) — DS present but validation fails",
            Severity::Critical,
            "The parent's DS does not match the zone's keys (or RRSIGs are expired). Validating resolvers SERVFAIL this zone — it is failing closed right now. Fix the DS/keys immediately.",
            "The zone is in a bogus state: validating resolvers refuse its data, and the operator is demonstrably not monitoring DNSSEC health.",
        ),
        DnssecDisposition::ChainUnverified => (
            "chain unverified — could not obtain the DNSSEC RRs",
            Severity::Unmeasured,
            "The measurement could not confirm or deny the chain (no AD consensus). Not a finding — re-run.",
            "Chain state unknown from this vantage; no conclusion available on this pass.",
        ),
        DnssecDisposition::Unsigned => (
            "unsigned — no DNSKEY at the apex",
            Severity::High,
            "The zone publishes no DNSSEC keys. Responses for this domain are not cryptographically verifiable; resolvers must trust the transport alone.",
            "No signatures to defeat: cache poisoning and forged responses face only transport-level defenses (source-port/TXID entropy).",
        ),
        DnssecDisposition::NoZone => (
            "no zone (NXDOMAIN)",
            Severity::Unmeasured,
            "The domain does not exist; DNSSEC state is not applicable to a non-zone.",
            "No zone, no surface.",
        ),
        DnssecDisposition::Unreachable => (
            "unreachable — transient lookup error",
            Severity::Unmeasured,
            "Lookups failed (timeout/refused); nothing was measured. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
    };
    ControlReport {
        control: ControlId::Dnssec,
        rfc_requirement: rfc_requirement(ControlId::Dnssec),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn spf_report(d: SpfDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        SpfDisposition::HardFail => (
            "hardfail (-all) — enforced",
            Severity::Ok,
            "SPF authorizes specific senders and tells receivers to reject the rest.",
            "Sender-IP spoofing of this domain fails SPF outright at conforming receivers.",
        ),
        SpfDisposition::SoftFail => (
            "softfail (~all) — deployed, not enforcing",
            Severity::Medium,
            "SPF is published but ~all only asks receivers to mark, not reject. Move to -all once legitimate senders are confirmed.",
            "Spoofed mail is marked, not blocked: softfail typically lands in spam rather than being refused — usable with a pretext that survives a spam folder, and DMARC disposition decides the rest.",
        ),
        SpfDisposition::OtherPolicy => (
            "record present, terminal qualifier neither -all nor ~all",
            Severity::Medium,
            "SPF is published but ends in a neutral/permissive qualifier (?all, +all, or no all mechanism) — receivers get no rejection instruction at all. Terminate the record with -all.",
            "SPF exists but instructs nothing: spoofed senders do not fail SPF here, so DMARC's SPF leg never fires.",
        ),
        SpfDisposition::NotConfigured => (
            "not configured — no SPF record",
            Severity::High,
            "Any IP on the internet can send mail claiming this domain and SPF offers receivers nothing to check. Publish `v=spf1 … -all`.",
            "Unrestricted sender spoofing: no sender-authorization record exists to fail.",
        ),
        SpfDisposition::NoMail => (
            "no mail domain (null MX)",
            Severity::NotApplicable,
            "The domain declares it sends/receives no mail; SPF has nothing to authorize.",
            "No mail surface declared.",
        ),
        SpfDisposition::TransientError => (
            "transient lookup error",
            Severity::Unmeasured,
            "Could not measure SPF on this pass. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
    };
    ControlReport {
        control: ControlId::Spf,
        rfc_requirement: rfc_requirement(ControlId::Spf),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn dkim_report(d: DkimDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        DkimDisposition::Verified => (
            "verified — selector resolved, key valid",
            Severity::Ok,
            "DKIM signing is configured and the published key verifies.",
            "Message-content forgery must defeat a working signature; replay/selector-confusion is the remaining surface.",
        ),
        DkimDisposition::NotFoundDefaults => (
            "not found with 81 default selectors — absence NOT proven",
            Severity::Unmeasured,
            "The 81 common selectors were probed and none matched. This does not prove DKIM is absent — the domain may use a custom selector. Find yours in any outbound message's DKIM-Signature header (the s= tag) and provide it.",
            "Default-selector sweep came back empty; a custom selector may exist. Absence of DKIM is unconfirmed from the zone alone.",
        ),
        DkimDisposition::NotProbed => (
            "not probed — no selector was available to probe",
            Severity::Unmeasured,
            "DKIM was not measured on this pass (no selector was available to probe). No claim is made either way.",
            "Not measured on this pass; no claim either way.",
        ),
        DkimDisposition::NoMailDomain => (
            "no mail domain (null MX)",
            Severity::NotApplicable,
            "The domain declares no mail; DKIM has nothing to sign.",
            "No mail surface declared.",
        ),
        DkimDisposition::TransientError => (
            "transient lookup error",
            Severity::Unmeasured,
            "Could not measure DKIM on this pass. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
        DkimDisposition::KeyMismatch => (
            "key mismatch — selector resolves, key fails validation",
            Severity::Critical,
            "A DKIM selector exists but its published key does not validate — signed mail from this domain fails verification right now. Fix or rotate the published key.",
            "Signatures from this domain fail verification: receivers see broken DKIM, and DMARC alignment on the DKIM leg cannot pass.",
        ),
        DkimDisposition::Revoked => (
            "key revoked — selector publishes an empty p= (RFC 6376)",
            Severity::High,
            "The published key is revoked — an empty p= means the key was deliberately withdrawn, so no signature under it verifies. Mail from this domain is unsigned in practice, leaving spoofers the same surface as a domain with no DKIM. Re-publish a valid key to resume signing.",
            "The selector's key is withdrawn, so DKIM cannot vouch for this domain's mail — spoofing is unopposed until a new key is published.",
        ),
        DkimDisposition::Wildcard => (
            "wildcard *._domainkey — the selector sweep proves nothing",
            Severity::Unmeasured,
            "A nonexistent selector name resolved, so this domain publishes a wildcard and the 81-selector sweep is not probative — every probe \"resolves\" against it. Provide your actual selector (the s= tag in any outbound DKIM-Signature header) to measure DKIM definitively.",
            "DKIM could not be measured: the wildcard masks whether a real key exists. A specific selector is required to tell signed from unsigned.",
        ),
    };
    ControlReport {
        control: ControlId::Dkim,
        rfc_requirement: rfc_requirement(ControlId::Dkim),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn dmarc_report(d: DmarcDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        DmarcDisposition::Reject => (
            "reject (p=reject) — enforced",
            Severity::Ok,
            "DMARC tells receivers to refuse mail that fails SPF/DKIM alignment.",
            "Unaligned spoofed mail is rejected outright at conforming receivers.",
        ),
        DmarcDisposition::Quarantine => (
            "quarantine (p=quarantine) — enforcing, intermediate",
            Severity::Ok,
            "Failing mail is quarantined (spam-foldered), not refused. Consider p=reject once reports confirm alignment.",
            "Spoofed mail reaches the spam folder rather than being refused; inbox delivery requires beating alignment.",
        ),
        DmarcDisposition::Monitor => (
            "monitor (p=none) — deployed, not enforcing",
            Severity::Medium,
            "DMARC is published but p=none instructs receivers to deliver failing mail normally. It observes; it blocks nothing. Move to quarantine/reject once reports are clean.",
            "Policy exists but permits delivery of failing mail: spoofed messages are delivered while the owner only receives reports about them.",
        ),
        DmarcDisposition::InvalidPolicy => (
            "record present but invalid — required p= tag missing or unrecognized",
            Severity::High,
            "The DMARC record exists but has no usable p= tag (RFC 9989 requires it), so receivers ignore the record entirely — the domain pays DMARC's operational cost and gets none of its protection. Fix the p= tag.",
            "Invalid policy equals no policy: alignment failures carry no owner instruction, while the owner likely believes DMARC is deployed.",
        ),
        DmarcDisposition::NotConfigured => (
            "not configured — no DMARC record",
            Severity::High,
            "Without DMARC, SPF/DKIM results carry no instruction — receivers decide alone what to do with spoofed mail. Publish a policy, even p=none, then ratchet.",
            "No alignment policy: display-from spoofing is left to per-receiver heuristics, with no domain-owner instruction to reject.",
        ),
        DmarcDisposition::NoMail => (
            "no mail domain (null MX)",
            Severity::NotApplicable,
            "The domain declares no mail; DMARC has no legitimate traffic to police (a p=reject record on no-mail domains is still good hygiene).",
            "No mail surface declared.",
        ),
        DmarcDisposition::TransientError => (
            "transient lookup error",
            Severity::Unmeasured,
            "Could not measure DMARC on this pass. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
    };
    ControlReport {
        control: ControlId::Dmarc,
        rfc_requirement: rfc_requirement(ControlId::Dmarc),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn dane_report(d: DaneDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        DaneDisposition::TlsaPublished => (
            "TLSA published at _25._tcp.<mx> — certificate match not verified by this pass",
            Severity::Ok,
            "DANE TLSA records are published for the MX. This pass measured publication only — the certificate comparison is a DANE-validating sender's job (and a future prober's).",
            "TLSA pins exist for the MX; whether they match the live certificate was not verified by this pass.",
        ),
        // Verified/Mismatch strings describe the SMTP certificate prober's
        // measurements; the engine has no emission site for either yet.
        DaneDisposition::Verified => (
            "verified — TLSA matches the mail server certificate",
            Severity::Ok,
            "DANE pins the MX certificate in signed DNS; TLS to this mail server is downgrade-resistant.",
            "STARTTLS stripping and certificate substitution are detectable by DANE-validating senders.",
        ),
        DaneDisposition::Mismatch => (
            "mismatch — TLSA present but does not match the certificate",
            Severity::Critical,
            "The published TLSA no longer matches the server's certificate — DANE-validating senders refuse delivery to this MX right now. Update the TLSA (and automate rotation).",
            "The pin is stale: DANE-validating peers hard-fail delivery, and the mismatch shows certificate rotation without DNS follow-through.",
        ),
        DaneDisposition::NotConfigured => (
            "not configured — MX exists, no TLSA",
            Severity::Low,
            "No TLSA record for the MX. Transport TLS depends on opportunistic STARTTLS (or MTA-STS if enforced) rather than a DNS pin.",
            "No DNS pin on the MX certificate: an on-path STARTTLS strip or cert swap is not detectable via DANE.",
        ),
        DaneDisposition::NoMx => (
            "no MX published — zone exists, no mail routing",
            Severity::Low,
            "The zone publishes no MX records, so DANE has nothing to pin — but a domain without MX can still be spoofed FROM; SPF and DMARC carry that burden here.",
            "No inbound mail path, so no DANE surface; spoofing FROM the domain is governed by its SPF/DMARC posture, not DANE.",
        ),
        DaneDisposition::NoMail => (
            "no mail declared (null MX, RFC 7505)",
            Severity::NotApplicable,
            "The domain explicitly declares it accepts no mail; there is no mail server to pin.",
            "No mail surface declared.",
        ),
        DaneDisposition::TransientError => (
            "transient lookup error",
            Severity::Unmeasured,
            "Could not measure DANE on this pass. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
        DaneDisposition::DnssecRequired => (
            "dnssec required — zone unsigned, TLSA cannot be trusted",
            Severity::Low,
            "DANE only means something inside a signed zone (RFC 7672 §1.3.2). Sign the zone first; TLSA records in an unsigned zone are unverifiable.",
            "Any TLSA present is unverifiable without DNSSEC; DANE offers no obstacle here.",
        ),
    };
    ControlReport {
        control: ControlId::Dane,
        rfc_requirement: rfc_requirement(ControlId::Dane),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn mta_sts_report(d: MtaStsDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        MtaStsDisposition::Enforced => (
            "enforced (mode: enforce)",
            Severity::Ok,
            "Senders honoring MTA-STS require verified TLS to this domain's MX — downgrade to plaintext is refused.",
            "STARTTLS stripping fails against MTA-STS-honoring senders; delivery requires verified TLS.",
        ),
        MtaStsDisposition::NotEnforced => (
            "published, not enforcing (mode: testing or none)",
            Severity::Medium,
            "The policy is published but its mode blocks nothing yet — senders report failures instead of refusing delivery. Move to mode:enforce.",
            "Policy present but advisory: transport downgrade still succeeds, it just gets reported.",
        ),
        MtaStsDisposition::RecordAbsent => (
            "record absent — zone exists, no MTA-STS",
            Severity::High,
            "No transport policy: senders may fall back to plaintext delivery, so mail to this domain is exposed to STARTTLS stripping. Publish an MTA-STS policy (or deploy DANE).",
            "Inbound transport is downgradeable: an on-path attacker can strip STARTTLS and read/modify mail in transit, and no sender policy forbids the fallback.",
        ),
        MtaStsDisposition::NoZone => (
            "no zone (NXDOMAIN)",
            Severity::Unmeasured,
            "The domain does not exist; MTA-STS is not applicable.",
            "No zone, no surface.",
        ),
        MtaStsDisposition::PolicyInvalid => (
            "hint published, policy missing or invalid — advertised but not servable",
            Severity::High,
            "_mta-sts advertises a policy, but the HTTPS policy file is unfetchable or not a valid policy — senders get nothing enforceable. An advertised policy that cannot be served is a measured absence, not a transient. Fix the policy endpoint.",
            "The domain advertises MTA-STS it cannot serve: transport downgrade remains fully available, and the broken endpoint shows the deployment is unmonitored.",
        ),
        MtaStsDisposition::TransientError => (
            "transient error — discovery lookup failed",
            Severity::Unmeasured,
            "The _mta-sts discovery lookup failed; nothing was measured. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
    };
    ControlReport {
        control: ControlId::MtaSts,
        rfc_requirement: rfc_requirement(ControlId::MtaSts),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn caa_report(d: CaaDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        CaaDisposition::Configured => (
            "configured — issuance restricted to named CAs",
            Severity::Ok,
            "Only the listed CAs may issue certificates for this domain; all others must refuse.",
            "Mis-issuance requires compromising one of the named CAs specifically, not just any CA.",
        ),
        CaaDisposition::NotConfigured => (
            "not configured — zone exists, no CAA",
            Severity::Low,
            "Any publicly-trusted CA may issue for this domain. Publish CAA records naming your CA(s).",
            "Certificate mis-issuance can proceed through any CA — the weakest one in the ecosystem sets the bar.",
        ),
        CaaDisposition::NoZone => (
            "no zone (NXDOMAIN)",
            Severity::Unmeasured,
            "The domain does not exist; CAA is not applicable.",
            "No zone, no surface.",
        ),
        CaaDisposition::TransientError => (
            "transient lookup error",
            Severity::Unmeasured,
            "Could not measure CAA on this pass. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
    };
    ControlReport {
        control: ControlId::Caa,
        rfc_requirement: rfc_requirement(ControlId::Caa),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn cds_report(d: CdsDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        CdsDisposition::Published => (
            "published — automated DS maintenance signaled",
            Severity::Ok,
            "The zone advertises CDS/CDNSKEY, so the parent can maintain the DS automatically — key rollovers won't strand the chain.",
            "DS rotation is automated; a stale-DS window during rollover is unlikely.",
        ),
        CdsDisposition::NotPublished => (
            "not published — zone exists, no CDS/CDNSKEY",
            Severity::Low,
            "DS updates at the parent are manual. Rollovers depend on someone remembering the registrar step — the classic way chains break.",
            "Manual DS maintenance: a future key rollover may leave a stale DS (bogus zone) or a dropped chain.",
        ),
        CdsDisposition::NoZone => (
            "no zone (NXDOMAIN)",
            Severity::Unmeasured,
            "The domain does not exist; CDS is not applicable.",
            "No zone, no surface.",
        ),
        CdsDisposition::TransientError => (
            "transient lookup error",
            Severity::Unmeasured,
            "Could not measure CDS on this pass. Not a finding — re-run.",
            "No measurement obtained on this pass.",
        ),
    };
    ControlReport {
        control: ControlId::Cds,
        rfc_requirement: rfc_requirement(ControlId::Cds),
        measured,
        tri: d.chain(),
        severity,
        consequence_blue: blue,
        consequence_red: red,
    }
}

// =============================================================================
// truth_chain — the model constructor, and the severity ordering
// =============================================================================

/// Build the eight-control render model from a ScoredAnalysis. Canonical
/// (protocol-layer) order; use [`by_severity`] for worst-first ordering.
pub fn truth_chain(a: &ScoredAnalysis) -> [ControlReport; 8] {
    [
        dnssec_report(a.dnssec_disposition),
        spf_report(a.spf_disposition),
        dkim_report(a.dkim_disposition),
        dmarc_report(a.dmarc_disposition),
        dane_report(a.dane_disposition),
        mta_sts_report(a.mta_sts_disposition),
        caa_report(a.caa_disposition),
        cds_report(a.cds_disposition),
    ]
}

/// Worst-first ordering. Stable within a severity tier (canonical order),
/// so equal-severity controls keep a deterministic, familiar order.
pub fn by_severity(reports: &[ControlReport; 8]) -> [ControlReport; 8] {
    let mut sorted = *reports;
    sorted.sort_by_key(|r| r.severity);
    sorted
}

// =============================================================================
// Tally — the ONE score computation (was duplicated in report.rs and the TUI)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub present: usize,
    pub absent: usize,
    pub unmeasured: usize,
    pub not_applicable: usize,
}

impl Tally {
    pub fn of(reports: &[ControlReport; 8]) -> Tally {
        reports.iter().fold(
            Tally {
                present: 0,
                absent: 0,
                unmeasured: 0,
                not_applicable: 0,
            },
            |mut t, r| {
                match r.tri {
                    TriState::Present => t.present += 1,
                    TriState::Absent => t.absent += 1,
                    TriState::Indet => t.unmeasured += 1,
                    TriState::NotApplicable => t.not_applicable += 1,
                }
                t
            },
        )
    }

    /// Denominator per the Sensitivity Row Requirement: measured controls only.
    pub fn denominator(&self) -> usize {
        self.present + self.absent
    }

    /// Integer percent (0 when nothing was measured — never a fake 100).
    pub fn percent(&self) -> usize {
        self.present
            .saturating_mul(100)
            .checked_div(self.denominator())
            .unwrap_or(0)
    }
}

// =============================================================================
// Tests — the contract pinned
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn all_dispositions() -> Vec<ControlReport> {
        let mut v = Vec::new();
        for d in [
            DnssecDisposition::SignedAndDelegated,
            DnssecDisposition::SignedNotDelegated,
            DnssecDisposition::BrokenChain,
            DnssecDisposition::ChainUnverified,
            DnssecDisposition::Unsigned,
            DnssecDisposition::NoZone,
            DnssecDisposition::Unreachable,
        ] {
            v.push(dnssec_report(d));
        }
        for d in [
            SpfDisposition::HardFail,
            SpfDisposition::SoftFail,
            SpfDisposition::OtherPolicy,
            SpfDisposition::NotConfigured,
            SpfDisposition::NoMail,
            SpfDisposition::TransientError,
        ] {
            v.push(spf_report(d));
        }
        for d in [
            DkimDisposition::Verified,
            DkimDisposition::NotFoundDefaults,
            DkimDisposition::NotProbed,
            DkimDisposition::NoMailDomain,
            DkimDisposition::TransientError,
            DkimDisposition::KeyMismatch,
        ] {
            v.push(dkim_report(d));
        }
        for d in [
            DmarcDisposition::Reject,
            DmarcDisposition::Quarantine,
            DmarcDisposition::Monitor,
            DmarcDisposition::InvalidPolicy,
            DmarcDisposition::NotConfigured,
            DmarcDisposition::NoMail,
            DmarcDisposition::TransientError,
        ] {
            v.push(dmarc_report(d));
        }
        for d in [
            DaneDisposition::TlsaPublished,
            DaneDisposition::Verified,
            DaneDisposition::Mismatch,
            DaneDisposition::NotConfigured,
            DaneDisposition::NoMx,
            DaneDisposition::NoMail,
            DaneDisposition::TransientError,
            DaneDisposition::DnssecRequired,
        ] {
            v.push(dane_report(d));
        }
        for d in [
            MtaStsDisposition::Enforced,
            MtaStsDisposition::NotEnforced,
            MtaStsDisposition::PolicyInvalid,
            MtaStsDisposition::RecordAbsent,
            MtaStsDisposition::NoZone,
            MtaStsDisposition::TransientError,
        ] {
            v.push(mta_sts_report(d));
        }
        for d in [
            CaaDisposition::Configured,
            CaaDisposition::NotConfigured,
            CaaDisposition::NoZone,
            CaaDisposition::TransientError,
        ] {
            v.push(caa_report(d));
        }
        for d in [
            CdsDisposition::Published,
            CdsDisposition::NotPublished,
            CdsDisposition::NoZone,
            CdsDisposition::TransientError,
        ] {
            v.push(cds_report(d));
        }
        v
    }

    /// Every (control, disposition) pair carries all three layers, non-empty,
    /// for both audiences. An empty string would be a silent contract hole.
    #[test]
    fn every_disposition_carries_all_three_layers() {
        let reports = all_dispositions();
        assert_eq!(
            reports.len(),
            48,
            "disposition census changed — update this test's inventory"
        );
        for r in &reports {
            assert!(
                !r.rfc_requirement.is_empty(),
                "{:?}: empty RFC layer",
                r.control
            );
            assert!(
                !r.measured.is_empty(),
                "{:?}: empty measured layer",
                r.control
            );
            assert!(
                !r.consequence(Audience::BlueTeam).is_empty(),
                "{:?}: empty blue consequence",
                r.control
            );
            assert!(
                !r.consequence(Audience::RedTeam).is_empty(),
                "{:?}: empty red consequence",
                r.control
            );
        }
    }

    /// §8 enforcement ruling, pinned: the three deployed-but-not-enforcing
    /// states score Present (deployment) with severity Medium (the enforcement
    /// gap) — the score never erases the gap, the severity never erases the
    /// deployment.
    #[test]
    fn enforcement_ruling_pinned() {
        for r in [
            spf_report(SpfDisposition::SoftFail),
            dmarc_report(DmarcDisposition::Monitor),
            mta_sts_report(MtaStsDisposition::NotEnforced),
            // Fourth member of the class, found by the 2026-08-19 panel: a
            // published SPF with a neutral/permissive terminal is deployed and
            // not enforcing — same epistemic type as the ruling's three.
            spf_report(SpfDisposition::OtherPolicy),
        ] {
            assert_eq!(
                r.tri,
                TriState::Present,
                "{:?}: non-enforcing must score Present",
                r.control
            );
            assert_eq!(
                r.severity,
                Severity::Medium,
                "{:?}: enforcement gap must rank Medium",
                r.control
            );
        }
    }

    /// Deployed-but-INVALID is measured absence, never a policy claim: an
    /// unusable DMARC record and an unservable MTA-STS policy score Absent
    /// with a ranked severity (the panel found both previously reported as
    /// real policies or as transients).
    #[test]
    fn invalid_deployments_are_measured_absence() {
        for r in [
            dmarc_report(DmarcDisposition::InvalidPolicy),
            mta_sts_report(MtaStsDisposition::PolicyInvalid),
        ] {
            assert_eq!(
                r.tri,
                TriState::Absent,
                "{:?}: invalid must score Absent",
                r.control
            );
            assert_eq!(
                r.severity,
                Severity::High,
                "{:?}: invalid-while-advertised ranks High",
                r.control
            );
        }
    }

    /// NO FAKE DATA, DANE edition: publication is the only measured fact, so
    /// the emitted-on-presence variant must say so and must not claim a match.
    #[test]
    fn tlsa_presence_is_not_verification() {
        let r = dane_report(DaneDisposition::TlsaPublished);
        assert!(r.measured.contains("not verified"));
        assert!(!r
            .consequence(Audience::BlueTeam)
            .contains("downgrade-resistant"));
    }

    /// Deployed-but-WRONG is the worst tier: the control asserts something
    /// false right now.
    #[test]
    fn broken_deployments_are_critical() {
        assert_eq!(
            dnssec_report(DnssecDisposition::BrokenChain).severity,
            Severity::Critical
        );
        assert_eq!(
            dane_report(DaneDisposition::Mismatch).severity,
            Severity::Critical
        );
        assert_eq!(
            dkim_report(DkimDisposition::KeyMismatch).severity,
            Severity::Critical
        );
    }

    /// The denominator doctrine and the severity doctrine are DIFFERENT axes:
    ///
    ///   - Unmeasured severity ⟹ Indet tri. Nothing that wasn't measured may
    ///     enter the denominator or rank as a finding. (Strict.)
    ///   - Indet tri does NOT imply Unmeasured severity. Island-of-security is
    ///     the proof case: a measured, provable state (DNSKEY present, DS
    ///     absent at the parent — the .dev specimen arc) that stays OUT of the
    ///     score denominator but ranks as a real finding. Same for
    ///     dnssec-required DANE: the precondition gap is measured.
    ///
    /// Every Indet that ranks above Unmeasured must appear in the named
    /// exception list below — a new Indet variant must consciously choose.
    #[test]
    fn unmeasured_is_never_a_finding() {
        let reports = all_dispositions();
        for r in reports
            .iter()
            .filter(|r| r.severity == Severity::Unmeasured)
        {
            assert_eq!(
                r.tri,
                TriState::Indet,
                "{:?} ({}): Unmeasured severity requires Indet tri-state",
                r.control,
                r.measured
            );
        }
        let measured_but_unchained = [
            "island of security — DNSKEY present, no DS at the parent",
            "dnssec required — zone unsigned, TLSA cannot be trusted",
        ];
        for r in reports.iter().filter(|r| r.tri == TriState::Indet) {
            if r.severity != Severity::Unmeasured {
                assert!(
                    measured_but_unchained.contains(&r.measured),
                    "{:?} ({}): a ranked Indet must be a named measured-but-unchained exception",
                    r.control,
                    r.measured
                );
            }
        }
    }

    /// The severity declaration order IS the sort order, worst first.
    #[test]
    fn severity_sorts_worst_first() {
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Ok);
        assert!(Severity::Ok < Severity::Unmeasured);
        assert!(Severity::Unmeasured < Severity::NotApplicable);
    }

    /// The tri collapse in the model equals the disposition's own chain() —
    /// the model adds meaning, it never re-decides the verdict.
    #[test]
    fn model_never_rewrites_the_collapse() {
        assert_eq!(
            dnssec_report(DnssecDisposition::SignedNotDelegated).tri,
            DnssecDisposition::SignedNotDelegated.chain()
        );
        assert_eq!(
            dkim_report(DkimDisposition::NotProbed).tri,
            DkimDisposition::NotProbed.chain()
        );
        assert_eq!(
            mta_sts_report(MtaStsDisposition::NotEnforced).tri,
            MtaStsDisposition::NotEnforced.chain()
        );
    }

    /// NO FAKE DATA: the not-probed state must not claim a probe ran, and the
    /// probed-empty state must keep saying absence is unproven.
    #[test]
    fn dkim_probe_claims_are_honest() {
        let not_probed = dkim_report(DkimDisposition::NotProbed);
        assert!(
            !not_probed.measured.contains("81"),
            "NotProbed must not claim the 81-selector sweep ran"
        );
        assert!(not_probed.measured.contains("not probed"));
        let swept = dkim_report(DkimDisposition::NotFoundDefaults);
        assert!(swept.measured.contains("81"));
        assert!(swept.measured.contains("NOT proven"));
    }

    /// by_severity is a permutation of the input, worst-first, stable within
    /// a tier.
    #[test]
    fn by_severity_orders_and_preserves() {
        let model = [
            dnssec_report(DnssecDisposition::Unsigned),      // High
            spf_report(SpfDisposition::HardFail),            // Ok
            dkim_report(DkimDisposition::NotProbed),         // Unmeasured
            dmarc_report(DmarcDisposition::Monitor),         // Medium
            dane_report(DaneDisposition::Mismatch),          // Critical
            mta_sts_report(MtaStsDisposition::RecordAbsent), // High
            caa_report(CaaDisposition::NotConfigured),       // Low
            cds_report(CdsDisposition::NotPublished),        // Low
        ];
        let sorted = by_severity(&model);
        let severities: Vec<Severity> = sorted.iter().map(|r| r.severity).collect();
        let mut expect = severities.clone();
        expect.sort();
        assert_eq!(severities, expect, "must be sorted worst-first");
        assert_eq!(sorted[0].control, ControlId::Dane, "Critical first");
        // Stable within the High tier: DNSSEC (canonical index 0) before MTA-STS.
        assert_eq!(sorted[1].control, ControlId::Dnssec);
        assert_eq!(sorted[2].control, ControlId::MtaSts);
        assert_eq!(Tally::of(&sorted), Tally::of(&model), "permutation only");
    }

    /// Score arithmetic: unmeasured and N/A leave the denominator; an
    /// all-unmeasured scan scores 0, not a fake 100.
    #[test]
    fn tally_denominator_doctrine() {
        let model = [
            dnssec_report(DnssecDisposition::SignedAndDelegated), // Present
            spf_report(SpfDisposition::NotConfigured),            // Absent
            dkim_report(DkimDisposition::NotProbed),              // Indet
            dmarc_report(DmarcDisposition::Reject),               // Present
            dane_report(DaneDisposition::NoMail),                 // N/A
            mta_sts_report(MtaStsDisposition::TransientError),    // Indet
            caa_report(CaaDisposition::Configured),               // Present
            cds_report(CdsDisposition::NotPublished),             // Absent
        ];
        let t = Tally::of(&model);
        assert_eq!(
            (t.present, t.absent, t.unmeasured, t.not_applicable),
            (3, 2, 2, 1)
        );
        assert_eq!(t.denominator(), 5);
        assert_eq!(t.percent(), 60);

        let nothing = [
            dnssec_report(DnssecDisposition::Unreachable),
            spf_report(SpfDisposition::TransientError),
            dkim_report(DkimDisposition::NotProbed),
            dmarc_report(DmarcDisposition::TransientError),
            dane_report(DaneDisposition::TransientError),
            mta_sts_report(MtaStsDisposition::TransientError),
            caa_report(CaaDisposition::TransientError),
            cds_report(CdsDisposition::TransientError),
        ];
        let t0 = Tally::of(&nothing);
        assert_eq!(t0.denominator(), 0);
        assert_eq!(
            t0.percent(),
            0,
            "nothing measured must never read as a score"
        );
    }
}
