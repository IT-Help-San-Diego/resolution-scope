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
    CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
    DmarcDisposition, DnssecDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition,
    TlsRptDisposition, TlsaZone,
};
use crate::tristate::TriState;
use resolution_scope_types::SealSpelling;
use serde::{Deserialize, Serialize};

// =============================================================================
// ControlId — controls in canonical (protocol-layer) order
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
    TlsRpt,
    Csync,
}

impl ControlId {
    pub const ALL: [ControlId; 10] = [
        ControlId::Dnssec,
        ControlId::Spf,
        ControlId::Dkim,
        ControlId::Dmarc,
        ControlId::Dane,
        ControlId::MtaSts,
        ControlId::Caa,
        ControlId::Cds,
        ControlId::TlsRpt,
        ControlId::Csync,
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
            ControlId::TlsRpt => "TLS-RPT",
            ControlId::Csync => "CSYNC",
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
    /// Seal-layer spelling of the disposition that produced this report. This
    /// lets the seal preimage read the same one-control-per-row truth_chain()
    /// producer as the renderers, instead of re-enumerating the controls by hand.
    pub seal_disposition: &'static str,
    /// Layer 1 — the RFC requirement, including optionality.
    pub rfc_requirement: &'static str,
    /// Layer 2 — the measured state at full fidelity (disposition label).
    pub measured: &'static str,
    /// Layer 2 collapsed — presentation tri-state (§8: collapse happens here,
    /// at the model boundary, never upstream in the engine's scoring).
    pub tri: TriState,
    /// Consequence-derived severity for ordering.
    pub severity: Severity,
    /// DANE-only: the MX-host zone relationship (the `tlsa_zone` attribution
    /// measurement). `None` for every other control. A measurement, never an
    /// ownership claim — the renderer turns it into the "lives outside your
    /// zone" narrative, not a "your provider is blocking you" verdict.
    pub tlsa_zone: Option<TlsaZone>,
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

    /// The DANE attribution narrative — fired only for `ForeignZone`, the one
    /// case where the MX host lives in a zone the domain owner does not
    /// control. `None` otherwise. A measurement-faithful statement, never an
    /// ownership claim: the zone cut is observed, the "who" is left to the
    /// reader. Surfaces render this as a continuation line under the DANE row,
    /// never as a verdict or a severity.
    pub fn dane_attribution(&self) -> Option<&'static str> {
        match self.tlsa_zone {
            Some(TlsaZone::ForeignZone) => Some(
                "MX host lives outside this domain's own zone — DANE requires either that \
                 operator publishing TLSA or moving MX to a host you control",
            ),
            _ => None,
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
            // §1.3.2, not §4 — pinned by the known-answer vector table
            // (docs/arm2-rfc-known-answer-vectors.md row A1). The two lines
            // rendered adjacent on screen with different section numbers for
            // the same requirement; §1.3.2 is the verified one.
            "Optional (RFC 7672). TLSA at _25._tcp.<mx-host> for each MX; \
             requires a DNSSEC-signed zone (§1.3.2) to mean anything."
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
            // RFC 7344 status — SETTLED, three authorities, do not re-litigate:
            // (1) rfc-index.xml <current-status> = PROPOSED STANDARD;
            // (2) datatracker std_level = "ps";
            // (3) RFC 8078 §6.1 VERBATIM: "[RFC7344] was published as
            //     Informational; this document elevates RFC 7344 to Standards
            //     Track."
            // The document's own header still says "Informational" because the
            // RFC Editor NEVER retro-edits a published RFC's header — that
            // frozen 2014 text is the trap (it also produces the many
            // "Informational" hits on the info page; the current-status line
            // alongside them says Proposed Standard). Status comes from the
            // INDEX / datatracker, never the frozen header. The load-bearing
            // fact either way is §6's SHOULD: the parent is recommended, never
            // obligated.
            "Optional (RFC 7344, Proposed Standard — elevated from Informational by RFC 8078 §6.1; \
             further updated by RFC 9615/9975). CDS/CDNSKEY at the apex \
             signal automated DS maintenance to the parent zone; the parent MAY act on it but is \
             not normatively required to (§6 SHOULD, not MUST)."
        }
        ControlId::TlsRpt => {
            "Optional (RFC 8460). TXT at _smtp._tls.<domain>: v=TLSRPTv1 plus rua= — \
             where senders deliver aggregate TLS-success/failure reports. Pairs with MTA-STS: \
             the reporting channel that tells the operator their policy is (or is not) working."
        }
        ControlId::Csync => {
            "Optional (RFC 7477). CSYNC RR at the apex signals the parent's agent to copy \
             delegation records (NS/A/AAAA) from the child — automated child-to-parent sync \
             for delegation changes. NOT for DS sync (that is CDS). Absence is the standing \
             state outside a delegation change, not a deficiency."
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
            "signed but not delegated — DNSKEY present, no DS at the parent",
            Severity::High,
            "The zone signs its data but the parent holds no DS, so no resolver can build a chain of trust from the root: validating resolvers treat it as Insecure (RFC 4033 §5), the same state as an unsigned zone. This is the false-confidence case — the operator signed believing the zone was protected, and it is not. Publish the DS at the registrar to complete the chain.",
            "Signatures exist but nothing chains to the root: a validating resolver treats this zone as Insecure, identical to an unsigned one, so spoofed responses are not rejected on signature grounds.",
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
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Dnssec),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn spf_report(d: SpfDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        SpfDisposition::HardFail => (
            "hardfail (-all) — strongest publisher assertion",
            Severity::Ok,
            "SPF authorizes specific senders and asserts the rest are unauthorized — the strongest statement the record can make. RFC 9989 §7.1 names a trade: because SPF runs early in the SMTP transaction, -all can cause rejection before DMARC is consulted, so mail that would have passed via an aligned DKIM signature may be refused — and those rejections never reach the DATA phase, so they never appear in your aggregate reports.",
            "Sender-IP spoofing of this domain fails SPF outright at conforming receivers, and may be refused before DMARC is evaluated.",
        ),
        SpfDisposition::SoftFail => (
            "softfail (~all) — publisher's weaker assertion",
            Severity::Ok,
            "RFC 7208 §2.6.5: softfail is a weak statement by the publishing domain that the host is probably not authorized. It is not a lesser version of -all but a different trade: RFC 9989 §7.1 documents two harms that -all carries and ~all avoids — rejection before DMARC is consulted, and permanent absence from your own aggregate reports. Neither qualifier enforces; DMARC turns the assertion into a disposition.",
            "Spoofed mail is marked, not blocked: softfail typically lands in spam rather than being refused — usable with a pretext that survives a spam folder, and DMARC disposition decides the rest.",
        ),
        SpfDisposition::OtherPolicy => (
            "record present, no negative assertion (?all or no all)",
            Severity::High,
            "SPF is published but makes no negative assertion — ?all is explicitly neutral, and a record with no all mechanism defaults to neutral. It asserts nothing against unauthorized senders, so DMARC's SPF leg can never contribute a fail.",
            "SPF exists but instructs nothing: spoofed senders do not fail SPF here, so DMARC's SPF leg never fires.",
        ),
        SpfDisposition::PositiveAll => (
            "authorizes-all (+all) — every sender is authorized",
            Severity::Critical,
            "RFC 7208 §8.3: a pass means the domain 'can now, in the sense of reputation, be considered responsible for sending the message.' +all affirms that ANY host may inject mail with this identity — it authorizes the entire internet and lends the domain's reputation to every spoofer. This is the one disposition that makes forgery succeed rather than merely go unblocked. Remove it or replace with -all once legitimate senders are known.",
            "Any host on the internet can send mail that passes SPF for this domain: +all authorizes every sender, so the domain's reputation is available to anyone who spoofs it.",
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
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Spf),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
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
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Dkim),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
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
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Dmarc),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn dane_report(d: DaneDisposition, z: TlsaZone) -> ControlReport {
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
        // Severity::NotApplicable, matching the tri-state. The deficiency here
        // is REAL but it is DNSSEC's, and the DNSSEC row already scores it —
        // ranking this Low too would count one unsigned zone as two findings.
        // The remediation still names the fix, so the reader is not left
        // wondering what to do; it just isn't charged twice for it.
        DaneDisposition::DnssecRequired => (
            "not applicable — MX host zone is unsigned, so DANE cannot apply",
            Severity::NotApplicable,
            "DANE only means something inside a signed zone (RFC 7672 §1.3.2). This is not an unknown: the MX host's zone was queried and carries no DNSKEY. Sign the zone first — then TLSA records become verifiable and this control starts applying.",
            "DANE is structurally unavailable here, not merely undeployed: any TLSA present is unverifiable without DNSSEC, so DANE offers no obstacle.",
        ),
    };
    ControlReport {
        control: ControlId::Dane,
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Dane),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: Some(z),
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
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::MtaSts),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn caa_report(d: CaaDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        CaaDisposition::FullyRestricted => (
            "fully-restricted — issue \";\"",
            Severity::Ok,
            "The domain affirmatively prohibits ALL certificate issuance (RFC 8659 §4.2): no CA may issue any certificate. The strongest CAA state.",
            "Certificate mis-issuance would require a CA to violate an explicit no-issuance property outright — there is no authorized CA to compromise.",
        ),
        CaaDisposition::Configured => (
            "configured — issuance restricted to named CAs",
            Severity::Ok,
            "Only the listed CAs may issue certificates for this domain; all others must refuse.",
            "Mis-issuance requires compromising one of the named CAs specifically, not just any CA.",
        ),
        CaaDisposition::WildcardFullyRestricted => (
            "wildcard-fully-restricted — issuewild \";\"",
            Severity::Ok,
            "The domain affirmatively prohibits wildcard-certificate issuance (RFC 8659 §4.3): no CA may issue for *.example. This is stricter than a named-CA restriction.",
            "A wildcard-certificate mis-issuance would require a CA to violate an explicit no-issuance property, not just pick a different CA.",
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
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Caa),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn cds_report(d: CdsDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        CdsDisposition::Published => (
            "published — automated DS maintenance signaled",
            Severity::Ok,
            "The zone advertises CDS/CDNSKEY, so a parent that honors RFC 7344 §6.2 can maintain the DS automatically — key rollovers won't strand the chain. This is an observation about what the child published, not a mandate on the parent: the parent-side obligation is a SHOULD, not a MUST.",
            "DS rotation is automated only if the parent honors the signal; RFC 7344 does not normatively require it to.",
        ),
        CdsDisposition::DeletionRequested => (
            "deletion-requested — null CDS/CDNSKEY (RFC 8078 §4)",
            Severity::High,
            "The operator has published the DNSSEC delete signal (algorithm 0): the parent is asked to remove the DS RRset. This zone is being deliberately decommissioned from DNSSEC.",
            "The zone is transitioning to unsigned — every DNSSEC-provided guarantee (authenticity, integrity) is being withdrawn by the operator's own signed instruction.",
        ),
        // RULED: policy/RULING_cds_cdnskey_20260821.md — "LEAVE IT". Do not
        // relabel this arm as "no rollover in progress" / "absence is correct"
        // / a healthy resting state. That premise (publication signals a
        // rollover IN PROGRESS) is FALSIFIED BY MEASUREMENT: 6 of 16 signed
        // zones publish CDS/CDNSKEY at rest — and 4 of those 6 share
        // byte-identical KSK material (tag 2371), so it is 3 independent
        // operators, which makes the finding stronger: a hosting provider does
        // not put every customer zone into permanent rollover.
        //
        // Absence cannot carry a rollover claim at all — it is precisely the
        // state where nothing is learned about rollover. The legitimate home
        // for "no rollover in progress" is ungraded vector N1 (CDS MATCHES the
        // parent DS) in docs/cds-match-differ-scope-out.md, which requires a
        // PUBLISHED CDS to compare. Grade N1/N2 for Published zones if that
        // sentence is wanted on screen; never relabel NotPublished.
        //
        // Pinned by cds_not_published_copy_is_ruled_do_not_soften.
        CdsDisposition::NotPublished => (
            "not published — zone exists, no CDS/CDNSKEY",
            Severity::Low,
            "DS updates at the parent are manual. If your keys change and the parent DS is not updated in step, the domain stops resolving (SERVFAIL) for every validating resolver until it is fixed. Publishing CDS/CDNSKEY lets a supporting parent maintain the DS automatically. This is an availability control: it protects you from your own key changes, not from an attacker. Remediation: publish CDS and CDNSKEY records matching your DS at your DNS operator; if your operator provides no way to create them, the remediation is procedural — write the registrar DS step into your key-change runbook.",
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
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Cds),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn tls_rpt_report(d: TlsRptDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        TlsRptDisposition::Published => (
            "published (v=TLSRPTv1, rua present)",
            Severity::Ok,
            "Senders deliver aggregate TLS-success/failure reports to the published rua — the operator can SEE when mail transport policy (MTA-STS/DANE) fails in the field.",
            "Reporting channel live: transport failures against this domain generate sender-side telemetry the operator receives.",
        ),
        TlsRptDisposition::RecordAbsent => (
            "record absent — zone exists, no TLS-RPT",
            Severity::Low,
            "No reporting channel: MTA-STS/DANE failures happen invisibly — the operator learns nothing when senders cannot enforce TLS. Publish v=TLSRPTv1 with a rua.",
            "Transport downgrades are undetected: an operator relying on MTA-STS gets no field signal when it fails.",
        ),
        TlsRptDisposition::PolicyInvalid => (
            "record present but non-functional (bad rua / version / multiple records)",
            Severity::Medium,
            "An advertised TLS-RPT record that cannot receive reports — measured absence of the reporting channel (RFC 8460 §3: exactly one v=TLSRPTv1 record counts).",
            "A broken reporting endpoint: senders discard the policy and no telemetry arrives — worse than none because it looks configured.",
        ),
        TlsRptDisposition::NoZone => (
            "no zone — domain does not exist",
            Severity::Ok,
            "No zone, so no TLS-RPT question applies.",
            "No zone; nothing to report on.",
        ),
        TlsRptDisposition::TransientError => (
            "unmeasured (lookup error)",
            Severity::Ok,
            "The lookup errored — nothing was measured.",
            "Measurement unavailable.",
        ),
    };
    ControlReport {
        control: ControlId::TlsRpt,
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::TlsRpt),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
        consequence_blue: blue,
        consequence_red: red,
    }
}

fn csync_report(d: CsyncDisposition) -> ControlReport {
    let (measured, severity, blue, red) = match d {
        CsyncDisposition::Published => (
            "published (single CSYNC RR)",
            Severity::Ok,
            "Delegation sync is automated: the parent's agent can copy NS/A/AAAA changes from the child on signal (RFC 7477), removing the manual registry step.",
            "Delegation changes propagate automatically to the parent — no manual registrar step on nameserver moves.",
        ),
        CsyncDisposition::RecordAbsent => (
            "record absent — standing state outside a delegation change",
            Severity::Ok,
            "No CSYNC: delegation updates go through the registrar manually. Normal for most zones — absence is expected outside a delegation change (the CDS precedent).",
            "Delegation changes are manual (registrar step). No automation signal present.",
        ),
        CsyncDisposition::PolicyInvalid => (
            "multiple CSYNC records — parental agents MUST ignore the set",
            Severity::Low,
            "More than one CSYNC RR: RFC 7477 §2 requires parental agents to ignore the whole set — a measured, non-functional automation signal.",
            "Conflicting sync signals: the automation is dead weight until the set is a single record.",
        ),
        CsyncDisposition::NoZone => (
            "no zone — domain does not exist",
            Severity::Ok,
            "No zone, so no CSYNC question applies.",
            "No zone; nothing to sync.",
        ),
        CsyncDisposition::TransientError => (
            "unmeasured (lookup error)",
            Severity::Ok,
            "The lookup errored — nothing was measured.",
            "Measurement unavailable.",
        ),
    };
    ControlReport {
        control: ControlId::Csync,
        seal_disposition: d.seal_spelling(),
        rfc_requirement: rfc_requirement(ControlId::Csync),
        measured,
        tri: d.chain(),
        severity,
        tlsa_zone: None,
        consequence_blue: blue,
        consequence_red: red,
    }
}

// =============================================================================
// truth_chain — the model constructor, and the severity ordering
// =============================================================================

/// Build the ten-control render model from a ScoredAnalysis. Canonical
/// (protocol-layer) order; use [`by_severity`] for worst-first ordering.
pub fn truth_chain(a: &ScoredAnalysis) -> [ControlReport; 10] {
    [
        dnssec_report(a.dnssec_disposition),
        spf_report(a.spf_disposition),
        dkim_report(a.dkim_disposition),
        dmarc_report(a.dmarc_disposition),
        dane_report(a.dane_disposition, a.tlsa_zone),
        mta_sts_report(a.mta_sts_disposition),
        caa_report(a.caa_disposition),
        cds_report(a.cds_disposition),
        tls_rpt_report(a.tls_rpt_disposition),
        csync_report(a.csync_disposition),
    ]
}

/// Worst-first ordering. Stable within a severity tier (canonical order),
/// so equal-severity controls keep a deterministic, familiar order.
pub fn by_severity(reports: &[ControlReport; 10]) -> [ControlReport; 10] {
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
    pub fn of(reports: &[ControlReport; 10]) -> Tally {
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
// Risk-Weighted Score (RWS) — a derived view, NOT sealed (spec §6)
// =============================================================================
//
// The Coverage Score (Tally) is the primary measurement and stays sealed. The
// Risk-Weighted Score is a DERIVED view over the same eight dispositions: it is
// computed on read, tagged SCORING_VERSION, and never enters the seal. The two
// are always shown together (NIST CSF's warning against a single hidden
// weighted number).
//
// Identity-weighting (spec §12): each control has ONE fixed weight, keyed on
// its IDENTITY (the absent-state severity — "how bad is it to not have this"),
// never its CURRENT state. A Present control earns its full weight whether
// enforcing (Ok) or deployed-but-not-enforcing (Medium); the enforcement gap is
// a severity label fact, never a weight fact.

/// Version of the risk-weighting formula. Changing the weight mapping or the
/// formula bumps this — NEVER SEAL_SCHEME (the seal binds dispositions only;
/// RWS is a derived view over those same sealed dispositions).
pub const SCORING_VERSION: u32 = 1;

/// The consequence weight of a control, keyed on its IDENTITY (its absent-state
/// severity), NOT its current state. Derived from the `*_report` constructor for
/// that control's "missing" disposition — single producer, so a future severity
/// re-ruling propagates automatically. CSYNC is the ruled zero-weight exception
/// (policy/RULING_csync_20260901.md, ratified 2026-09-01):
/// `RecordAbsent` is the expected standing state outside a delegation change,
/// so it is measured and shown but excluded from RWS rather than pretending the
/// absent-state severity is High or Low.
pub fn identity_weight(control: ControlId) -> u32 {
    match absent_severity(control) {
        Severity::High => 3,
        Severity::Low => 1,
        // CSYNC RecordAbsent is Ok: measured/shown, but zero-weight in RWS —
        // RULED (policy/RULING_csync_20260901.md, ratified 2026-09-01): RFC
        // 7477 §5 partitions CSYNC out of the security domain by
        // construction, and the measured operator asymmetry (elites leave
        // CDS standing; nobody leaves CSYNC standing — three sweeps, 0/N)
        // corroborates. Outside a delegation-change window an absent
        // CDS/CSYNC is the expected standing state, so the zero band shows
        // and measures it but excludes it from RWS. Reopening criterion and
        // the DnssecRequired follow-up live in the ruling document.
        _ => 0,
    }
}

/// The severity of a control's "you don't have this" disposition — read from the
/// report constructor, never a hand-kept table. This is the single-producer link:
/// a future severity re-ruling changes the weight automatically.
fn absent_severity(control: ControlId) -> Severity {
    match control {
        ControlId::Dnssec => dnssec_report(DnssecDisposition::Unsigned).severity,
        ControlId::Spf => spf_report(SpfDisposition::NotConfigured).severity,
        // DKIM's "missing" state is Revoked (empty p=, unsigned in practice →
        // High), NOT NotFoundDefaults (Unmeasured — the honest "absence not
        // proven" state). See the DKIM report constructor for the distinction.
        ControlId::Dkim => dkim_report(DkimDisposition::Revoked).severity,
        ControlId::Dmarc => dmarc_report(DmarcDisposition::NotConfigured).severity,
        ControlId::MtaSts => mta_sts_report(MtaStsDisposition::RecordAbsent).severity,
        ControlId::Dane => dane_report(DaneDisposition::NotConfigured, TlsaZone::SameZone).severity,
        ControlId::Caa => caa_report(CaaDisposition::NotConfigured).severity,
        ControlId::Cds => cds_report(CdsDisposition::NotPublished).severity,
        ControlId::TlsRpt => tls_rpt_report(TlsRptDisposition::RecordAbsent).severity,
        ControlId::Csync => csync_report(CsyncDisposition::RecordAbsent).severity,
    }
}

/// The risk-weighted score, 0–100. Derived FROM the sealed dispositions via
/// truth_chain() — it is a view, not a measurement, so it is NOT sealed.
/// `None` when nothing is measurable (denominator 0) — the same honest
/// "unmeasured" handling as the Coverage Score (never a fake 100).
///
/// Formula (bounded 0–100 by construction):
///   Σ identity_weight(control)  where tri == Present
///   ÷ Σ identity_weight(control)  where tri ∈ {Present, Absent}
/// `Indet` and `NotApplicable` are excluded from both sums, exactly as the
/// Coverage Score excludes them.
pub fn risk_weighted_score(reports: &[ControlReport; 10]) -> Option<u32> {
    let mut covered: u32 = 0; // Σ identity_weight where tri == Present
    let mut surface: u32 = 0; // Σ identity_weight where tri ∈ {Present, Absent}
    for r in reports {
        let w = identity_weight(r.control);
        match r.tri {
            TriState::Present => {
                covered += w;
                surface += w;
            }
            TriState::Absent => surface += w,
            TriState::Indet | TriState::NotApplicable => {}
        }
    }
    if surface == 0 {
        return None; // nothing measured — never a fake 100
    }
    Some(covered.saturating_mul(100) / surface)
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
            SpfDisposition::PositiveAll,
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
            DkimDisposition::Revoked,
            DkimDisposition::Wildcard,
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
            v.push(dane_report(d, TlsaZone::SameZone));
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
            CaaDisposition::FullyRestricted,
            CaaDisposition::WildcardFullyRestricted,
            CaaDisposition::Configured,
            CaaDisposition::NotConfigured,
            CaaDisposition::NoZone,
            CaaDisposition::TransientError,
        ] {
            v.push(caa_report(d));
        }
        for d in [
            CdsDisposition::Published,
            CdsDisposition::DeletionRequested,
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
            54,
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

    /// §8 enforcement ruling, pinned: deployed-but-not-enforcing states score
    /// Present (deployment) — the score never erases the gap, the severity
    /// never erases the deployment.
    ///
    /// The two axes are independent, and §8 governs only the first. TriState
    /// answers "is it published"; severity answers "how bad is the gap".
    /// Two severity re-rulings have moved states on the second axis while
    /// every member kept TriState::Present, which is exactly the separation
    /// §8 requires:
    ///   - `OtherPolicy` Medium -> High (?all/+all assert nothing at all)
    ///   - `SoftFail`    Medium -> Ok   (a hedged-but-adverse position, the
    ///     same posture as DMARC quarantine, which already scored Ok)
    ///
    /// What remains Medium is the genuinely deficient middle: MTA-STS
    /// `NotEnforced`, where the publisher has declared the policy MUST NOT be
    /// applied, and DMARC `Monitor`, which requests no action at all.
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
        }

        // Severity is the SEPARATE axis, and the four members no longer share
        // a rank — the states mean four different things.
        assert_eq!(
            mta_sts_report(MtaStsDisposition::NotEnforced).severity,
            Severity::Medium,
            "testing mode protects nothing by the publisher's own declaration"
        );
        assert_eq!(
            dmarc_report(DmarcDisposition::Monitor).severity,
            Severity::Medium,
            "p=none requests no action"
        );
        assert_eq!(
            spf_report(SpfDisposition::SoftFail).severity,
            Severity::Ok,
            "~all is a hedged-but-adverse position, like DMARC quarantine"
        );
        assert_eq!(
            spf_report(SpfDisposition::OtherPolicy).severity,
            Severity::High,
            "?all/+all assert nothing — not equivalent to ~all's weak negative"
        );
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
        let r = dane_report(DaneDisposition::TlsaPublished, TlsaZone::SameZone);
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
            dane_report(DaneDisposition::Mismatch, TlsaZone::SameZone).severity,
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
            dnssec_report(DnssecDisposition::Unsigned), // High
            spf_report(SpfDisposition::HardFail),       // Ok
            dkim_report(DkimDisposition::NotProbed),    // Unmeasured
            dmarc_report(DmarcDisposition::Monitor),    // Medium
            dane_report(DaneDisposition::Mismatch, TlsaZone::SameZone), // Critical
            mta_sts_report(MtaStsDisposition::RecordAbsent), // High
            caa_report(CaaDisposition::NotConfigured),  // Low
            cds_report(CdsDisposition::NotPublished),   // Low
            tls_rpt_report(TlsRptDisposition::RecordAbsent), // Low
            csync_report(CsyncDisposition::RecordAbsent), // Ok
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
            dane_report(DaneDisposition::NoMail, TlsaZone::SameZone), // N/A
            mta_sts_report(MtaStsDisposition::TransientError),    // Indet
            caa_report(CaaDisposition::Configured),               // Present
            cds_report(CdsDisposition::NotPublished),             // Absent
            tls_rpt_report(TlsRptDisposition::Published),         // Present
            csync_report(CsyncDisposition::RecordAbsent),         // Absent
        ];
        let t = Tally::of(&model);
        assert_eq!(
            (t.present, t.absent, t.unmeasured, t.not_applicable),
            (4, 3, 2, 1)
        );
        assert_eq!(t.denominator(), 7);
        assert_eq!(t.percent(), 57);

        let nothing = [
            dnssec_report(DnssecDisposition::Unreachable),
            spf_report(SpfDisposition::TransientError),
            dkim_report(DkimDisposition::NotProbed),
            dmarc_report(DmarcDisposition::TransientError),
            dane_report(DaneDisposition::TransientError, TlsaZone::SameZone),
            mta_sts_report(MtaStsDisposition::TransientError),
            caa_report(CaaDisposition::TransientError),
            cds_report(CdsDisposition::TransientError),
            tls_rpt_report(TlsRptDisposition::TransientError),
            csync_report(CsyncDisposition::TransientError),
        ];
        let t0 = Tally::of(&nothing);
        assert_eq!(t0.denominator(), 0);
        assert_eq!(
            t0.percent(),
            0,
            "nothing measured must never read as a score"
        );
    }

    // ── Risk-Weighted Score (spec §10 acceptance tests) ─────────────────────
    // Identity-weighting: each control's weight is its absent-state severity
    // (High 3 / Low 1), never its current state.

    /// Test 7 — weight is DERIVED, not hardcoded: reading the report constructor
    /// for the control's "missing" disposition yields the weight. A future
    /// severity re-ruling changes the weight automatically (one assertion per
    /// source, per the mutation method).
    #[test]
    fn identity_weight_is_derived_not_hardcoded() {
        // The five High controls → 3, the three Low → 1 (spec §5).
        assert_eq!(identity_weight(ControlId::Dnssec), 3);
        assert_eq!(identity_weight(ControlId::Spf), 3);
        assert_eq!(identity_weight(ControlId::Dkim), 3);
        assert_eq!(identity_weight(ControlId::Dmarc), 3);
        assert_eq!(identity_weight(ControlId::MtaSts), 3);
        assert_eq!(identity_weight(ControlId::Dane), 1);
        assert_eq!(identity_weight(ControlId::Caa), 1);
        assert_eq!(identity_weight(ControlId::Cds), 1);
        // The derivation link, pinned per source (test 7's core):
        assert_eq!(
            dmarc_report(DmarcDisposition::NotConfigured).severity,
            Severity::High,
            "DMARC's missing disposition is High; identity_weight derives 3 from it"
        );
        assert_eq!(
            dane_report(DaneDisposition::NotConfigured, TlsaZone::SameZone).severity,
            Severity::Low,
            "DANE's missing disposition is Low; identity_weight derives 1 from it"
        );
        // Punch-list item 2: the two new controls' weights are pinned with
        // their own derivation links, same discipline as the eight above.
        // TLS-RPT absent is a real reporting gap (Low, weight 1 — a mail
        // domain flying blind on its own TLS failure data).
        assert_eq!(
            identity_weight(ControlId::TlsRpt),
            1,
            "TLS-RPT identity weight is 1"
        );
        assert_eq!(
            tls_rpt_report(TlsRptDisposition::RecordAbsent).severity,
            Severity::Low,
            "TLS-RPT's missing disposition is Low; identity_weight derives 1 from it"
        );
        // CSYNC absent is the EXPECTED standing state outside a delegation
        // change — zero band (measured + shown, excluded from RWS), RULED:
        // policy/RULING_csync_20260901.md (ratified 2026-09-01). The pin
        // is now the ruled state; the reopening criterion lives in the
        // ruling document (see identity_weight).
        assert_eq!(
            identity_weight(ControlId::Csync),
            0,
            "CSYNC identity weight is the ruled zero band (policy/RULING_csync_20260901.md)"
        );
        assert_eq!(
            csync_report(CsyncDisposition::RecordAbsent).severity,
            Severity::Ok,
            "CSYNC's absent-state severity is Ok — measured as the expected standing state (the ruled zero band's source); a future re-ruling changes this arm and the weight follows automatically"
        );
    }

    /// The CDS/CDNSKEY `NotPublished` copy is RULED, not stylistic:
    /// policy/RULING_cds_cdnskey_20260821.md — "LEAVE IT".
    ///
    /// This premise has now been re-proposed three times (a Hermes brief, an
    /// uncommitted rewrite in the shared checkout, and again on 2026-08-24),
    /// twice by an agent that had the ruling available. A comment did not stop
    /// it, so this is the mechanical gate: the softening reaches the reader
    /// only through these strings, and this test fails if it does.
    #[test]
    fn cds_not_published_copy_is_ruled_do_not_soften() {
        let r = cds_report(CdsDisposition::NotPublished);

        // The ruled state. (a) NotApplicable was rejected — a signed zone HAS
        // the surface, was measured, and answered. (b) relabelling FAIL while
        // keeping the arithmetic was rejected as "an arithmetic penalty with
        // words denying it" — the display-vs-state defect shape.
        assert_eq!(
            r.tri,
            TriState::Absent,
            "measured absence, not NotApplicable"
        );
        assert_eq!(
            r.severity,
            Severity::Low,
            "Low is the concession; erasing the finding is not"
        );

        // The falsified premise, in every phrasing it has arrived in. Absence
        // is the state where NOTHING is learned about rollover, so no absence
        // copy may make a rollover claim in either direction.
        let all = format!(
            "{} {} {}",
            r.measured,
            r.consequence(Audience::BlueTeam),
            r.consequence(Audience::RedTeam)
        )
        .to_lowercase();
        for banned in [
            "no rollover in progress",
            "not currently in rollover",
            "no rollover is in progress",
            "absence is correct",
            "resting state",
            "healthy state",
            "not a defect",
            "no key rollover",
        ] {
            assert!(
                !all.contains(banned),
                "RULED AGAINST (policy/RULING_cds_cdnskey_20260821.md): absence cannot carry a \
                 rollover claim — {banned:?} re-asserts the premise falsified by 6-of-16 \
                 publishing at rest. The legitimate home is vector N1 (CDS matches parent DS) \
                 for PUBLISHED zones: docs/cds-match-differ-scope-out.md"
            );
        }

        // The finding the ruling exists to protect: manual DS maintenance was
        // reportable on 10 of 16 signed zones in the ruling's own sample.
        assert!(
            r.consequence(Audience::BlueTeam).contains("manual"),
            "the manual-DS-maintenance finding must survive any rewording"
        );
    }

    /// DANE's `DnssecRequired` is a MEASURED structural unavailability, not a
    /// gap in our knowledge — the distinction Carey caught rendering as "?".
    #[test]
    fn dane_dnssec_required_is_measured_unavailability_not_a_gap() {
        // Carey caught this on screen: an unsigned mail domain rendered DNSSEC
        // FAIL two rows above a DANE "?" — the tool asking a question it had
        // just answered itself.
        //
        // The emitting gate is the evidence. dane_host_zone_requires_dnssec
        // fires ONLY on Unsigned/NoZone and deliberately passes Unreachable and
        // ChainUnverified through to the TLSA loop. So every emission of this
        // disposition stands on a completed measurement. Indet claimed the
        // opposite.
        let req = dane_report(DaneDisposition::DnssecRequired, TlsaZone::SameZone);
        assert_eq!(
            req.tri,
            TriState::NotApplicable,
            "DnssecRequired is a MEASURED structural unavailability — its gate fires only on \
             measured Unsigned/NoZone — so it must not render as couldn't-measure"
        );
        assert_eq!(
            req.severity,
            Severity::NotApplicable,
            "the unsigned zone is DNSSEC's finding; scoring it here too counts it twice"
        );

        // The genuine couldn't-measure keeps Indet. If this ever equals the
        // line above, the distinction this whole change exists to draw is gone.
        let transient = dane_report(DaneDisposition::TransientError, TlsaZone::SameZone);
        assert_eq!(
            transient.tri,
            TriState::Indet,
            "TransientError is the real couldn't-measure and must stay Indet"
        );
        assert_ne!(
            req.tri, transient.tri,
            "measured-unavailable and couldn't-measure must remain distinguishable"
        );

        // Absent was the other candidate and is wrong: it attributes DNSSEC's
        // failure to DANE. NoMx is the correctly-Absent sibling — mail routing
        // is genuinely missing there, which IS DANE's own surface.
        assert_eq!(
            dane_report(DaneDisposition::NoMx, TlsaZone::SameZone).tri,
            TriState::Absent,
            "NoMx stays Absent — a missing mail path is DANE's own measured gap"
        );

        // Not-applicable must never be silent about the remedy.
        let blue = req.consequence(Audience::BlueTeam);
        assert!(
            blue.contains("7672"),
            "must cite the RFC that makes DANE conditional on DNSSEC"
        );
        assert!(
            blue.contains("Sign the zone"),
            "not-applicable must still tell the operator what unlocks the control"
        );
        assert!(
            !req.measured.contains("cannot be trusted"),
            "the old wording read as a DANE verdict; the finding belongs to DNSSEC"
        );
    }

    /// SPF `+all` is the inverted control — the one disposition that makes
    /// forgery SUCCEED. RFC 7208 §8.3: a pass means the domain "can now, in
    /// the sense of reputation, be considered responsible for sending the
    /// message." A record authorizing every sender conveys exactly the
    /// information of no record, which is already `Absent`.
    ///
    /// Ruled 2026-08-24 (Claude Science, RFC 7208 §2.6.3/§8.3 verified): the
    /// sharper test than §8's "score deployment" is "does the record authorize
    /// anything?" — `+all` authorizes everyone, so `Absent` + `Critical`.
    #[test]
    fn spf_positive_all_is_critical_and_absent() {
        let r = spf_report(SpfDisposition::PositiveAll);

        assert_eq!(
            r.tri,
            TriState::Absent,
            "+all authorizes everyone = no selective authorization = Absent"
        );
        assert_eq!(
            r.severity,
            Severity::Critical,
            "+all is the one disposition that makes forgery succeed"
        );

        let blue = r.consequence(Audience::BlueTeam);
        assert!(
            blue.contains("8.3"),
            "must cite RFC 7208 §8.3 (the reputation-lending definition)"
        );
        assert!(
            blue.contains("reputation"),
            "the consequence must name that +all lends the domain's reputation to spoofers"
        );

        // ?all stays the distinct neutral case — splitting +all out must not
        // have dragged the neutral case with it.
        let neutral = spf_report(SpfDisposition::OtherPolicy);
        assert_eq!(
            neutral.tri,
            TriState::Present,
            "?all/no-all is still a published record"
        );
        assert_eq!(
            neutral.severity,
            Severity::High,
            "neutral is High, not Critical"
        );
        assert_ne!(
            r.severity, neutral.severity,
            "PositiveAll (Critical) and OtherPolicy (High) must remain distinguishable"
        );
    }

    /// DNSSEC `SignedNotDelegated` is resolver-identical to unsigned, so it
    /// must score the same — not milder.
    ///
    /// RFC 4033 §5 "Insecure": "signed proof of the non-existence of a DS
    /// record… subsequent branches in the tree are provably insecure." A
    /// validating resolver reaches the identical state for an unsigned zone
    /// and a signed-but-undelegated one. The old mapping scored them
    /// differently (`Unsigned`=Absent/High vs `SignedNotDelegated`=Indet/
    /// Medium), which *rewarded* a half-finished deployment — the
    /// display-vs-state defect in numeric form (Indet removed DNSSEC's weight
    /// 3 from both sums).
    ///
    /// Ruled 2026-08-24 (Claude Science, RFC 4033 §5 verified). The
    /// false-confidence reading ("the operator signed believing they were
    /// protected, and they aren't") is the sharpest sentence — it lives in the
    /// consequence TEXT, not the tri-state: belief is prose, resolver state is
    /// Insecure.
    #[test]
    fn dnssec_signed_not_delegated_is_high_and_absent() {
        let r = dnssec_report(DnssecDisposition::SignedNotDelegated);

        assert_eq!(
            r.tri,
            TriState::Absent,
            "resolver-identical to unsigned, so Absent not Indet"
        );
        assert_eq!(
            r.severity,
            Severity::High,
            "no protection and a false claim — not Medium"
        );

        // The false-confidence reading must be present in the consequence text.
        let blue = r.consequence(Audience::BlueTeam);
        assert!(
            blue.contains("Insecure"),
            "must name the RFC 4033 §5 state a resolver reaches"
        );
        assert!(
            blue.contains("false-confidence"),
            "the sharpest sentence: the operator signed believing they were protected, and they aren't"
        );

        // And it must be prose, not the tri-state — the tri-state is the
        // resolver's state (Insecure = Absent), not the operator's belief.
        assert_ne!(
            r.tri,
            TriState::Indet,
            "couldn't-measure is wrong; this is precisely measured"
        );
    }

    /// SPF qualifier severities encode ASSERTION STRENGTH, not enforcement —
    /// RFC 7208 §2.6.5 ("a weak statement by the publishing ADMD") and the
    /// deferral of action to receiver local policy. Neither qualifier
    /// enforces; DMARC turns the assertion into a disposition.
    ///
    /// Ruling (Claude Science, 2026-08-23, standards-verified first-hand):
    /// Option 1 — per-control severity stands, the WORDING carries the
    /// layering. Cross-control severity was rejected ON FACT, not purity:
    /// RFC 9989 §7.1 cautions the publisher AGAINST -all (early SMTP
    /// rejection before DMARC is consulted, and those rejections never reach
    /// the DATA phase so they never appear in aggregate reports), so making
    /// softfail worse when DMARC is absent would penalise the safer
    /// publication exactly where it is most correct.
    #[test]
    fn spf_severities_rank_assertion_strength_not_enforcement() {
        let hard = spf_report(SpfDisposition::HardFail);
        let soft = spf_report(SpfDisposition::SoftFail);
        let other = spf_report(SpfDisposition::OtherPolicy);

        // -all is the strongest assertion — but its consequence must state
        // the RFC 9989 §7.1 trade, not report one side of it.
        assert_eq!(hard.severity, Severity::Ok);
        assert!(
            hard.consequence_blue.contains("9989"),
            "hardfail must cite the §7.1 trade: {}",
            hard.consequence_blue
        );

        // ~all is a legitimate posture, not a lesser one. RFC 9989 §7.1
        // documents two harms -all carries that ~all avoids (rejection before
        // DMARC is consulted; permanent absence from aggregate reports), so a
        // taxonomy awarding Ok only to the qualifier the RFC cautions against
        // would measure the wrong axis. Ruled 2026-08-23 after the DMARC
        // ladder showed the offset: quarantine ("possible the mail is valid")
        // passed while softfail ("probably not authorized") did not — the same
        // epistemic posture scored two different ways.
        assert_eq!(soft.severity, Severity::Ok);
        assert!(
            soft.consequence_blue.contains("weak statement"),
            "softfail must use the publisher-assertion framing: {}",
            soft.consequence_blue
        );
        assert!(
            soft.consequence_blue.contains("9989"),
            "softfail must cite the §7.1 trade that justifies parity: {}",
            soft.consequence_blue
        );
        assert!(!soft.consequence_blue.contains("Move to -all"));
        assert!(!soft.consequence_blue.contains("path toward -all"));

        // The unconditional-DMARC defect: this control never measures DMARC,
        // so it must not assert a co-control's state.
        assert!(
            !soft.consequence_blue.contains("With DMARC enforcing"),
            "softfail must not assert an unmeasured co-control state: {}",
            soft.consequence_blue
        );

        // ?all / +all make NO negative assertion — not equivalent to ~all's
        // weak one. +all authorizes the entire internet. Severity orders
        // worst-first, so the harsher rank sorts BELOW the weaker one.
        assert_eq!(other.severity, Severity::High);
        assert!(
            other.severity < soft.severity,
            "no-assertion must outrank a weak negative assertion"
        );

        // SPF's ladder must stay aligned with DMARC's: both middle rungs are
        // hedged publisher positions and both pass; both bottom rungs take no
        // adverse position and both are findings. The offset between them was
        // a display inconsistency with no basis in the standards text.
        assert_eq!(
            soft.severity,
            dmarc_report(DmarcDisposition::Quarantine).severity,
            "hedged-but-adverse must score the same on both ladders"
        );
    }

    /// A domain missing only CAA (weight 1) vs missing only DMARC (weight 3) —
    /// identical Coverage, but RWS separates them (spec §1 test 2).
    #[test]
    fn risk_weighted_score_reveals_what_coverage_hides() {
        // All present except CAA absent.
        let missing_caa = [
            dnssec_report(DnssecDisposition::SignedAndDelegated),
            spf_report(SpfDisposition::HardFail),
            dkim_report(DkimDisposition::Verified),
            dmarc_report(DmarcDisposition::Reject),
            dane_report(DaneDisposition::TlsaPublished, TlsaZone::SameZone),
            mta_sts_report(MtaStsDisposition::Enforced),
            caa_report(CaaDisposition::NotConfigured), // absent (weight 1)
            cds_report(CdsDisposition::Published),
            tls_rpt_report(TlsRptDisposition::Published),
            csync_report(CsyncDisposition::Published),
        ];
        // All present except DMARC absent.
        let missing_dmarc = [
            dnssec_report(DnssecDisposition::SignedAndDelegated),
            spf_report(SpfDisposition::HardFail),
            dkim_report(DkimDisposition::Verified),
            dmarc_report(DmarcDisposition::NotConfigured), // absent (weight 3)
            dane_report(DaneDisposition::TlsaPublished, TlsaZone::SameZone),
            mta_sts_report(MtaStsDisposition::Enforced),
            caa_report(CaaDisposition::Configured),
            cds_report(CdsDisposition::Published),
            tls_rpt_report(TlsRptDisposition::Published),
            csync_report(CsyncDisposition::Published),
        ];

        // Identical Coverage Score (both 9/10 measured controls present).
        assert_eq!(
            Tally::of(&missing_caa).percent(),
            Tally::of(&missing_dmarc).percent()
        );
        // RWS separates them: missing DMARC (weight 3) drags harder than missing CAA (weight 1).
        let rws_caa = risk_weighted_score(&missing_caa).unwrap();
        let rws_dmarc = risk_weighted_score(&missing_dmarc).unwrap();
        assert!(
            rws_dmarc < rws_caa,
            "missing DMARC (weight 3) must lower RWS more than missing CAA (weight 1): \
             {rws_dmarc} vs {rws_caa}"
        );
        // Exact arithmetic (max denominator 19): missing CAA = 18/19, missing DMARC = 16/19.
        assert_eq!(rws_caa, 94); // 18/19
        assert_eq!(rws_dmarc, 84); // 16/19
    }

    /// Tests 3 + 4 — Indet (Unmeasured) and NotApplicable are excluded from both
    /// sums; adding them must not move RWS.
    #[test]
    fn risk_weighted_score_excludes_unmeasured_and_not_applicable() {
        let base = [
            dnssec_report(DnssecDisposition::SignedAndDelegated), // Present (3)
            spf_report(SpfDisposition::NotConfigured),            // Absent (3)
            dkim_report(DkimDisposition::NotProbed),              // Indet — excluded
            dmarc_report(DmarcDisposition::Reject),               // Present (3)
            dane_report(DaneDisposition::NoMail, TlsaZone::NoMxHost), // N/A — excluded
            mta_sts_report(MtaStsDisposition::Enforced),          // Present (3)
            caa_report(CaaDisposition::NotConfigured),            // Absent (1)
            cds_report(CdsDisposition::NotPublished),             // Absent (1)
            tls_rpt_report(TlsRptDisposition::Published),         // Present (1)
            csync_report(CsyncDisposition::TransientError),       // Indet — excluded
        ];
        // Present: DNSSEC(3) + DMARC(3) + MTA-STS(3) + TLS-RPT(1) = 10;
        // Absent: SPF(3) + CAA(1) + CDS(1) = 5.
        // RWS = 10 / 15 = 66.
        let rws = risk_weighted_score(&base).unwrap();
        assert_eq!(rws, 66); // 10/15
        assert_eq!(Tally::of(&base).percent(), 57); // 4/7 coverage — RWS ≠ coverage here
    }

    /// Test 6 — all-Absent → 0, all-Present → 100; test 5 — bounds hold.
    #[test]
    fn risk_weighted_score_bounds_zero_and_full() {
        let all_absent = [
            dnssec_report(DnssecDisposition::Unsigned),    // High → 3
            spf_report(SpfDisposition::NotConfigured),     // 3
            dkim_report(DkimDisposition::Revoked),         // 3
            dmarc_report(DmarcDisposition::NotConfigured), // 3
            dane_report(DaneDisposition::NotConfigured, TlsaZone::SameZone), // 1
            mta_sts_report(MtaStsDisposition::RecordAbsent), // 3
            caa_report(CaaDisposition::NotConfigured),     // 1
            cds_report(CdsDisposition::NotPublished),      // 1
            tls_rpt_report(TlsRptDisposition::RecordAbsent), // 1
            csync_report(CsyncDisposition::RecordAbsent), // 1 (absent but Ok-severity — excluded from RWS by the Ok rule, still Absent for tally)
        ];
        assert_eq!(risk_weighted_score(&all_absent), Some(0));

        let all_present = [
            dnssec_report(DnssecDisposition::SignedAndDelegated),
            spf_report(SpfDisposition::HardFail),
            dkim_report(DkimDisposition::Verified),
            dmarc_report(DmarcDisposition::Reject),
            dane_report(DaneDisposition::TlsaPublished, TlsaZone::SameZone),
            mta_sts_report(MtaStsDisposition::Enforced),
            caa_report(CaaDisposition::Configured),
            cds_report(CdsDisposition::Published),
            tls_rpt_report(TlsRptDisposition::Published),
            csync_report(CsyncDisposition::Published),
        ];
        assert_eq!(risk_weighted_score(&all_present), Some(100));
    }

    /// Test 8 — identity weight, not state weight: a p=none DMARC (Monitor,
    /// Medium) weighs the SAME as a p=reject DMARC (Reject, Ok). Both are
    /// Present → full identity weight (3). The enforcement gap is a label fact.
    #[test]
    fn risk_weighted_score_identity_not_state() {
        let p_reject = dmarc_report(DmarcDisposition::Reject); // Ok
        let p_none = dmarc_report(DmarcDisposition::Monitor); // Medium
        assert_eq!(p_reject.severity, Severity::Ok);
        assert_eq!(p_none.severity, Severity::Medium);
        // Both Present → both contribute identity_weight(DMARC) = 3.
        assert_eq!(identity_weight(ControlId::Dmarc), 3);
        // And the score does not vary on the severity of a Present control:
        // build two models identical except the DMARC enforcement level.
        let mut reject_model = [
            dnssec_report(DnssecDisposition::SignedAndDelegated),
            spf_report(SpfDisposition::HardFail),
            dkim_report(DkimDisposition::Verified),
            p_reject,
            dane_report(DaneDisposition::TlsaPublished, TlsaZone::SameZone),
            mta_sts_report(MtaStsDisposition::Enforced),
            caa_report(CaaDisposition::Configured),
            cds_report(CdsDisposition::Published),
            tls_rpt_report(TlsRptDisposition::Published),
            csync_report(CsyncDisposition::Published),
        ];
        let none_model = {
            reject_model[3] = p_none;
            reject_model
        };
        assert_eq!(
            risk_weighted_score(&reject_model),
            risk_weighted_score(&none_model),
            "a Present DMARC weighs the same whether p=reject (Ok) or p=none (Medium)"
        );
    }

    /// Nothing measured → None (never a fake 100), matching the Coverage Score's
    /// "nothing measured" doctrine.
    #[test]
    fn risk_weighted_score_none_when_nothing_measured() {
        let nothing = [
            dnssec_report(DnssecDisposition::Unreachable),
            spf_report(SpfDisposition::TransientError),
            dkim_report(DkimDisposition::NotProbed),
            dmarc_report(DmarcDisposition::TransientError),
            dane_report(DaneDisposition::TransientError, TlsaZone::SameZone),
            mta_sts_report(MtaStsDisposition::TransientError),
            caa_report(CaaDisposition::TransientError),
            cds_report(CdsDisposition::TransientError),
            tls_rpt_report(TlsRptDisposition::TransientError),
            csync_report(CsyncDisposition::TransientError),
        ];
        assert_eq!(risk_weighted_score(&nothing), None);
    }

    /// Test 1 — degenerate: when the only measured controls share one weight,
    /// RWS == Coverage. Construct with only the three Low controls measured.
    #[test]
    fn risk_weighted_score_degenerate_equals_coverage() {
        let model = [
            dnssec_report(DnssecDisposition::Unreachable), // Indet — excluded
            spf_report(SpfDisposition::TransientError),    // Indet
            dkim_report(DkimDisposition::NotProbed),       // Indet
            dmarc_report(DmarcDisposition::TransientError), // Indet
            dane_report(DaneDisposition::TlsaPublished, TlsaZone::SameZone), // Present (1)
            mta_sts_report(MtaStsDisposition::TransientError), // Indet
            caa_report(CaaDisposition::NotConfigured),     // Absent (1)
            cds_report(CdsDisposition::NotPublished),      // Absent (1)
            tls_rpt_report(TlsRptDisposition::RecordAbsent), // Absent (1)
            csync_report(CsyncDisposition::TransientError), // Indet — excluded
        ];
        // Measured controls: DANE (Present 1), CAA (Absent 1), CDS (Absent 1), TLS-RPT (Absent 1).
        // Coverage = 1/4 = 25; RWS = 1/4 = 25 (equal because all weight 1).
        assert_eq!(Tally::of(&model).percent(), 25);
        assert_eq!(risk_weighted_score(&model), Some(25));
    }

    /// Test 10 — SCORING_VERSION and SEAL_SCHEME are distinct, independently
    /// bumpable constants: a formula change bumps the former, never the latter.
    #[test]
    fn scoring_version_is_distinct_from_seal_scheme() {
        use crate::seal::SEAL_SCHEME;
        // SCORING_VERSION starts at 1 and is a u32; SEAL_SCHEME is a &str —
        // structurally distinct provenance axes (a formula bump cannot collide
        // with a seal-scheme bump). The one load-bearing fact: the seal scheme
        // string identifies the SEAL scheme, not the scoring formula.
        assert_eq!(SCORING_VERSION, 1);
        assert_eq!(SEAL_SCHEME, "resolution-scope-sha3-512-v5");
    }
}
