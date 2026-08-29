// analysis.rs — DNS control scoring
//
// Each public function in this module runs OUTSIDE the seL4 compartment.
// Results are packed into ScoredAnalysis and sent over the IPC endpoint.

use anyhow::Result;
use hickory_resolver::net::NetError;
use hickory_resolver::TokioResolver;
use tracing::{debug, warn};

use crate::denial_proof::{
    extract_denial_proof, DenialProof, LookupReceipt, ReceiptRcode, RecordEntry,
};
use crate::truth_chain::ControlId;
use crate::TriState;

// =============================================================================
// Verdict type surface — re-exported from the shared no_std crate
// =============================================================================
//
// The eight disposition enums + ScoredAnalysis now live in
// `resolution-scope-types` (single producer, shared with native/). Re-exported
// here so `crate::analysis::<Type>` keeps resolving for the scoring functions
// and the other modules (seal, report, truth_chain, ipc) with zero churn. The
// enum VARIANT NAMES are load-bearing — the verdict seal hashes the Debug repr
// — which is exactly why the definitions must not be duplicated anywhere.
pub use resolution_scope_types::{
    CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
    DnssecDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition, TlsaZone,
};

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
    Ok(
        analyse_domain_with_receipts(resolver, domain, dkim_selectors, resolver_identity)
            .await?
            .0,
    )
}

/// Analyse a domain AND return the per-control lookup receipts captured at
/// each control's primary lookup site (Layer-4 capture, SPEC §5 step 1).
/// Receipts are beside-the-seal provenance (R-B): the ScoredAnalysis and its
/// seal are byte-identical whether or not the caller keeps the receipts.
pub async fn analyse_domain_with_receipts(
    resolver: &TokioResolver,
    domain: &str,
    dkim_selectors: &[String],
    resolver_identity: &str,
) -> Result<(ScoredAnalysis, Vec<LookupReceipt>, Vec<RecordEntry>)> {
    debug!(domain, "starting analysis");

    let session_id: u64 = rand_session_id();
    let timestamp_local: u64 = unix_now();

    let mut r_dnssec = None;
    let mut r_spf = None;
    let mut r_dkim = None;
    let mut r_dmarc = None;
    let mut r_dane = None;
    let mut r_mta_sts = None;
    let mut r_caa = None;
    let mut r_cds = None;

    // Raw records captured at classification time — BESIDE the seal (R-B),
    // exactly like the receipts. The ScoredAnalysis and its seal are
    // byte-identical whether or not the caller keeps the records.
    let mut records: Vec<RecordEntry> = Vec::new();

    // ── DNSSEC chain ────────────────────────────────────────────────────────
    // hickory-resolver with validate=true performs AD-bit + RRSIG chain check.
    // The dnssec-ring feature (enforced by compile_error! in lib.rs) is what
    // makes this verification real rather than a no-op.
    let dnssec_disposition = score_dnssec(resolver, domain, &mut r_dnssec, &mut records).await;
    let dnssec_chain = dnssec_disposition.chain();

    // ── Email controls (stub — wire up full probes in Tier 2) ───────────────
    // Every scorer returns ONLY its disposition; the tri-state is derived via
    // chain() right here and nowhere else. Hand-pairing (TriState, Disposition)
    // tuples let the two verdict channels disagree — the 2026-08-19 adversarial
    // panel found three live divergences that way. Derived means impossible.
    let spf_disposition = score_spf(resolver, domain, &mut r_spf, &mut records).await;
    let spf = spf_disposition.chain();
    // The selector sweep is now wired: probe the 81 defaults (plus any
    // caller-supplied selector via analyse_domain_with_selectors). The honest
    // dispositions are Verified / KeyMismatch / NotFoundDefaults — no longer
    // a hardcoded NotProbed stub.
    let dkim_disposition =
        score_dkim(resolver, domain, dkim_selectors, &mut r_dkim, &mut records).await;
    let dkim = dkim_disposition.chain();
    let dmarc_disposition = score_dmarc(resolver, domain, &mut r_dmarc, &mut records).await;
    let dmarc = dmarc_disposition.chain();
    let (dane_disposition, tlsa_zone) =
        score_dane(resolver, domain, &mut r_dane, &mut records).await;
    let dane = dane_disposition.chain();
    let mta_sts_disposition = score_mta_sts(resolver, domain, &mut r_mta_sts, &mut records).await;
    let mta_sts = mta_sts_disposition.chain();
    let caa_disposition = score_caa(resolver, domain, &mut r_caa, &mut records).await;
    let caa = caa_disposition.chain();
    let cds_disposition = score_cds_cdnskey(resolver, domain, &mut r_cds, &mut records).await;
    let cds_cdnskey = cds_disposition.chain();

    // ControlId declaration order — one receipt per control that yielded one
    // (a transport error outside the vocabulary yields none, loudly logged).
    let receipts: Vec<LookupReceipt> = [
        r_dnssec, r_spf, r_dkim, r_dmarc, r_dane, r_mta_sts, r_caa, r_cds,
    ]
    .into_iter()
    .flatten()
    .collect();

    let analysis = ScoredAnalysis {
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
        tlsa_zone,
        mta_sts,
        mta_sts_disposition,
        caa,
        caa_disposition,
        cds_cdnskey,
        cds_disposition,
    };
    Ok((analysis, receipts, records))
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

// =============================================================================
// Layer-4 receipt capture — the witness's record of each control's lookup
// =============================================================================
//
// One receipt per control per scan (SPEC-receipt-column §1): the receipt
// records the control's PRIMARY lookup — the entry query of its probe
// sequence (DNSSEC=DNSKEY, SPF=apex TXT, DKIM=wildcard-sentinel TXT,
// DMARC=_dmarc TXT, DANE=MX, MTA-STS=_mta-sts TXT, CAA=apex CAA,
// CDS=apex CDS). Multi-lookup refinement (e.g. DANE's TLSA leg) is a carded
// follow-up ruling, not silently decided here.
//
// Receipts ride BESIDE the seal (R-B): nothing here touches canonical_input,
// and elapsed_ms is run metadata about the observer, never sealed.

/// Map a wire ResponseCode into the ruled 5-token receipt vocabulary.
/// Rcodes outside the vocabulary (FormErr, NotImp, …) return None — the
/// receipt row is skipped rather than misfiled under a wrong token: a receipt
/// that lies is worse than a missing receipt, and vocabulary widening is a
/// spec ruling, not an implementation shortcut.
fn receipt_rcode_token(rc: hickory_proto::op::ResponseCode) -> Option<ReceiptRcode> {
    use hickory_proto::op::ResponseCode;
    match rc {
        ResponseCode::NoError => Some(ReceiptRcode::NoError),
        ResponseCode::NXDomain => Some(ReceiptRcode::NxDomain),
        ResponseCode::ServFail => Some(ReceiptRcode::ServFail),
        ResponseCode::Refused => Some(ReceiptRcode::Refused),
        _ => None,
    }
}

/// Build the receipt for a failed lookup. NoRecordsFound carries the wire
/// rcode and the authority section (the denial proof, hickory-preserved —
/// gate measured open 2026-08-25, four probes). Timeout is the no-response
/// failure mode (TIMEOUT token, no proof — a "response" that is the absence
/// of a response). Other transport errors have no honest representation in
/// the ruled vocabulary: no row, loudly logged.
fn receipt_from_err(control: ControlId, e: &NetError, elapsed_ms: u64) -> Option<LookupReceipt> {
    use hickory_resolver::net::DnsError;
    match e {
        NetError::Dns(DnsError::NoRecordsFound(nr)) => {
            match receipt_rcode_token(nr.response_code) {
                Some(rcode) => Some(LookupReceipt {
                    control,
                    rcode,
                    answer_count: 0,
                    denial_proof: extract_denial_proof(nr.authorities.as_deref().unwrap_or(&[])),
                    elapsed_ms,
                }),
                None => {
                    warn!(
                        control = ?control,
                        rcode = ?nr.response_code,
                        "rcode outside receipt vocabulary — no receipt row"
                    );
                    None
                }
            }
        }
        NetError::Timeout => Some(LookupReceipt {
            control,
            rcode: ReceiptRcode::Timeout,
            answer_count: 0,
            denial_proof: DenialProof::None,
            elapsed_ms,
        }),
        _ => {
            warn!(
                control = ?control,
                error = %e,
                "transport error not representable in receipt vocabulary — no receipt row"
            );
            None
        }
    }
}

/// A positive answer carries no denial to grade: NOERROR, the answer count,
/// proof `none`. (hickory delivers NODATA as Err(NoRecordsFound), so the Ok
/// arm always has answers.)
fn receipt_from_answers(control: ControlId, answers: usize, elapsed_ms: u64) -> LookupReceipt {
    LookupReceipt {
        control,
        rcode: ReceiptRcode::NoError,
        answer_count: answers.min(u16::MAX as usize) as u16,
        denial_proof: DenialProof::None,
        elapsed_ms,
    }
}

/// The primary-lookup capture shim: run the lookup, fill the control's
/// receipt slot from the outcome, hand the result back untouched. The
/// disposition path is byte-identical with or without the capture.
async fn observed_lookup(
    resolver: &TokioResolver,
    control: ControlId,
    name: &str,
    rt: hickory_proto::rr::RecordType,
    out: &mut Option<LookupReceipt>,
) -> core::result::Result<hickory_resolver::lookup::Lookup, NetError> {
    let started = std::time::Instant::now();
    let res = resolver.lookup(name, rt).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    *out = match &res {
        Ok(l) => Some(receipt_from_answers(control, l.answers().len(), elapsed_ms)),
        Err(e) => receipt_from_err(control, e, elapsed_ms),
    };
    res
}

/// TXT-flavoured twin of [`observed_lookup`].
async fn observed_txt_lookup(
    resolver: &TokioResolver,
    control: ControlId,
    name: &str,
    out: &mut Option<LookupReceipt>,
) -> core::result::Result<hickory_resolver::lookup::Lookup, NetError> {
    let started = std::time::Instant::now();
    let res = resolver.txt_lookup(name).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    *out = match &res {
        Ok(l) => Some(receipt_from_answers(control, l.answers().len(), elapsed_ms)),
        Err(e) => receipt_from_err(control, e, elapsed_ms),
    };
    res
}

async fn score_dnssec(
    resolver: &TokioResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> DnssecDisposition {
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

    match observed_lookup(
        resolver,
        ControlId::Dnssec,
        domain,
        RecordType::DNSKEY,
        receipt,
    )
    .await
    {
        Ok(resp) => {
            let answers = resp.answers();
            // Raw DNSKEY material — the record the chain was validated against.
            // BESIDE the seal (R-B), rendered via hickory's own DNSKEY Display
            // (flags/protocol/algorithm/key-tag/public-key) so a reader can
            // re-derive which key material produced the verdict.
            use hickory_proto::dnssec::rdata::DNSSECRData;
            for rec in answers {
                if let hickory_proto::rr::RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = &rec.data {
                    records.push(RecordEntry {
                        control: ControlId::Dnssec,
                        value: dnskey.to_string(),
                    });
                }
            }
            dnssec_disposition_from_answer(
                answers_present(answers),
                answers.first().map(|r| r.proof),
            )
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

async fn score_spf(
    resolver: &TokioResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> SpfDisposition {
    // SPF is a TXT record at the apex beginning with "v=spf1". The qualifier
    // (-all hardfail vs ~all softfail) is the deployed-but-not-enforcing
    // distinction: ~all is advisory, -all is enforced.
    match observed_txt_lookup(resolver, ControlId::Spf, domain, receipt).await {
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
            // The raw record bytes are BESIDE the seal (R-B): captured here so a
            // reader can re-derive what the scorer read, but never sealed.
            for r in &spf_records {
                records.push(RecordEntry {
                    control: ControlId::Spf,
                    value: r.clone(),
                });
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
    } else if spf_records.iter().any(|r| r.contains("+all")) {
        SpfDisposition::PositiveAll
    } else {
        SpfDisposition::OtherPolicy
    }
}

async fn score_dmarc(
    resolver: &TokioResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> DmarcDisposition {
    // DMARC policy at _dmarc.<domain> TXT "v=DMARC1; p=...". p=none is
    // deployed-but-not-enforcing (monitor only), p=quarantine is intermediate,
    // p=reject is enforced. Same shape as MtaStsDisposition::NotEnforced.
    let dmarc_domain = format!("_dmarc.{}", domain);
    match observed_txt_lookup(resolver, ControlId::Dmarc, dmarc_domain.as_str(), receipt).await {
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
            // Raw bytes BESIDE the seal (R-B) — captured, never sealed.
            for r in &dmarc_records {
                records.push(RecordEntry {
                    control: ControlId::Dmarc,
                    value: r.clone(),
                });
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

/// The sentinel selector for wildcard detection. A nonexistent name that
/// nonetheless resolves to TXT is a wildcard `*._domainkey` synthesis — the
/// 81-selector sweep proves nothing against it. High-entropy and clearly a
/// probe so a legitimate selector cannot collide with it.
pub(crate) const WILDCARD_PROBE_SELECTOR: &str = "resolutionscope-wildcard-probe._domainkey";

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
/// Precedence: revoked beats valid (an empty p= on ANY selector means mail
/// cannot verify through it — but a revoked key is a deliberate withdrawal, not
/// a misconfiguration, so it collapses to Absent at High, not Critical); a valid
/// key beats "not found"; a definitive miss beats transient (we DID probe,
/// nothing matched — NotFoundDefaults, NOT evidence of absence); only when
/// every selector failed transiently do we say we couldn't measure at all.
fn dkim_disposition_from_counts(
    found_valid: usize,
    found_revoked: usize,
    definitive_miss: usize,
    transient: usize,
) -> DkimDisposition {
    if found_revoked > 0 {
        DkimDisposition::Revoked
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
/// report Verified / Revoked / KeyMismatch / NotFoundDefaults / Wildcard.
async fn score_dkim(
    resolver: &TokioResolver,
    domain: &str,
    extra_selectors: &[String],
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> DkimDisposition {
    // Wildcard detection FIRST (2026-08-21 ruling): if a nonexistent selector
    // name resolves to TXT, the domain publishes `*._domainkey` and the sweep
    // proves nothing — every probe "resolves" against the wildcard, so the
    // honest NotFoundDefaults uncertainty is structurally unreachable. That is
    // its own disposition, not a key verdict.
    let sentinel = format!("{}.{}", WILDCARD_PROBE_SELECTOR, domain);
    let sentinel_probe: DkimSelectorProbe =
        match observed_txt_lookup(resolver, ControlId::Dkim, &sentinel, receipt).await {
            Ok(rdata) => Ok(dkim_txt_chunks(rdata.answers())),
            Err(e) => Err(record_absence_verdict(&e, domain)),
        };
    if dkim_wildcard_detected(&sentinel_probe) {
        return DkimDisposition::Wildcard;
    }

    let selectors = build_dkim_selector_list(extra_selectors);

    // Resolve every selector to its probe outcome (chunks, or a tri-state
    // verdict of a failed lookup). The testable logic — classification and
    // precedence — lives in dkim_key_state + dkim_disposition_from_probes;
    // only the network resolution stays here.
    let mut probes: Vec<DkimSelectorProbe> = Vec::with_capacity(selectors.len());
    for sel in &selectors {
        let fqdn = format!("{}.{}", sel, domain);
        match resolver.txt_lookup(fqdn.as_str()).await {
            Ok(rdata) => {
                let chunks = dkim_txt_chunks(rdata.answers());
                // Raw key bytes BESIDE the seal (R-B): captured per selector so
                // a reader can re-derive WHICH selector published WHICH key.
                for chunk in &chunks {
                    records.push(RecordEntry {
                        control: ControlId::Dkim,
                        value: format!("{sel} => {chunk}"),
                    });
                }
                probes.push(Ok(chunks));
            }
            Err(e) => probes.push(Err(record_absence_verdict(&e, domain))),
        }
    }

    dkim_disposition_from_probes(&probes)
}

/// Collect TXT strings from a resolved DKIM lookup's answer records.
fn dkim_txt_chunks(answers: &[hickory_proto::rr::Record]) -> Vec<String> {
    let mut chunks = Vec::new();
    for rec in answers {
        if let hickory_proto::rr::RData::TXT(txt) = &rec.data {
            for c in &txt.txt_data {
                chunks.push(String::from_utf8_lossy(c).to_string());
            }
        }
    }
    chunks
}

/// A nonexistent selector name resolving to non-empty TXT data is a wildcard
/// `*._domainkey` synthesis — the sweep proves nothing.
fn dkim_wildcard_detected(probe: &DkimSelectorProbe) -> bool {
    matches!(probe, Ok(chunks) if !chunks.is_empty())
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
/// is a zone CONTAINING the host — the host exists within an existing zone and
/// publishes no TLSA); `None` = couldn't measure (transient, or the host's own
/// domain is missing).
///
/// This is the branch `score_dane` skipped when every other control's Err
/// path routed through `record_absence_verdict` — the skip folded measured
/// absence into couldn't-measure, the INVERSE conflation of the original
/// `&[usize]` bug (which folded couldn't-measure into measured absence).
/// Both directions lose the distinction DANE's four-way split exists to hold.
///
/// An MX target is a LEAF name, not a zone cut: `_25._tcp.mail3.cia.gov`
/// NXDOMAIN carries the SOA of the zone that CONTAINS the host (`cia.gov`),
/// not the host's own (nonexistent) zone. So the "did the host's domain
/// vanish" test is SUFFIX containment (`cia.gov` contains `mail3.cia.gov`),
/// not the exact equality `record_absence_verdict` uses for the apex — that
/// exact match was why a subdomain/third-party MX host reported TransientError
/// instead of the measured absence it actually is (Arm 1: cia.gov, google.com).
fn tlsa_err_to_count(e: &NetError, host: &str) -> Option<usize> {
    use hickory_proto::op::ResponseCode;
    use hickory_resolver::net::DnsError;
    let host = host.trim_end_matches('.');
    match e {
        // NODATA on an existing zone: the host exists, no TLSA → measured absence.
        NetError::Dns(DnsError::NoRecordsFound(nr))
            if nr.response_code == ResponseCode::NoError =>
        {
            Some(0)
        }
        // NXDOMAIN: the name `_25._tcp.<host>` does not exist. Measured absence
        // iff the SOA's zone contains the host (suffix); a TLD/root SOA means
        // the host's own domain is missing → couldn't measure.
        NetError::Dns(DnsError::NoRecordsFound(nr))
            if nr.response_code == ResponseCode::NXDomain =>
        {
            match nr.soa.as_ref().map(|s| s.name.to_ascii()) {
                Some(z) if zone_contains_host(host, z.trim_end_matches('.')) => Some(0),
                _ => None,
            }
        }
        // SERVFAIL / timeout / anything else: nothing measured → None.
        _ => None,
    }
}

/// True when `zone` is a zone that CONTAINS `host` — `zone` equals `host`, or
/// is a proper label-boundary suffix of it. A containing zone must itself be a
/// real (>=2-label) zone: `cia.gov` contains `mail3.cia.gov`, but a bare TLD
/// (`com`) is NOT counted as containing `mail.example.com` — that case is the
/// host's whole domain missing, which is couldn't-measure, not measured absence.
fn zone_contains_host(host: &str, zone: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let z = zone.trim_end_matches('.').to_ascii_lowercase();
    z.contains('.') && (h == z || h.ends_with(&format!(".{}", z)))
}

/// Pure: classify the MX host's zone relationship to the scanned domain's zone
/// from the two zone cut (SOA owner) names. The DANE attribution field — a
/// measurement, never an ownership claim (the "provider-gated" verdict was
/// retracted because DNS observes zone cuts, not contracts).
///
/// - `SameZone`       — host apex == domain apex (self-operated mail).
/// - `DescendantZone` — host apex is a strict subdomain of domain apex (still
///   owner-controlled, e.g. `amazon.com` -> `amazon-smtp.amazon.com`).
/// - `ForeignZone`    — host apex is neither (someone else's infra, e.g.
///   `microsoft.com` -> `protection.outlook.com`).
/// - `ZoneUnmeasured` — either apex is `None` (SOA walk failed).
///
/// `None` for either apex means the zone cut couldn't be measured — an honest
/// non-classification, never a guess.
fn classify_tlsa_zone(domain_apex: Option<&str>, host_apex: Option<&str>) -> TlsaZone {
    let (Some(d), Some(h)) = (domain_apex, host_apex) else {
        return TlsaZone::ZoneUnmeasured;
    };
    let d = d.trim_end_matches('.').to_ascii_lowercase();
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    if h == d {
        TlsaZone::SameZone
    } else if h.ends_with(&format!(".{}", d)) {
        TlsaZone::DescendantZone
    } else {
        TlsaZone::ForeignZone
    }
}

/// Pure: the SOA owner name from an answer section. The SOA owner name is, by
/// definition, the zone cut — this is what separates `smtp.google.com` (apex
/// `google.com`) from `mail.example.com` (apex `example.com`) without a PSL
/// table. `None` when no SOA is present in the answers.
fn soa_owner_from_answers(answers: &[hickory_proto::rr::Record]) -> Option<String> {
    answers
        .iter()
        .find(|r| matches!(&r.data, hickory_proto::rr::RData::SOA(_)))
        .map(|r| r.name.to_ascii())
}

/// Pure: the SOA owner name carried in a lookup error's authority section. A
/// leaf name's SOA arrives in `NoRecordsFound` (the containing zone); `None`
/// for a transient error (ServFail/timeout) — couldn't measure the zone, not
/// "no zone".
fn soa_owner_from_error(e: &NetError) -> Option<String> {
    use hickory_resolver::net::DnsError;
    match e {
        NetError::Dns(DnsError::NoRecordsFound(nr)) => nr.soa.as_ref().map(|s| s.name.to_ascii()),
        _ => None,
    }
}

/// Pure: collapse a SOA lookup's Ok/Err into the containing apex name. Extracted
/// from `zone_apex_of` so the Ok/Err dispatch is unit-pinned without a resolver
/// (the async wrapper's only remaining job is the I/O call itself). The three
/// mutation survivors in the old wrapper were the two match-arm return-value
/// delegates; this function makes that delegation a tested decision.
///
/// Precedence: the answer section wins over the error's authority section (a
/// lookup is either Ok or Err, so at most one is populated — but the function is
/// total and `answers` takes priority by construction).
fn apex_from_soa_result(
    answers: Option<&[hickory_proto::rr::Record]>,
    error: Option<&NetError>,
) -> Option<String> {
    match (answers, error) {
        (Some(a), _) => soa_owner_from_answers(a),
        (None, Some(e)) => soa_owner_from_error(e),
        (None, None) => None,
    }
}

/// Derive the zone apex that CONTAINS `name` by asking for the SOA and reading
/// its owner. If `name` is itself the apex the SOA comes back in the answer
/// section; if it is a leaf the SOA arrives in the authority section
/// (`NoRecordsFound` with `soa` populated). `None` when the lookup errored
/// (couldn't measure the zone, not \"no zone\").
async fn zone_apex_of(resolver: &TokioResolver, name: &str) -> Option<String> {
    use hickory_proto::rr::RecordType;
    match resolver.lookup(name, RecordType::SOA).await {
        Ok(resp) => apex_from_soa_result(Some(resp.answers()), None),
        Err(e) => apex_from_soa_result(None, Some(&e)),
    }
}

/// Pure gate: does an MX host's zone DNSSEC state force `DnssecRequired`?
/// Extracted so the host-zone decision is unit-pinned without a mock resolver
/// (the async `score_dane` can't be — same pattern as `dane_from_tlsa_counts`).
/// Fires on `Unsigned` (no DNSKEY) and `NoZone` (zone missing) — both mean
/// "this host's zone cannot carry a trustable TLSA." `SignedAndDelegated`,
/// `SignedNotDelegated` (island — still signed), `BrokenChain`, and
/// `ChainUnverified` pass through to the TLSA loop, which measures the host's
/// own answer. `Unreachable` also passes through (couldn't measure the zone →
/// let the TLSA lookup report its own outcome).
fn dane_host_zone_requires_dnssec(d: DnssecDisposition) -> bool {
    matches!(d, DnssecDisposition::Unsigned | DnssecDisposition::NoZone)
}

async fn score_dane(
    resolver: &TokioResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> (DaneDisposition, TlsaZone) {
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
    //
    // Returns the disposition AND the DANE attribution zone (`tlsa_zone`) — the
    // zone-cut relationship of the MX host to the scanned domain, a sealed
    // primary measurement (see types::TlsaZone). It is orthogonal to the
    // disposition: two domains can both read `NotConfigured` while one hosts
    // its own MX (its gap) and the other points at a third-party operator (the
    // operator's gap).
    use hickory_proto::rr::RecordType;

    match observed_lookup(resolver, ControlId::Dane, domain, RecordType::MX, receipt).await {
        Ok(mx) => {
            let exchanges: Vec<hickory_proto::rr::Name> = mx
                .answers()
                .iter()
                .filter_map(|r| mx_exchange_from_rdata(&r.data).cloned())
                .collect();

            match classify_mx(&exchanges) {
                MxShape::NoMx => (DaneDisposition::NoMx, TlsaZone::NoMxHost),
                MxShape::NoMail => (DaneDisposition::NoMail, TlsaZone::NoMxHost),
                MxShape::Hosts(hosts) => {
                    // ── DANE attribution zone (the tlsa_zone measurement) ──
                    // The zone-cut relationship of the PRIMARY MX host to the
                    // scanned domain. First resolvable host wins (the primary
                    // MX determines the mail architecture).
                    let domain_apex = zone_apex_of(resolver, domain).await;
                    let mut tlsa_zone = TlsaZone::ZoneUnmeasured;
                    for host in &hosts {
                        if let Some(host_apex) = zone_apex_of(resolver, host).await {
                            tlsa_zone =
                                classify_tlsa_zone(domain_apex.as_deref(), Some(&host_apex));
                            break;
                        }
                    }

                    // ── DNSSEC precondition gate (Claude Science 2026-08-21) ──
                    // DANE's TLSA lives in the MX HOST's zone, not the mail
                    // domain's apex. A host in an UNSIGNED zone cannot carry a
                    // trustable TLSA (RFC 7672 requires DNSSEC). Emit
                    // DnssecRequired — a real finding (severity Low, Indet, out
                    // of the denominator) — when ANY MX host's zone is unsigned.
                    // The specimen that separates this from an apex gate is
                    // it-help.tech: apex DS=1 (signed) but MX smtp.google.com
                    // lives in google.com, which is UNSIGNED. An apex gate would
                    // report Absent (a measured failure attributed to the wrong
                    // party); the host-zone gate reports DnssecRequired.
                    for host in &hosts {
                        if let Some(apex) = zone_apex_of(resolver, host).await {
                            // Internal sub-measurement of the MX host's zone —
                            // not the control's primary lookup; no receipt slot.
                            let d = score_dnssec(resolver, &apex, &mut None, &mut Vec::new()).await;
                            if dane_host_zone_requires_dnssec(d) {
                                warn!(
                                    domain,
                                    host = %host,
                                    apex = %apex,
                                    "SMTP DANE host zone unsigned — DnssecRequired"
                                );
                                return (DaneDisposition::DnssecRequired, tlsa_zone);
                            }
                        }
                        // zone_apex_of None = couldn't measure the host zone;
                        // fall through to the TLSA loop, which will report the
                        // host's own lookup outcome honestly.
                    }

                    let mut counts = Vec::with_capacity(hosts.len());
                    for host in &hosts {
                        let tlsa_name = format!("_25._tcp.{host}");
                        match resolver.lookup(tlsa_name.as_str(), RecordType::TLSA).await {
                            Ok(resp) => {
                                // Raw TLSA records — the actual DANE pins, keyed
                                // with the host they belong to. BESIDE the seal
                                // (R-B). hickory's TLSA Display renders the
                                // usage/selector/matching-type + association data.
                                for rec in resp.answers() {
                                    if let hickory_proto::rr::RData::TLSA(tlsa) = &rec.data {
                                        records.push(RecordEntry {
                                            control: ControlId::Dane,
                                            value: format!("{host} => {tlsa}"),
                                        });
                                    }
                                }
                                counts.push(Some(resp.answers().len()))
                            }
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
                    (dane_from_tlsa_counts(&counts), tlsa_zone)
                }
            }
        }
        Err(e) => {
            // NODATA (no MX) -> NoMx; NXDOMAIN (domain missing) -> Indet.
            // record_absence_verdict applies the SOA disambiguation — the same
            // mechanism _dmarc/_mta-sts use, now generalized to the MX lookup.
            warn!(domain, error = %e, "MX lookup error for DANE");
            let disposition = record_absence_to_dane(&e, domain);
            let zone = match disposition {
                DaneDisposition::NoMx => TlsaZone::NoMxHost,
                _ => TlsaZone::ZoneUnmeasured,
            };
            (disposition, zone)
        }
    }
}

async fn score_mta_sts(
    resolver: &TokioResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> MtaStsDisposition {
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
    let has_hint = match observed_txt_lookup(
        resolver,
        ControlId::MtaSts,
        mta_sts_domain.as_str(),
        receipt,
    )
    .await
    {
        Ok(rdata) => {
            // Capture the raw _mta-sts discovery TXT (v=STSv1; id=…) — the
            // hint that a policy MAY be published. BESIDE the seal (R-B).
            let mut hint_present = false;
            for rec in rdata.answers() {
                if let hickory_proto::rr::RData::TXT(txt) = &rec.data {
                    for s in &txt.txt_data {
                        let s = String::from_utf8_lossy(s);
                        if s.starts_with("v=STSv1") {
                            hint_present = true;
                            records.push(RecordEntry {
                                control: ControlId::MtaSts,
                                value: s.to_string(),
                            });
                        }
                    }
                }
            }
            hint_present
        }
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
        Ok(policy) => {
            // The fetched policy text — the actual enforcement content. BESIDE
            // the seal (R-B). A reader can re-derive the mode/mx/max_age the
            // verdict was computed from.
            records.push(RecordEntry {
                control: ControlId::MtaSts,
                value: policy.clone(),
            });
            match mta_sts_policy_state(&policy) {
                MtaStsPolicyState::Enforce => MtaStsDisposition::Enforced,
                // Valid policy, mode testing/none — deployed, not enforcing (§8).
                MtaStsPolicyState::TestingOrNone => MtaStsDisposition::NotEnforced,
                // Fetched bytes that are not a valid policy: the old code lumped
                // this into NotEnforced, reporting "published (mode testing/none)"
                // for garbage — a mode that was never measured.
                MtaStsPolicyState::Invalid => MtaStsDisposition::PolicyInvalid,
            }
        }
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

/// Pure CAA value-grading: does any CAA record publish `issue ";"` — the
/// "no CA may issue ANY certificate" signal (RFC 8659 §4.2)? Detected by
/// tag == "issue" (case-insensitive) and the raw value being exactly the
/// no-issuer sentinel `;` (hickory encodes an absent issuer name as a lone
/// semicolon). This is the strongest CAA state — it wins over every other
/// grading (a domain that forbids all issuance cannot be "restricted to a
/// list"). Extracted pure so the detection is regression-pinned without
/// network.
fn caa_fully_restricted(records: &[hickory_proto::rr::Record]) -> bool {
    records.iter().any(|rec| {
        if let hickory_proto::rr::RData::CAA(caa) = &rec.data {
            caa.tag.eq_ignore_ascii_case("issue") && caa.value == b";"
        } else {
            false
        }
    })
}

/// Pure CAA value-grading: does any CAA record publish `issuewild ";"` — the
/// "no CA may issue a wildcard certificate" signal (RFC 8659 §4.3)? Detected
/// by tag == "issuewild" (case-insensitive) and the raw value being exactly the
/// no-issuer sentinel `;` (hickory encodes an absent issuer name as a lone
/// semicolon). Extracted pure so the detection is regression-pinned without
/// network.
fn caa_wildcard_fully_restricted(records: &[hickory_proto::rr::Record]) -> bool {
    records.iter().any(|rec| {
        if let hickory_proto::rr::RData::CAA(caa) = &rec.data {
            caa.tag.eq_ignore_ascii_case("issuewild") && caa.value == b";"
        } else {
            false
        }
    })
}

/// Pure CDS/CDNSKEY value-grading: does any record carry the null (delete)
/// signal? hickory models RFC 8078 §4's delete algorithm as `algorithm: None` —
/// a CDS/CDNSKEY with no algorithm field means "remove the DS RRset", not a
/// normal rollover hint. Extracted pure so the deletion detection is
/// regression-pinned without network.
fn cds_deletion_requested(records: &[hickory_proto::rr::Record]) -> bool {
    use hickory_proto::dnssec::rdata::DNSSECRData;
    records.iter().any(|rec| {
        if let hickory_proto::rr::RData::DNSSEC(dnssec) = &rec.data {
            match dnssec {
                DNSSECRData::CDS(cds) => cds.algorithm().is_none(),
                DNSSECRData::CDNSKEY(cdnskey) => cdnskey.algorithm().is_none(),
                _ => false,
            }
        } else {
            false
        }
    })
}

async fn score_caa(
    resolver: &TokioResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> CaaDisposition {
    // CAA record lookup.
    // RecordType::CAA = 257, confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // A CAA record constrains which CAs may issue certificates for this domain.
    // Absent = no CAA policy (any CA can issue) — informatively absent, not a failure.
    use hickory_proto::rr::RecordType;

    match observed_lookup(resolver, ControlId::Caa, domain, RecordType::CAA, receipt).await {
        Ok(resp) => {
            if answers_present(resp.answers()) {
                // Raw CAA presentation strings BESIDE the seal (R-B) — captured
                // via the RData's own Display (`{flags} {tag} "{value}"`).
                for rec in resp.answers() {
                    if let hickory_proto::rr::RData::CAA(caa) = &rec.data {
                        records.push(RecordEntry {
                            control: ControlId::Caa,
                            value: caa.to_string(),
                        });
                    }
                }
                if caa_fully_restricted(resp.answers()) {
                    CaaDisposition::FullyRestricted // issue ";" — no CA at all
                } else if caa_wildcard_fully_restricted(resp.answers()) {
                    CaaDisposition::WildcardFullyRestricted
                } else {
                    CaaDisposition::Configured
                }
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

async fn score_cds_cdnskey(
    resolver: &TokioResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> CdsDisposition {
    // CDS (type 59) and CDNSKEY (type 60) are published at the child zone apex
    // as a standing declaration that the parent may maintain the DS from them
    // (RFC 7344; RFC 8078 §2.1). NOT a rollover-in-progress signal: both
    // resting states are RFC-sanctioned (publish-at-rest AND remove-after-sync,
    // 7344 §4.1/§5), and absence never means "no rollover" — that misread is
    // the banned frame (see the truth_chain pin + docs/DNS-LESSON-cds-*).
    // Both types confirmed present in hickory 0.26 (hickory_rr_types.md).
    //
    // Semantics:
    //   Present  — at least one CDS or CDNSKEY record exists (declaration published)
    //   Absent   — neither record type has any records (no declaration published)
    //   Indet    — lookup error other than NXDOMAIN/NOERROR-NODATA
    //
    // We check CDS first; if present we return immediately.
    // Otherwise we fall through to CDNSKEY as the authoritative answer.
    use hickory_proto::rr::RecordType;

    // ── CDS (type 59) ────────────────────────────────────────────────────────
    let cds_absent =
        match observed_lookup(resolver, ControlId::Cds, domain, RecordType::CDS, receipt).await {
            Ok(resp) => {
                if answers_present(resp.answers()) {
                    // Raw CDS material — the DS the parent is asked to publish.
                    // BESIDE the seal (R-B), via hickory's CDS Display (key-tag/
                    // algorithm/digest-type/digest).
                    use hickory_proto::dnssec::rdata::DNSSECRData;
                    for rec in resp.answers() {
                        if let hickory_proto::rr::RData::DNSSEC(DNSSECRData::CDS(cds)) = &rec.data {
                            records.push(RecordEntry {
                                control: ControlId::Cds,
                                value: format!("CDS {cds}"),
                            });
                        }
                    }
                    return if cds_deletion_requested(resp.answers()) {
                        CdsDisposition::DeletionRequested // null CDS — DS removal (RFC 8078 §4)
                    } else {
                        CdsDisposition::Published // CDS record found
                    };
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
                // Raw CDNSKEY material, BESIDE the seal (R-B).
                use hickory_proto::dnssec::rdata::DNSSECRData;
                for rec in resp.answers() {
                    if let hickory_proto::rr::RData::DNSSEC(DNSSECRData::CDNSKEY(cdnskey)) =
                        &rec.data
                    {
                        records.push(RecordEntry {
                            control: ControlId::Cds,
                            value: format!("CDNSKEY {cdnskey}"),
                        });
                    }
                }
                if cds_deletion_requested(resp.answers()) {
                    CdsDisposition::DeletionRequested // null CDNSKEY — DS removal
                } else {
                    CdsDisposition::Published
                }
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
    // Arm 2 — RFC known-answer vectors (offline, the RFC is the oracle)
    //
    // These are the constructed-input half of the known-answer corpus: each
    // asserts the engine's PURE disposition function agrees with what the RFC
    // mandates. No network, fully deterministic. The citations were verified
    // against current RFC text on 2026-08-21 — including two corrections the
    // draft table carried (DANE DNSSEC requirement is §1.3.2 not §4; CDS/CDNSKEY
    // is Informational not Standards Track). See
    // docs/arm2-rfc-known-answer-vectors.md for the prose table + citation log.
    // -------------------------------------------------------------------------
    #[test]
    fn rfc_known_answer_vectors() {
        use hickory_proto::dnssec::Proof;

        // --- DNSSEC (RFC 4035 §4.3) ---
        assert_eq!(
            dnssec_disposition_from_answer(true, Some(Proof::Secure)),
            DnssecDisposition::SignedAndDelegated,
            "D1: signed + DS at parent validates"
        );
        assert_eq!(
            dnssec_disposition_from_answer(true, Some(Proof::Insecure)),
            DnssecDisposition::SignedNotDelegated,
            "D2: DNSKEY present, no DS = island"
        );
        assert_eq!(
            dnssec_disposition_from_answer(false, None),
            DnssecDisposition::Unsigned,
            "D3: no DNSKEY = unsigned"
        );
        assert_eq!(
            dnssec_disposition_from_answer(true, Some(Proof::Bogus)),
            DnssecDisposition::BrokenChain,
            "D4: validation fails = bogus/broken"
        );

        // --- SPF (RFC 7208 §4.6.2 qualifiers, §4.5 none-result; null MX RFC 7505 §3) ---
        assert_eq!(
            spf_disposition_from_records(&["v=spf1 include:_spf.google.com -all".to_string()]),
            SpfDisposition::HardFail,
            "S1: -all = hard fail"
        );
        assert_eq!(
            spf_disposition_from_records(&["v=spf1 include:_spf.google.com ~all".to_string()]),
            SpfDisposition::SoftFail,
            "S2: ~all = soft fail (advisory)"
        );
        assert_eq!(
            spf_disposition_from_records(&["v=spf1 +all".to_string()]),
            SpfDisposition::PositiveAll,
            "G5: +all = permissive, never misread as enforced"
        );
        assert_eq!(
            spf_disposition_from_records(&[]),
            SpfDisposition::NotConfigured,
            "S3: no SPF TXT"
        );
        assert_eq!(
            classify_mx(&[hickory_proto::rr::Name::root()]),
            MxShape::NoMail,
            "S4: null MX (MX 0 .) = no-mail"
        );

        // --- DKIM (RFC 6376 §3.6.1) ---
        assert_eq!(
            dkim_key_state(&["v=DKIM1; p=".to_string()]),
            DkimKeyState::Revoked,
            "K1: empty p= = revoked"
        );
        assert_eq!(
            dkim_key_state(&["v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ".to_string()]),
            DkimKeyState::Valid,
            "K3: valid key"
        );

        // --- DMARC (RFC 9989 §4.7) ---
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=reject"),
            DmarcDisposition::Reject,
            "M1: p=reject"
        );
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=none"),
            DmarcDisposition::Monitor,
            "M2: p=none = monitor"
        );
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=quarantine"),
            DmarcDisposition::Quarantine,
            "G1: p=quarantine = intermediate enforcement"
        );
        assert_eq!(
            dmarc_disposition_from_record("v=DMARC1; p=bogus"),
            DmarcDisposition::InvalidPolicy,
            "M3: unrecognized p= = invalid policy, never a policy"
        );

        // --- DANE (RFC 7672 §1.3.2; null MX RFC 7505 §3) ---
        assert!(
            dane_host_zone_requires_dnssec(DnssecDisposition::Unsigned),
            "A1: unsigned MX host zone => DnssecRequired"
        );
        assert!(
            !dane_host_zone_requires_dnssec(DnssecDisposition::SignedAndDelegated),
            "A3: signed host zone passes the gate"
        );
        assert_eq!(
            dane_from_tlsa_counts(&[Some(1)]),
            DaneDisposition::TlsaPublished,
            "A3: signed + TLSA = published"
        );
        assert_eq!(
            dane_from_tlsa_counts(&[Some(0)]),
            DaneDisposition::NotConfigured,
            "A4: signed + no TLSA = not configured (measured absence)"
        );
        assert_eq!(
            dane_from_tlsa_counts(&[None]),
            DaneDisposition::TransientError,
            "A-nasa: SERVFAIL on a signed host zone = transient, not swallowed"
        );

        // --- MTA-STS (RFC 8461 §3.2 field enumeration; §5 mode semantics) ---
        // G3: enforce-vs-testing is ALREADY distinguished — the pure policy
        // classifier mta_sts_policy_state splits Enforce vs TestingOrNone, and
        // the report maps them to severity Ok vs Medium. SciSpace's G3 called
        // this a code-gap; it is a doc-gap (the distinction shipped, never
        // asserted). These two assertions pin it + a negative control.
        assert_eq!(
            mta_sts_policy_state("version: STSv1\nmode: enforce\nmx: mail.example.com"),
            MtaStsPolicyState::Enforce,
            "G3: mode=enforce => Enforce (severity Ok)"
        );
        assert_eq!(
            mta_sts_policy_state("version: STSv1\nmode: testing\nmx: mail.example.com"),
            MtaStsPolicyState::TestingOrNone,
            "G3: mode=testing => TestingOrNone (deployed, not enforcing)"
        );
        assert_eq!(
            mta_sts_policy_state("version: STSv1\nmode: none\nmx: mail.example.com"),
            MtaStsPolicyState::TestingOrNone,
            "G3-none: mode=none => TestingOrNone (RFC 8461 §5: no active policy)"
        );
        assert_eq!(
            mta_sts_policy_state("version: STSv1\nmode: enforce"),
            MtaStsPolicyState::Invalid,
            "G3-negative: no mx= line is invalid, never read as a mode"
        );

        // --- CAA (RFC 8659 §3, §4.2, §4.3) ---
        // Value-grading now ships: `issue ";"` (RFC 8659 §4.2) is a distinct
        // FullyRestricted state — ALL issuance prohibited — and `issuewild ";"`
        // (RFC 8659 §4.3) is WildcardFullyRestricted. Neither collapses into
        // presence-only Configured.
        {
            use hickory_proto::rr::rdata::CAA;
            use hickory_proto::rr::{RData, Record};
            // Ruling A — issue ";" (RFC 8659 §4.2): no CA may issue ANY cert.
            let fully_restricted = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::CAA(CAA::new_issue(false, None, vec![])),
            );
            assert!(
                caa_fully_restricted(&[fully_restricted]),
                "Ruling A: issue ';' = no CA may issue any cert (FullyRestricted)"
            );
            let named_issue = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::CAA(CAA::new_issue(
                    false,
                    Some(mx_name("ca.example.net.")),
                    vec![],
                )),
            );
            assert!(
                !caa_fully_restricted(&[named_issue]),
                "Ruling A-negative: issue with a named CA is not fully restricted"
            );
            let wildcard_restricted = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::CAA(CAA::new_issuewild(false, None, vec![])),
            );
            assert!(
                caa_wildcard_fully_restricted(std::slice::from_ref(&wildcard_restricted)),
                "G4: issuewild ';' = wildcard fully restricted"
            );
            assert!(
                !caa_fully_restricted(std::slice::from_ref(&wildcard_restricted)),
                "Ruling A-vs-G4: issuewild ';' is NOT issue ';' (different tags)"
            );
            let named_wildcard = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::CAA(CAA::new_issuewild(
                    false,
                    Some(mx_name("ca.example.net.")),
                    vec![],
                )),
            );
            assert!(
                !caa_wildcard_fully_restricted(&[named_wildcard]),
                "G4-negative: issuewild with a named CA is not fully restricted"
            );
            let normal_issue = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::CAA(CAA::new_issue(
                    false,
                    Some(mx_name("ca.example.net.")),
                    vec![],
                )),
            );
            assert!(
                !caa_wildcard_fully_restricted(&[normal_issue]),
                "G4-negative: a plain issue record is not issuewild"
            );
        }

        // --- CDS/CDNSKEY (RFC 7344 §4.1/§5/§6.2; null CDS = RFC 8078 §4) ---
        // Value-grading ships: the null CDS/CDNSKEY (algorithm 0) is a distinct
        // DeletionRequested state — the operator requests DS removal — NOT
        // collapsed into presence-only Published.
        {
            use hickory_proto::dnssec::rdata::{DNSSECRData, CDNSKEY, CDS};
            use hickory_proto::dnssec::{Algorithm, DigestType};
            use hickory_proto::rr::{RData, Record};
            let null_cds = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::DNSSEC(DNSSECRData::CDS(CDS::new(
                    0,
                    None,
                    DigestType::SHA256,
                    vec![],
                ))),
            );
            assert!(
                cds_deletion_requested(&[null_cds]),
                "G2: null CDS (algorithm 0) = DS deletion requested (RFC 8078 §4)"
            );
            let normal_cds = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::DNSSEC(DNSSECRData::CDS(CDS::new(
                    2371,
                    Some(Algorithm::ECDSAP256SHA256),
                    DigestType::SHA256,
                    vec![0xAB, 0xCD],
                ))),
            );
            assert!(
                !cds_deletion_requested(&[normal_cds]),
                "G2-negative: a normal CDS is not a deletion request"
            );
            let null_cdnskey = Record::from_rdata(
                mx_name("example.com."),
                300,
                RData::DNSSEC(DNSSECRData::CDNSKEY(CDNSKEY::new(
                    false,
                    false,
                    false,
                    None,
                    vec![],
                ))),
            );
            assert!(
                cds_deletion_requested(&[null_cdnskey]),
                "G2-cdnskey: null CDNSKEY (algorithm 0) = DS deletion requested"
            );
        }
    }

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
        assert_eq!(tlsa_err_to_count(&servfail_err(), "mail.example.com"), None);
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
    fn tlsa_err_nxdomain_containing_zone_is_measured_absence() {
        // NXDOMAIN whose SOA is the zone CONTAINING the host (mail3.cia.gov →
        // SOA cia.gov): the host is a leaf name inside an existing zone, no TLSA
        // → measured absence. This is the Arm-1 cia.gov/google.com bug — the old
        // exact-equality match read a containing-zone SOA as "host missing".
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(tlsa_err_to_count(&e, "mail.example.com."), Some(0));
    }

    #[test]
    fn tlsa_err_nxdomain_tld_zone_is_unmeasured() {
        // NXDOMAIN whose SOA is a bare TLD (the host's whole domain is missing):
        // couldn't measure, NOT measured absence. The >=2-label requirement in
        // zone_contains_host excludes a bare TLD from "containing" the host.
        let e = nxdomain_err_with_soa("com.");
        assert_eq!(tlsa_err_to_count(&e, "mail.example.com."), None);
    }

    #[test]
    fn zone_contains_host_suffix_matching() {
        // The three shapes the fix distinguishes: own zone, containing zone
        // (subdomain MX host), and third-party MX host — all measured absence;
        // a bare TLD is never a containing zone.
        assert!(zone_contains_host("mail.example.com", "example.com"));
        assert!(zone_contains_host("mail3.cia.gov", "cia.gov"));
        assert!(zone_contains_host("aspmx.l.google.com", "l.google.com"));
        assert!(zone_contains_host("example.com", "example.com"));
        assert!(!zone_contains_host("mail.example.com", "com"));
        assert!(!zone_contains_host("example.com", "com"));
    }

    // --- the DANE attribution zone classifier (tlsa_zone) --------------------
    // The zone-cut relationship is the observable proxy for "whose MX host is
    // this" — never an ownership claim. Pinned against the measured fixtures
    // (Science's retracted google.com case is deliberately ABSENT).

    #[test]
    fn classify_tlsa_zone_measured_fixtures() {
        use super::TlsaZone;
        // google.com -> smtp.google.com (host apex == domain apex) — same zone.
        assert_eq!(
            classify_tlsa_zone(Some("google.com"), Some("google.com")),
            TlsaZone::SameZone
        );
        // amazon.com -> amazon-smtp.amazon.com — host zone is a subdomain.
        assert_eq!(
            classify_tlsa_zone(Some("amazon.com"), Some("amazon-smtp.amazon.com")),
            TlsaZone::DescendantZone
        );
        // apple.com -> g.apple.com — a DIFFERENT descendant topology: the apex
        // is a delegated intermediate zone (g.apple.com), not the MX host name
        // itself. The amazon case's apex IS the host name; this one isn't, so
        // the descendant branch is pinned by two distinct shapes.
        assert_eq!(
            classify_tlsa_zone(Some("apple.com"), Some("g.apple.com")),
            TlsaZone::DescendantZone
        );
        // outlook.com -> olc.protection.outlook.com — third-party-looking but
        // actually the operator's own delegated zone (same family as microsoft).
        assert_eq!(
            classify_tlsa_zone(Some("outlook.com"), Some("olc.protection.outlook.com")),
            TlsaZone::DescendantZone
        );
        // microsoft.com -> protection.outlook.com — foreign zone.
        assert_eq!(
            classify_tlsa_zone(Some("microsoft.com"), Some("protection.outlook.com")),
            TlsaZone::ForeignZone
        );
        // dhs.gov -> gpphosted.com (Proofpoint) — foreign, the discriminating pair.
        assert_eq!(
            classify_tlsa_zone(Some("dhs.gov"), Some("gpphosted.com")),
            TlsaZone::ForeignZone
        );
        // cia.gov (self-hosted) -> cia.gov — same zone.
        assert_eq!(
            classify_tlsa_zone(Some("cia.gov"), Some("cia.gov")),
            TlsaZone::SameZone
        );
    }

    #[test]
    fn classify_tlsa_zone_trailing_dot_and_case_insensitive() {
        use super::TlsaZone;
        // zone_apex_of returns `to_ascii()` names with a trailing dot; the
        // classifier must trim + lowercase before comparing.
        assert_eq!(
            classify_tlsa_zone(Some("Amazon.COM."), Some("amazon-smtp.amazon.com.")),
            TlsaZone::DescendantZone
        );
    }

    #[test]
    fn classify_tlsa_zone_label_boundary_negative() {
        use super::TlsaZone;
        // The `.` prefix in the `.{d}` suffix form is load-bearing: a bare
        // `ends_with(d)` would classify `notamazon.com` as a DESCENDANT of
        // `amazon.com`. This negative test pins the label boundary — the same
        // un-normalized-input discipline as the trailing-dot trim, because
        // cargo-mutants cannot see a dropped character in a format string.
        assert_eq!(
            classify_tlsa_zone(Some("amazon.com"), Some("notamazon.com")),
            TlsaZone::ForeignZone
        );
        // The same boundary on the suffix side: a host that merely shares a
        // string tail is foreign, not a descendant.
        assert_eq!(
            classify_tlsa_zone(Some("apple.com"), Some("pineapple.com")),
            TlsaZone::ForeignZone
        );
    }

    #[test]
    fn classify_tlsa_zone_unmeasured_when_either_apex_missing() {
        use super::TlsaZone;
        assert_eq!(
            classify_tlsa_zone(None, Some("example.com")),
            TlsaZone::ZoneUnmeasured
        );
        assert_eq!(
            classify_tlsa_zone(Some("example.com"), None),
            TlsaZone::ZoneUnmeasured
        );
        assert_eq!(classify_tlsa_zone(None, None), TlsaZone::ZoneUnmeasured);
    }

    // --- the DANE host-zone DNSSEC gate (Claude Science 2026-08-21) -----------
    // DnssecRequired was declared-and-never-emitted. The gate fires when an MX
    // HOST's zone is unsigned — not the mail domain's apex. The discriminating
    // specimen is it-help.tech (apex signed, MX smtp.google.com in UNSIGNED
    // google.com): an apex gate reports Absent, the host gate reports
    // DnssecRequired. Pinned as a pure predicate — one assertion per source.

    #[test]
    fn dane_host_zone_unsigned_requires_dnssec() {
        assert!(dane_host_zone_requires_dnssec(DnssecDisposition::Unsigned));
        assert!(dane_host_zone_requires_dnssec(DnssecDisposition::NoZone));
    }

    #[test]
    fn dane_host_zone_signed_passes_gate() {
        // Signed (delegated OR island — still signs its records) and the other
        // states must NOT fire the gate; they fall through to the TLSA loop.
        // One-contributor rule: each pass-through is its own assertion so a
        // gate-that-always-fires cannot survive by one arm doing the work.
        assert!(!dane_host_zone_requires_dnssec(
            DnssecDisposition::SignedAndDelegated
        ));
        assert!(!dane_host_zone_requires_dnssec(
            DnssecDisposition::SignedNotDelegated
        ));
        assert!(!dane_host_zone_requires_dnssec(
            DnssecDisposition::BrokenChain
        ));
        assert!(!dane_host_zone_requires_dnssec(
            DnssecDisposition::ChainUnverified
        ));
        assert!(!dane_host_zone_requires_dnssec(
            DnssecDisposition::Unreachable
        ));
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

    // --- dkim_txt_chunks: the pure DKIM TXT-collection core -------------------
    // Three survivors were in dkim_txt_chunks (the DKIM key's p= may span
    // multiple TXT strings, RFC 6376 §3.6.1). The function was pure but had no
    // direct test — score_dkim (its only caller) is async and untested, so its
    // return-value mutants survived. These two pin it: every chunk collected,
    // and non-TXT records ignored.

    #[test]
    fn dkim_txt_chunks_collects_every_txt_string() {
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{RData, Record};
        let txt = RData::TXT(TXT::new(vec![
            "v=DKIM1; p=".to_string(),
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ".to_string(),
        ]));
        let rec = Record::from_rdata(mx_name("sel._domainkey.example.com."), 300, txt);
        assert_eq!(
            dkim_txt_chunks(&[rec]),
            vec![
                "v=DKIM1; p=".to_string(),
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ".to_string(),
            ]
        );
    }

    #[test]
    fn dkim_txt_chunks_ignores_non_txt_records() {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};
        use std::net::Ipv4Addr;
        let a = Record::from_rdata(
            mx_name("example.com."),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        assert!(dkim_txt_chunks(&[a]).is_empty());
    }

    // --- soa_owner_from_answers / soa_owner_from_error -----------------------
    // The pure core extracted from zone_apex_of (the async DnssecRequired
    // helper). Three return-value survivors in zone_apex_of were the
    // observe_flux shape — a network wrapper whose pure core had no test.
    // Extracted; these four pin both directions of both cores.

    #[test]
    fn soa_owner_from_answers_reads_the_apex_name() {
        use hickory_proto::rr::rdata::SOA;
        use hickory_proto::rr::{Name, RData, Record};
        let soa = SOA::new(
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            3600,
            600,
            86400,
            3600,
        );
        let rec = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            3600,
            RData::SOA(soa),
        );
        assert_eq!(
            soa_owner_from_answers(&[rec]),
            Some("example.com.".to_string())
        );
    }

    #[test]
    fn soa_owner_from_answers_is_none_without_soa() {
        // A non-SOA answer (an A record) carries no apex.
        assert_eq!(soa_owner_from_answers(&[one_record()]), None);
    }

    #[test]
    fn soa_owner_from_error_reads_the_containing_zone() {
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(soa_owner_from_error(&e), Some("example.com.".to_string()));
    }

    #[test]
    fn soa_owner_from_error_is_none_on_transient() {
        assert_eq!(soa_owner_from_error(&servfail_err()), None);
    }

    // --- apex_from_soa_result: the Ok/Err dispatch (zone_apex_of's 3 survivors) ---
    // The three return-value delegates in the old zone_apex_of were the two
    // match-arm bodies and their collapse. Extracted into this pure dispatcher;
    // one assertion per arm, per the method rule.

    #[test]
    fn apex_result_delegates_answers_to_soa_owner() {
        use hickory_proto::rr::rdata::SOA;
        use hickory_proto::rr::{Name, RData, Record};
        let soa = SOA::new(
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            3600,
            600,
            86400,
            3600,
        );
        let rec = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            3600,
            RData::SOA(soa),
        );
        assert_eq!(
            apex_from_soa_result(Some(&[rec]), None),
            Some("example.com.".to_string())
        );
    }

    #[test]
    fn apex_result_delegates_error_to_soa_owner() {
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(
            apex_from_soa_result(None, Some(&e)),
            Some("example.com.".to_string())
        );
    }

    #[test]
    fn apex_result_prefers_answers_over_error() {
        // The (Some(a), _) arm wins over the (None, Some(e)) arm: empty answers
        // => None, even though the error carries a populated SOA. Pins the
        // `_` in the answers arm (the precedence, not just the happy path).
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(apex_from_soa_result(Some(&[]), Some(&e)), None);
    }

    #[test]
    fn apex_result_is_none_on_no_answers_and_no_error() {
        // Totality: the (None, None) arm. Unreachable from a real Result (lookup
        // is Ok or Err), but the function must be total.
        assert_eq!(apex_from_soa_result(None, None), None);
    }

    // --- tlsa_err_to_count: the NXDomain guard must not read transient as ---
    // measured absence. The guard `response_code == NXDomain` is what keeps a
    // non-NXDOMAIN NoRecordsFound from being promoted to Some(0) ("no TLSA").
    // A ServFail that happens to carry an SOA must still be None — the guard,
    // not the SOA, decides.

    #[test]
    fn tlsa_err_to_count_non_nxdomain_with_soa_is_unmeasured() {
        use hickory_proto::op::{Query, ResponseCode};
        use hickory_proto::rr::{rdata::SOA, Name, Record, RecordType};
        use hickory_resolver::net::{DnsError, NoRecords};
        let q = Query::query(
            Name::from_ascii("_25._tcp.mail3.example.com.").unwrap(),
            RecordType::TLSA,
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
        let rec: Record<SOA> =
            Record::from_rdata(Name::from_ascii("example.com.").unwrap(), 3600, soa);
        let mut nr = NoRecords::new(Box::new(q), ResponseCode::ServFail);
        nr.soa = Some(Box::new(rec));
        let e = NetError::Dns(DnsError::NoRecordsFound(nr));
        // ServFail with a containing SOA is a transient failure, NOT a measured
        // "no TLSA" — the NXDomain guard is what enforces this.
        assert_eq!(tlsa_err_to_count(&e, "mail3.example.com"), None);
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
            TriState::Absent
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
        // Revoked key beats a valid key (an empty p= is a withdrawal, not a
        // misconfiguration — Revoked, not KeyMismatch).
        assert_eq!(
            dkim_disposition_from_counts(1, 1, 0, 0),
            DkimDisposition::Revoked
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

    /// dkim_wildcard_detected: only a non-empty TXT synthesis on a sentinel
    /// name is a wildcard; an empty answer or a failed lookup is not.
    #[test]
    fn dkim_wildcard_detected_classifies() {
        assert!(dkim_wildcard_detected(&Ok(vec!["v=DKIM1; p=".to_string()])));
        assert!(!dkim_wildcard_detected(&Ok(vec![])));
        assert!(!dkim_wildcard_detected(&Err(TriState::Absent)));
        assert!(!dkim_wildcard_detected(&Err(TriState::Indet)));
    }

    /// Revoked and Wildcard collapse to the tri-state the ruling fixed:
    /// Revoked→Absent (no signature verifies), Wildcard→Indet (unmeasured).
    #[test]
    fn dkim_revoked_and_wildcard_collapse() {
        assert_eq!(DkimDisposition::Revoked.chain(), TriState::Absent);
        assert_eq!(DkimDisposition::Wildcard.chain(), TriState::Indet);
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
        // A revoked key beats a valid key (Revoked, not KeyMismatch).
        let probes2 = vec![
            Ok(vec!["v=DKIM1; p=".to_string()]),     // Revoked
            Ok(vec!["v=DKIM1; p=MIGf".to_string()]), // Valid
        ];
        assert_eq!(
            dkim_disposition_from_probes(&probes2),
            DkimDisposition::Revoked
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
        assert_eq!(
            mta_sts_policy_state(testing),
            MtaStsPolicyState::TestingOrNone
        );
        let none = "version: STSv1\nmode: none\nmx: smtp.example.com\n";
        assert_eq!(mta_sts_policy_state(none), MtaStsPolicyState::TestingOrNone);
        let enforce = "version: STSv1\nmode: enforce\nmx: smtp.example.com\n";
        assert_eq!(mta_sts_policy_state(enforce), MtaStsPolicyState::Enforce);
        // Contrast: garbage is Invalid, not TestingOrNone — the arm must not
        // absorb it either direction.
        assert_eq!(
            mta_sts_policy_state("hello world"),
            MtaStsPolicyState::Invalid
        );
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
        // The 2026-08-19 panel case: ?all / bare redirect MUST read
        // OtherPolicy; +all MUST read PositiveAll (its own variant, split out
        // per the 2026-08-24 ruling) — the old fallback fabricated HardFail.
        assert_eq!(
            spf_disposition_from_records(&rec("v=spf1 mx ?all")),
            SpfDisposition::OtherPolicy
        );
        assert_eq!(
            spf_disposition_from_records(&rec("v=spf1 +all")),
            SpfDisposition::PositiveAll
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
