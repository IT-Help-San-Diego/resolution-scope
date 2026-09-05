// analysis.rs — DNS control scoring
//
// Each public function in this module runs OUTSIDE the seL4 compartment.
// Results are packed into ScoredAnalysis and sent over the IPC endpoint.

use crate::egress::{FetchEntry, FetchOutcome, ScopeResolver};
use crate::resolver::Vantage;
use anyhow::Result;
use hickory_resolver::net::NetError;
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
    CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
    DmarcDisposition, DnssecDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition,
    TlsRptDisposition, TlsaZone,
};

// =============================================================================
// analyse_domain — top-level entry point
// =============================================================================

/// Analyse a domain with the default probe set (no caller-supplied DKIM
/// selectors). Thin wrapper over [`analyse_domain_with_selectors`].
///
/// The sealed `resolver_identity` comes from the vantage's choice and from
/// nowhere else: no entry point takes a label (Science,
/// two-gaps-closed-and-the-vantage-collision.md — this function once sealed
/// the literal "default" for the vantage the CLI sealed as "cloudflare").
pub async fn analyse_domain(v: &Vantage, domain: &str) -> Result<ScoredAnalysis> {
    analyse_domain_with_selectors(v, domain, &[]).await
}

/// Analyse a domain, probing the caller-supplied DKIM selectors in addition
/// to (and ahead of) the 81 defaults. A user who knows their selector gets a
/// definitive `Verified` / `KeyMismatch` instead of the sweep's
/// "absence NOT proven".
pub async fn analyse_domain_with_selectors(
    v: &Vantage,
    domain: &str,
    dkim_selectors: &[String],
) -> Result<ScoredAnalysis> {
    Ok(analyse_domain_with_receipts(v, domain, dkim_selectors)
        .await?
        .0)
}

/// Analyse a domain AND return the per-control lookup receipts captured at
/// each control's primary lookup site (Layer-4 capture, SPEC §5 step 1).
/// Receipts are beside-the-seal provenance (R-B): the ScoredAnalysis and its
/// seal are byte-identical whether or not the caller keeps the receipts.
///
/// `resolver_identity` is `v.identity()` — a pure function of the resolver
/// choice (destination + transport), never of the code path.
pub async fn analyse_domain_with_receipts(
    v: &Vantage,
    domain: &str,
    dkim_selectors: &[String],
) -> Result<(ScoredAnalysis, Vec<LookupReceipt>, Vec<RecordEntry>)> {
    let resolver: &ScopeResolver = v;
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
    let mta_sts_disposition = score_mta_sts(v, domain, &mut r_mta_sts, &mut records).await;
    let mta_sts = mta_sts_disposition.chain();
    let caa_disposition = score_caa(resolver, domain, &mut r_caa, &mut records).await;
    let caa = caa_disposition.chain();
    let cds_disposition = score_cds_cdnskey(resolver, domain, &mut r_cds, &mut records).await;
    let cds_cdnskey = cds_disposition.chain();

    let mut r_tls_rpt = None;
    let tls_rpt_disposition = score_tls_rpt(resolver, domain, &mut r_tls_rpt).await;
    let tls_rpt = tls_rpt_disposition.chain();
    let mut r_csync = None;
    let csync_disposition = score_csync(resolver, domain, dnssec_disposition, &mut r_csync).await;
    let csync = csync_disposition.chain();

    // ControlId declaration order — one receipt per control that yielded one
    // (a transport error outside the vocabulary yields none, loudly logged).
    let receipts: Vec<LookupReceipt> = [
        r_dnssec, r_spf, r_dkim, r_dmarc, r_dane, r_mta_sts, r_caa, r_cds, r_tls_rpt, r_csync,
    ]
    .into_iter()
    .flatten()
    .collect();

    let analysis = ScoredAnalysis {
        domain: domain.to_string(),
        session_id,
        timestamp_local,
        resolver_identity: v.identity(),
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
        tls_rpt,
        tls_rpt_disposition,
        csync,
        csync_disposition,
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
        // A bare rcode with no records. MEASURED against a loopback stub
        // (2026-09-05): hickory delivers SERVFAIL as
        // `Dns(ResponseCode(ServFail))` and REFUSED as
        // `Dns(ResponseCode(Refused))` — a DIFFERENT variant from the
        // `NoRecordsFound` arm above, whose `response_code` is only ever
        // NoError or NXDomain. Without this arm both fell to `_ => None`, so
        // `ReceiptRcode::ServFail` and `ReceiptRcode::Refused` were written,
        // mapped by `receipt_rcode_token`, and STRUCTURALLY UNREACHABLE: a
        // scan whose every lookup was REFUSED produced ZERO receipts out of
        // the ten `ControlId::ALL` expects. On an instrument whose receipts
        // ARE the provenance, two entire failure classes left no evidence.
        //
        // `DenialProof::None` is correct here rather than lazy: this shape
        // carries no authority section to extract a denial from, which is
        // exactly what distinguishes it from the NoRecordsFound arm.
        NetError::Dns(DnsError::ResponseCode(rc)) => match receipt_rcode_token(*rc) {
            Some(rcode) => Some(LookupReceipt {
                control,
                rcode,
                answer_count: 0,
                denial_proof: DenialProof::None,
                elapsed_ms,
            }),
            None => {
                warn!(
                    control = ?control,
                    rcode = ?rc,
                    "rcode outside receipt vocabulary — no receipt row"
                );
                None
            }
        },
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
    resolver: &ScopeResolver,
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
    resolver: &ScopeResolver,
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
    resolver: &ScopeResolver,
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
            let disposition = dnssec_disposition_from_answer(
                answers_present(answers),
                answers.first().map(|r| r.proof),
            );
            // `Insecure` is ambiguous by the spec's own construction: RFC
            // 4035 §5.2 makes a resolver report "no authentication path" and
            // "path I cannot walk" identically. Only the ambiguous grade
            // pays for the discriminating DS lookup; the receipt stays on
            // the primary DNSKEY lookup (a second receipt row per control is
            // a schema question, not this change's call — the DS material
            // itself is captured beside the seal below).
            if disposition == DnssecDisposition::SignedNotDelegated {
                if let Ok(ds_resp) = observed_lookup(
                    resolver,
                    ControlId::Dnssec,
                    domain,
                    RecordType::DS,
                    &mut None,
                )
                .await
                {
                    let ds_answers = ds_resp.answers();
                    for rec in ds_answers {
                        if let hickory_proto::rr::RData::DNSSEC(DNSSECRData::DS(ds)) = &rec.data {
                            records.push(RecordEntry {
                                control: ControlId::Dnssec,
                                value: format!("DS {ds}"),
                            });
                        }
                    }
                    // Per-record authentication + evaluability live inside
                    // the gate fn: only Secure-proof DS records count
                    // (§5.2's AUTHENTICATED DS RRset), and a record is
                    // evaluatable only when algorithm AND digest both are.
                    // Absent/unauthenticated DS keeps the proof-derived
                    // grade: never flip on a measurement that did not
                    // complete.
                    if let Some(pairs) = ds_records_none_evaluatable(ds_answers) {
                        warn!(
                            domain,
                            ds_alg_digest_pairs = ?pairs,
                            "authenticated DS present but no record is evaluatable \
                             by this validator — chain unwalkable, not unsigned \
                             (RFC 4035 §5.2 + RFC 6840 §5.2, instrument-level)"
                        );
                        return DnssecDisposition::ChainUnverified;
                    }
                }
            }
            disposition
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

/// RFC 4035 §5.2 measured at instrument level, not resolver level. Both of
/// §5.2's unsupported-algorithm paragraphs mandate the fail-open: the
/// validator treats the case "as it would the case of an authenticated NSEC
/// RRset proving that no DS RRset exists", and "the resolver SHOULD treat
/// the child zone as if it were unsigned". RFC 6840 §5.2 extends the same
/// rule to DS records with unsupported DIGEST algorithms ("MUST be treated
/// the same way"). That fail-open is right for a resolver deciding whether
/// to answer and wrong for an instrument deciding what to report — it
/// erases the line between "no authentication path exists" (the island)
/// and "a path exists this validator cannot walk". The DS RRset is the
/// discriminating measurement the answer proof alone cannot supply:
/// `Insecure` with no authenticated DS is the island; `Insecure` with an
/// authenticated DS RRset containing no evaluatable record is an unwalkable
/// chain — `ChainUnverified`, never `Unsigned`.
///
/// The unit is the DS RECORD, algorithm AND digest jointly — the exact
/// complement of the validator's own insecure-gate
/// (`!algorithm.is_supported() || !digest_type.is_supported()`,
/// hickory-net dnssec/mod.rs). An algorithm-only check misses the compound
/// case (one record supported-alg/unknown-digest beside another
/// unknown-alg/supported-digest: no record is walkable, yet each column
/// contains a supported member) — the adversarial-verify refutation that
/// produced this form. Only `Proof::Secure` records count: §5.2 speaks of
/// an AUTHENTICATED DS RRset, and an unvalidated record must never flip a
/// grade in either direction.
///
/// Not a future concern: IANA already lists 17 (SM2, RFC 9563), 23
/// (GOST R 34.10-2012, RFC 9558), and 18 (ML-DSA-44, post-quantum lattice;
/// early allocation, draft-stage reference) — all `Unknown` to this build's
/// validator — so zones this gate discriminates exist in the measurable
/// wild today, and an algorithm transition arrives here as new numbers,
/// not a redesign. `is_supported()` is the validator's own self-report of
/// its build, never a hand-maintained list (the mirror-drift class); note
/// it includes SHA-1-era RSA (5, 7) — a SHA-1-only chain is walkable to
/// this validator and never reaches the gate.
///
/// Returns `Some(sorted, deduped (algorithm, digest_type) pairs)` when the
/// authenticated DS set is non-empty and NO record is evaluatable; `None`
/// when any record is evaluatable or no authenticated DS is present.
fn ds_records_none_evaluatable(records: &[hickory_proto::rr::Record]) -> Option<Vec<(u8, u8)>> {
    use hickory_proto::dnssec::rdata::DNSSECRData;
    use hickory_proto::dnssec::{Algorithm, DigestType, Proof};
    let mut pairs: Vec<(u8, u8)> = records
        .iter()
        .filter(|rec| rec.proof == Proof::Secure)
        .filter_map(|rec| match &rec.data {
            hickory_proto::rr::RData::DNSSEC(DNSSECRData::DS(ds)) => {
                Some((u8::from(ds.algorithm()), u8::from(ds.digest_type())))
            }
            _ => None,
        })
        .collect();
    if pairs.is_empty() {
        return None;
    }
    if pairs.iter().any(|&(alg, dig)| {
        Algorithm::from_u8(alg).is_supported() && DigestType::from(dig).is_supported()
    }) {
        return None;
    }
    pairs.sort_unstable();
    pairs.dedup();
    Some(pairs)
}

async fn score_spf(
    resolver: &ScopeResolver,
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
    resolver: &ScopeResolver,
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
        Err(e) => {
            // The sub-label under-claim repair: on `_dmarc` NXDOMAIN whose SOA
            // names an ancestor zone, the packet cannot decide whether the
            // DOMAIN exists — spend ONE `name_exists` query at the domain
            // rather than losing the measurement to Indet. Identical wiring to
            // `score_tls_rpt` (PR #45/#47); deliberately NOT routed through
            // `observed_lookup` (same one-receipt-per-control census rule).
            let exists = if nxdomain_soa_is_not(&e, domain) {
                name_exists(resolver, domain).await
            } else {
                None
            };
            dmarc_err_to_disposition(&e, domain, exists)
        }
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
    resolver: &ScopeResolver,
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
/// measured. `Some(0)` = a MEASURED absence (NODATA, or an NXDOMAIN at a name
/// whose host is known to exist); `None` = couldn't measure (transient, or the
/// host's own domain is missing, or existence was never probed).
///
/// This is the branch `score_dane` skipped when every other control's Err
/// path routed through `record_absence_verdict` — the skip folded measured
/// absence into couldn't-measure, the INVERSE conflation of the original
/// `&[usize]` bug (which folded couldn't-measure into measured absence).
/// Both directions lose the distinction DANE's four-way split exists to hold.
///
/// An MX target is a LEAF name, not a zone cut: `_25._tcp.mail3.cia.gov`
/// NXDOMAIN carries the SOA of the CLOSEST ENCLOSING ZONE THAT EXISTS
/// (`cia.gov`), which says NOTHING about whether the host's own domain
/// exists. The previous guard (`zone_contains_host`, deleted with this
/// change) inferred existence from the SOA name by suffix containment plus a
/// `contains('.')` proxy for "a real zone rather than a TLD"; that proxy only
/// holds for single-label TLDs, so `_25._tcp.mail.nosuchdomain.co.uk`
/// NXDOMAIN + SOA `co.uk` graded `Some(0)` — "measured absence" for a domain
/// that does not exist. Measured live 2026-09-04: `.co.uk` and `.com.au`
/// defective, `.com` correct only by accident (`com` carries no dot).
///
/// The replacement is a MEASUREMENT, not a string property: `host_exists`
/// carries the outcome of one SOA query at the host name ITSELF, made by the
/// call site that owns the resolver (`score_dane`). `Some(true)` = the name
/// resolves (NOERROR, including NODATA on a name that exists) so the TLSA's
/// absence is measured; `Some(false)` = the name is NXDOMAIN so its domain
/// does not exist and nothing is measurable; `None` = not probed, or the
/// probe itself failed — never claim. The one SOA-name test that survives is
/// EXACT equality with the host, which needs no probe at all: a zone that
/// answered for itself demonstrably exists.
fn tlsa_err_to_count(e: &NetError, host: &str, host_exists: Option<bool>) -> Option<usize> {
    use hickory_proto::op::ResponseCode;
    use hickory_resolver::net::DnsError;
    let host = host.trim_end_matches('.');
    match e {
        // NODATA on an existing zone: the host exists, no TLSA → measured
        // absence. The probe is not consulted — the name `_25._tcp.<host>`
        // answered NOERROR itself, so the host demonstrably exists.
        NetError::Dns(DnsError::NoRecordsFound(nr))
            if nr.response_code == ResponseCode::NoError =>
        {
            Some(0)
        }
        // NXDOMAIN: the name `_25._tcp.<host>` does not exist. The SOA names
        // the closest enclosing zone that exists, which decides nothing unless
        // it is the host itself. Otherwise the probe decides.
        NetError::Dns(DnsError::NoRecordsFound(nr))
            if nr.response_code == ResponseCode::NXDomain =>
        {
            match nr.soa.as_ref().map(|s| s.name.to_ascii()) {
                Some(z) if z.trim_end_matches('.').eq_ignore_ascii_case(host) => Some(0),
                _ => match host_exists {
                    Some(true) => Some(0), // measured: the host exists, no TLSA
                    Some(false) => None,   // measured: the host's domain is gone
                    None => None,          // never probed / probe failed
                },
            }
        }
        // SERVFAIL / timeout / anything else: nothing measured → None.
        _ => None,
    }
}

/// The zone name carried by the SOA in a lookup error's authority section.
/// By-ref sibling of hickory's consuming `NetError::into_soa`; the trailing
/// dot is trimmed so the result is directly comparable with a scanned name.
/// `None` when the error carried no SOA — nothing measured about the zone.
fn err_soa_zone(e: &NetError) -> Option<String> {
    use hickory_resolver::net::DnsError;
    match e {
        NetError::Dns(DnsError::NoRecordsFound(nr)) => Some(
            nr.soa
                .as_ref()?
                .name
                .to_ascii()
                .trim_end_matches('.')
                .to_string(),
        ),
        _ => None,
    }
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

/// Pure: does the QUERIED NAME itself exist, read from its own lookup outcome?
///
/// The existence half of the SOA query `zone_apex_and_existence` makes — the
/// signal `apex_from_soa_result` throws away. This is the measurement that
/// replaces every string-property inference about an NXDOMAIN's SOA name:
///
///   Ok (NOERROR with answers)              -> Some(true)   the name exists
///   NoRecordsFound, rcode NOERROR (NODATA) -> Some(true)   the name exists,
///                                                          it just has no SOA
///   NoRecordsFound, rcode NXDOMAIN         -> Some(false)  the name does not
///                                                          exist, and neither
///                                                          does its domain
///   SERVFAIL / Refused / timeout / other   -> None         couldn't measure
///
/// `None` is never "absent": an unanswerable probe must not license a claim.
fn name_exists_from_lookup(ok: bool, error: Option<&NetError>) -> Option<bool> {
    use hickory_proto::op::ResponseCode;
    use hickory_resolver::net::DnsError;
    if ok {
        return Some(true);
    }
    match error {
        Some(NetError::Dns(DnsError::NoRecordsFound(nr))) => match nr.response_code {
            ResponseCode::NoError => Some(true),
            ResponseCode::NXDomain => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Pure: is an existence probe WORTH A QUERY for this error and name?
///
/// True iff the error is an NXDOMAIN whose SOA owner is not exactly `name`
/// (a missing SOA counts as "needed"). False for NODATA and every transient
/// shape — a probe cannot rescue those and must not be spent on them; false
/// for the exact-equality case, where the zone answered for itself and its
/// existence is already in the packet.
///
/// Extracted PURE so the "when do we spend a query" decision is unit-pinned
/// without a resolver — the same reason `apex_from_soa_result` was extracted
/// from `zone_apex_of`.
fn nxdomain_soa_is_not(e: &NetError, name: &str) -> bool {
    use hickory_proto::op::ResponseCode;
    use hickory_resolver::net::DnsError;
    match e {
        NetError::Dns(DnsError::NoRecordsFound(nr))
            if nr.response_code == ResponseCode::NXDomain =>
        {
            match err_soa_zone(e) {
                Some(z) => !z.eq_ignore_ascii_case(name.trim_end_matches('.')),
                None => true,
            }
        }
        _ => false,
    }
}

/// One SOA query at `name`, read for BOTH facts it carries.
///
/// `.0` — the zone apex that CONTAINS `name`. If `name` is itself the apex the
/// SOA comes back in the answer section; if it is a leaf the SOA arrives in the
/// authority section (`NoRecordsFound` with `soa` populated). `None` when the
/// lookup errored without an SOA (couldn't measure the zone, not "no zone").
/// NOTE this value is the closest enclosing zone THAT EXISTS: for a name whose
/// domain does not exist it is the registry suffix, which is why `.1` exists.
///
/// `.1` — whether `name` ITSELF exists (`name_exists_from_lookup`).
///
/// Deliberately NOT routed through `observed_lookup`: this is an internal
/// sub-measurement, not a control's primary lookup, and a second receipt for
/// a `ControlId` breaks the one-receipt-per-control census
/// (engine/tests/control_enumeration_invariants.rs). Same precedent as the DS
/// refinement lookup and the MX-host `score_dnssec` sub-call, both of which
/// pass `&mut None`.
async fn zone_apex_and_existence(
    resolver: &ScopeResolver,
    name: &str,
) -> (Option<String>, Option<bool>) {
    use hickory_proto::rr::RecordType;
    match resolver.lookup(name, RecordType::SOA).await {
        Ok(resp) => (
            apex_from_soa_result(Some(resp.answers()), None),
            name_exists_from_lookup(true, None),
        ),
        Err(e) => (
            apex_from_soa_result(None, Some(&e)),
            name_exists_from_lookup(false, Some(&e)),
        ),
    }
}

/// Does this NAME exist? One SOA query at the name itself — the measurement
/// that separates "the record is absent from a zone that exists" from "the
/// domain does not exist", with no external data and no Public Suffix List.
///
/// The PSL was rejected deliberately: it is a mutable third-party list, so a
/// verdict derived from it depends on which snapshot produced it, which would
/// need a vendored pinned copy plus its identity in the receipt and in this
/// log to keep verdicts re-derivable. A query is reproducible by anyone with
/// a resolver and has no vintage.
async fn name_exists(resolver: &ScopeResolver, name: &str) -> Option<bool> {
    zone_apex_and_existence(resolver, name).await.1
}

/// The zone apex half of `zone_apex_and_existence`, for the one caller that
/// needs the zone cut and not the existence (the scanned domain's own apex,
/// whose existence the MX lookup that reached this code already established).
async fn zone_apex_of(resolver: &ScopeResolver, name: &str) -> Option<String> {
    zone_apex_and_existence(resolver, name).await.0
}

/// Pure: may a ZONE-BASED decision use this MX host's measured apex?
///
/// `score_dane` asks it twice — once for the `tlsa_zone` attribution, once for
/// the DnssecRequired gate — and the two guards it folds are NOT
/// interchangeable, which is the whole reason it is a named function instead
/// of an inline comparison:
///
///   `Some(false)` — the host was MEASURED not to exist. Its "apex" is only
///                   the registry suffix that answered the NXDOMAIN. Using it
///                   attributes the host to someone else's zone (a sealed
///                   `ForeignZone` for a host with no zone), and lets an
///                   unsigned registry suffix `return` DnssecRequired for a
///                   host that has no zone to sign. -> refuse the apex.
///   `None`        — the probe COULD NOT MEASURE. That is not evidence of
///                   absence and must not be spent as if it were: whatever
///                   apex the packet did carry is still the best measurement
///                   in hand. -> the apex stands.
///   `Some(true)`  — measured to exist. -> the apex stands.
///
/// WHY THIS IS A FUNCTION AND NOT `exists != Some(true)`: with hickory 0.26.1
/// only NoError and NXDomain responses become `NoRecordsFound` (hickory-net
/// src/error.rs), and every other rcode becomes `ResponseCode(_)` with NO SOA.
/// So `apex.is_some()` currently IMPLIES `exists.is_some()`, and the two
/// spellings are indistinguishable end to end — a wired control cannot tell
/// them apart, which is exactly how the `!= Some(true)` mutant survived the
/// full suite on #45. Extracting the decision makes the `None` row reachable
/// in a unit test (`host_zone_for_decision_separates_unmeasured_from_absent`)
/// and pins the intended semantics against a future error shape that carries
/// an SOA beside a rcode this crate cannot read as existence.
fn host_zone_for_decision(apex: Option<&str>, exists: Option<bool>) -> Option<&str> {
    match exists {
        Some(false) => None,
        Some(true) | None => apex,
    }
}

/// LAZY, MEMOISED per-host probe for `score_dane`: `zone_apex_and_existence`
/// at `hosts[i]`, taken on FIRST NEED and reused by every later reader.
///
/// `cache[i]` is `None` until host `i` is actually reached. Both of
/// `score_dane`'s zone loops short-circuit (`break` at the first resolvable
/// host; `return` at the first unsigned one), so an eager pass over every host
/// spends queries the scan's own control flow proves it never needs — measured
/// as 5 host-SOA questions where 1 suffices on a five-host unsigned-provider
/// MX (engine/tests/dane_probe_cost.rs). Memoisation is what keeps the
/// laziness honest: the gate loop re-reading a host the attribution loop
/// already probed must NOT put a second question on the wire, and must not
/// risk a different answer for the same host inside one scan.
async fn host_probe_at(
    resolver: &ScopeResolver,
    hosts: &[String],
    cache: &mut [Option<(Option<String>, Option<bool>)>],
    i: usize,
) -> (Option<String>, Option<bool>) {
    if let Some(hit) = &cache[i] {
        return hit.clone();
    }
    let fresh = zone_apex_and_existence(resolver, &hosts[i]).await;
    cache[i] = Some(fresh.clone());
    fresh
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
    resolver: &ScopeResolver,
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
                    // ── the per-host SOA probe: LAZY and MEMOISED ──────────
                    // One SOA query per MX host reads BOTH facts: the zone apex
                    // (the zone-cut attribution) and whether the host NAME
                    // ITSELF exists. The apex alone could not supply the second,
                    // because an NXDOMAIN's SOA names the closest enclosing zone
                    // THAT EXISTS and says nothing about the queried name's own
                    // domain.
                    //
                    // It is taken ON FIRST NEED, not eagerly for every host.
                    // Both loops below short-circuit — the attribution loop
                    // `break`s at the first resolvable host, the gate loop
                    // `return`s at the first unsigned one — and an eager pass
                    // spends a query for every host those `break`s never reach.
                    // MEASURED on the loopback stub (engine/tests/dane_probe_cost.rs),
                    // host-SOA questions on the wire, five MX hosts in an
                    // unsigned provider zone (the Google Workspace / Microsoft
                    // 365 shape this gate's own comment cites): eager 5, lazy 1,
                    // pre-probe 2. The eager pass made the DANE scan DEARER than
                    // before on the dominant real-world mail shape, which is the
                    // opposite of what this log's COST line claimed.
                    let domain_apex = zone_apex_of(resolver, domain).await;
                    let mut host_probe: Vec<Option<(Option<String>, Option<bool>)>> =
                        vec![None; hosts.len()];

                    // ── DANE attribution zone (the tlsa_zone measurement) ──
                    // The zone-cut relationship of the PRIMARY MX host to the
                    // scanned domain. First resolvable host wins (the primary
                    // MX determines the mail architecture). A host MEASURED not
                    // to exist is skipped: its "apex" is only the registry
                    // suffix that answered the NXDOMAIN, and classifying that
                    // yields `ForeignZone` — a sealed measurement asserting the
                    // mail host lives in someone else's zone, when the host has
                    // no zone at all. `ZoneUnmeasured` is the honest value.
                    let mut tlsa_zone = TlsaZone::ZoneUnmeasured;
                    for i in 0..hosts.len() {
                        let (apex, exists) =
                            host_probe_at(resolver, &hosts, &mut host_probe, i).await;
                        if let Some(apex) = host_zone_for_decision(apex.as_deref(), exists) {
                            tlsa_zone = classify_tlsa_zone(domain_apex.as_deref(), Some(apex));
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
                    //
                    // A host MEASURED not to exist is SKIPPED, and this skip is
                    // load-bearing: without it the gate scores the DNSKEY of
                    // the closest ENCLOSING zone (the registry suffix that
                    // answered the NXDOMAIN) as if it were the host's own zone,
                    // and an unsigned enclosing zone `return`s DnssecRequired
                    // here — "not applicable — MX host zone is unsigned" for a
                    // host that has no zone at all — BEFORE the TLSA loop below
                    // ever runs. A repair confined to `tlsa_err_to_count` is
                    // bypassed on that whole input subset.
                    for i in 0..hosts.len() {
                        let (apex, exists) =
                            host_probe_at(resolver, &hosts, &mut host_probe, i).await;
                        if let Some(apex) = host_zone_for_decision(apex.as_deref(), exists) {
                            // Internal sub-measurement of the MX host's zone —
                            // not the control's primary lookup; no receipt slot.
                            let d = score_dnssec(resolver, apex, &mut None, &mut Vec::new()).await;
                            if dane_host_zone_requires_dnssec(d) {
                                warn!(
                                    domain,
                                    host = %hosts[i],
                                    apex = %apex,
                                    "SMTP DANE host zone unsigned — DnssecRequired"
                                );
                                return (DaneDisposition::DnssecRequired, tlsa_zone);
                            }
                        }
                        // apex None (or a host measured not to exist) = no zone
                        // to gate on; fall through to the TLSA loop, which will
                        // report the host's own lookup outcome honestly.
                    }

                    let mut counts = Vec::with_capacity(hosts.len());
                    for (i, host) in hosts.iter().enumerate() {
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
                                // NODATA (the host exists, no TLSA) is a
                                // MEASURED absence — Some(0) — not "couldn't
                                // measure". An NXDOMAIN is decided by the
                                // per-host existence MEASUREMENT, never by a
                                // string property of the SOA name.
                                //
                                // MEASURED, NOT ASSUMED — and this read costs
                                // nothing: `host_probe_at` is a cache hit for
                                // every host here. The DnssecRequired gate above
                                // reads EVERY host's zone before this loop can
                                // run (it only stops by `return`ing, which ends
                                // the scan), so by now every host has been
                                // probed exactly once.
                                //
                                // That is also why this call site does NOT carry
                                // `score_tls_rpt`'s `nxdomain_soa_is_not` gate,
                                // which asks "is a probe worth a query for this
                                // packet". Here the answer is always "the query
                                // is already spent", so the gate could save
                                // nothing — and a branch that cannot change an
                                // outcome is an unkillable mutant, MEASURED as
                                // one: deleting it left all 258 tests passing.
                                // The unambiguous case is still short-circuited,
                                // in the place where it is load-bearing —
                                // `tlsa_err_to_count`'s exact-equality arm never
                                // consults `host_exists` at all, so an NXDOMAIN
                                // whose SOA names the host itself is immune to a
                                // probe that could not answer (pinned wired by
                                // `an_exact_soa_tlsa_nxdomain_is_immune_to_an_unanswerable_probe`).
                                warn!(domain, host = %host, error = %e, "SMTP DANE TLSA lookup error");
                                let exists =
                                    host_probe_at(resolver, &hosts, &mut host_probe, i).await.1;
                                counts.push(tlsa_err_to_count(&e, host, exists));
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
    v: &Vantage,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
    records: &mut Vec<RecordEntry>,
) -> MtaStsDisposition {
    let resolver: &ScopeResolver = v;
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
            // NODATA (no hint) = measured absence; NXDOMAIN under an ANCESTOR
            // SOA = spend the one-query probe (the under-claim repair, same
            // wiring as `score_dmarc`/`score_tls_rpt`); transient = Indet.
            let exists = if nxdomain_soa_is_not(&e, domain) {
                name_exists(resolver, domain).await
            } else {
                None
            };
            return mta_sts_err_to_disposition(&e, domain, exists);
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
    // The URL comes from the vantage (`Vantage::policy_url`): no port in
    // production; `:<port>` only under the E7 test seam.
    let policy_url = v.policy_url(domain);
    // The HTTP I/O lives inline here (it is async glue, not a decision); the
    // status→ok/err decision is the pure `mta_sts_policy_from_response` below,
    // so the `!status.is_success()` gate and the body passthrough are unit-pinned
    // rather than hidden behind a live request. A Result-returning fetch helper
    // was the one place whose FnValue mutants (return fabricated Ok(empty) bytes)
    // survived mutation testing.
    //
    // The client comes from the vantage (`Vantage::http_client`): the policy
    // host is resolved THROUGH THE CHOSEN RESOLVER (never libc getaddrinfo —
    // a cleartext leak to the system stub under every choice), 3xx is never
    // followed (RFC 8461 §3.3: "HTTP 3xx redirects MUST NOT be followed"),
    // environment proxies are ignored. The attempt and its outcome go to the
    // egress ledger BEFORE the verdict is decided, so the surface's HTTPS line
    // rests on a socket-layer fact, never on the disposition.
    let policy_host = format!("mta-sts.{}", domain);
    let via = v.identity();
    let ledger = v.ledger().clone();
    let record_outcome = |addrs: Vec<std::net::IpAddr>,
                          peer: Option<std::net::SocketAddr>,
                          outcome: FetchOutcome| {
        ledger.record_fetch(FetchEntry {
            url: policy_url.clone(),
            host: policy_host.clone(),
            addrs,
            peer,
            via: via.clone(),
            outcome,
        });
    };
    record_outcome(Vec::new(), None, FetchOutcome::NotAttempted);
    let policy_result: anyhow::Result<String> = async {
        // A lookup result, recorded as such: the addresses the vantage
        // returned for the policy host. NOT the destination — hyper-util
        // connects to ONE of them (the next only on error); the destination
        // is the peer read off the response's socket below.
        let addrs: Vec<std::net::IpAddr> = match v.lookup_ip(policy_host.as_str()).await {
            Ok(ips) => ips.iter().collect(),
            Err(_) => Vec::new(), // the client's own resolution reports the error below
        };
        let client = v.http_client()?;
        let resp = match client.get(&policy_url).send().await {
            Ok(r) => r,
            Err(e) => {
                // Classified from the typed source chain, never from
                // `Display` (`FetchOutcome` doc): a wrong certificate and a
                // closed port print the same Display text. No response, so
                // no peer — reqwest's socket is outside the ledger.
                record_outcome(addrs, None, FetchOutcome::classify(&e));
                return Err(e.into());
            }
        };
        // The peer: hyper-util's getpeername on the socket the response came
        // over (reqwest `Response::remote_addr`, HttpInfo) — the one measured
        // destination a surface may print behind the arrow.
        let peer = resp.remote_addr();
        let status = resp.status();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let body = if status.is_redirection() {
            String::new() // never followed; the body of a 3xx is not a policy
        } else {
            match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    record_outcome(
                        addrs,
                        peer,
                        FetchOutcome::RequestFailed(crate::egress::error_chain(&e)),
                    );
                    return Err(e.into());
                }
            }
        };
        let (outcome, result) = mta_sts_fetch_outcome(status, location.as_deref(), body);
        record_outcome(addrs, peer, outcome);
        result
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

/// Pure: the response gate for an MTA-STS policy fetch — the ledger outcome
/// and the verdict input, decided together so neither can be dropped without
/// the other. A 3xx is recorded with its Location and NEVER followed (RFC
/// 8461 §3.3: "HTTP 3xx redirects MUST NOT be followed"); it fails the fetch
/// through the same non-2xx gate as a 404. Extracted so the redirect arm is
/// unit-pinned: deleting the `is_redirection` branch turns a 301 into a
/// `Status(301, n)` — n the length of the body it was handed: 0 on the
/// production path, which never reads a 3xx body (`score_mta_sts` passes
/// `String::new()`), 50 in the unit test, which passes its 50-byte policy —
/// that the wire line would print as "not a policy" instead of "not
/// followed".
fn mta_sts_fetch_outcome(
    status: reqwest::StatusCode,
    location: Option<&str>,
    body: String,
) -> (FetchOutcome, anyhow::Result<String>) {
    if status.is_redirection() {
        let outcome = FetchOutcome::Redirect(status.as_u16(), location.unwrap_or("").to_string());
        let result = mta_sts_policy_from_response(status, String::new());
        return (outcome, result);
    }
    let outcome = FetchOutcome::Status(status.as_u16(), body.len());
    (outcome, mta_sts_policy_from_response(status, body))
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

// Back-compat shim for the existing tests: "enforced" = the three-way state
// reads Enforce.
// ── TLS-RPT (RFC 8460) ─────────────────────────────────────────────────────
//
// TXT at _smtp._tls.<domain>: `v=TLSRPTv1; rua=<uri>[,<uri>...]`. The
// measurement is one lookup + the RFC's own three validity rules, read
// first-hand from the corpus:
//   * records not beginning `v=TLSRPTv1;` are DISCARDED;
//   * after discarding, the count must be EXACTLY ONE — "If the number of
//     resulting records is not one, senders MUST assume the recipient domain
//     does not implement TLSRPT" (§3);
//   * rua is required and must carry at least one parseable mailto:/https:
//     URI (commas, !, ; must be percent-encoded inside the URI — bare ones
//     break the field parser).
async fn score_tls_rpt(
    resolver: &ScopeResolver,
    domain: &str,
    receipt: &mut Option<LookupReceipt>,
) -> TlsRptDisposition {
    let tlsrpt_name = format!("_smtp._tls.{}", domain);
    match observed_txt_lookup(resolver, ControlId::TlsRpt, tlsrpt_name.as_str(), receipt).await {
        Ok(rdata) => {
            // Gather every TXT string at the name; each ANSWER record's
            // char-strings are first concatenated per the RFC's multi-string
            // rule ("treated as if those strings are concatenated").
            let mut records_text: Vec<String> = Vec::new();
            for rec in rdata.answers() {
                if let hickory_proto::rr::RData::TXT(txt) = &rec.data {
                    let joined: String = txt
                        .txt_data
                        .iter()
                        .map(|s| String::from_utf8_lossy(s).to_string())
                        .collect();
                    records_text.push(joined);
                }
            }
            if records_text.is_empty() {
                // Zone exists (the lookup succeeded), no records: NODATA
                // handled by the error path; an empty Ok with answers means
                // the resolver returned something odd — treat as absent.
                return TlsRptDisposition::RecordAbsent;
            }
            // RFC rule 1: discard records not beginning "v=TLSRPTv1;"
            let valid: Vec<&String> = records_text
                .iter()
                .filter(|t| t.trim_start().starts_with("v=TLSRPTv1;"))
                .collect();
            // RFC rule 2: exactly one valid record counts
            if valid.len() != 1 {
                if valid.is_empty() {
                    return TlsRptDisposition::RecordAbsent;
                }
                return TlsRptDisposition::PolicyInvalid; // >1 valid record
            }
            // RFC rule 3: rua present + at least one parseable URI
            let record = valid[0];
            let rua_ok = record.split(';').any(|f| {
                let f = f.trim();
                if let Some(rest) = f.strip_prefix("rua=") {
                    rest.split(',').any(|uri| {
                        let uri = uri.trim();
                        (uri.starts_with("mailto:") && uri.len() > "mailto:".len() + 3)
                            || (uri.starts_with("https://") && uri.len() > "https://".len() + 3)
                    })
                } else {
                    false
                }
            });
            if rua_ok {
                TlsRptDisposition::Published
            } else {
                TlsRptDisposition::PolicyInvalid // no parseable rua endpoint
            }
        }
        Err(e) => {
            // The SOA in this packet names the closest enclosing zone THAT
            // EXISTS; when it is not the scanned domain itself the packet
            // cannot say whether the domain exists. Spend ONE query on the
            // domain's own name rather than guessing from the SOA's shape.
            let exists = if nxdomain_soa_is_not(&e, domain) {
                name_exists(resolver, domain).await
            } else {
                None
            };
            tls_rpt_err_to_disposition(&e, domain, exists)
        }
    }
}

fn tls_rpt_err_to_disposition(
    e: &NetError,
    domain: &str,
    domain_exists: Option<bool>,
) -> TlsRptDisposition {
    if e.is_nx_domain() {
        // NXDOMAIN on `_smtp._tls.<domain>` says the queried NAME is absent.
        // It never says the domain is. The refuting evidence rides in the same
        // packet: the SOA in the authority section names the zone that
        // answered. READ it — assuming absence from the response code alone is
        // derivation, and it printed "domain does not exist" over live zones
        // (cia.gov, irs.gov, apple.com, amazon.com, akamai.com, wellsfargo.com,
        // bankofamerica.com, nih.gov all return NXDOMAIN carrying their OWN
        // SOA), contradicting the MTA-STS row of the same sealed report.
        //
        // EXACT ZONE EQUALITY still decides the free case: `RecordAbsent` is
        // claimed with no probe when the SOA names the scanned domain itself,
        // because the zone answered for itself and its existence is already in
        // the packet.
        //
        // THE PROPER-ANCESTOR CASE IS NOW MEASURED, not guessed. PR #42 left it
        // at `NoZone` and said so plainly: `support.google.com` with SOA
        // `google.com` (zone exists, name absent) and `nonexistent.co.uk` with
        // SOA `co.uk` (domain genuinely does not exist) are the SAME shape with
        // OPPOSITE correct answers, so `NoZone` was printing "no zone — domain
        // does not exist" (truth_chain.rs) over a live name. Its comment named
        // the repair — "a second measurement, carried as its own board item".
        // This is that board item: `domain_exists` carries one SOA query at the
        // scanned domain itself, made by `score_tls_rpt`, which owns the
        // resolver.
        //
        //   Some(true)  -> the domain exists, only `_smtp._tls.<domain>` is
        //                  absent -> RecordAbsent (a measured Low finding, back
        //                  in both score sums)
        //   Some(false) -> the domain does not exist -> NoZone, and the claim
        //                  the renderer prints is true
        //   None        -> the probe was SPENT and could not answer
        //                  (SERVFAIL, Refused, timeout) -> NoZone, unchanged
        //                  from before. Note this is NOT an abstention: NoZone
        //                  still renders "domain does not exist", so for a live
        //                  name whose probe did not answer the instrument still
        //                  prints a claim the packets cannot support.
        //
        //                  It is the ONLY way to reach this arm with `None`.
        //                  Every NXDOMAIN whose SOA is not the scanned name
        //                  exactly — a bare-TLD SOA and a missing SOA included —
        //                  IS probed (`nxdomain_soa_is_not` returns true for
        //                  both), and a transient failure never reaches this
        //                  branch at all: `is_nx_domain()` is false for it and
        //                  it exits below as TransientError.
        match err_soa_zone(e) {
            Some(z) if z.eq_ignore_ascii_case(domain.trim_end_matches('.')) => {
                TlsRptDisposition::RecordAbsent
            }
            _ => match domain_exists {
                Some(true) => TlsRptDisposition::RecordAbsent,
                Some(false) | None => TlsRptDisposition::NoZone,
            },
        }
    } else if e.is_no_records_found() {
        TlsRptDisposition::RecordAbsent // definitive NODATA: zone exists, no record
    } else {
        TlsRptDisposition::TransientError
    }
}

// ── CSYNC (RFC 7477) ───────────────────────────────────────────────────────
//
// One CSYNC RR at the apex (type 62): SOA serial + flags + type bit map. The
// measurement only asks IS the automation signal published and is it singular
// — the parental-agent processing rules (validation, serial comparison) are
// the PARENT's behavior, not this domain's posture. RFC 7477 §2: "parental
// agents MUST ignore a child's CSYNC RDATA set if multiple CSYNC resource
// records are found; only a single CSYNC record should ever be present."
/// Pure gate (RFC 7477 §5): CSYNC requires the child zone "signed, current
/// and properly linked to the parent zone with a DS record", and the parental
/// agent MUST validate the signal as DNSSEC-"secure" — impossible without a
/// chain. On a measured-unsigned apex an absent CSYNC is inapplicability, not
/// a gap (policy/RULING_csync_20260901.md; the DANE DnssecRequired
/// precedent). Only `Unsigned` fires: `NoZone` is carried by CSYNC's own
/// probe (the apex IS the probed zone, unlike DANE's separate MX-host zone),
/// and the chain anomalies (`SignedNotDelegated`, `BrokenChain`,
/// `ChainUnverified`, `Unreachable`) pass through rather than over-assert —
/// the DANE gate's conservatism, kept deliberately.
fn csync_absent_is_inapplicable(apex: DnssecDisposition) -> bool {
    matches!(apex, DnssecDisposition::Unsigned)
}

async fn score_csync(
    resolver: &ScopeResolver,
    domain: &str,
    apex_dnssec: DnssecDisposition,
    receipt: &mut Option<LookupReceipt>,
) -> CsyncDisposition {
    use hickory_proto::rr::RecordType;
    // The lookup always runs, gate or no gate: the receipt census (one
    // receipt per ControlId::ALL) must hold, and a genuinely Published
    // record on an unsigned zone stays measured as Published — the parent's
    // refusal to consume it is the parent's layer. Only measured ABSENCE is
    // reinterpreted: on an unsigned apex it is inapplicability (§5), not a
    // gap.
    match observed_lookup(
        resolver,
        ControlId::Csync,
        domain,
        RecordType::CSYNC,
        receipt,
    )
    .await
    {
        Ok(resp) => {
            let count = resp.answers().len();
            if count == 0 {
                if csync_absent_is_inapplicable(apex_dnssec) {
                    CsyncDisposition::DnssecRequired
                } else {
                    CsyncDisposition::RecordAbsent
                }
            } else if count == 1 {
                CsyncDisposition::Published
            } else {
                CsyncDisposition::PolicyInvalid // multiple: parents MUST ignore
            }
        }
        Err(e) => {
            if e.is_nx_domain() {
                CsyncDisposition::NoZone
            } else if e.is_no_records_found() {
                if csync_absent_is_inapplicable(apex_dnssec) {
                    CsyncDisposition::DnssecRequired
                } else {
                    CsyncDisposition::RecordAbsent
                }
            } else {
                CsyncDisposition::TransientError
            }
        }
    }
}

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
    resolver: &ScopeResolver,
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
    resolver: &ScopeResolver,
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

fn dmarc_err_to_disposition(
    e: &NetError,
    domain: &str,
    domain_exists: Option<bool>,
) -> DmarcDisposition {
    // The under-claim repair (MEASUREMENT_SEMANTICS, "record_absence_verdict
    // under-claims on sub-label scans"): `_dmarc.<domain>` NXDOMAIN whose SOA
    // names a PROPER ANCESTOR zone (support.example.com under SOA example.com)
    // is a record that is GENUINELY ABSENT from a live domain, not
    // "could not measure". `record_absence_verdict`'s exact-equality arm only
    // claims when the SOA IS the scanned domain; every ancestor shape fell to
    // Indet and lost the measurement. Same packet, same refuting evidence, and
    // the same one-query probe TLS-RPT already wires (`score_tls_rpt`):
    //   Some(true)  -> the domain exists, only `_dmarc.` is absent -> NotConfigured
    //   Some(false) | None -> keep the abstention (TransientError)
    if e.is_nx_domain() && nxdomain_soa_is_not(e, domain) {
        return match domain_exists {
            Some(true) => DmarcDisposition::NotConfigured,
            Some(false) | None => DmarcDisposition::TransientError,
        };
    }
    match record_absence_verdict(e, domain) {
        TriState::Indet => DmarcDisposition::TransientError,
        _ => DmarcDisposition::NotConfigured,
    }
}

fn mta_sts_err_to_disposition(
    e: &NetError,
    domain: &str,
    domain_exists: Option<bool>,
) -> MtaStsDisposition {
    // The under-claim repair (see `dmarc_err_to_disposition`): `_mta-sts`
    // NXDOMAIN under a PROPER ANCESTOR SOA on a live domain is a MEASURED
    // record absence (`RecordAbsent`), not "could not measure". The probe
    // semantics are identical to TLS-RPT's:
    //   Some(true)  -> RecordAbsent (a measured Low finding, in both sums)
    //   Some(false) | None -> TransientError (keep the abstention)
    if e.is_nx_domain() && nxdomain_soa_is_not(e, domain) {
        return match domain_exists {
            Some(true) => MtaStsDisposition::RecordAbsent,
            Some(false) | None => MtaStsDisposition::TransientError,
        };
    }
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
    use crate::resolver::{ResolverChoice, Vantage};
    use hickory_resolver::config::ResolverOpts;

    // -------------------------------------------------------------------------
    // Helper — the default vantage: Cloudflare over plain 53 (UDP, TCP on
    // truncation), DNSSEC validated locally. (An older comment here said
    // "Cloudflare DoT" — it never was; ledger f7ad6d0 measured plain 53.)
    // -------------------------------------------------------------------------

    /// The options every vantage builds with — the REAL constructor input
    /// (`ResolverChoice::options`), so the validate-flag gate below asserts on
    /// the producer, not on a local re-derivation. (The previous test built
    /// its own opts, set the flag, and asserted its own assignment — a check
    /// that could not fail; deleting `validate = true` from the helper left
    /// it green. Audit 2026-08-29, same defect shape as the NXNAME-inversion
    /// precedent.)
    fn test_resolver_opts() -> ResolverOpts {
        ResolverChoice::default().options()
    }

    fn make_test_vantage() -> Vantage {
        // The default choice: Cloudflare over plain 53. In sandboxed /
        // offline environments the live tests must be run with `--ignored`
        // suppressed or a loopback stub substituted (tests/support).
        Vantage::build(ResolverChoice::default()).expect("test vantage construction")
    }

    // -------------------------------------------------------------------------
    // Unit: resolver_options_validate_is_set
    // Verifies that the opts every vantage is BUILT WITH carry validate=true.
    // This is the Section A.3 gate: if validate is false the golden fixtures
    // would pass vacuously even without DNSSEC signatures.
    // -------------------------------------------------------------------------
    #[test]
    fn resolver_options_validate_is_set() {
        // Default opts have validate=false; the producer must flip it.
        let default_opts = ResolverOpts::default();
        assert!(
            !default_opts.validate,
            "sanity: default validate should be false"
        );
        assert!(
            test_resolver_opts().validate,
            "ResolverChoice::options() must carry validate=true — if this \
             fails, every DNSSEC golden fixture passes vacuously (A.3)"
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
                let vantage = make_test_vantage();
                let result = analyse_domain(&vantage, $domain)
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

        // --- DNSSEC unsupported-DS gate (RFC 4035 §5.2 + RFC 6840 §5.2) ---
        // 4035 §5.2: unsupported algorithms in an AUTHENTICATED DS RRset →
        // resolver SHOULD treat the child as unsigned. 6840 §5.2: DS records
        // with unsupported DIGEST algorithms MUST be treated the same way.
        // Right for a resolver, wrong for an instrument: the gate below
        // discriminates "no path" from "path this validator cannot walk",
        // per RECORD (algorithm AND digest jointly — the exact complement of
        // the validator's own insecure-gate). Numbers are live IANA
        // assignments: alg 13 = ECDSA-P256 (evaluatable), 17 = SM2,
        // 18 = ML-DSA-44 (post-quantum, early allocation), 23 = GOST-2012,
        // 1 = RSAMD5 (known, refused); digest 2 = SHA-256 (evaluatable),
        // 3 = GOST 34.11-94 (Unknown to this validator).
        {
            use hickory_proto::dnssec::rdata::{DNSSECRData, DS};
            use hickory_proto::dnssec::{Algorithm, DigestType, Proof};
            use hickory_proto::rr::{RData, Record};
            let ds = |alg: u8, dig: u8, proof: Proof| {
                let mut rec = Record::from_rdata(
                    mx_name("example.com."),
                    300,
                    RData::DNSSEC(DNSSECRData::DS(DS::new(
                        12345,
                        Algorithm::from_u8(alg),
                        DigestType::from(dig),
                        vec![0xAA; 32],
                    ))),
                );
                rec.proof = proof;
                rec
            };
            let s = Proof::Secure;
            assert_eq!(
                ds_records_none_evaluatable(&[ds(13, 2, s)]),
                None,
                "D5a: evaluatable record (ECDSA-P256 + SHA-256) — gate must NOT fire"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[ds(18, 2, s)]),
                Some(vec![(18, 2)]),
                "D5b: ML-DSA-44 only (IANA 18, post-quantum) — unwalkable, gate fires"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[ds(18, 2, s), ds(13, 2, s)]),
                None,
                "D5c: one evaluatable RECORD suffices — §5.2 'does not support ANY'"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[
                    ds(23, 2, s),
                    ds(18, 2, s),
                    ds(17, 2, s),
                    ds(18, 2, s)
                ]),
                Some(vec![(17, 2), (18, 2), (23, 2)]),
                "D5d: multiple unevaluatable records, sorted + deduped"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[ds(1, 2, s)]),
                Some(vec![(1, 2)]),
                "D5e: RSAMD5 — known to the parser, refused by the validator; \
                 known-but-unverifiable is still unwalkable"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[]),
                None,
                "D5f: no DS = the island case — gate must NOT fire (never \
                 converts a genuine island into ChainUnverified)"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[ds(13, 3, s), ds(18, 2, s)]),
                Some(vec![(13, 3), (18, 2)]),
                "D5g: the compound refuting vector — supported alg with unknown \
                 digest beside unknown alg with supported digest: each COLUMN \
                 has a supported member, NO RECORD is walkable — gate fires \
                 (this is what an algorithm-only check misgraded as island)"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[ds(13, 3, s)]),
                Some(vec![(13, 3)]),
                "D5h: supported algorithm, unsupported digest (RFC 6840 §5.2) — \
                 unwalkable, gate fires"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[ds(18, 2, Proof::Indeterminate)]),
                None,
                "D5i: unauthenticated DS records do not count — §5.2 speaks of \
                 an AUTHENTICATED DS RRset; an unvalidated record must never \
                 flip a grade"
            );
            assert_eq!(
                ds_records_none_evaluatable(&[ds(5, 2, s)]),
                None,
                "D5j: RSASHA1 counts evaluatable — the gate inherits the \
                 validator's own build list (SHA-1-era RSA included), never a \
                 hand-maintained policy list"
            );
        }

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
        let resolver = make_test_vantage();
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
        let resolver = make_test_vantage();

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
    fn tlsa_err_nodata_ignores_the_probe() {
        // NODATA on _25._tcp.<host>: the name itself answered NOERROR, so the
        // host demonstrably exists and no TLSA is a measured absence (Some(0)),
        // NOT couldn't-measure. All three probe values must agree — the probe
        // is not consulted on this arm, and if it ever were, a `Some(false)`
        // from a racing probe would destroy a measurement already in hand.
        for probe in [Some(true), Some(false), None] {
            assert_eq!(
                tlsa_err_to_count(
                    &no_records_err(hickory_proto::op::ResponseCode::NoError),
                    "mail.example.com",
                    probe
                ),
                Some(0),
                "probe {probe:?} must not reach the NODATA arm"
            );
        }
    }

    #[test]
    fn tlsa_err_servfail_is_unmeasured_even_when_the_probe_says_exists() {
        // SERVFAIL: nothing was measured about the TLSA → None. A probe saying
        // the host exists must NOT rescue it: existence is not a TLSA answer.
        assert_eq!(
            tlsa_err_to_count(&servfail_err(), "mail.example.com", None),
            None
        );
        assert_eq!(
            tlsa_err_to_count(&servfail_err(), "mail.example.com", Some(true)),
            None
        );
    }

    #[test]
    fn tlsa_err_nxdomain_own_zone_is_measured_absence_without_a_probe() {
        // NXDOMAIN with the HOST's own zone in the SOA: the zone answered for
        // itself, so it exists and only _25._tcp.<host> is absent → measured
        // absence with NO probe spent (`None` here means "never probed"). The
        // host is passed in its PRODUCTION shape — WITH the trailing dot, as
        // Name::to_ascii() emits it — so this exercises the host-side
        // trim_end_matches that the sanitised form would leave untested.
        let e = nxdomain_err_with_soa("mail.example.com.");
        assert_eq!(tlsa_err_to_count(&e, "mail.example.com.", None), Some(0));
    }

    /// THE DEFECT, AND ITS TWO CONTROLS. One error fixture — NXDOMAIN carrying
    /// the registry suffix `co.uk` — driven through the mapper with the ONLY
    /// variable being the existence measurement. The packet is held constant;
    /// the probe is the sole difference. Measured live 2026-09-04 from one
    /// vantage: `_25._tcp.mail.nosuchdomain-zz9q.co.uk` NXDOMAIN SOA `co.uk`
    /// graded Some(0) "measured absence" for a domain that does not exist,
    /// because the deleted `zone_contains_host` used `z.contains('.')` as a
    /// proxy for "a real zone rather than a TLD" and `co.uk` contains a dot.
    #[test]
    fn tlsa_err_nxdomain_ancestor_soa_is_decided_by_the_probe() {
        let e = nxdomain_err_with_soa("co.uk.");
        // NEGATIVE. The name does not exist → nothing about TLSA was measured.
        assert_eq!(
            tlsa_err_to_count(&e, "mail.nosuchdomain-zz9q.co.uk", Some(false)),
            None,
            "a domain that does not exist cannot have a measured TLSA absence"
        );
        // POSITIVE. Same packet, name measured to exist → measured absence.
        assert_eq!(
            tlsa_err_to_count(&e, "mail.nosuchdomain-zz9q.co.uk", Some(true)),
            Some(0),
            "an existing host with no TLSA is a measured absence"
        );
        // UNPROBED. Never claim from a measurement that was not taken.
        assert_eq!(
            tlsa_err_to_count(&e, "mail.nosuchdomain-zz9q.co.uk", None),
            None,
            "an unprobed host licenses no claim"
        );
    }

    #[test]
    fn tlsa_err_nxdomain_containing_zone_needs_the_probe_now() {
        // The Arm-1 shape (mail.example.com → SOA example.com). Before this
        // change suffix containment graded it Some(0) from the SOA name alone.
        // That inference is gone: the SAME shape is `nonexistent.co.uk` under
        // SOA `co.uk`, with the opposite correct answer. The measurement, not
        // the string, decides — and the ordinary parent case is still graded
        // Some(0), just for a reason the packet plus one query supports.
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(
            tlsa_err_to_count(&e, "mail.example.com.", Some(true)),
            Some(0)
        );
        assert_eq!(
            tlsa_err_to_count(&e, "mail.example.com.", Some(false)),
            None
        );
        assert_eq!(tlsa_err_to_count(&e, "mail.example.com.", None), None);
    }

    #[test]
    fn tlsa_err_nxdomain_row_four_regression_pin() {
        // ROW 4 of the live repro, the one that was CORRECT and must stay:
        // `_25._tcp.aspmx.l.google.com` NXDOMAIN SOA `l.google.com` — a third-
        // party MX host that really does exist inside a real zone. It grades
        // Some(0) as before; the difference is that the grade now rests on the
        // host's own SOA answering, not on `l.google.com` happening to contain
        // a dot.
        let e = nxdomain_err_with_soa("l.google.com.");
        assert_eq!(
            tlsa_err_to_count(&e, "aspmx.l.google.com", Some(true)),
            Some(0)
        );
    }

    #[test]
    fn tlsa_err_nxdomain_tld_zone_is_unmeasured() {
        // ROW 3 of the live repro — correct BY ACCIDENT before this change
        // (`com` carries no dot, so the deleted `contains('.')` proxy refused
        // it). It is still None, now for a measured reason.
        let e = nxdomain_err_with_soa("com.");
        assert_eq!(
            tlsa_err_to_count(&e, "mail.example.com.", Some(false)),
            None
        );
        assert_eq!(tlsa_err_to_count(&e, "mail.example.com.", None), None);
    }

    // --- the existence probe's two pure halves ------------------------------

    #[test]
    fn name_exists_from_lookup_table() {
        // Ok: the name answered with records → it exists.
        assert_eq!(name_exists_from_lookup(true, None), Some(true));
        // NODATA: the name exists, it just carries no SOA of its own. This is
        // the arm that makes a leaf MX host readable — a leaf is NOT a zone
        // apex, so its SOA query returns NODATA, not an answer.
        assert_eq!(
            name_exists_from_lookup(
                false,
                Some(&no_records_err(hickory_proto::op::ResponseCode::NoError))
            ),
            Some(true)
        );
        // NXDOMAIN: the name does not exist, and neither does its domain.
        assert_eq!(
            name_exists_from_lookup(
                false,
                Some(&no_records_err(hickory_proto::op::ResponseCode::NXDomain))
            ),
            Some(false)
        );
        // Transient shapes measure nothing. NEVER Some(anything).
        assert_eq!(
            name_exists_from_lookup(
                false,
                Some(&no_records_err(hickory_proto::op::ResponseCode::ServFail))
            ),
            None
        );
        assert_eq!(name_exists_from_lookup(false, Some(&servfail_err())), None);
        assert_eq!(
            name_exists_from_lookup(
                false,
                Some(&no_records_err(hickory_proto::op::ResponseCode::Refused))
            ),
            None
        );
        assert_eq!(name_exists_from_lookup(false, None), None);
    }

    /// MUT12, the mutant that survived #45's whole suite: replacing
    /// `host_exists[i] == Some(false)` with `!= Some(true)` at BOTH zone
    /// guards in `score_dane`. Nothing distinguished "MEASURED not to exist"
    /// from "COULD NOT MEASURE", and no wired test could: with hickory 0.26.1
    /// only NoError and NXDomain responses carry an SOA into `NoRecordsFound`
    /// (hickory-net src/error.rs), so a probe that returns `None` returns no
    /// apex either, and both spellings do nothing. The mutant was EQUIVALENT
    /// end to end — surviving because it was unreachable, not because the
    /// suite was thin, which is why the decision was extracted to
    /// `host_zone_for_decision` where the `None` row IS reachable.
    ///
    /// The row that matters is the third: an apex measured, existence NOT
    /// measured. Unmeasured existence is not absence, so the apex stands.
    #[test]
    fn host_zone_for_decision_separates_unmeasured_from_absent() {
        // measured to exist -> the apex stands
        assert_eq!(
            host_zone_for_decision(Some("provider.test"), Some(true)),
            Some("provider.test")
        );
        // MEASURED not to exist -> the apex is only the zone that ANSWERED the
        // NXDOMAIN, never the host's own. Refuse it.
        assert_eq!(host_zone_for_decision(Some("co.test"), Some(false)), None);
        // COULD NOT MEASURE -> not evidence of absence. The apex stands.
        // This is the row `!= Some(true)` gets wrong.
        assert_eq!(
            host_zone_for_decision(Some("provider.test"), None),
            Some("provider.test")
        );
        // No apex measured -> nothing to decide with, whatever existence says.
        assert_eq!(host_zone_for_decision(None, Some(true)), None);
        assert_eq!(host_zone_for_decision(None, Some(false)), None);
        assert_eq!(host_zone_for_decision(None, None), None);
    }

    #[test]
    fn nxdomain_soa_is_not_decides_when_to_spend_a_query() {
        // NXDOMAIN whose SOA IS the name: the packet already proves the zone
        // exists — no query is owed.
        assert!(!nxdomain_soa_is_not(
            &nxdomain_err_with_soa("example.com."),
            "example.com"
        ));
        // Same, normalised: DNS names are case-insensitive and the SOA owner
        // arrives fully qualified. Without this a bare `==` mutant survives.
        assert!(!nxdomain_soa_is_not(
            &nxdomain_err_with_soa("Example.COM."),
            "eXaMpLe.com."
        ));
        // Proper ancestor, and a bare TLD: undecidable from the packet → probe.
        assert!(nxdomain_soa_is_not(
            &nxdomain_err_with_soa("google.com."),
            "support.google.com"
        ));
        assert!(nxdomain_soa_is_not(
            &nxdomain_err_with_soa("co.uk."),
            "nonexistent.co.uk"
        ));
        assert!(nxdomain_soa_is_not(
            &nxdomain_err_with_soa("com."),
            "example.com"
        ));
        // No SOA carried at all: nothing measured about the zone → probe.
        assert!(nxdomain_soa_is_not(&nxdomain_err_no_soa(), "example.com"));
        // NODATA and transient shapes: a probe cannot rescue them and must not
        // be spent. These are the arms that keep the cost claim honest.
        assert!(!nxdomain_soa_is_not(
            &no_records_err(hickory_proto::op::ResponseCode::NoError),
            "example.com"
        ));
        assert!(!nxdomain_soa_is_not(&servfail_err(), "example.com"));
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

    // --- the CSYNC apex gate (RFC 7477 §5; policy/RULING_csync_20260901.md) --
    // Narrower than DANE's on purpose: the apex IS the probed zone, so NoZone
    // is carried by CSYNC's own probe rather than the gate.

    #[test]
    fn csync_unsigned_apex_makes_absence_inapplicable() {
        assert!(csync_absent_is_inapplicable(DnssecDisposition::Unsigned));
    }

    #[test]
    fn csync_gate_passes_everything_but_unsigned() {
        // One-contributor rule, same as the DANE gate tests above: each
        // pass-through is its own assertion.
        assert!(!csync_absent_is_inapplicable(
            DnssecDisposition::SignedAndDelegated
        ));
        assert!(!csync_absent_is_inapplicable(
            DnssecDisposition::SignedNotDelegated
        ));
        assert!(!csync_absent_is_inapplicable(
            DnssecDisposition::BrokenChain
        ));
        assert!(!csync_absent_is_inapplicable(
            DnssecDisposition::ChainUnverified
        ));
        assert!(!csync_absent_is_inapplicable(DnssecDisposition::NoZone));
        assert!(!csync_absent_is_inapplicable(
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
        // None is the honest probe value for a SERVFAIL: is_nx_domain() is
        // false, so the ancestor-SOA branch cannot fire and None is inert.
        assert_eq!(
            dmarc_err_to_disposition(&servfail_err(), "example.com", None),
            DmarcDisposition::TransientError
        );
        assert_eq!(
            dmarc_err_to_disposition(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com",
                None
            ),
            DmarcDisposition::NotConfigured
        );
    }

    #[test]
    fn mta_sts_err_indet_is_transient_not_recordabsent() {
        // None is inert for non-NXDOMAIN shapes (see the dmarc twin above).
        assert_eq!(
            mta_sts_err_to_disposition(&servfail_err(), "example.com", None),
            MtaStsDisposition::TransientError
        );
        assert_eq!(
            mta_sts_err_to_disposition(
                &no_records_err(hickory_proto::op::ResponseCode::NoError),
                "example.com",
                None
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

    /// NXDOMAIN that carried NO SOA in its authority section — nothing was
    /// measured about the zone, so the conservative reading must stand.
    fn nxdomain_err_no_soa() -> NetError {
        use hickory_proto::op::{Query, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_resolver::net::{DnsError, NoRecords};
        let q = Query::query(
            Name::from_ascii("_smtp._tls.example.com.").unwrap(),
            RecordType::TXT,
        );
        let nr = NoRecords::new(Box::new(q), ResponseCode::NXDomain);
        NetError::Dns(DnsError::NoRecordsFound(nr))
    }

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

    /// PINS THE REVERT. `record_absence_verdict` compares the SOA zone to the
    /// scanned domain by EXACT equality, and must keep doing so: suffix
    /// containment would grade a genuinely absent domain under a multi-label
    /// registry suffix as "zone exists". PR #42 tried containment here and
    /// reverted it; without this test the revert is unguarded and a future
    /// edit re-applies it silently.
    ///
    /// Negative control (watched failing 2026-09-04): swap the comparison at
    /// `record_absence_verdict` for suffix containment and this test fails on
    /// the `.co.uk` row while the rest of the suite stays green. The
    /// containment helper it named, `zone_contains_host`, is now DELETED — it
    /// was the site of the registry-suffix defect and is gone rather than
    /// left in the file for the next author to reuse. The prohibition it
    /// pinned is unchanged and this test still enforces it.
    ///
    /// STILL TRUE AFTER THE EXISTENCE PROBE, and named so it is not mistaken
    /// for a repaired path: `record_absence_verdict` is deliberately NOT
    /// probed in this change. It under-claims on sub-label scans — `_dmarc`
    /// and `_mta-sts` NXDOMAIN under an ancestor SOA read Indet ("could not
    /// measure") for a record that is genuinely absent. That loses a
    /// measurement but never asserts a falsehood, so it stays out of scope;
    /// the same probe would repair it.
    // ── The sub-label under-claim repair, pure mapper controls ─────────────
    // `record_absence_verdict` stays exact-equality (pinned above); the
    // repair lives in the *_err_to_disposition mappers, which consult ONE
    // existence probe when the SOA is a PROPER ANCESTOR of the scanned name.
    // Three probe values, three verdicts, both controls — the same matrix
    // TLS-RPT's repair carries. Before the repair every ancestor shape read
    // TransientError ("could not measure") for a record that is genuinely
    // absent from a live domain: a LOST measurement, never a false claim —
    // which is why this was ranked below the over-claiming repairs.

    #[test]
    fn dmarc_ancestor_soa_is_decided_by_the_probe() {
        // The support.google.com shape: `_dmarc.support.google.com` NXDOMAIN
        // carrying SOA google.com. The packet cannot decide whether
        // support.google.com exists; the probe can.
        let e = nxdomain_err_with_soa("google.com.");
        assert_eq!(
            dmarc_err_to_disposition(&e, "support.google.com", Some(true)),
            DmarcDisposition::NotConfigured,
            "a live domain's _dmarc NXDOMAIN under an ancestor SOA is a MEASURED absence"
        );
        assert_eq!(
            dmarc_err_to_disposition(&e, "support.google.com", Some(false)),
            DmarcDisposition::TransientError,
            "a nonexistent domain keeps the abstention"
        );
        assert_eq!(
            dmarc_err_to_disposition(&e, "support.google.com", None),
            DmarcDisposition::TransientError,
            "an unanswerable probe keeps the abstention"
        );
    }

    #[test]
    fn mta_sts_ancestor_soa_is_decided_by_the_probe() {
        let e = nxdomain_err_with_soa("google.com.");
        assert_eq!(
            mta_sts_err_to_disposition(&e, "support.google.com", Some(true)),
            MtaStsDisposition::RecordAbsent,
            "a live domain's _mta-sts NXDOMAIN under an ancestor SOA is a MEASURED absence"
        );
        assert_eq!(
            mta_sts_err_to_disposition(&e, "support.google.com", Some(false)),
            MtaStsDisposition::TransientError
        );
        assert_eq!(
            mta_sts_err_to_disposition(&e, "support.google.com", None),
            MtaStsDisposition::TransientError
        );
    }

    #[test]
    fn sublabel_probe_is_not_spent_when_the_packet_decides() {
        // The exact-equality SOA (the domain's own zone) decides with NO
        // probe; the mapper must ignore the probe entirely in that shape —
        // including a LIED Some(true), which would otherwise be consulted.
        let own = nxdomain_err_with_soa("example.com.");
        assert_eq!(
            dmarc_err_to_disposition(&own, "example.com", Some(true)),
            DmarcDisposition::NotConfigured,
            "the exact-equality arm decides; the probe value is inert"
        );
        // NODATA is a measured absence by the packet itself; also inert.
        let nodata = no_records_err(hickory_proto::op::ResponseCode::NoError);
        assert_eq!(
            dmarc_err_to_disposition(&nodata, "example.com", Some(false)),
            DmarcDisposition::NotConfigured
        );
        // A SERVFAIL is never an NXDOMAIN; the probe must not be consulted.
        assert_eq!(
            mta_sts_err_to_disposition(&servfail_err(), "example.com", Some(true)),
            MtaStsDisposition::TransientError
        );
    }

    #[test]
    fn record_absence_soa_test_is_exact_not_containment() {
        // A registry suffix answering for a name below it means the name was
        // never delegated — the domain does not exist, and Indet is the honest
        // verdict. Containment would call this "zone exists".
        assert_eq!(
            record_absence_verdict(&nxdomain_err_with_soa("co.uk."), "nonexistent.co.uk"),
            TriState::Indet,
            "a registry-suffix SOA is not the domain's own zone"
        );
        // Structurally identical shape, ordinary parent zone: still Indet,
        // because this packet cannot tell the two apart. The sub-label case is
        // carried as a follow-up that needs a measurement, not an inference.
        assert_eq!(
            record_absence_verdict(&nxdomain_err_with_soa("google.com."), "support.google.com"),
            TriState::Indet,
            "a parent-zone SOA is not the domain's own zone either"
        );
        // The sound case, unchanged: the zone answered for itself.
        assert_eq!(
            record_absence_verdict(&nxdomain_err_with_soa("example.com."), "example.com"),
            TriState::Absent
        );
    }

    // --- TLS-RPT NXDOMAIN: the SOA is in the packet, so READ it --------------
    // `tls_rpt_err_to_disposition` used to `let _ = domain;` and return NoZone
    // for every NXDOMAIN, which renders (truth_chain.rs:790) as
    // "no zone — domain does not exist" at Severity::Ok — a sealed assertion
    // that a live domain is absent, contradicted by the MTA-STS row of the
    // SAME report a few lines above. The fix is deliberately narrow: ONLY an
    // SOA naming the scanned domain EXACTLY moves the verdict. These are the
    // paired controls: the positive that must pass, and the three negatives
    // that must fail if the exact-equality test is loosened.

    #[test]
    fn tls_rpt_err_nxdomain_own_zone_is_record_absent() {
        // POSITIVE. NXDOMAIN for `_smtp._tls.example.com` carrying the
        // domain's OWN SOA: the zone answered, so the zone exists and only the
        // name is absent -> RecordAbsent (Low), which is also a MEASURED
        // absence and re-enters both score sums.
        let e = nxdomain_err_with_soa("example.com.");
        assert_eq!(
            tls_rpt_err_to_disposition(&e, "example.com", None),
            TlsRptDisposition::RecordAbsent
        );
    }

    #[test]
    fn tls_rpt_err_nxdomain_own_zone_match_is_case_and_dot_insensitive() {
        // POSITIVE, the comparison's own normalisation. DNS names are
        // case-insensitive (RFC 4343) and the SOA owner arrives fully
        // qualified, so the equality test must trim the trailing dot on the
        // scanned name and compare ASCII-case-insensitively. Without this
        // test a bare `z == domain` mutant SURVIVES the whole suite — the
        // other fixtures happen to be lowercase and dotless on both sides.
        assert_eq!(
            tls_rpt_err_to_disposition(
                &nxdomain_err_with_soa("Example.COM."),
                "eXaMpLe.com.",
                None
            ),
            TlsRptDisposition::RecordAbsent
        );
    }

    /// THE ASSERTION THIS CHANGE REPAIRS. PR #42 pinned BOTH ancestor rows to
    /// `NoZone` and said why: `support.google.com` with SOA `google.com` (zone
    /// exists, name absent) and `nonexistent.co.uk` with SOA `co.uk` (domain
    /// genuinely does not exist) are the SAME shape with OPPOSITE correct
    /// answers, and no string rule separates them. `NoZone` is not an
    /// abstention — it renders "no zone — domain does not exist" — so the
    /// google.com row was a sealed FALSE claim about a live name.
    ///
    /// The second measurement its comment asked for now exists. Same packet,
    /// opposite probe, opposite verdict — and that this assertion MOVED is the
    /// visible proof the behaviour did.
    #[test]
    fn tls_rpt_err_nxdomain_ancestor_zone_is_decided_by_the_probe() {
        let ancestor = nxdomain_err_with_soa("google.com.");
        // POSITIVE, and the repair: the domain resolves, so only the leaf name
        // is absent. A measured Low finding, back in both score sums.
        assert_eq!(
            tls_rpt_err_to_disposition(&ancestor, "support.google.com", Some(true)),
            TlsRptDisposition::RecordAbsent
        );
        // NEGATIVE, structurally identical packet: the registry suffix answered
        // for a name that was never delegated. NoZone, and the claim is true.
        assert_eq!(
            tls_rpt_err_to_disposition(
                &nxdomain_err_with_soa("co.uk."),
                "nonexistent.co.uk",
                Some(false)
            ),
            TlsRptDisposition::NoZone
        );
        // UNPROBED (transient probe, or no probe spent): the inherited verdict
        // stands. Recorded plainly rather than dressed as restraint — NoZone
        // still prints "domain does not exist", so this path can still print a
        // claim the packet cannot support. It is narrowed, not eliminated.
        assert_eq!(
            tls_rpt_err_to_disposition(&ancestor, "support.google.com", None),
            TlsRptDisposition::NoZone
        );
    }

    #[test]
    fn tls_rpt_err_nxdomain_tld_zone_is_no_zone() {
        // NEGATIVE. A bare-TLD SOA means the domain's own zone is what is
        // missing -> NoZone is CORRECT and must stay reachable. This test is
        // the one that fails if the SOA read is made unconditional (return
        // RecordAbsent for every NXDOMAIN): `com` is not equal to
        // `example.com`, so exact equality refuses it.
        let e = nxdomain_err_with_soa("com.");
        assert_eq!(
            tls_rpt_err_to_disposition(&e, "example.com", Some(false)),
            TlsRptDisposition::NoZone
        );
    }

    #[test]
    fn tls_rpt_err_nxdomain_without_soa_is_no_zone() {
        // NEGATIVE, third arm — kept a separate test so it is exercised on
        // its own rather than shadowed by the assertions above. An NXDOMAIN
        // that carried NO SOA measured nothing about the zone; the conservative
        // NoZone stands. Measured kill: adding `None => RecordAbsent` to the
        // match in `tls_rpt_err_to_disposition` fails THIS test and no other.
        // (A weaker mutant — having `err_soa_zone` fall back to the QUERY name
        // when no SOA was carried — survives, and correctly so: the query name
        // `_smtp._tls.example.com` is not equal to `example.com`, so the
        // verdict is NoZone either way. Recorded rather than hidden.)
        assert_eq!(
            tls_rpt_err_to_disposition(&nxdomain_err_no_soa(), "example.com", Some(false)),
            TlsRptDisposition::NoZone
        );
    }

    #[test]
    fn tls_rpt_and_mta_sts_rows_agree_the_zone_exists() {
        // The self-contradiction, pinned shut. ONE error shape — NXDOMAIN
        // carrying the domain's own SOA, which the sweep measured on 8 of 10
        // sampled real domains — driven through BOTH controls' Err mappings
        // and BOTH renderers. Before the fix the MTA-STS row read
        // "record absent — zone exists, no MTA-STS" while the TLS-RPT row of
        // the same sealed report read "no zone — domain does not exist".
        let e = nxdomain_err_with_soa("example.com.");
        // The probe is None here — the exact-equality arm decides before any
        // probe is spent (nxdomain_soa_is_not is false), so the None carries
        // no meaning in this shape. Passing Some(true) would take the new
        // ancestor-SOA branch and change the verdict, which is exactly what
        // the under-claim repair's own controls pin separately.
        let tls =
            crate::truth_chain::tls_rpt_report(tls_rpt_err_to_disposition(&e, "example.com", None));
        let mta =
            crate::truth_chain::mta_sts_report(mta_sts_err_to_disposition(&e, "example.com", None));

        assert_eq!(mta.measured, "record absent — zone exists, no MTA-STS");
        assert_eq!(tls.measured, "record absent — zone exists, no TLS-RPT");
        assert!(
            !tls.measured.contains("does not exist"),
            "TLS-RPT row still asserts the domain is absent while MTA-STS says the zone exists: {}",
            tls.measured
        );
        // And the control is back INSIDE the denominator: Tally::denominator()
        // is present+absent, and risk_weighted_score sums weight only for
        // Present/Absent (truth_chain.rs). Indet dropped it out of both.
        assert_eq!(tls.tri, TriState::Absent);
        assert_eq!(mta.tri, TriState::Absent);
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
        // "no TLSA" — the NXDomain guard is what enforces this. A probe saying
        // the host exists must not promote it either.
        assert_eq!(tlsa_err_to_count(&e, "mail3.example.com", None), None);
        assert_eq!(tlsa_err_to_count(&e, "mail3.example.com", Some(true)), None);
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

    // --- the redirect gate: recorded with its Location, never followed --------
    #[test]
    fn mta_sts_fetch_outcome_records_a_redirect_and_never_follows_it() {
        use reqwest::StatusCode;
        // Negative control: every 3xx is recorded as a Redirect with its
        // Location and fails the fetch — the body a redirecting server sent
        // is never read as a policy. Mutant: delete the `is_redirection`
        // branch of `mta_sts_fetch_outcome` → `Status(301, 50)` (the
        // 50-byte body below), this fails.
        for code in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let (outcome, result) = mta_sts_fetch_outcome(
                code,
                Some("https://policy.example.net/x"),
                "version: STSv1\nmode: enforce\nmx: smtp.example.com\n".to_string(),
            );
            assert_eq!(
                outcome,
                FetchOutcome::Redirect(code.as_u16(), "https://policy.example.net/x".into()),
                "{code}"
            );
            assert!(result.is_err(), "{code}: a redirect is never a policy");
        }
        // A 3xx without a Location still records the code.
        let (outcome, result) = mta_sts_fetch_outcome(StatusCode::FOUND, None, String::new());
        assert_eq!(outcome, FetchOutcome::Redirect(302, String::new()));
        assert!(result.is_err());
        // Positive control: a 200 passes the body through as the policy; a
        // 404 is a recorded status that fails the gate.
        let body = "version: STSv1\nmode: enforce\nmx: smtp.example.com\n".to_string();
        let (outcome, result) = mta_sts_fetch_outcome(StatusCode::OK, None, body.clone());
        assert_eq!(outcome, FetchOutcome::Status(200, body.len()));
        assert_eq!(result.unwrap(), body);
        let (outcome, result) = mta_sts_fetch_outcome(StatusCode::NOT_FOUND, None, "nope".into());
        assert_eq!(outcome, FetchOutcome::Status(404, 4));
        assert!(result.is_err());
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
