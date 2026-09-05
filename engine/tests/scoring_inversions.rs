//! Surviving mutants in the scoring core, killed.
//!
//! WHY THIS FILE EXISTS. `cargo-mutants` over `engine/src/analysis.rs` at
//! origin/main (2026-09-05: 235 mutants, 20 minutes) left 15 survivors where
//! the recorded baseline said 7 — the ratchet the nightly scaffold promised
//! went backwards, because nothing schedules that scaffold. Four survivors sat
//! in the scoring core. This file kills the one that INVERTS A VERDICT:
//!
//!   analysis.rs:2140  `if count == 0` in score_csync  ->  replace == with !=
//!
//! WHY IT SURVIVED, which is the interesting part and was NOT what I first
//! assumed. The branch reads `if count == 0 { absent } else if count == 1
//! { Published } else { PolicyInvalid }`, so my first attempt served a NODATA
//! answer expecting to exercise `count == 0` directly. It does not reach that
//! line at all: hickory surfaces NODATA as an `Err`, so the disposition came
//! back `TransientError` and the Ok-arm was never entered. `count == 0` is
//! unreachable through this resolver.
//!
//! That makes the mutant observable from the OTHER side. With `!=`, the
//! condition is always TRUE for any answer that arrives, so a genuinely
//! PUBLISHED CSYNC record — count == 1 — takes the absence branch and is
//! graded RecordAbsent or DnssecRequired. The tool would report that a domain
//! published nothing while holding its record in hand. No test served a real
//! CSYNC record, which is precisely why the mutant lived.

mod support;

use std::collections::HashMap;

use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use resolution_scope_engine::CsyncDisposition;
use support::{key, Canned, Stub};

/// CSYNC is RR type 62. The engine ASKS with `RecordType::Unknown(62)`, which
/// is correct on the wire, but hickory 0.26 has a typed `RecordType::CSYNC`
/// and parses 62 back into it — so anything matching on the PARSED query, the
/// stub included, sees `CSYNC` and never `Unknown(62)`. My first version of
/// this file keyed the canned answer on `Unknown(62)`, the stub never matched
/// it, every query came back REFUSED, and both tests failed with
/// `TransientError` while `stub.saw(...)` reported the query had never
/// happened. It had; I was asking the wrong question about it.
const CSYNC: RecordType = RecordType::CSYNC;

/// The engine does not parse the payload — this branch only COUNTS answers —
/// so an opaque body that round-trips is exactly the fidelity needed here.
const CSYNC_ON_THE_WIRE: RecordType = RecordType::Unknown(62);

fn n(s: &str) -> Name {
    Name::from_ascii(if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{s}.")
    })
    .unwrap()
}

fn vantage_at(stub: &Stub) -> Vantage {
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    Vantage::build_unvalidating_for_tests(choice).unwrap()
}

fn csync_record(owner: &str) -> Record {
    // SOA serial (4) + flags (2) + a minimal type bitmap, per RFC 7477 §2.1.
    // The bytes are never read by the engine; they exist so the record encodes
    // and decodes as a real answer rather than as a malformed one.
    Record::from_rdata(
        n(owner),
        3600,
        RData::Unknown {
            code: CSYNC_ON_THE_WIRE,
            rdata: NULL::with(vec![0, 0, 0, 1, 0, 3, 0, 1, 0x40]),
        },
    )
}

/// A domain that PUBLISHES one CSYNC record must be graded `Published`.
///
/// Kills `replace == with != in score_csync` (analysis.rs:2140). Under that
/// mutant the always-true condition sends this single answer down the absence
/// branch, and the scan reports `RecordAbsent`/`DnssecRequired` for a record
/// it just received — a fabricated absence, the direction this project treats
/// as worst.
#[tokio::test]
async fn a_published_csync_is_published_not_absent() {
    let mut c = HashMap::new();
    c.insert(
        key("apex.test", CSYNC),
        Canned::ok(vec![csync_record("apex.test")]),
    );
    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "apex.test").await.unwrap();
    assert_eq!(
        a.csync_disposition,
        CsyncDisposition::Published,
        "one CSYNC answer is a PUBLISHED record; grading it absent would deny a record the scan holds in hand"
    );
}

/// Two CSYNC records are `PolicyInvalid` — parents MUST ignore the set.
///
/// This is the third arm, and it pins the ordering the first test cannot see:
/// with `count` compared correctly, one answer and two answers must land in
/// DIFFERENT arms. A mutant that collapses them would pass the test above.
#[tokio::test]
async fn two_csync_records_are_policy_invalid() {
    let mut c = HashMap::new();
    c.insert(
        key("apex.test", CSYNC),
        Canned::ok(vec![csync_record("apex.test"), csync_record("apex.test")]),
    );
    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "apex.test").await.unwrap();
    assert_eq!(
        a.csync_disposition,
        CsyncDisposition::PolicyInvalid,
        "multiple CSYNC records are a policy error the parent must ignore (RFC 7477)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS-RPT — the same disposition shape as CSYNC, reached over TXT.
//
// TLS-RPT and CSYNC have IDENTICAL enums (Published / RecordAbsent / NoZone /
// TransientError / PolicyInvalid) and near-identical branch structure. CSYNC
// was broken because the engine asked with an untyped RecordType; TLS-RPT asks
// with TXT, so a positive test here isolates that bug to the record type
// rather than to the shape both controls share. `TlsRptDisposition::Published`
// was, like CSYNC's, asserted by no integration test before this file.
//
// The two boundary tests also kill the remaining scoring survivors from the
// 2026-09-05 re-baseline:
//   analysis.rs:2001  `uri.len() > "mailto:".len() + 3`  ->  + replaced by - or *

fn tls_rpt_world(txt: &str) -> HashMap<(String, RecordType), Canned> {
    let mut c = HashMap::new();
    c.insert(
        key("_smtp._tls.apex.test", RecordType::TXT),
        Canned::ok(vec![Record::from_rdata(
            n("_smtp._tls.apex.test"),
            3600,
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![txt.to_string()])),
        )]),
    );
    c
}

async fn tls_rpt_for(txt: &str) -> resolution_scope_engine::TlsRptDisposition {
    let stub = Stub::start_with(tls_rpt_world(txt)).await;
    let v = vantage_at(&stub);
    analyse_domain(&v, "apex.test")
        .await
        .unwrap()
        .tls_rpt_disposition
}

/// A published TLS-RPT record with a real reporting address reads `Published`.
///
/// The positive observation this control had never had. If it failed the way
/// CSYNC did, the shape would be the suspect; it passes, so the CSYNC defect
/// is isolated to that control's untyped RecordType.
#[tokio::test]
async fn a_published_tls_rpt_record_is_published() {
    assert_eq!(
        tls_rpt_for("v=TLSRPTv1; rua=mailto:reports@apex.test").await,
        resolution_scope_engine::TlsRptDisposition::Published,
        "a valid record with a parseable rua endpoint is PUBLISHED"
    );
}

/// A rua URI too short to be an address is NOT a parseable endpoint.
///
/// `"mailto:".len() + 3` is 10, so `mailto:a@b` (exactly 10) must FAIL the
/// length test and the record is PolicyInvalid. Kills `replace + with -`
/// (threshold 4), under which this would read Published.
#[tokio::test]
async fn a_rua_uri_at_the_length_floor_is_not_parseable() {
    assert_eq!(
        tls_rpt_for("v=TLSRPTv1; rua=mailto:a@b").await,
        resolution_scope_engine::TlsRptDisposition::PolicyInvalid,
        "a 10-character mailto: is at the floor, not above it — a record with no usable endpoint is PolicyInvalid"
    );
}

/// A short but genuine reporting address is parseable.
///
/// `mailto:r@apex.test` is 18 characters: above the real threshold of 10, and
/// below the 21 that `replace + with *` would impose. Kills that mutant, under
/// which a legitimate record would be graded PolicyInvalid — a fabricated
/// policy error against a domain that published a working endpoint.
#[tokio::test]
async fn a_short_but_real_rua_address_is_accepted() {
    assert_eq!(
        tls_rpt_for("v=TLSRPTv1; rua=mailto:r@apex.test").await,
        resolution_scope_engine::TlsRptDisposition::Published,
        "an 18-character mailto: is a working endpoint; grading it invalid would accuse a correct domain"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CAA — the third control to get its first positive wire-path observation.
//
// `CaaDisposition::FullyRestricted` was asserted by no integration test. The
// detector wants tag == "issue" and the raw value bytes == b";", which is how
// hickory encodes an absent issuer name. Whether a record built with
// `CAA::new_issue(false, None, vec![])` actually ROUND-TRIPS to those bytes is
// the thing this test settles rather than assumes — the CSYNC defect was
// exactly a round-trip assumption nobody had checked.

/// A domain publishing `issue ";"` forbids all certificate issuance.
#[tokio::test]
async fn a_caa_issue_semicolon_reads_fully_restricted() {
    use hickory_proto::rr::rdata::CAA;
    let mut c = HashMap::new();
    c.insert(
        key("apex.test", RecordType::CAA),
        Canned::ok(vec![Record::from_rdata(
            n("apex.test"),
            3600,
            RData::CAA(CAA::new_issue(false, None, vec![])),
        )]),
    );
    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "apex.test").await.unwrap();
    assert_eq!(
        a.caa_disposition,
        resolution_scope_engine::CaaDisposition::FullyRestricted,
        "issue \";\" is the no-CA-may-issue sentinel (RFC 8659 §4.2)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CDS — both positive states, neither previously observed over the wire.
//
// RFC 8078 §4: a CDS whose algorithm field is ZERO is the DELETE sentinel,
// asking the parent to remove the DS RRset. hickory models that as
// `algorithm: Option<Algorithm>` = None, and the engine detects it with
// `cds.algorithm().is_none()`. A CDS carrying a real algorithm is an ordinary
// rollover hint and reads Published.
//
// The two states differ by ONE field, and the difference decides whether the
// tool reports "this domain wants its DNSSEC delegation removed" — which is a
// destructive request — or "this domain is rolling a key". Getting them
// backwards would be a serious mislabel, and nothing observed either.

fn cds_world(
    rd: hickory_proto::dnssec::rdata::DNSSECRData,
) -> HashMap<(String, RecordType), Canned> {
    let mut c = HashMap::new();
    c.insert(
        key("apex.test", RecordType::CDS),
        Canned::ok(vec![Record::from_rdata(
            n("apex.test"),
            3600,
            RData::DNSSEC(rd),
        )]),
    );
    c
}

async fn cds_for(
    rd: hickory_proto::dnssec::rdata::DNSSECRData,
) -> resolution_scope_engine::CdsDisposition {
    let stub = Stub::start_with(cds_world(rd)).await;
    let v = vantage_at(&stub);
    analyse_domain(&v, "apex.test")
        .await
        .unwrap()
        .cds_disposition
}

/// A null CDS (algorithm 0) is a DELETION request, not a publication.
#[tokio::test]
async fn a_null_cds_reads_deletion_requested() {
    use hickory_proto::dnssec::rdata::{DNSSECRData, CDS};
    use hickory_proto::dnssec::DigestType;
    let cds = CDS::new(0, None, DigestType::SHA256, vec![0]);
    assert_eq!(
        cds_for(DNSSECRData::CDS(cds)).await,
        resolution_scope_engine::CdsDisposition::DeletionRequested,
        "algorithm 0 is the RFC 8078 delete sentinel — the domain is asking the parent to remove its DS"
    );
}

/// A CDS carrying a real algorithm is an ordinary rollover hint.
#[tokio::test]
async fn a_real_cds_reads_published_not_deletion() {
    use hickory_proto::dnssec::rdata::{DNSSECRData, CDS};
    use hickory_proto::dnssec::{Algorithm, DigestType};
    let cds = CDS::new(
        12345,
        Some(Algorithm::ECDSAP256SHA256),
        DigestType::SHA256,
        vec![0u8; 32],
    );
    assert_eq!(
        cds_for(DNSSECRData::CDS(cds)).await,
        resolution_scope_engine::CdsDisposition::Published,
        "a CDS with a real algorithm is a rollover hint; calling it a deletion request would invert a destructive signal"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DANE — the last control from the blind-spot list that a single-record world
// cannot reach, and the only one left needing a CHAIN.
//
// `DaneDisposition::TlsaPublished` was asserted only by a pure unit test over
// `dane_from_tlsa_counts`, never over the wire. The wire path is longer than
// any other control's: MX lookup, then a per-host DNSSEC gate on the host's
// own apex, then a TLSA lookup at `_25._tcp.<host>`. The pure test cannot see
// any of that, and the CSYNC defect lived precisely in a wire path a pure test
// could not see.

fn dane_world() -> HashMap<(String, RecordType), Canned> {
    use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
    use hickory_proto::rr::rdata::{MX, TLSA};
    let mut c = HashMap::new();
    c.insert(
        key("apex.test", RecordType::MX),
        Canned::ok(vec![Record::from_rdata(
            n("apex.test"),
            3600,
            RData::MX(MX::new(10, n("mail.apex.test"))),
        )]),
    );
    // A textbook "3 1 1" pin: DANE-EE, SPKI, SHA-256.
    c.insert(
        key("_25._tcp.mail.apex.test", RecordType::TLSA),
        Canned::ok(vec![Record::from_rdata(
            n("_25._tcp.mail.apex.test"),
            3600,
            RData::TLSA(TLSA::new(
                CertUsage::DaneEe,
                Selector::Spki,
                Matching::Sha256,
                vec![0xab; 32],
            )),
        )]),
    );
    c
}

/// An MX host publishing a TLSA record reads `TlsaPublished`.
///
/// The chain this walks, none of which a pure test touches: the MX lookup
/// resolves the host, the per-host DNSSEC gate finds no measurable apex here
/// and correctly falls through rather than returning DnssecRequired, and the
/// TLSA lookup at `_25._tcp.<host>` returns one record which the counter reads
/// as published.
#[tokio::test]
async fn an_mx_host_with_a_tlsa_record_reads_tlsa_published() {
    let stub = Stub::start_with(dane_world()).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "apex.test").await.unwrap();
    assert_eq!(
        a.dane_disposition,
        resolution_scope_engine::DaneDisposition::TlsaPublished,
        "one TLSA record on the MX host is a published DANE pin"
    );
    assert!(
        stub.saw("_25._tcp.mail.apex.test", RecordType::TLSA),
        "the TLSA query must actually reach the wire at the RFC 7672 name"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DKIM — the last entry on the blind-spot list.
//
// `DkimDisposition::Verified` was asserted only by a pure unit test over
// `dkim_disposition_from_counts`, never over the wire. The wire path builds a
// selector list, probes each `<selector>._domainkey.<domain>` for TXT, and
// classifies the `p=` value. `analyse_domain_with_selectors` lets a caller
// supply a selector, so this needs no guess about which of the 81 defaults a
// fixture would match.
//
// Verified and Revoked differ ONLY by whether `p=` carries a value. That one
// difference is the difference between "this domain signs its mail" and "this
// domain has withdrawn its key", which are opposite operational facts, and
// neither had ever been produced by a scan in a test.

fn dkim_world(p_value: &str) -> HashMap<(String, RecordType), Canned> {
    use hickory_proto::rr::rdata::TXT;
    let mut c = HashMap::new();
    c.insert(
        key("cc1._domainkey.apex.test", RecordType::TXT),
        Canned::ok(vec![Record::from_rdata(
            n("cc1._domainkey.apex.test"),
            3600,
            RData::TXT(TXT::new(vec![format!("v=DKIM1; k=rsa; p={p_value}")])),
        )]),
    );
    c
}

async fn dkim_for(p_value: &str) -> resolution_scope_engine::DkimDisposition {
    let stub = Stub::start_with(dkim_world(p_value)).await;
    let v = vantage_at(&stub);
    resolution_scope_engine::analysis::analyse_domain_with_selectors(
        &v,
        "apex.test",
        &["cc1".to_string()],
    )
    .await
    .unwrap()
    .dkim_disposition
}

/// A selector publishing a key reads `Verified`.
#[tokio::test]
async fn a_dkim_selector_with_a_key_reads_verified() {
    assert_eq!(
        dkim_for("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestkeymaterial").await,
        resolution_scope_engine::DkimDisposition::Verified,
        "a selector carrying a non-empty p= is a published, usable key"
    );
}

/// The same selector with an EMPTY `p=` is a revocation, not a key.
///
/// One character of difference decides between "this domain signs its mail"
/// and "this domain has withdrawn its key". Grading a revocation as Verified
/// would tell an operator their signing is healthy at the moment it is not.
#[tokio::test]
async fn a_dkim_selector_with_an_empty_p_reads_revoked() {
    assert_eq!(
        dkim_for("").await,
        resolution_scope_engine::DkimDisposition::Revoked,
        "an empty p= is RFC 6376 key revocation, the opposite operational fact from Verified"
    );
}
