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
