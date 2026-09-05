//! The receipt census: every control leaves an evidence row, whatever the
//! failure class.
//!
//! WHY THIS EXISTS. `ControlId::ALL` is ten controls and the design is one
//! receipt each — the receipts ARE the provenance this instrument sells. But
//! `receipt_from_err` matched only two error shapes, and MEASURED against a
//! loopback stub on 2026-09-05, a scan whose every lookup returned REFUSED
//! produced ZERO receipts out of ten. `ReceiptRcode::ServFail` and
//! `ReceiptRcode::Refused` were written in the vocabulary, mapped correctly by
//! `receipt_rcode_token`, and structurally unreachable: their only caller sat
//! inside the `NoRecordsFound` arm, whose `response_code` hickory only ever
//! populates with NoError or NXDomain.
//!
//! Two entire failure classes left no evidence at all. This file is the census
//! that would have caught it, exercised across every class the vocabulary
//! names.

mod support;

use std::collections::HashMap;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use resolution_scope_engine::analysis::analyse_domain_with_receipts;
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use support::{key, Canned, Stub};

/// Every control name a scan of `apex.test` asks for, including DKIM's
/// wildcard-detection sentinel — which a ten-name world silently omits, and
/// whose omission looks exactly like a missing receipt. That near-miss is why
/// the sentinel is spelled out here rather than assumed.
const SCANNED: &[(&str, RecordType)] = &[
    ("apex.test", RecordType::DNSKEY),
    ("apex.test", RecordType::TXT),
    ("apex.test", RecordType::MX),
    ("apex.test", RecordType::CAA),
    ("apex.test", RecordType::CDS),
    ("apex.test", RecordType::CDNSKEY),
    ("apex.test", RecordType::CSYNC),
    ("_dmarc.apex.test", RecordType::TXT),
    ("_smtp._tls.apex.test", RecordType::TXT),
    ("_mta-sts.apex.test", RecordType::TXT),
    (
        "resolutionscope-wildcard-probe._domainkey.apex.test",
        RecordType::TXT,
    ),
];

async fn census(world: HashMap<(String, RecordType), Canned>) -> usize {
    let stub = Stub::start_with(world).await;
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    let v = Vantage::build_unvalidating_for_tests(choice).unwrap();
    let (_a, receipts, _r) = analyse_domain_with_receipts(&v, "apex.test", &[])
        .await
        .unwrap();
    receipts.len()
}

fn world_of(c: Canned) -> HashMap<(String, RecordType), Canned> {
    SCANNED
        .iter()
        .map(|(n, rt)| (key(n, *rt), c.clone()))
        .collect()
}

/// REFUSED on every lookup still leaves ten rows.
///
/// This is the regression. Before the `Dns(ResponseCode(..))` arm existed the
/// count here was ZERO — the stub's default for an unknown key is REFUSED, so
/// every control failed into a shape that produced no receipt at all.
#[tokio::test]
async fn every_control_leaves_a_receipt_when_every_lookup_is_refused() {
    assert_eq!(
        census(world_of(Canned::code(ResponseCode::Refused))).await,
        10,
        "a REFUSED scan must still produce one receipt per control — the receipt is the evidence that the question was asked"
    );
}

/// SERVFAIL likewise. A broken upstream is a measurement, not a silence.
#[tokio::test]
async fn every_control_leaves_a_receipt_when_every_lookup_servfails() {
    assert_eq!(
        census(world_of(Canned::code(ResponseCode::ServFail))).await,
        10,
        "a SERVFAIL scan must still produce one receipt per control"
    );
}

/// And the class that always worked, kept as the positive control so a future
/// regression cannot be mistaken for a harness fault.
#[tokio::test]
async fn every_control_leaves_a_receipt_on_nxdomain() {
    assert_eq!(
        census(world_of(Canned::with_soa(
            ResponseCode::NXDomain,
            "apex.test"
        )))
        .await,
        10,
        "the well-handled class must stay at ten"
    );
}
