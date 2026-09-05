//! The sub-label repair's COST, measured — not derived (2026-09-04, hermes).
//!
//! The #49 semantics entry's COST line is prose ("at most ONE extra wire
//! query per control"), and the semantics-numbers gate only covers tagged
//! blocks — so until this file + its tagged block land, those numbers are
//! testimony. This file is the meter, same shape as dane_probe_cost.rs: it
//! counts SOA questions for the SCANNED NAME that actually reach a loopback
//! stub, in the one regime that matters (ancestor-SOA NXDOMAIN on both
//! `_dmarc` and `_mta-sts`, live scanned name).
//!
//! The question worth MEASURING rather than deriving: `_dmarc` and
//! `_mta-sts` each spend their own `name_exists` probe in their own Err arm,
//! and both probes ask the SAME question (SOA at the scanned name). Does the
//! second ride a resolver cache, or does the wire see two? MEASURED: the
//! wire sees TWO. The test vantage has no cache between sequential control
//! scans — the same property dane_probe_cost.rs documented for the pre-probe
//! DANE tree ("its attribution pass and its gate pass each queried, with no
//! cache between them", which is why #47 needed an EXPLICIT memo). My first
//! draft of this file asserted 1 and FAILED at the meter — the assumption
//! was falsified before it could ship into the document, which is this
//! whole arc working.
//!
//! MEASURED (SOA questions for the scanned name on the wire, one scan):
//!
//!   world                                  questions
//!   _dmarc + _mta-sts both ancestor-SOA    2 — one per control; the probes
//!                                          are NOT shared across controls
//!                                          (a shared memoised probe is the
//!                                          carded follow-up, named in the
//!                                          #49 semantics entry)
//!   neither leg probe-eligible (packet
//!   decides / NODATA)                      0
//!   scanned name GONE (probe answers
//!   NXDOMAIN; both abstain)                2 — both probes are spent even
//!                                          though both verdicts abstain

mod support;

use std::collections::HashMap;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use support::{key, Canned, Stub};

/// `sub.exists.test` scanned; the ONE variable is the scanned name's own SOA
/// answer. `_dmarc` and `_mta-sts` both NXDOMAIN under the proper ancestor
/// `exists.test`.
fn sublabel_cost_world(scanned_soa: Canned) -> HashMap<(String, RecordType), Canned> {
    let mut c = HashMap::new();
    c.insert(
        key("_dmarc.sub.exists.test", RecordType::TXT),
        Canned::with_soa(ResponseCode::NXDomain, "exists.test"),
    );
    c.insert(
        key("_mta-sts.sub.exists.test", RecordType::TXT),
        Canned::with_soa(ResponseCode::NXDomain, "exists.test"),
    );
    c.insert(key("sub.exists.test", RecordType::SOA), scanned_soa);
    c
}

fn vantage_at(stub: &Stub) -> Vantage {
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    Vantage::build_unvalidating_for_tests(choice).unwrap()
}

/// One scan; returns (SOA questions for the scanned name that reached the
/// wire, dmarc disposition).
async fn measure(scanned_soa: Canned) -> (usize, resolution_scope_engine::DmarcDisposition) {
    let stub = Stub::start_with(sublabel_cost_world(scanned_soa)).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "sub.exists.test").await.unwrap();
    let count = stub
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(nm, t, _)| *t == RecordType::SOA && nm == "sub.exists.test.")
        .count();
    (count, a.dmarc_disposition)
}

/// THE COST CLAIM, as measured: two probe-eligible legs, TWO questions on
/// the wire — each control spends its own probe, and nothing shares them.
/// This is the number the #49 entry's COST line must be read against ("at
/// most ONE extra wire query per control" — one per CONTROL, not one per
/// SCAN). If a future shared-memo PR lands, this count flips to 1 and this
/// assertion + the doc's COST line change in the same commit.
#[tokio::test]
async fn two_probe_eligible_legs_cost_two_wire_questions() {
    let (count, d) = measure(Canned::with_soa(ResponseCode::NoError, "exists.test")).await;
    assert_eq!(
        d,
        resolution_scope_engine::DmarcDisposition::NotConfigured,
        "the world must arm the probe path (live name) or the count is meaningless"
    );
    assert_eq!(
        count, 2,
        "one question per control — the probes are not shared across controls; \
         a shared memo would make this 1 and must change the doc in the same commit"
    );
}

/// The probes are still spent when the name does not exist — both controls
/// abstain, but both measurements were taken (one question each; the verdict
/// does not claw back the query).
#[tokio::test]
async fn a_nonexistent_name_still_spends_both_probes() {
    let (count, d) = measure(Canned::with_soa(ResponseCode::NXDomain, "exists.test")).await;
    assert_eq!(
        d,
        resolution_scope_engine::DmarcDisposition::TransientError,
        "a gone name keeps the abstention"
    );
    assert_eq!(
        count, 2,
        "both controls' probes reach the wire even when both verdicts abstain"
    );
}

/// The packet-decides shape spends NOTHING. Apex-style: `_dmarc` NXDOMAIN
/// carrying the scanned name's own SOA. (MTA-STS stays ancestor-SOA here —
/// this pins the DMARC zero-cost arm and, by symmetry with the inert-probe
/// control in analysis.rs, the never-probe principle for the packet-decided
/// control.)
#[tokio::test]
async fn packet_decided_leg_spends_no_probe() {
    let mut c = HashMap::new();
    c.insert(
        key("_dmarc.decided.test", RecordType::TXT),
        Canned::with_soa(ResponseCode::NXDomain, "decided.test"),
    );
    // _mta-sts also exact-equality so no probe from it either.
    c.insert(
        key("_mta-sts.decided.test", RecordType::TXT),
        Canned::with_soa(ResponseCode::NXDomain, "decided.test"),
    );
    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "decided.test").await.unwrap();
    assert_eq!(
        a.dmarc_disposition,
        resolution_scope_engine::DmarcDisposition::NotConfigured,
        "exact-equality arm: a measured absence with no probe"
    );
    let count = stub
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(nm, t, _)| *t == RecordType::SOA && nm == "decided.test.")
        .count();
    assert_eq!(
        count, 0,
        "the exact-equality shortcut must not spend a query"
    );
}
