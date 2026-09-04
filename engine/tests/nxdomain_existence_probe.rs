//! The NXDOMAIN existence probe, wired — both controls per guard, every
//! packet on 127.0.0.1.
//!
//! THE DEFECT these tests pin shut. An NXDOMAIN's SOA names the CLOSEST
//! ENCLOSING ZONE THAT EXISTS. It says NOTHING about whether the queried
//! name's own domain exists. Inferring existence from the SOA's label count,
//! dot count, or any other string property of the zone name is a derivation,
//! and it is wrong. Measured live 2026-09-04, one moment, one vantage:
//!
//!   _25._tcp.mail.nosuchdomain-zz9q.co.uk   NXDOMAIN SOA co.uk        Some(0) DEFECT
//!   _25._tcp.mail.nosuchdomain-zz9q.com.au  NXDOMAIN SOA com.au       Some(0) DEFECT
//!   _25._tcp.mail.nosuchdomain-zz9q.com     NXDOMAIN SOA com          None    right by accident
//!   _25._tcp.aspmx.l.google.com             NXDOMAIN SOA l.google.com Some(0) CORRECT
//!
//! The pure mapper controls live in engine/src/analysis.rs beside the
//! mappers. These are the WIRING controls: they kill the mutants a pure test
//! cannot reach — a call site that stops probing, a call site that hardcodes
//! the answer, and the DnssecRequired gate that `return`s BEFORE the TLSA
//! loop and would otherwise bypass the whole repair.
//!
//!   P1  dangling_mx_host_is_not_a_measured_dane_absence
//!       Two scans. ONE canned entry differs — the MX host's own SOA answer.
//!       NXDOMAIN there (the host's domain does not exist) => TransientError
//!       and ZoneUnmeasured; an SOA answer there (the host exists) =>
//!       NotConfigured. Same MX, same TLSA packet, opposite verdicts.
//!   P2  tls_rpt_ancestor_soa_is_decided_by_a_second_query
//!       Two scans of a SUB-LABEL name whose `_smtp._tls` NXDOMAIN carries a
//!       proper-ancestor SOA. The scanned name resolves => RecordAbsent; it
//!       does not => NoZone.
//!   P3  the probe question is actually asked (the stub's own `seen` log)

mod support;

use std::collections::HashMap;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{MX, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::analysis::TlsaZone;
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use resolution_scope_engine::{DaneDisposition, TlsRptDisposition};
use support::{key, Canned, Stub};

fn n(s: &str) -> Name {
    Name::from_ascii(if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{s}.")
    })
    .unwrap()
}

fn soa_answer(owner: &str) -> Canned {
    let soa = SOA::new(
        n("ns1.invalid."),
        n("hostmaster.invalid."),
        1,
        3600,
        600,
        86400,
        3600,
    );
    Canned::ok(vec![Record::from_rdata(n(owner), 3600, RData::SOA(soa))])
}

/// The stub serves unsigned answers, so the vantage must not validate — a
/// validating resolver turns every unsigned NXDOMAIN into a transient failure
/// and no disposition under test is reachable. Same seam the egress-ledger
/// scan tests use.
fn vantage_at(stub: &Stub) -> Vantage {
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    Vantage::build_unvalidating_for_tests(choice).unwrap()
}

/// The canned world for P1, parameterised on the ONE entry under test: what
/// the MX host's own SOA query answers.
///
/// `dangling.test` has one MX, `mail.nx.co.test`, a host inside the registry
/// suffix `co.test`. Its TLSA name answers NXDOMAIN carrying the SOA of
/// `co.test` — the closest enclosing zone that exists — which is EXACTLY the
/// shape the deleted `zone_contains_host` graded as a measured absence,
/// because `co.test` contains a dot.
///
/// `co.test`'s DNSKEY answers NODATA (unsigned). That is deliberate: it arms
/// the DnssecRequired gate, so a scan that scores the ENCLOSING zone as if it
/// were the host's own zone returns `DnssecRequired` and never reaches the
/// TLSA loop at all. Without that arming, mutant M6 (deleting the gate's
/// existence skip) survives.
fn p1_world(host_soa: Canned) -> HashMap<(String, RecordType), Canned> {
    let mut c = HashMap::new();
    c.insert(
        key("dangling.test", RecordType::MX),
        Canned::ok(vec![Record::from_rdata(
            n("dangling.test"),
            300,
            RData::MX(MX::new(10, n("mail.nx.co.test"))),
        )]),
    );
    // The scanned domain is a zone apex and exists.
    c.insert(
        key("dangling.test", RecordType::SOA),
        soa_answer("dangling.test"),
    );
    // THE ENTRY UNDER TEST.
    c.insert(key("mail.nx.co.test", RecordType::SOA), host_soa);
    // The TLSA leg: identical in both scans.
    c.insert(
        key("_25._tcp.mail.nx.co.test", RecordType::TLSA),
        Canned::with_soa(ResponseCode::NXDomain, "co.test"),
    );
    // The enclosing registry suffix is UNSIGNED — this is what makes the
    // DnssecRequired bypass reachable.
    c.insert(
        key("co.test", RecordType::DNSKEY),
        Canned::code(ResponseCode::NoError),
    );
    c
}

/// P1. The DANE half, both controls, one canned entry apart.
#[tokio::test]
async fn dangling_mx_host_is_not_a_measured_dane_absence() {
    // ── NEGATIVE: the MX host's domain does not exist ──────────────────────
    // The host's own SOA query answers NXDOMAIN. Nothing about a TLSA record
    // is measurable at a name that does not exist, so DANE must abstain —
    // and the attribution must abstain with it, because "co.test" is not the
    // host's zone, it is merely the zone that answered.
    let stub = Stub::start_with(p1_world(Canned::with_soa(
        ResponseCode::NXDomain,
        "co.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "dangling.test").await.unwrap();
    assert_eq!(
        a.dane_disposition,
        DaneDisposition::TransientError,
        "a dangling MX target is not a measured DANE absence"
    );
    assert_eq!(
        a.tlsa_zone,
        TlsaZone::ZoneUnmeasured,
        "a host with no zone is not in a FOREIGN zone"
    );
    // P3 — the probe question was actually asked, not assumed.
    assert!(
        stub.saw("mail.nx.co.test", RecordType::SOA),
        "the existence probe must reach the wire"
    );

    // ── POSITIVE: same world, the host EXISTS ─────────────────────────────
    // One canned entry differs: the host's SOA query now answers. The TLSA
    // packet is byte-identical to the negative's, so the probe is the sole
    // variable — and the verdict flips to a measured absence.
    let stub = Stub::start_with(p1_world(soa_answer("mail.nx.co.test"))).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "dangling.test").await.unwrap();
    assert_eq!(
        a.dane_disposition,
        DaneDisposition::NotConfigured,
        "an existing MX host with no TLSA is a measured absence"
    );
    assert_eq!(a.tlsa_zone, TlsaZone::ForeignZone);
}

/// The canned world for P2, parameterised on the ONE entry under test: what
/// the SCANNED NAME's own SOA query answers.
///
/// `sub.exists.test` is scanned; its `_smtp._tls` name answers NXDOMAIN
/// carrying the SOA of the proper ancestor `exists.test`. PR #42 left that
/// shape at `NoZone`, which renders "no zone — domain does not exist" — a
/// false claim whenever the scanned name is live. The packet cannot separate
/// it from `nonexistent.co.uk` under SOA `co.uk`; one query can.
fn p2_world(scanned_soa: Canned) -> HashMap<(String, RecordType), Canned> {
    let mut c = HashMap::new();
    c.insert(
        key("_smtp._tls.sub.exists.test", RecordType::TXT),
        Canned::with_soa(ResponseCode::NXDomain, "exists.test"),
    );
    c.insert(key("sub.exists.test", RecordType::SOA), scanned_soa);
    c
}

/// P2. The TLS-RPT half, both controls, one canned entry apart.
#[tokio::test]
async fn tls_rpt_ancestor_soa_is_decided_by_a_second_query() {
    // ── POSITIVE: the scanned name EXISTS (NODATA on its SOA — a leaf name
    // that is not a zone apex). Only `_smtp._tls.<name>` is absent.
    let stub = Stub::start_with(p2_world(Canned::with_soa(
        ResponseCode::NoError,
        "exists.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "sub.exists.test").await.unwrap();
    assert_eq!(
        a.tls_rpt_disposition,
        TlsRptDisposition::RecordAbsent,
        "a live sub-label name must not be told it does not exist"
    );
    assert!(
        stub.saw("sub.exists.test", RecordType::SOA),
        "the existence probe must reach the wire"
    );

    // ── NEGATIVE: structurally identical packet, the scanned name is GONE.
    let stub = Stub::start_with(p2_world(Canned::with_soa(
        ResponseCode::NXDomain,
        "exists.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "sub.exists.test").await.unwrap();
    assert_eq!(
        a.tls_rpt_disposition,
        TlsRptDisposition::NoZone,
        "a name that does not exist keeps NoZone, and there the claim is true"
    );
}

/// The probe is NOT spent when the packet already decides. An apex scan whose
/// `_smtp._tls` NXDOMAIN carries the domain's OWN SOA takes the exact-equality
/// shortcut, and no SOA question for the scanned name is ever asked. This is
/// the cost claim's control: without it, "zero extra queries on the common
/// case" is an assertion rather than a measurement.
#[tokio::test]
async fn apex_scan_spends_no_probe_on_tls_rpt() {
    let mut c = HashMap::new();
    c.insert(
        key("_smtp._tls.apex.test", RecordType::TXT),
        Canned::with_soa(ResponseCode::NXDomain, "apex.test"),
    );
    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "apex.test").await.unwrap();
    assert_eq!(a.tls_rpt_disposition, TlsRptDisposition::RecordAbsent);
    // DANE's MX lookup is REFUSED here, so nothing else asks for this SOA.
    assert!(
        !stub.saw("apex.test", RecordType::SOA),
        "the exact-equality shortcut must not spend a query"
    );
}
