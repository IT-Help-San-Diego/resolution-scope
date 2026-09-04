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
use resolution_scope_engine::{
    DaneDisposition, DmarcDisposition, MtaStsDisposition, TlsRptDisposition,
};
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

// ─────────────────────────────────────────────────────────────────────────────
// P7-P8 — the SUB-LABEL UNDER-CLAIM repair (2026-09-04, hermes lane).
//
// `record_absence_verdict` stays exact-equality (pinned in the pure tests);
// the mappers for `_dmarc` and `_mta-sts` now consult ONE existence probe
// when the NXDOMAIN's SOA is a PROPER ANCESTOR of the scanned name — the
// item MEASUREMENT_SEMANTICS named as "knowingly out of scope" of #47:
// "under-claims on sub-label scans — `_dmarc` and `_mta-sts` NXDOMAIN under
// an ancestor SOA read Indet (could not measure) for a record that is
// genuinely absent. That direction loses a measurement but never asserts a
// falsehood." Same packet shape, same one-query repair TLS-RPT already
// carries; this closes the asymmetry the #47 entry called "conspicuous".

/// The canned world for P7/P8, parameterised on the ONE entry under test:
/// what the SCANNED NAME's own SOA query answers. Both `_dmarc` and
/// `_mta-sts` NXDOMAIN carry the SOA of the proper ancestor `exists.test`.
fn sublabel_world(scanned_soa: Canned) -> HashMap<(String, RecordType), Canned> {
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

/// P7. The `_dmarc` half, both controls, one canned entry apart. Before the
/// repair a live sub-label name read TransientError ("could not measure")
/// for a record that is genuinely absent — the measurement was LOST, never
/// a false claim. After: NotConfigured (a measured absence, back in both
/// score sums) when the name exists; the abstention kept when it does not.
#[tokio::test]
async fn dmarc_ancestor_soa_is_decided_by_a_second_query() {
    // ── POSITIVE: the scanned name EXISTS (NODATA on its SOA). The whole
    // world is byte-identical to the negative below except this one entry.
    let stub = Stub::start_with(sublabel_world(Canned::with_soa(
        ResponseCode::NoError,
        "exists.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "sub.exists.test").await.unwrap();
    assert_eq!(
        a.dmarc_disposition,
        DmarcDisposition::NotConfigured,
        "a live sub-label name's _dmarc absence is MEASURED, not unmeasured"
    );
    assert!(
        stub.saw("sub.exists.test", RecordType::SOA),
        "the existence probe must reach the wire"
    );

    // ── NEGATIVE: structurally identical packet, the scanned name is GONE.
    let stub = Stub::start_with(sublabel_world(Canned::with_soa(
        ResponseCode::NXDomain,
        "exists.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "sub.exists.test").await.unwrap();
    assert_eq!(
        a.dmarc_disposition,
        DmarcDisposition::TransientError,
        "a name that does not exist keeps the abstention"
    );
}

/// P8. The `_mta-sts` half, same shape.
#[tokio::test]
async fn mta_sts_ancestor_soa_is_decided_by_a_second_query() {
    let stub = Stub::start_with(sublabel_world(Canned::with_soa(
        ResponseCode::NoError,
        "exists.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "sub.exists.test").await.unwrap();
    assert_eq!(
        a.mta_sts_disposition,
        MtaStsDisposition::RecordAbsent,
        "a live sub-label name's _mta-sts absence is MEASURED, not unmeasured"
    );
    assert!(stub.saw("sub.exists.test", RecordType::SOA));

    let stub = Stub::start_with(sublabel_world(Canned::with_soa(
        ResponseCode::NXDomain,
        "exists.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "sub.exists.test").await.unwrap();
    assert_eq!(
        a.mta_sts_disposition,
        MtaStsDisposition::TransientError,
        "a name that does not exist keeps the abstention"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P4-P6 — the classes PR #45 shipped without a control (2026-09-04).
//
// P4  A host that EXISTS whose PROBE cannot answer. The probe added a new way
//     for a correctly-configured domain's DANE row to move, and neither the
//     Moves list nor any test named it: NotConfigured -> TransientError, which
//     is Absent -> Indet, Low -> Unmeasured, and the control LEAVES the
//     denominator, so coverage and the risk-weighted score both move.
// P5  A MIXED MX list. Every wired probe control shipped with #45 used ONE MX
//     host, so the per-host INDEX — the thing that carries each measurement to
//     the right host — was unpinned, and `host_exists[i] -> host_exists[0]`
//     survived the whole suite.
// P6  The packet that decides by itself. When the TLSA NXDOMAIN's SOA names
//     the host EXACTLY, the zone answered for itself and no probe is asked;
//     that case must therefore be IMMUNE to a probe that cannot answer.
// ─────────────────────────────────────────────────────────────────────────────

/// The F2 world: the ordinary third-party-provider shape. `f2.test` has one
/// MX, `mx.provider.test`, a host that EXISTS in a zone that is not the
/// scanned domain's. Its TLSA name answers NXDOMAIN carrying the SOA of the
/// proper ancestor `provider.test`, so the packet alone cannot decide and the
/// probe is consulted. `provider.test`'s DNSKEY is REFUSED (`Unreachable`), so
/// the DnssecRequired gate does not fire and the TLSA loop is reached.
///
/// The parameter is the host's own SOA answer — the probe, and nothing else.
fn p4_world(host_soa: Canned) -> HashMap<(String, RecordType), Canned> {
    let mut c = HashMap::new();
    c.insert(
        key("f2.test", RecordType::MX),
        Canned::ok(vec![Record::from_rdata(
            n("f2.test"),
            300,
            RData::MX(MX::new(10, n("mx.provider.test"))),
        )]),
    );
    c.insert(key("f2.test", RecordType::SOA), soa_answer("f2.test"));
    // THE ENTRY UNDER TEST.
    c.insert(key("mx.provider.test", RecordType::SOA), host_soa);
    c.insert(
        key("_25._tcp.mx.provider.test", RecordType::TLSA),
        Canned::with_soa(ResponseCode::NXDomain, "provider.test"),
    );
    c
}

/// P4. An existing, correctly-configured MX host whose EXISTENCE PROBE is
/// REFUSED reads `TransientError`, not `NotConfigured`. Both controls; the
/// TLSA packet is byte-identical across them, so the probe's own answer is the
/// only variable.
///
/// This is a REGRESSION CLASS, recorded rather than argued away: nothing at
/// the domain changed, the host exists and is configured exactly as before,
/// and a query that the instrument newly asks — not any measurement of the
/// domain — moved the verdict out of the denominator. The abstention is the
/// right verdict for an unanswerable probe (the alternative is claiming an
/// absence nothing measured), and the honest accounting is to name the class,
/// which docs/MEASUREMENT_SEMANTICS.md now does.
#[tokio::test]
async fn an_existing_host_whose_probe_is_refused_abstains_rather_than_claiming_absence() {
    // ── POSITIVE: the probe answers. The host exists; no TLSA is a measured
    // absence.
    let stub = Stub::start_with(p4_world(Canned::with_soa(
        ResponseCode::NoError,
        "provider.test",
    )))
    .await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "f2.test").await.unwrap();
    assert_eq!(
        a.dane_disposition,
        DaneDisposition::NotConfigured,
        "an existing provider-hosted MX with no TLSA is a measured absence"
    );
    assert_eq!(a.tlsa_zone, TlsaZone::ForeignZone);

    // ── NEGATIVE: the probe is REFUSED. Nothing about the host changed.
    let stub = Stub::start_with(p4_world(Canned::code(ResponseCode::Refused))).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "f2.test").await.unwrap();
    assert_eq!(
        a.dane_disposition,
        DaneDisposition::TransientError,
        "an unanswerable probe must abstain — it may not be spent as an absence"
    );
    assert_eq!(
        a.tlsa_zone,
        TlsaZone::ZoneUnmeasured,
        "no zone was measured for the host, so none may be attributed"
    );
}

/// P5a. A MIXED MX list, existing host FIRST, dangling host SECOND — the
/// arrangement that pins the per-host index.
///
/// `mx1.provider.test` exists (its TLSA NXDOMAIN under an ancestor SOA is a
/// MEASURED absence, `Some(0)`); `gone.nx.co.test` does not (`None`, nothing
/// measurable at a name whose domain is gone). The fold takes any `None` to
/// `TransientError`. Carry host 1's measurement to host 2 — the
/// `host_probe_at(..., i) -> host_probe_at(..., 0)` mutant — and BOTH hosts
/// read `Some(0)`, the fold reads `NotConfigured`, and this assertion fails.
/// A single-host world cannot make that mutation observable at all.
#[tokio::test]
async fn a_mixed_mx_list_carries_each_hosts_own_measurement() {
    let mut c = HashMap::new();
    c.insert(
        key("mixed.test", RecordType::MX),
        Canned::ok(vec![
            Record::from_rdata(
                n("mixed.test"),
                300,
                RData::MX(MX::new(10, n("mx1.provider.test"))),
            ),
            Record::from_rdata(
                n("mixed.test"),
                300,
                RData::MX(MX::new(20, n("gone.nx.co.test"))),
            ),
        ]),
    );
    c.insert(key("mixed.test", RecordType::SOA), soa_answer("mixed.test"));
    // Host 1 EXISTS (NODATA on its own SOA, under provider.test).
    c.insert(
        key("mx1.provider.test", RecordType::SOA),
        Canned::with_soa(ResponseCode::NoError, "provider.test"),
    );
    // Host 2's domain does NOT exist.
    c.insert(
        key("gone.nx.co.test", RecordType::SOA),
        Canned::with_soa(ResponseCode::NXDomain, "co.test"),
    );
    // Both TLSA legs are the SAME shape: NXDOMAIN under a proper-ancestor SOA.
    // Only the per-host probe separates them.
    c.insert(
        key("_25._tcp.mx1.provider.test", RecordType::TLSA),
        Canned::with_soa(ResponseCode::NXDomain, "provider.test"),
    );
    c.insert(
        key("_25._tcp.gone.nx.co.test", RecordType::TLSA),
        Canned::with_soa(ResponseCode::NXDomain, "co.test"),
    );
    // The registry suffix is UNSIGNED: if the gate ever read the dead host's
    // enclosing zone as its own, the scan would return DnssecRequired instead.
    c.insert(
        key("co.test", RecordType::DNSKEY),
        Canned::code(ResponseCode::NoError),
    );

    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "mixed.test").await.unwrap();
    assert_eq!(
        a.dane_disposition,
        DaneDisposition::TransientError,
        "host 2's domain is gone — its own measurement, not host 1's, decides its count"
    );
    assert_eq!(
        a.tlsa_zone,
        TlsaZone::ForeignZone,
        "attribution follows the FIRST resolvable host"
    );
    assert!(stub.saw("mx1.provider.test", RecordType::SOA));
    assert!(stub.saw("gone.nx.co.test", RecordType::SOA));
}

/// P5b. The same mixed list with the DANGLING host FIRST — the attribution
/// loop's skip, on a list where skipping actually changes the answer.
///
/// `gone.mixed.test` does not exist, and the NXDOMAIN that says so carries the
/// SOA of `mixed.test` — the scanned domain's own zone, because that is the
/// closest enclosing zone that exists. Attribute the dead host to that zone
/// and the sealed `tlsa_zone` reads `SameZone`: "this domain operates its own
/// mail", asserted about a host with no zone at all. Skipping it, the
/// attribution falls to the live host and reads `ForeignZone`.
#[tokio::test]
async fn a_dangling_primary_mx_does_not_claim_the_scanned_domains_zone() {
    let mut c = HashMap::new();
    c.insert(
        key("mixed.test", RecordType::MX),
        Canned::ok(vec![
            Record::from_rdata(
                n("mixed.test"),
                300,
                RData::MX(MX::new(10, n("gone.mixed.test"))),
            ),
            Record::from_rdata(
                n("mixed.test"),
                300,
                RData::MX(MX::new(20, n("mx1.provider.test"))),
            ),
        ]),
    );
    c.insert(key("mixed.test", RecordType::SOA), soa_answer("mixed.test"));
    c.insert(
        key("gone.mixed.test", RecordType::SOA),
        Canned::with_soa(ResponseCode::NXDomain, "mixed.test"),
    );
    c.insert(
        key("mx1.provider.test", RecordType::SOA),
        Canned::with_soa(ResponseCode::NoError, "provider.test"),
    );
    c.insert(
        key("_25._tcp.gone.mixed.test", RecordType::TLSA),
        Canned::with_soa(ResponseCode::NXDomain, "mixed.test"),
    );
    c.insert(
        key("_25._tcp.mx1.provider.test", RecordType::TLSA),
        Canned::with_soa(ResponseCode::NXDomain, "provider.test"),
    );

    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "mixed.test").await.unwrap();
    assert_eq!(
        a.tlsa_zone,
        TlsaZone::ForeignZone,
        "a host that does not exist may not be attributed to the zone that \
         merely answered its NXDOMAIN"
    );
    assert_eq!(
        a.dane_disposition,
        DaneDisposition::TransientError,
        "the dangling host contributes None, and the fold abstains"
    );
}

/// P6. The packet that decides by itself is IMMUNE to a probe that cannot
/// answer. `_25._tcp.mx.provider.test` NXDOMAIN carrying the SOA of
/// `mx.provider.test` — the host ITSELF — proves the host exists, because a
/// zone that answers for itself demonstrably exists. So the host-SOA question
/// is never asked for this decision, the P4 exposure does not apply, and the
/// verdict must stay `NotConfigured` even with the probe REFUSED.
#[tokio::test]
async fn an_exact_soa_tlsa_nxdomain_is_immune_to_an_unanswerable_probe() {
    let mut c = p4_world(Canned::code(ResponseCode::Refused));
    c.insert(
        key("_25._tcp.mx.provider.test", RecordType::TLSA),
        Canned::with_soa(ResponseCode::NXDomain, "mx.provider.test"),
    );
    let stub = Stub::start_with(c).await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "f2.test").await.unwrap();
    assert_eq!(
        a.dane_disposition,
        DaneDisposition::NotConfigured,
        "the SOA names the host itself — the packet already proves existence, \
         so a failed probe cannot move this verdict"
    );
}
