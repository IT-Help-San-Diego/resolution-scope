//! The DANE existence probe's COST, measured — not derived.
//!
//! docs/MEASUREMENT_SEMANTICS.md carries a COST line for the NXDOMAIN
//! existence probe, and the first version of that line was a DERIVATION that
//! measurement contradicts. It said the DANE scan issues FEWER queries than
//! before because `score_dane` "already issued `lookup(host, SOA)` TWICE per
//! MX host". Both of the pre-probe loops SHORT-CIRCUIT — the attribution loop
//! `break`s at the first resolvable host, the DNSSEC gate `return`s at the
//! first unsigned one — so the old cost was two questions TOTAL, not two per
//! host, and an eager probe over every host made the dominant real-world mail
//! shape DEARER.
//!
//! This file is the meter. It counts host-SOA questions that actually reach a
//! loopback stub for a scan of a domain with N MX hosts, in both regimes of
//! the DnssecRequired gate. Every number in that COST line comes from here.
//!
//! MEASURED, host-SOA questions on the wire (`mxN.provider.test`/SOA):
//!
//!   MX hosts        1    2    3    5
//!   gate ARMED (unsigned provider zone — the Google Workspace / Microsoft
//!   365 shape the gate's own comment cites as its specimen):
//!     pre-probe     2    2    2    2     (fcd282e, the tree before PR #45)
//!     eager  (#45)  1    2    3    5     ← DEARER from three hosts up
//!     lazy   (this) 1    1    1    1
//!   gate NOT ARMED (the gate must read every host's zone, so every host is
//!   reached and no `break` can help):
//!     pre-probe     2    3    4    6
//!     eager  (#45)  1    2    3    5
//!     lazy   (this) 1    2    3    5
//!
//! The pre-probe row was measured the same way, on a worktree at 3935807^,
//! with this file's world and this file's counter.

mod support;

use std::collections::HashMap;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{MX, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use resolution_scope_engine::DaneDisposition;
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

/// `cost.test` with `hosts` MX targets, all in the zone `provider.test` — the
/// third-party-provider shape. Every host EXISTS (its own SOA query answers
/// NODATA under `provider.test`) and publishes no TLSA, so nothing here is a
/// verdict edge case: the scan is the ordinary one whose cost is at issue.
///
/// `gate_armed` is the only other variable. Armed = `provider.test` publishes
/// no DNSKEY (NODATA), which is `Unsigned`, which makes the DnssecRequired
/// gate `return` at the FIRST host. Not armed = the DNSKEY question is REFUSED
/// (`Unreachable`), so the gate falls through and reads every host's zone.
fn cost_world(hosts: usize, gate_armed: bool) -> HashMap<(String, RecordType), Canned> {
    let mut c = HashMap::new();
    let mxs: Vec<Record> = (1..=hosts)
        .map(|i| {
            Record::from_rdata(
                n("cost.test"),
                300,
                RData::MX(MX::new((10 * i) as u16, n(&format!("mx{i}.provider.test")))),
            )
        })
        .collect();
    c.insert(key("cost.test", RecordType::MX), Canned::ok(mxs));
    c.insert(key("cost.test", RecordType::SOA), soa_answer("cost.test"));
    for i in 1..=hosts {
        c.insert(
            key(&format!("mx{i}.provider.test"), RecordType::SOA),
            Canned::with_soa(ResponseCode::NoError, "provider.test"),
        );
        c.insert(
            key(&format!("_25._tcp.mx{i}.provider.test"), RecordType::TLSA),
            Canned::with_soa(ResponseCode::NoError, "provider.test"),
        );
    }
    if gate_armed {
        c.insert(
            key("provider.test", RecordType::DNSKEY),
            Canned::with_soa(ResponseCode::NoError, "provider.test"),
        );
    }
    c
}

/// One scan; returns (host-SOA questions that reached the wire, disposition).
async fn measure(hosts: usize, gate_armed: bool) -> (usize, DaneDisposition) {
    let stub = Stub::start_with(cost_world(hosts, gate_armed)).await;
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    let v = Vantage::build_unvalidating_for_tests(choice).unwrap();
    let a = analyse_domain(&v, "cost.test").await.unwrap();
    let count = stub
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(nm, t, _)| {
            *t == RecordType::SOA && nm.starts_with("mx") && nm.contains("provider.test")
        })
        .count();
    (count, a.dane_disposition)
}

/// THE COST CLAIM, armed. The gate `return`s at the first unsigned host, so a
/// lazy probe asks exactly ONE host-SOA question no matter how long the MX
/// list is. This is the assertion the eager probe fails: it scales with the
/// host count (1, 2, 3, 5) and overtakes the pre-probe cost of 2 at three
/// hosts.
#[tokio::test]
async fn dnssec_gate_armed_costs_one_host_probe_regardless_of_mx_count() {
    for hosts in [1usize, 2, 3, 5] {
        let (count, disposition) = measure(hosts, true).await;
        assert_eq!(
            disposition,
            DaneDisposition::DnssecRequired,
            "mx={hosts}: the world must actually arm the gate, or the count is meaningless"
        );
        assert_eq!(
            count, 1,
            "mx={hosts}: the gate returns at the first host, so exactly one host-SOA \
             question may reach the wire (eager probing asked {hosts})"
        );
    }
}

/// THE COST CLAIM, not armed. Here the gate genuinely needs every host's zone,
/// so the probe count is the host count — and memoisation is what keeps it
/// there: the attribution loop and the gate loop both read host 0, and only
/// ONE question for it may reach the wire. The pre-probe tree spent N+1 (its
/// attribution pass and its gate pass each queried, with no cache between
/// them), so this is strictly cheaper than before at every host count.
#[tokio::test]
async fn dnssec_gate_not_armed_costs_one_host_probe_per_host_not_two() {
    for hosts in [1usize, 2, 3, 5] {
        let (count, disposition) = measure(hosts, false).await;
        assert_eq!(
            disposition,
            DaneDisposition::NotConfigured,
            "mx={hosts}: existing hosts with no TLSA are a measured absence"
        );
        assert_eq!(
            count, hosts,
            "mx={hosts}: one memoised question per host reached — never a second \
             for a host both loops read"
        );
    }
}
