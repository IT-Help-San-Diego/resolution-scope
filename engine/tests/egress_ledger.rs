//! The egress ledger, both controls per guard, all on 127.0.0.1:0.
//!
//!   E1  negative_control_stub_only          a scan through a loopback stub as
//!                                           the sole server: the ledger's
//!                                           destination set is exactly the stub
//!   E2  detector_sees_foreign_destination   the control of the control: a
//!                                           vantage at a DIFFERENT loopback
//!                                           port is recorded at that port —
//!                                           the ledger reports the wire, not
//!                                           the configured address
//!   E4  transport_token_matches_the_socket  `/tcp` records only tcp
//!                                           connections, zero datagrams;
//!                                           plain records udp datagrams
//!   E5  mta_sts_fetch_attempt_is_observable the HTTPS line rests on a
//!                                           socket-layer fact: a listener
//!                                           accepts exactly once when the
//!                                           hint is present, never when absent
//!   E6  resolve_hook_returns_port_zero      the vantage's DNS hook yields port
//!                                           0 so hyper substitutes the URL port
//!
//! E3 (failed_send_is_never_recorded) lives beside the ledger in
//! engine/src/egress.rs, where the send-result seam is.

mod support;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hickory_proto::rr::rdata::{A, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use resolution_scope_engine::analysis::analyse_domain;
use resolution_scope_engine::egress::{FetchOutcome, Layer};
use resolution_scope_engine::resolver::{ResolverChoice, Vantage, VantageResolve};
use support::{key, Canned, Stub};

fn vantage_at(stub: &Stub) -> Vantage {
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    Vantage::build(choice).unwrap()
}

#[tokio::test]
async fn negative_control_stub_only() {
    let stub = Stub::start().await;
    let v = vantage_at(&stub);
    let a = analyse_domain(&v, "example.test").await.unwrap();
    assert_eq!(a.domain, "example.test");
    let snap = v.ledger().drain();
    let want: std::collections::BTreeSet<SocketAddr> = [stub.addr].into_iter().collect();
    assert_eq!(
        snap.destinations(),
        want,
        "every datagram went to the stub and nowhere else"
    );
    assert!(snap.datagrams_sent > 0);
    assert_eq!(snap.tcp_connects, 0);
    assert_eq!(snap.quic_connections, 0);
    assert_eq!(snap.undecoded_datagrams, 0, "our own datagrams decode");
    assert!(
        snap.cleartext_qnames.iter().any(|q| q == "example.test."),
        "the scanned name left in the clear: {:?}",
        &snap.cleartext_qnames[..snap.cleartext_qnames.len().min(8)]
    );
    // The ledger and the stub agree on the count of what left.
    assert_eq!(
        snap.datagrams_sent,
        stub.seen_count(),
        "ledger datagrams == questions the stub received"
    );
}

#[tokio::test]
async fn detector_sees_foreign_destination() {
    let home = Stub::start().await;
    let foreign = Stub::start().await;
    assert_ne!(home.addr, foreign.addr);
    // A vantage at the FOREIGN port: the ledger must say so.
    let v = vantage_at(&foreign);
    let _ = v.lookup("example.test", RecordType::A).await;
    let snap = v.ledger().drain();
    let home_set: std::collections::BTreeSet<SocketAddr> = [home.addr].into_iter().collect();
    let foreign_set: std::collections::BTreeSet<SocketAddr> = [foreign.addr].into_iter().collect();
    assert_ne!(
        snap.destinations(),
        home_set,
        "the detector must not be blind to where datagrams went"
    );
    assert_eq!(snap.destinations(), foreign_set);
    assert_eq!(home.seen_count(), 0);
    assert!(foreign.seen_count() > 0);
}

#[tokio::test]
async fn transport_token_matches_the_socket() {
    let stub = Stub::start().await;
    let port = stub.addr.port();

    // `/tcp`: every connection hickory asked for is tcp; zero datagrams.
    let tcp: ResolverChoice = format!("tcp://127.0.0.1#{port}").parse().unwrap();
    let v = Vantage::build(tcp).unwrap();
    let _ = v.lookup("example.test", RecordType::A).await;
    let snap = v.ledger().drain();
    let protocols: Vec<&str> = snap
        .entries
        .iter()
        .filter_map(|e| match &e.layer {
            Layer::Connection { protocol, .. } => Some(*protocol),
            _ => None,
        })
        .collect();
    assert!(!protocols.is_empty());
    assert!(protocols.iter().all(|p| *p == "tcp"), "{protocols:?}");
    assert_eq!(
        snap.datagrams_sent, 0,
        "a TCP-only vantage sends no datagrams"
    );
    assert!(
        snap.tcp_connects >= 1,
        "the TCP connect completed at the stub"
    );
    assert!(stub.seen_via("tcp") > 0 && stub.seen_via("udp") == 0);

    // Plain: udp seen, datagrams counted.
    let v = vantage_at(&stub);
    let _ = v.lookup("example.test", RecordType::A).await;
    let snap = v.ledger().drain();
    assert!(snap.entries.iter().any(|e| matches!(
        &e.layer,
        Layer::Connection {
            protocol: "udp",
            ..
        }
    )));
    assert!(snap.datagrams_sent > 0);
    assert_eq!(snap.per_destination[0].1.protocol, "udp");
}

#[tokio::test]
async fn mta_sts_fetch_attempt_is_observable_without_a_cert() {
    // A listener that accepts and closes: the fetch can never succeed (no
    // certificate), but the ACCEPT is the socket-layer fact the HTTPS line
    // needs.
    async fn listener() -> (SocketAddr, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let a = accepted.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                a.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });
        (addr, accepted)
    }

    // Positive: the hint is present → the fetch is attempted → accept fires once.
    let mut canned = HashMap::new();
    canned.insert(
        key("_mta-sts.example.test", RecordType::TXT),
        Canned::ok(vec![Record::from_rdata(
            Name::from_ascii("_mta-sts.example.test.").unwrap(),
            300,
            RData::TXT(TXT::new(vec!["v=STSv1; id=1".to_string()])),
        )]),
    );
    let stub = Stub::start_with(canned).await;
    let (addr, accepted) = listener().await;
    // Unvalidating (test seam): a loopback stub serves no DNSSEC chain, and
    // hickory's validator returns the chain-walk's REFUSED as the lookup's
    // own error, so the canned TXT would never reach the scorer.
    let v = Vantage::build_unvalidating_for_tests(stub.choice_plain().parse().unwrap())
        .unwrap()
        .with_fetch_override("mta-sts.example.test", addr);
    let a = analyse_domain(&v, "example.test").await.unwrap();
    let snap = v.ledger().drain();
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "exactly one connection reached the policy host"
    );
    assert_eq!(snap.fetches.len(), 1, "one fetch entry for the policy URL");
    let f = &snap.fetches[0];
    assert_eq!(
        f.url,
        "https://mta-sts.example.test/.well-known/mta-sts.txt"
    );
    assert_eq!(f.host, "mta-sts.example.test");
    assert_eq!(f.via, v.identity());
    assert!(
        matches!(
            f.outcome,
            FetchOutcome::TlsError(_) | FetchOutcome::ConnectError(_)
        ),
        "a closed socket is a failed handshake or connection, never a status: {:?}",
        f.outcome
    );
    assert_ne!(f.outcome, FetchOutcome::NotAttempted);
    assert_eq!(
        a.mta_sts_disposition,
        resolution_scope_engine::MtaStsDisposition::PolicyInvalid,
        "hint present, policy not servable"
    );

    // Negative: no hint → nothing fetched, nothing accepted, no entry.
    let stub = Stub::start().await;
    let (addr, accepted) = listener().await;
    let v = vantage_at(&stub).with_fetch_override("mta-sts.example.test", addr);
    let a = analyse_domain(&v, "example.test").await.unwrap();
    let snap = v.ledger().drain();
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(snap.fetches.is_empty());
    assert_ne!(
        a.mta_sts_disposition,
        resolution_scope_engine::MtaStsDisposition::PolicyInvalid
    );
}

#[tokio::test]
async fn resolve_hook_returns_port_zero() {
    let mut canned = HashMap::new();
    canned.insert(
        key("mta-sts.example.test", RecordType::A),
        Canned::ok(vec![Record::from_rdata(
            Name::from_ascii("mta-sts.example.test.").unwrap(),
            300,
            RData::A(A::new(127, 0, 0, 1)),
        )]),
    );
    let stub = Stub::start_with(canned).await;
    let v = Vantage::build_unvalidating_for_tests(stub.choice_plain().parse().unwrap()).unwrap();
    let hook = VantageResolve::new(v.resolver().clone());
    let name: reqwest::dns::Name = "mta-sts.example.test".parse().unwrap();
    let addrs: Vec<SocketAddr> = reqwest::dns::Resolve::resolve(&hook, name)
        .await
        .expect("the stub answers A")
        .collect();
    assert!(!addrs.is_empty());
    assert!(addrs.iter().all(|a| a.port() == 0), "{addrs:?}");
    assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    // And the lookup went through the ledger like every other.
    let snap = v.ledger().drain();
    assert!(snap
        .cleartext_qnames
        .iter()
        .any(|q| q == "mta-sts.example.test."));
}
