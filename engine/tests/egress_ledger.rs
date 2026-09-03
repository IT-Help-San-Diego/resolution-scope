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
//!   E7  policy_host_is_resolved_through_the_vantage_client
//!                                           the client itself (no override)
//!                                           asks the vantage's stub for the
//!                                           policy host; a second stub sees
//!                                           nothing; the connect goes to the
//!                                           loopback address the stub answered
//!                                           — E5's override answers BEFORE the
//!                                           hook, so E5 cannot pin this
//!   E8  fetch_failures_are_classified_by_layer
//!                                           an alert after the ClientHello →
//!                                           TlsError and the name WAS in the
//!                                           ClientHello; a closed port →
//!                                           ConnectError; no A record →
//!                                           Unresolved. reqwest's Display is
//!                                           byte-identical for the first two
//!   E9  peer_is_the_socket_the_response_came_over
//!                                           `FetchEntry.peer` is getpeername
//!                                           on the response's socket, equal
//!                                           to the listener that answered and
//!                                           never taken from the lookup
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
    assert_eq!(snap.quic_sockets, 0);
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
    // The listener ACCEPTED, so the TCP connect completed; what failed is
    // the TLS handshake (EOF after the ClientHello left). Never a
    // ConnectError — that would print "no TLS handshake began", and the
    // accept says otherwise. (Before E8 this arm accepted either variant
    // and so could not fail on the SNI claim.)
    assert!(
        matches!(f.outcome, FetchOutcome::TlsError(_)),
        "an accepted-then-closed socket is a failed handshake, never a status or a connect failure: {:?}",
        f.outcome
    );
    assert_eq!(f.peer, None, "no response, so no measured peer");
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

/// E7 — the policy host is resolved THROUGH THE VANTAGE by the client itself.
///
/// No `with_fetch_override`: reqwest's `.resolve()` override answers BEFORE
/// the custom resolver is consulted, so E5 never exercises the hook — two
/// mutants of `Vantage::http_client` survive E5/E6: (1) delete the
/// `.dns_resolver(..)` call (hyper-util's GaiResolver then asks libc, i.e.
/// the SYSTEM stub, for `mta-sts.example.test` — a cleartext leak under
/// every choice); (2) hand the hook a resolver built from a different config
/// (`Vantage::build(ResolverChoice::default())`'s, say) instead of
/// `self.resolver`. Under either mutant the vantage's stub never sees the
/// question (libc / Cloudflare get it, and NXDOMAIN it) and the failure is
/// `Unresolved`, so both assertions below fire.
///
/// Positive control: the stub answers `mta-sts.example.test` A with
/// 127.0.0.1 — an address libc would never return for that name — and the
/// client's connect goes there. macOS lets an unprivileged process bind
/// 127.0.0.1:443, so where that bind succeeds the connect is observed as an
/// ACCEPT on the loopback listener (the strong form); where it does not
/// (Linux CI, or 443 in use) the connect is observed as a socket-stage
/// `ConnectError` to a resolved address (never `Unresolved`), which the two
/// mutants cannot produce either. Both forms are printed so the run says
/// which it took.
#[tokio::test]
async fn policy_host_is_resolved_through_the_vantage_client() {
    let mut canned = HashMap::new();
    canned.insert(
        key("mta-sts.example.test", RecordType::A),
        Canned::ok(vec![Record::from_rdata(
            Name::from_ascii("mta-sts.example.test.").unwrap(),
            300,
            RData::A(A::new(127, 0, 0, 1)),
        )]),
    );
    let home = Stub::start_with(canned).await;
    let other = Stub::start().await;
    let v = Vantage::build_unvalidating_for_tests(home.choice_plain().parse().unwrap()).unwrap();

    // The strong form's listener, when 127.0.0.1:443 is bindable here.
    let accepted = Arc::new(AtomicUsize::new(0));
    let strong = match tokio::net::TcpListener::bind("127.0.0.1:443").await {
        Ok(l) => {
            let a = accepted.clone();
            tokio::spawn(async move {
                while let Ok((s, _)) = l.accept().await {
                    a.fetch_add(1, Ordering::SeqCst);
                    drop(s);
                }
            });
            true
        }
        Err(e) => {
            eprintln!("E7: 127.0.0.1:443 not bindable here ({e}); taking the connect-error form");
            false
        }
    };

    let err = v
        .http_client()
        .unwrap()
        .get("https://mta-sts.example.test/.well-known/mta-sts.txt")
        .send()
        .await
        .expect_err("nothing serves a policy on loopback 443");

    // Who was asked: the vantage's stub, and only it.
    assert!(
        home.saw("mta-sts.example.test", RecordType::A),
        "the vantage's stub was asked for the policy host: {:?}",
        home.seen.lock().unwrap()
    );
    assert_eq!(
        other.seen_count(),
        0,
        "the control stub, which the vantage does not point at, saw nothing"
    );
    let snap = v.ledger().drain();
    assert!(
        snap.cleartext_qnames
            .iter()
            .any(|q| q == "mta-sts.example.test."),
        "the lookup went through the ledger like every other"
    );
    // Where the connect went: the address the stub answered.
    let outcome = FetchOutcome::classify(&err);
    if strong {
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the connect reached 127.0.0.1:443 — the address the vantage's stub answered: {outcome:?}"
        );
        assert!(
            matches!(outcome, FetchOutcome::TlsError(_)),
            "accepted then closed: the TLS stage, not resolution or connect: {outcome:?}"
        );
        eprintln!("E7: strong form — accept observed on 127.0.0.1:443");
    } else {
        match &outcome {
            FetchOutcome::ConnectError(chain) => assert!(
                chain.contains("tcp connect error"),
                "the failure is at the socket, to a resolved address: {chain}"
            ),
            other => panic!("resolved through the vantage, so the failure is past DNS: {other:?}"),
        }
        eprintln!("E7: connect-error form — {outcome:?}");
    }
}

/// E8 — fetch failures are classified from the error's SOURCE CHAIN by the
/// layer that failed. reqwest's `Display` is byte-identical for a TLS
/// failure and a refused connect, so the old substring classifier
/// ("certificate" / "tls" / "TLS" in the Display) could never tell them
/// apart and printed "no SNI sent" for handshakes that had sent it.
#[tokio::test]
async fn fetch_failures_are_classified_by_layer() {
    // Negative control for TlsError: a listener that reads the ClientHello,
    // checks the name is in it (SNI, in the clear), and answers a fatal
    // handshake_failure alert. No certificate needed.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_addr = l.local_addr().unwrap();
    let saw_name = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw = saw_name.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut s, _)) = l.accept().await {
            let mut buf = vec![0u8; 8192];
            let mut got = 0;
            // One TLS record: 5-byte header, then `len` bytes.
            while got < 5 || got < 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize {
                match s.read(&mut buf[got..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
            }
            if buf[..got]
                .windows(b"mta-sts.example.test".len())
                .any(|w| w == b"mta-sts.example.test")
            {
                saw.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // TLS alert: level fatal (2), description handshake_failure (40).
            let _ = s
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
                .await;
            let _ = s.shutdown().await;
        }
    });
    let stub = Stub::start().await;
    let v = Vantage::build_unvalidating_for_tests(stub.choice_plain().parse().unwrap())
        .unwrap()
        .with_fetch_override("mta-sts.example.test", tls_addr);
    let err = v
        .http_client()
        .unwrap()
        .get("https://mta-sts.example.test/.well-known/mta-sts.txt")
        .send()
        .await
        .expect_err("the alert fails the handshake");
    let outcome = FetchOutcome::classify(&err);
    assert!(
        matches!(outcome, FetchOutcome::TlsError(_)),
        "an alert after the ClientHello is a TLS failure: {outcome:?}"
    );
    assert!(
        saw_name.load(std::sync::atomic::Ordering::SeqCst),
        "the name left this machine in the ClientHello (SNI) before the failure"
    );
    let text = err.to_string();
    assert!(
        !text.contains("certificate") && !text.contains("tls") && !text.contains("TLS"),
        "reqwest's Display never names the layer — a substring classifier could not see this: {text}"
    );
    eprintln!(
        "E8 TLS chain: {}",
        resolution_scope_engine::egress::error_chain(&err)
    );

    // Positive control for ConnectError: a closed port. SAME Display text.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let v = Vantage::build_unvalidating_for_tests(stub.choice_plain().parse().unwrap())
        .unwrap()
        .with_fetch_override("mta-sts.example.test", closed);
    let err2 = v
        .http_client()
        .unwrap()
        .get("https://mta-sts.example.test/.well-known/mta-sts.txt")
        .send()
        .await
        .expect_err("nothing listens");
    assert_eq!(
        err2.to_string(),
        text,
        "byte-identical Display for a TLS failure and a refused connect — the old classifier's blindness, shown"
    );
    let outcome2 = FetchOutcome::classify(&err2);
    match &outcome2 {
        FetchOutcome::ConnectError(chain) => assert!(
            chain.contains("tcp connect error"),
            "the chain names the layer: {chain}"
        ),
        other => panic!("a refused connect is a ConnectError: {other:?}"),
    }
    eprintln!(
        "E8 connect chain: {}",
        resolution_scope_engine::egress::error_chain(&err2)
    );

    // Unresolved: no A/AAAA at the stub, no override → the hook errors
    // before any HTTPS packet.
    let v = Vantage::build_unvalidating_for_tests(stub.choice_plain().parse().unwrap()).unwrap();
    let err3 = v
        .http_client()
        .unwrap()
        .get("https://mta-sts.unresolvable.test/.well-known/mta-sts.txt")
        .send()
        .await
        .expect_err("the stub refuses the name");
    let outcome3 = FetchOutcome::classify(&err3);
    match &outcome3 {
        FetchOutcome::Unresolved(chain) => assert!(chain.contains("dns error"), "{chain}"),
        other => panic!("a refused name is Unresolved: {other:?}"),
    }
    assert!(stub.saw("mta-sts.unresolvable.test", RecordType::A));
    eprintln!(
        "E8 dns chain: {}",
        resolution_scope_engine::egress::error_chain(&err3)
    );

    // And through the real scorer: hint present, the policy host RESOLVES
    // (a canned A, so the lookup set is non-empty), the connect pinned to
    // the alert listener → the ledger entry is TlsError, the resolved set
    // is recorded as such, the peer is None (no response), PolicyInvalid.
    // Mutant for the peer: `peer = addrs.first().map(|ip| (ip, 443))` on the
    // failed send — a lookup promoted to a measurement — yields
    // Some(127.0.0.1:443) here and the `peer == None` assertion fires.
    let mut canned = HashMap::new();
    canned.insert(
        key("_mta-sts.example.test", RecordType::TXT),
        Canned::ok(vec![Record::from_rdata(
            Name::from_ascii("_mta-sts.example.test.").unwrap(),
            300,
            RData::TXT(TXT::new(vec!["v=STSv1; id=1".to_string()])),
        )]),
    );
    canned.insert(
        key("mta-sts.example.test", RecordType::A),
        Canned::ok(vec![Record::from_rdata(
            Name::from_ascii("mta-sts.example.test.").unwrap(),
            300,
            RData::A(A::new(127, 0, 0, 1)),
        )]),
    );
    let stub = Stub::start_with(canned).await;
    let v = Vantage::build_unvalidating_for_tests(stub.choice_plain().parse().unwrap())
        .unwrap()
        .with_fetch_override("mta-sts.example.test", tls_addr);
    let a = analyse_domain(&v, "example.test").await.unwrap();
    let snap = v.ledger().drain();
    assert!(
        matches!(snap.fetches[0].outcome, FetchOutcome::TlsError(_)),
        "{:?}",
        snap.fetches[0].outcome
    );
    assert_eq!(
        snap.fetches[0].addrs,
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
        "the lookup result is recorded as the resolved set"
    );
    assert_eq!(
        snap.fetches[0].peer, None,
        "no response, so no peer — never filled in from the resolved set"
    );
    assert_eq!(
        a.mta_sts_disposition,
        resolution_scope_engine::MtaStsDisposition::PolicyInvalid
    );
}

/// E9 — the recorded peer is getpeername on the socket the response came
/// over, read from the same connector stack the policy fetch uses
/// (`Vantage::http_client` → hyper-util `HttpInfo` → `Response::remote_addr`).
/// Plain http:// to a loopback listener so a response can arrive without a
/// certificate; the TLS path adds a layer that delegates `connected()` to
/// the same TCP stream (hyper-rustls `MaybeHttpsStream::Https`), so the peer
/// it reports is the same socket's — confirmed live in the PR comment
/// against a real policy host.
///
/// Negative control: the lookup set is deliberately WRONG for the listener
/// (the stub answers the name with 127.0.0.2, the override sends the
/// connect to 127.0.0.1) — a peer taken from the lookup would read
/// 127.0.0.2; the socket says 127.0.0.1:<port>.
#[tokio::test]
async fn peer_is_the_socket_the_response_came_over() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = s.shutdown().await;
            });
        }
    });
    let mut canned = HashMap::new();
    canned.insert(
        key("peer.example.test", RecordType::A),
        Canned::ok(vec![Record::from_rdata(
            Name::from_ascii("peer.example.test.").unwrap(),
            300,
            RData::A(A::new(127, 0, 0, 2)),
        )]),
    );
    let stub = Stub::start_with(canned).await;
    let v = Vantage::build_unvalidating_for_tests(stub.choice_plain().parse().unwrap())
        .unwrap()
        .with_fetch_override("peer.example.test", addr);
    let looked_up: Vec<IpAddr> = v
        .lookup_ip("peer.example.test")
        .await
        .unwrap()
        .iter()
        .collect();
    assert_eq!(looked_up, [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
    let resp = v
        .http_client()
        .unwrap()
        .get(format!("http://peer.example.test:{}/", addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let peer = resp
        .remote_addr()
        .expect("hyper-util records HttpInfo on the connection");
    assert_eq!(peer, addr, "the peer is the listener's socket address");
    assert_ne!(
        peer.ip(),
        looked_up[0],
        "the peer is not the lookup result (which was deliberately wrong)"
    );
}
