//! The preflight guard, both controls.
//!
//!   P2  preflight_refuses_a_do_stripping_vantage   a loopback stub that
//!       answers `. DNSKEY` NOERROR with a key that is NOT a root anchor and
//!       NO RRSIG — the shape a DO/OPT-stripping forwarder produces — is
//!       refused before anything is sealed
//!   P2b preflight_refuses_a_refusing_vantage        a stub that REFUSES the
//!       root DNSKEY is refused (the positive control did not pass)
//!   P3  live_preflight_passes_on_cloudflare_plain_and_tls   #[ignore]:
//!       needs the network — the measured positive control

mod support;

use std::collections::HashMap;

use hickory_proto::dnssec::rdata::DNSKEY;
use hickory_proto::dnssec::{Algorithm, PublicKeyBuf};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use resolution_scope_engine::preflight::{ControlOutcome, Mode, PreflightRefusal};
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use support::{key, Canned, Stub};

#[tokio::test]
async fn preflight_refuses_a_do_stripping_vantage() {
    let mut canned = HashMap::new();
    let fake_key = DNSKEY::new(
        true,
        true,
        false,
        PublicKeyBuf::new(vec![0x42u8; 64], Algorithm::ECDSAP256SHA256),
    );
    canned.insert(
        key(".", RecordType::DNSKEY),
        Canned::ok(vec![Record::from_rdata(
            Name::root(),
            300,
            RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(fake_key)),
        )]),
    );
    let stub = Stub::start_with(canned).await;
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    let v = Vantage::build(choice).unwrap();
    let refusal = v
        .preflight()
        .await
        .expect_err("an unsigned root DNSKEY must refuse");
    match &refusal {
        PreflightRefusal::CannotValidate { positive } => {
            assert!(
                matches!(
                    positive,
                    ControlOutcome::Bogus
                        | ControlOutcome::Indeterminate
                        | ControlOutcome::Insecure
                ),
                "not Secure: {positive:?}"
            );
        }
        other => panic!("expected CannotValidate, got {other:?}"),
    }
    assert!(refusal.to_string().contains("not Secure"), "{refusal}");
    assert!(
        stub.saw(".", RecordType::DNSKEY),
        "the positive control was asked"
    );
    assert!(
        !stub.saw("dnssec-failed.org", RecordType::A),
        "the negative control is not spent on a vantage that already failed"
    );
}

#[tokio::test]
async fn preflight_refuses_a_refusing_vantage() {
    let stub = Stub::start().await;
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    let v = Vantage::build(choice).unwrap();
    let refusal = v.preflight().await.expect_err("REFUSED is not Secure");
    assert!(
        matches!(
            refusal,
            PreflightRefusal::CannotValidate { .. } | PreflightRefusal::Transport { .. }
        ),
        "{refusal:?}"
    );
}

#[tokio::test]
#[ignore = "network: the measured positive control against Cloudflare over plain 53 and over DoT"]
async fn live_preflight_passes_on_cloudflare_plain_and_tls() {
    for spelling in ["cloudflare", "tls://cloudflare"] {
        let v = Vantage::build(spelling.parse().unwrap()).unwrap();
        let r = v
            .preflight()
            .await
            .unwrap_or_else(|e| panic!("{spelling}: {e}"));
        eprintln!(
            "{spelling}: mode={:?} positive={} negative={} at={} datagrams={} tcp={} dests={:?}",
            r.mode,
            r.positive.1,
            r.negative.1,
            r.at_utc,
            r.egress.datagrams_sent,
            r.egress.tcp_connects,
            r.egress.destinations()
        );
        assert_eq!(r.positive.1, ControlOutcome::Secure);
        assert_eq!(
            r.mode,
            Mode::UpstreamAndLocal,
            "Cloudflare validates: SERVFAIL on the bogus fixture"
        );
    }
}
