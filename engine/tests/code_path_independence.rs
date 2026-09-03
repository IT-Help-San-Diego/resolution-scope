//! C1 — code-path independence of the sealed identity.
//!
//! For the same choice, every entry point yields identical identity bytes,
//! and those bytes are the choice's own. SHOWN TO FAIL on the base commit
//! (b4e2a77) against the old `analyse_domain`, which sealed the literal
//! "default" while `analyse_domain_with_selectors(.., "cloudflare")` sealed
//! "cloudflare" for the same resolver (run recorded in the PR body: the
//! assertion read `left: "default"`, `right: "cloudflare"`, 552 stub queries
//! in 97 ms). On this branch no signature remains through which a caller
//! can pass a label, so the only way to break this test is for an entry
//! point or the assembly to hardcode one.

mod support;

use resolution_scope_engine::analysis::{
    analyse_domain, analyse_domain_with_receipts, analyse_domain_with_selectors,
};
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};

#[tokio::test]
async fn every_entry_point_seals_the_same_identity_bytes() {
    let stub = support::Stub::start().await;
    let expected = format!("127.0.0.1#{}", stub.addr.port());
    let choice: ResolverChoice = stub.choice_plain().parse().unwrap();
    let v = Vantage::build(choice).unwrap();

    let a = analyse_domain(&v, "example.test").await.unwrap();
    let b = analyse_domain_with_selectors(&v, "example.test", &[])
        .await
        .unwrap();
    let (c, _receipts, _records) = analyse_domain_with_receipts(&v, "example.test", &[])
        .await
        .unwrap();

    assert_eq!(a.resolver_identity, v.identity());
    assert_eq!(b.resolver_identity, v.identity());
    assert_eq!(c.resolver_identity, v.identity());
    assert_eq!(a.resolver_identity, expected);
    assert!(
        stub.seen_count() > 0,
        "the stub must have been asked: the identity is not a fixture"
    );
}

/// The identity is the CHOICE's, not the wire's: two vantages at the same
/// stub with different spellings of the same choice seal identically, and a
/// different transport seals differently.
#[tokio::test]
async fn identity_follows_the_choice_not_the_call() {
    let stub = support::Stub::start().await;
    let port = stub.addr.port();
    let plain: ResolverChoice = format!("127.0.0.1:{port}").parse().unwrap();
    let plain2: ResolverChoice = format!("udp://127.0.0.1#{port}").parse().unwrap();
    assert_eq!(plain, plain2);
    let tcp: ResolverChoice = format!("tcp://127.0.0.1#{port}").parse().unwrap();
    let a = analyse_domain(&Vantage::build(plain).unwrap(), "example.test")
        .await
        .unwrap();
    let b = analyse_domain(&Vantage::build(tcp).unwrap(), "example.test")
        .await
        .unwrap();
    assert_eq!(a.resolver_identity, format!("127.0.0.1#{port}"));
    assert_eq!(b.resolver_identity, format!("127.0.0.1#{port}/tcp"));
}
