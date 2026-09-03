//! X1 / X2 — the transport-transparency probe (mandate M3 §3, criterion as
//! corrected by Science's signing control). #[ignore]: needs the network.
//!
//!   cargo test -p resolution-scope-engine --test transport_probe -- --ignored --nocapture
//!
//! For each resolver R ∈ {cloudflare, quad9, google} and transport T ∈
//! {plain, tcp, tls, https, quic, h3}: build the vantage, then for the
//! fixtures look up SOA and DNSKEY and record UTC to the second, ok/err with
//! hickory's exact Display and Debug text, elapsed ms, a hash of the RDATA
//! EXCLUDING RRSIG (SOA: the record's own Display; DNSKEY: Display sorted by
//! key bytes), the Proof per record, and the AD flag from the response
//! header. RRSIG bytes are hashed ONLY for pq / pq2 (offline-signed, stable);
//! resolutionscope.com's SOA RRSIG is online-signed at Route 53 — a different
//! signature on every fetch — and a byte difference there is EXPECTED, never
//! a transport finding.
//!
//! Hash: SHA3-256[:16] of the bytes (the engine's own digest crate); the raw
//! signature's first 16 hex characters are printed beside it so a reader can
//! compare with a separately-hashed run.

use std::time::Instant;

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::{RData, RecordType};
use resolution_scope_engine::egress::Layer;
use resolution_scope_engine::preflight::utc_now_to_the_second;
use resolution_scope_engine::resolver::{ResolverChoice, Vantage};
use sha3::{Digest, Sha3_256};

fn h16(bytes: &[u8]) -> String {
    let d = Sha3_256::digest(bytes);
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn hex16(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

struct Cell {
    resolver: &'static str,
    transport: &'static str,
    name: &'static str,
    rtype: &'static str,
    at: String,
    ms: u128,
    ok: bool,
    err_display: String,
    err_debug: String,
    rdata_hash: String,
    proofs: String,
    ad: String,
    rrsig: String,
}

async fn probe_cell(
    v: &Vantage,
    resolver: &'static str,
    transport: &'static str,
    name: &'static str,
    rt: RecordType,
) -> Cell {
    let at = utc_now_to_the_second();
    let started = Instant::now();
    let res = v.lookup(name, rt).await;
    let ms = started.elapsed().as_millis();
    let rtype = match rt {
        RecordType::SOA => "SOA",
        RecordType::DNSKEY => "DNSKEY",
        _ => "?",
    };
    match res {
        Ok(l) => {
            let mut plain: Vec<String> = Vec::new();
            let mut sigs: Vec<String> = Vec::new();
            let mut proofs: Vec<String> = Vec::new();
            for r in l.answers() {
                match &r.data {
                    RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                        sigs.push(format!(
                            "{}:{}/{}",
                            sig.input().type_covered,
                            h16(sig.sig()),
                            hex16(sig.sig())
                        ));
                    }
                    RData::DNSSEC(DNSSECRData::DNSKEY(k)) => {
                        // Display: flags, protocol, algorithm, key bytes — the RDATA, no RRSIG.
                        plain.push(format!("DNSKEY {k}"));
                        proofs.push(format!("{:?}", r.proof));
                    }
                    other => {
                        plain.push(other.to_string());
                        proofs.push(format!("{:?}", r.proof));
                    }
                }
            }
            plain.sort();
            sigs.sort();
            Cell {
                resolver,
                transport,
                name,
                rtype,
                at,
                ms,
                ok: true,
                err_display: String::new(),
                err_debug: String::new(),
                rdata_hash: h16(plain.join("\n").as_bytes()),
                proofs: proofs.join(","),
                ad: l.message().metadata.authentic_data.to_string(),
                rrsig: if sigs.is_empty() {
                    "none-in-answer".into()
                } else {
                    sigs.join(" ")
                },
            }
        }
        Err(e) => Cell {
            resolver,
            transport,
            name,
            rtype,
            at,
            ms,
            ok: false,
            err_display: e.to_string(),
            err_debug: format!("{e:?}").chars().take(160).collect(),
            rdata_hash: String::new(),
            proofs: String::new(),
            ad: String::new(),
            rrsig: String::new(),
        },
    }
}

// #[ignore] stays: eighteen vantages against three public resolvers over the
// open network; CI promises no network, and a transient timeout there would
// read as a transport finding. Run by hand (the command in the module doc)
// and paste the DIFFERENTIAL lines into the PR; the assertion at the end is
// what makes a real difference fail the run.
#[tokio::test]
#[ignore = "network: the M3 §3 transport differential against Cloudflare, Quad9, Google"]
async fn transport_differential_probe() {
    eprintln!("probe start {} (UTC)", utc_now_to_the_second());
    let resolvers = ["cloudflare", "quad9", "google"];
    let transports = ["plain", "tcp", "tls", "https", "quic", "h3"];
    let names: [(&str, RecordType); 6] = [
        ("pq.resolutionscope.com", RecordType::SOA),
        ("pq.resolutionscope.com", RecordType::DNSKEY),
        ("pq2.resolutionscope.com", RecordType::SOA),
        ("pq2.resolutionscope.com", RecordType::DNSKEY),
        ("resolutionscope.com", RecordType::SOA),
        ("resolutionscope.com", RecordType::DNSKEY),
    ];
    let mut cells: Vec<Cell> = Vec::new();
    let mut build_errors: Vec<String> = Vec::new();
    for r in resolvers {
        for t in transports {
            let spelling = if t == "plain" {
                r.to_string()
            } else {
                format!("{t}://{r}")
            };
            let choice: ResolverChoice = spelling.parse().unwrap();
            let v = match Vantage::build(choice) {
                Ok(v) => v,
                Err(e) => {
                    build_errors.push(format!("{spelling}: {e}"));
                    continue;
                }
            };
            let mut dead = false;
            for (name, rt) in names {
                if dead {
                    eprintln!(
                        "| {r} | {t} | {name} {} | - | skipped: transport already failed for this pair | | | | | |",
                        if rt == RecordType::SOA { "SOA" } else { "DNSKEY" }
                    );
                    continue;
                }
                let cell = probe_cell(&v, r, t, name, rt).await;
                if !cell.ok
                    && (cell.err_debug.starts_with("Timeout")
                        || cell.err_debug.starts_with("NoConnections")
                        || cell.err_debug.starts_with("Io"))
                {
                    dead = true;
                }
                eprintln!(
                    "| {} | {} | {} {} | {} | {} | {} | {} | {} | {} | {} |",
                    cell.resolver,
                    cell.transport,
                    cell.name,
                    cell.rtype,
                    cell.at,
                    if cell.ok { "ok" } else { "ERR" },
                    cell.ms,
                    if cell.ok {
                        &cell.rdata_hash
                    } else {
                        &cell.err_display
                    },
                    cell.proofs,
                    cell.ad,
                    if cell.ok {
                        &cell.rrsig
                    } else {
                        &cell.err_debug
                    },
                );
                cells.push(cell);
            }
            let snap = v.ledger().drain();
            let conns: Vec<String> = snap
                .entries
                .iter()
                .filter_map(|e| match &e.layer {
                    Layer::Connection { protocol, port } => Some(format!("{protocol}:{port}")),
                    _ => None,
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            eprintln!(
                "  wire {spelling}: datagrams={} tcp={} quic={} dests={:?} connections={:?}",
                snap.datagrams_sent,
                snap.tcp_connects,
                snap.quic_sockets,
                snap.destinations(),
                conns
            );
        }
    }
    for e in &build_errors {
        eprintln!("build error: {e}");
    }
    // The comparison, within one resolver across transports — printed in
    // full, THEN asserted, so a finding fails the run with the whole table
    // above it (before this the FINDING lines were printed and nothing was
    // asserted: a probe that could not fail on the property it is for).
    let findings = differential_findings(&cells);
    eprintln!("probe end {} (UTC)", utc_now_to_the_second());
    assert!(
        findings.is_empty(),
        "transport differential — {} finding(s):\n{}",
        findings.len(),
        findings.join("\n")
    );
}

/// The differential rule (M3 §3, with Science's signing control): within
/// one resolver, among the transports that ANSWERED a (name, rtype), the
/// RDATA-ex-RRSIG hash and the AD flag must be identical, and the RRSIG
/// bytes must be identical ONLY for the offline-signed pq / pq2 fixtures —
/// resolutionscope.com is online-signed at Route 53 and a different
/// signature per fetch is expected there, never a finding. The Proof column
/// is printed for the reader and not asserted: it is this machine's
/// validation result, not the resolver's answer.
///
/// Pure over the cells: every comparison is printed (one DIFFERENTIAL line
/// per group, one RRSIG line per pq group) and every violation is returned
/// as a line, so the unit test below exercises both controls without the
/// network. A group with fewer than two answering transports has nothing to
/// compare and yields no finding.
fn differential_findings(cells: &[Cell]) -> Vec<String> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut groups: BTreeMap<(&str, &str, &str), Vec<&Cell>> = BTreeMap::new();
    for c in cells {
        groups
            .entry((c.resolver, c.name, c.rtype))
            .or_default()
            .push(c);
    }
    let mut findings = Vec::new();
    for ((r, name, rtype), group) in groups {
        let answered: Vec<&Cell> = group.iter().copied().filter(|c| c.ok).collect();
        let hashes: BTreeSet<&str> = answered.iter().map(|c| c.rdata_hash.as_str()).collect();
        let proofs: BTreeSet<&str> = answered.iter().map(|c| c.proofs.as_str()).collect();
        let ads: BTreeSet<&str> = answered.iter().map(|c| c.ad.as_str()).collect();
        let transports: Vec<&str> = answered.iter().map(|c| c.transport).collect();
        let rdata_differs = hashes.len() > 1;
        let ad_differs = ads.len() > 1;
        eprintln!(
            "DIFFERENTIAL {r} {name} {rtype}: transports answered={transports:?} rdata-hashes={hashes:?} proofs={proofs:?} ad={ads:?}{}",
            if rdata_differs || ad_differs {
                "  <-- FINDING"
            } else if proofs.len() > 1 {
                "  (proof differs — local validation, printed not asserted)"
            } else {
                "  (identical)"
            }
        );
        if rdata_differs {
            findings.push(format!(
                "{r} {name} {rtype}: RDATA-ex-RRSIG differs across {transports:?}: {hashes:?}"
            ));
        }
        if ad_differs {
            findings.push(format!(
                "{r} {name} {rtype}: AD flag differs across {transports:?}: {ads:?}"
            ));
        }
        if name.starts_with("pq") {
            let sigs: BTreeSet<&str> = answered.iter().map(|c| c.rrsig.as_str()).collect();
            let differs = sigs.len() > 1;
            eprintln!(
                "  RRSIG bytes ({name}, offline-signed fixture): {sigs:?}{}",
                if differs {
                    "  <-- FINDING"
                } else {
                    "  (identical)"
                }
            );
            if differs {
                findings.push(format!(
                    "{r} {name} {rtype}: RRSIG bytes differ across {transports:?} on an offline-signed fixture: {sigs:?}"
                ));
            }
        }
    }
    findings
}

/// Both controls for the differential rule, without the network — the
/// assertion the probe makes must be able to fail on the property it is
/// cited for, and must stay quiet where a difference is by design.
#[test]
fn differential_rule_fires_on_a_difference_and_stays_quiet_on_identity() {
    #[allow(clippy::too_many_arguments)]
    fn cell(
        resolver: &'static str,
        transport: &'static str,
        name: &'static str,
        rtype: &'static str,
        ok: bool,
        rdata_hash: &str,
        ad: &str,
        rrsig: &str,
    ) -> Cell {
        Cell {
            resolver,
            transport,
            name,
            rtype,
            at: String::new(),
            ms: 0,
            ok,
            err_display: if ok {
                String::new()
            } else {
                "request timed out".into()
            },
            err_debug: if ok { String::new() } else { "Timeout".into() },
            rdata_hash: rdata_hash.into(),
            proofs: "Secure".into(),
            ad: ad.into(),
            rrsig: rrsig.into(),
        }
    }
    let pq = "pq.resolutionscope.com";
    let apex = "resolutionscope.com";

    // POSITIVE: identical RDATA, AD and RRSIG across three transports; an
    // errored transport is excluded; a lone answering transport on another
    // resolver has nothing to compare. No finding.
    let quiet = vec![
        cell("quad9", "plain", pq, "SOA", true, "h1", "true", "SOA:s1/s1"),
        cell("quad9", "tls", pq, "SOA", true, "h1", "true", "SOA:s1/s1"),
        cell("quad9", "quic", pq, "SOA", true, "h1", "true", "SOA:s1/s1"),
        cell("quad9", "h3", pq, "SOA", false, "", "", ""),
        cell(
            "google",
            "plain",
            pq,
            "SOA",
            true,
            "h1",
            "true",
            "SOA:s1/s1",
        ),
        cell("google", "h3", pq, "SOA", false, "", "", ""),
        // The online-signed apex: a different RRSIG per transport is
        // expected (Route 53 signs on the fly) and is NOT a finding.
        cell(
            "quad9",
            "plain",
            apex,
            "SOA",
            true,
            "h2",
            "true",
            "SOA:s2/s2",
        ),
        cell("quad9", "tls", apex, "SOA", true, "h2", "true", "SOA:s3/s3"),
    ];
    assert_eq!(differential_findings(&quiet), Vec::<String>::new());

    // NEGATIVE (the defect): the assertion fires on each property.
    // Mutant: `findings.push` deleted for a property → that case yields an
    // empty Vec and its assertion below fails.
    let rdata = vec![
        cell("quad9", "plain", pq, "SOA", true, "h1", "true", "SOA:s1/s1"),
        cell("quad9", "tls", pq, "SOA", true, "hX", "true", "SOA:s1/s1"),
    ];
    let f = differential_findings(&rdata);
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].contains("RDATA-ex-RRSIG differs"), "{f:?}");

    let ad = vec![
        cell(
            "cloudflare",
            "plain",
            pq,
            "DNSKEY",
            true,
            "h1",
            "true",
            "DNSKEY:s1/s1",
        ),
        cell(
            "cloudflare",
            "https",
            pq,
            "DNSKEY",
            true,
            "h1",
            "false",
            "DNSKEY:s1/s1",
        ),
    ];
    let f = differential_findings(&ad);
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].contains("AD flag differs"), "{f:?}");

    // RRSIG bytes on an offline-signed fixture (pq2 too) ARE a finding …
    let sig = vec![
        cell(
            "google",
            "plain",
            "pq2.resolutionscope.com",
            "SOA",
            true,
            "h1",
            "true",
            "SOA:s1/s1",
        ),
        cell(
            "google",
            "tcp",
            "pq2.resolutionscope.com",
            "SOA",
            true,
            "h1",
            "true",
            "SOA:sY/sY",
        ),
    ];
    let f = differential_findings(&sig);
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].contains("RRSIG bytes differ"), "{f:?}");
    // … and never on the online-signed apex, even with a differing hash
    // elsewhere in the same run (the two rules are independent).
    let apex_only = vec![
        cell(
            "google",
            "plain",
            apex,
            "DNSKEY",
            true,
            "h1",
            "true",
            "DNSKEY:s1/s1",
        ),
        cell(
            "google",
            "tcp",
            apex,
            "DNSKEY",
            true,
            "h1",
            "true",
            "DNSKEY:sZ/sZ",
        ),
    ];
    assert_eq!(differential_findings(&apex_only), Vec::<String>::new());

    // A difference across RESOLVERS is not a finding: the rule is within one
    // resolver. (Cloudflare and Quad9 may legitimately hold different cached
    // RRsets at the same second.)
    let across = vec![
        cell("quad9", "plain", pq, "SOA", true, "h1", "true", "SOA:s1/s1"),
        cell(
            "cloudflare",
            "plain",
            pq,
            "SOA",
            true,
            "hQ",
            "true",
            "SOA:s1/s1",
        ),
    ];
    assert_eq!(differential_findings(&across), Vec::<String>::new());
}

/// X2 — the DoT handshake succeeds with the bundled roots: a `tls://cloudflare`
/// vantage answers a lookup with Proof::Secure, the ledger shows TCP 853
/// connections and zero datagrams (this build holds no plain fallback).
#[tokio::test]
#[ignore = "network: DoT to 1.1.1.1:853 with webpki roots"]
async fn dot_handshake_succeeds_with_bundled_roots() {
    let v = Vantage::build("tls://cloudflare".parse().unwrap()).unwrap();
    let started = Instant::now();
    let l = v
        .lookup("cloudflare.com", RecordType::A)
        .await
        .expect("DoT lookup");
    let ms = started.elapsed().as_millis();
    let snap = v.ledger().drain();
    eprintln!(
        "tls://cloudflare cloudflare.com A: {} answers, proofs {:?}, {ms} ms; tcp_connects={} datagrams={} dests={:?}",
        l.answers().len(),
        l.answers().iter().map(|r| r.proof).collect::<Vec<_>>(),
        snap.tcp_connects,
        snap.datagrams_sent,
        snap.destinations()
    );
    assert!(!l.answers().is_empty());
    assert!(snap.tcp_connects >= 1);
    assert_eq!(snap.datagrams_sent, 0);
    assert!(snap.destinations().iter().all(|d| d.port() == 853));
}
