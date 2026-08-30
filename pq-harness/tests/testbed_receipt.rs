//! The negative receipt (SPEC §7.4): the deSEC testbed serves records
//! wire-labeled algorithm 18 that are round-3 Dilithium2, NOT FIPS-204
//! ML-DSA-44. A FIPS-204 verifier must therefore REJECT them — sealing
//! "18-labeled ≠ 18-proper" as a measurement, not an assertion.
//!
//! Fixtures were captured over TCP from the authoritative (95.217.209.184)
//! at the timestamp in fixtures/capture-timestamp.txt. No network in tests.

use base64::Engine;
use fips204::traits::{SerDes, Verifier};
use pq_harness::{rrsig_signed_data, rrsig_time, Rr, RrsigFields};

fn b64_tail(fields: &[&str], from: usize) -> Vec<u8> {
    let joined: String = fields[from..].concat();
    base64::engine::general_purpose::STANDARD
        .decode(joined)
        .expect("fixture base64")
}

#[test]
fn testbed_alg18_records_fail_fips204_verification() {
    // DNSKEY line: owner ttl IN DNSKEY flags proto alg key...
    let dnskey_line = include_str!("../fixtures/testbed-dnskey.txt");
    let df: Vec<&str> = dnskey_line.split_whitespace().collect();
    assert_eq!(df[3], "DNSKEY");
    assert_eq!(
        df[6], "18",
        "testbed DNSKEY must be wire-labeled algorithm 18"
    );
    let pubkey = b64_tail(&df, 7);
    assert_eq!(
        pubkey.len(),
        1312,
        "Dilithium2 and ML-DSA-44 share pk size — the trap"
    );

    // A + RRSIG lines.
    let mut a_rdata = None;
    let mut rrsig: Option<(RrsigFields, Vec<u8>, String)> = None;
    for line in include_str!("../fixtures/testbed-a-rrsig.txt").lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 4 && f[3] == "A" {
            let ip: Vec<u8> = f[4].split('.').map(|o| o.parse().unwrap()).collect();
            a_rdata = Some(ip);
        } else if f.len() > 12 && f[3] == "RRSIG" {
            assert_eq!(f[4], "A");
            assert_eq!(
                f[5], "18",
                "testbed RRSIG must be wire-labeled algorithm 18"
            );
            rrsig = Some((
                RrsigFields {
                    type_covered: 1,
                    algorithm: 18,
                    labels: f[6].parse().unwrap(),
                    orig_ttl: f[7].parse().unwrap(),
                    expiration: rrsig_time(f[8]),
                    inception: rrsig_time(f[9]),
                    keytag: f[10].parse().unwrap(),
                    signer: f[11].to_string(),
                },
                b64_tail(&f, 12),
                f[0].to_string(),
            ));
        }
    }
    let a_rdata = a_rdata.expect("A record in fixture");
    let (fields, sig_bytes, owner) = rrsig.expect("RRSIG in fixture");
    assert_eq!(
        sig_bytes.len(),
        2420,
        "Dilithium2 and ML-DSA-44 share sig size — the trap"
    );

    let msg = rrsig_signed_data(
        &fields,
        &[Rr {
            owner,
            class: 1,
            rdata: a_rdata,
        }],
    );

    let pk_arr: [u8; 1312] = pubkey.try_into().unwrap();
    let pk = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_arr)
        .expect("1312 bytes parse as an ML-DSA-44 key shape — indistinguishable on the wire");
    let sig_arr: [u8; 2420] = sig_bytes.try_into().unwrap();

    // THE RECEIPT: wire-labeled 18, rejected by FIPS-204.
    assert!(
        !pk.verify(&msg, &sig_arr, &[]),
        "testbed record VERIFIED under FIPS-204 — that would mean it is 18-proper \
         and the baseline's zero-publishers claim is false; re-measure immediately"
    );
}
