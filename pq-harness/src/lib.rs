//! pq-harness — verification side of the pq.resolutionscope.com fixture.
//!
//! Contract: docs/SPEC-mldsa44-signer-20260830.md §5.1 (KAT bake-off) + §7
//! (verification). Ground truth: draft-westerbaan-dnssec-mldsa-04 §6, whose
//! base64 blocks are extracted verbatim into fixtures/ (never hand-typed).
//!
//! The test-vector seed 0x00..0x1f is KAT-ONLY (SPEC §4 hard rule): its
//! private half is printed in a public Internet-Draft. Nothing in this crate
//! generates or stores production key material.

use sha2::{Digest, Sha256};

/// Lowercased, uncompressed DNS name wire format (RFC 4034 §6.2 canonical form).
pub fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            let lower = label.to_ascii_lowercase();
            assert!(!lower.is_empty() && lower.len() < 64, "bad label in {name}");
            out.push(lower.len() as u8);
            out.extend_from_slice(lower.as_bytes());
        }
    }
    out.push(0);
    out
}

/// RFC 4034 Appendix B key tag over full DNSKEY RDATA.
pub fn keytag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        ac += if i & 1 == 1 { b as u32 } else { (b as u32) << 8 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// DNSKEY RDATA: flags | protocol | algorithm | public key.
pub fn dnskey_rdata(flags: u16, protocol: u8, algorithm: u8, key: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(4 + key.len());
    r.extend_from_slice(&flags.to_be_bytes());
    r.push(protocol);
    r.push(algorithm);
    r.extend_from_slice(key);
    r
}

/// RFC 4034 §5.1.4: DS digest type 2 = SHA-256(owner_wire || DNSKEY RDATA).
pub fn ds_sha256(owner: &str, rdata: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(name_wire(owner));
    h.update(rdata);
    h.finalize().into()
}

/// The fixed (pre-signature) fields of an RRSIG, in RDATA order.
#[derive(Clone)]
pub struct RrsigFields {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub orig_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub keytag: u16,
    pub signer: String,
}

/// One RR of the covered RRset (owner + class + canonical RDATA).
pub struct Rr {
    pub owner: String,
    pub class: u16,
    pub rdata: Vec<u8>,
}

/// RFC 4034 §3.1.8.1 signed data:
/// RRSIG_RDATA (minus signature, signer uncompressed+lowercased)
/// || canonical RRset (each RR: owner | type | class | orig_ttl | rdlen | rdata),
/// RDATAs in canonical (byte-wise) order.
pub fn rrsig_signed_data(f: &RrsigFields, rrs: &[Rr]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&f.type_covered.to_be_bytes());
    msg.push(f.algorithm);
    msg.push(f.labels);
    msg.extend_from_slice(&f.orig_ttl.to_be_bytes());
    msg.extend_from_slice(&f.expiration.to_be_bytes());
    msg.extend_from_slice(&f.inception.to_be_bytes());
    msg.extend_from_slice(&f.keytag.to_be_bytes());
    msg.extend_from_slice(&name_wire(&f.signer));

    let mut sorted: Vec<&Rr> = rrs.iter().collect();
    sorted.sort_by(|a, b| a.rdata.cmp(&b.rdata));
    for rr in sorted {
        msg.extend_from_slice(&name_wire(&rr.owner));
        msg.extend_from_slice(&f.type_covered.to_be_bytes());
        msg.extend_from_slice(&rr.class.to_be_bytes());
        msg.extend_from_slice(&f.orig_ttl.to_be_bytes());
        msg.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rr.rdata);
    }
    msg
}

/// MX RDATA with canonical (lowercased, uncompressed) exchange name.
pub fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&preference.to_be_bytes());
    r.extend_from_slice(&name_wire(exchange));
    r
}

/// RRSIG presentation timestamp: either bare epoch digits or YYYYMMDDHHMMSS.
pub fn rrsig_time(s: &str) -> u32 {
    if s.len() == 14 {
        let num = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
        let (y, m, d) = (num(0, 4), num(4, 6), num(6, 8));
        let (hh, mm, ss) = (num(8, 10), num(10, 12), num(12, 14));
        // Howard Hinnant days_from_civil
        let yy = if m <= 2 { y - 1 } else { y };
        let era = if yy >= 0 { yy } else { yy - 399 } / 400;
        let yoe = yy - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        (days * 86400 + hh * 3600 + mm * 60 + ss) as u32
    } else {
        s.parse::<u32>().unwrap()
    }
}

// ---------- draft-westerbaan-dnssec-mldsa-04 §6 vectors ----------

pub const VECTOR_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f,
];
pub const VECTOR_KEYTAG: u16 = 59829;
pub const VECTOR_DS_HEX: &str =
    "812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa";
pub const VECTOR_PUBKEY_B64: &str = include_str!("../fixtures/vector-pubkey.b64");
pub const VECTOR_RRSIG_B64: &str = include_str!("../fixtures/vector-rrsig.b64");

pub fn vector_pubkey() -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(VECTOR_PUBKEY_B64.trim())
        .expect("vector pubkey base64")
}

pub fn vector_rrsig() -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(VECTOR_RRSIG_B64.trim())
        .expect("vector rrsig base64")
}

/// The §6 RRSIG fixed fields + MX RRset, exactly as printed in the draft.
pub fn vector_rrsig_fields() -> (RrsigFields, Vec<Rr>) {
    let f = RrsigFields {
        type_covered: 15, // MX
        algorithm: 18,
        labels: 2,
        orig_ttl: 3600,
        expiration: 1440021600,
        inception: 1438207200,
        keytag: VECTOR_KEYTAG,
        signer: "example.com.".into(),
    };
    let rrs = vec![Rr {
        owner: "example.com.".into(),
        class: 1,
        rdata: mx_rdata(10, "mail.example.com."),
    }];
    (f, rrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};


    fn fips204_keypair() -> (fips204::ml_dsa_44::PublicKey, fips204::ml_dsa_44::PrivateKey) {
        fips204::ml_dsa_44::KG::keygen_from_seed(&VECTOR_SEED)
    }

    fn mldsa_signing_key() -> ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa44> {
        ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::from_seed(&VECTOR_SEED.into())
    }

    fn mldsa_sig(bytes: &[u8]) -> Option<ml_dsa::Signature<ml_dsa::MlDsa44>> {
        ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(bytes).ok()
    }

    // ---- KAT leg 1: pure-Rust helpers reproduce the draft's derived values ----

    #[test]
    fn kat_keytag_and_ds_from_vector_pubkey() {
        let rdata = dnskey_rdata(257, 3, 18, &vector_pubkey());
        assert_eq!(keytag(&rdata), VECTOR_KEYTAG, "keytag must be 59829");
        assert_eq!(hex::encode(ds_sha256("example.com.", &rdata)), VECTOR_DS_HEX);
    }

    // ---- KAT leg 2: fips204 (the SPEC §5.1 signing pick) ----

    #[test]
    fn kat_fips204_keygen_reproduces_vector_pubkey() {
        let (pk, _sk) = fips204_keypair();
        assert_eq!(pk.into_bytes().to_vec(), vector_pubkey(), "fips204 pubkey != §6 vector");
    }

    #[test]
    fn kat_fips204_deterministic_sign_reproduces_vector_rrsig() {
        let (_pk, sk) = fips204_keypair();
        let (f, rrs) = vector_rrsig_fields();
        let msg = rrsig_signed_data(&f, &rrs);
        // FIPS 204 deterministic variant: rnd = 0^32.
        let sig = sk
            .try_sign_with_seed(&[0u8; 32], &msg, &[])
            .expect("fips204 deterministic sign");
        assert_eq!(sig.to_vec(), vector_rrsig(), "fips204 RRSIG != §6 vector");
    }

    #[test]
    fn kat_fips204_verifies_vector_rrsig() {
        let (pk, _sk) = fips204_keypair();
        let (f, rrs) = vector_rrsig_fields();
        let msg = rrsig_signed_data(&f, &rrs);
        let sig: [u8; 2420] = vector_rrsig().try_into().unwrap();
        assert!(pk.verify(&msg, &sig, &[]), "fips204 must verify the §6 RRSIG");
    }

    // ---- KAT leg 3: ml-dsa (SciSpace's pq-keygen crate, independent verifier) ----

    #[test]
    fn kat_mldsa_keygen_reproduces_vector_pubkey() {
        let enc = mldsa_signing_key().verifying_key().encode();
        assert_eq!(enc.as_slice(), vector_pubkey().as_slice(), "ml-dsa pubkey != §6 vector");
    }

    #[test]
    fn kat_mldsa_deterministic_sign_reproduces_vector_rrsig() {
        let sk = mldsa_signing_key();
        let (f, rrs) = vector_rrsig_fields();
        let msg = rrsig_signed_data(&f, &rrs);
        let sig = sk.sign_deterministic(&msg, &[]).expect("ml-dsa deterministic sign");
        assert_eq!(sig.encode().as_slice(), vector_rrsig().as_slice(), "ml-dsa RRSIG != §6 vector");
    }

    #[test]
    fn kat_mldsa_verifies_vector_rrsig() {
        let sk = mldsa_signing_key();
        let (f, rrs) = vector_rrsig_fields();
        let msg = rrsig_signed_data(&f, &rrs);
        let sig = mldsa_sig(&vector_rrsig()).expect("ml-dsa signature decode");
        assert!(
            sk.verifying_key().verify_with_context(&msg, &[], &sig),
            "ml-dsa must verify the §6 RRSIG"
        );
    }

    // ---- Cross-verification: fips204-signed, ml-dsa-verified ----

    #[test]
    fn cross_fips204_sign_mldsa_verify() {
        let (_pk, sk) = fips204_keypair();
        let msg = b"cross-verification: two independent FIPS-204 implementations";
        let sig = sk.try_sign_with_seed(&[0u8; 32], msg, &[]).unwrap();
        let sig2 = mldsa_sig(&sig).expect("decode fips204 sig in ml-dsa");
        assert!(mldsa_signing_key()
            .verifying_key()
            .verify_with_context(msg, &[], &sig2));
    }

    // ---- Negative controls (a verifier that can't fail proves nothing) ----

    #[test]
    fn negative_bitflip_signature_fails_both_crates() {
        let (pk, _sk) = fips204_keypair();
        let (f, rrs) = vector_rrsig_fields();
        let msg = rrsig_signed_data(&f, &rrs);
        let mut bad = vector_rrsig();
        bad[100] ^= 0x01;
        let bad_arr: [u8; 2420] = bad.clone().try_into().unwrap();
        assert!(!pk.verify(&msg, &bad_arr, &[]), "fips204 accepted a flipped bit");
        if let Some(sig) = mldsa_sig(&bad) {
            assert!(
                !mldsa_signing_key().verifying_key().verify_with_context(&msg, &[], &sig),
                "ml-dsa accepted a flipped bit"
            );
        } // undecodable is also a pass
    }

    #[test]
    fn negative_wrong_message_fails() {
        let (pk, _sk) = fips204_keypair();
        let (f, rrs) = vector_rrsig_fields();
        let mut msg = rrsig_signed_data(&f, &rrs);
        msg[0] ^= 0x01;
        let sig: [u8; 2420] = vector_rrsig().try_into().unwrap();
        assert!(!pk.verify(&msg, &sig, &[]), "fips204 verified against altered message");
    }

    #[test]
    fn negative_nonempty_context_fails() {
        let (pk, _sk) = fips204_keypair();
        let (f, rrs) = vector_rrsig_fields();
        let msg = rrsig_signed_data(&f, &rrs);
        let sig: [u8; 2420] = vector_rrsig().try_into().unwrap();
        assert!(!pk.verify(&msg, &sig, b"x"), "ctx must be empty per draft §4");
    }
}
