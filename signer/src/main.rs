//! pq-signer — ML-DSA-44 (algorithm 18) offline zone signer for the
//! pq.resolutionscope.com fixture.
//!
//! Contract: docs/SPEC-mldsa44-signer-20260830.md.
//! Reads a 32-byte seed from --seed-file, generates a deterministic CSK,
//! signs the apex-only zone, writes the signed zone file to stdout or --out.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use base64::Engine as _;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use sha2::{Digest, Sha256};

// ---------- wire helpers ----------

fn name_wire(name: &str) -> Vec<u8> {
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

fn keytag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        ac += if i & 1 == 1 { b as u32 } else { (b as u32) << 8 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

fn dnskey_rdata(flags: u16, protocol: u8, algorithm: u8, key: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(4 + key.len());
    r.extend_from_slice(&flags.to_be_bytes());
    r.push(protocol);
    r.push(algorithm);
    r.extend_from_slice(key);
    r
}

fn ds_sha256(owner: &str, rdata: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(name_wire(owner));
    h.update(rdata);
    h.finalize().into()
}

struct Rr {
    owner: String,
    class: u16,
    rdata: Vec<u8>,
}

struct RrsigFields {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    orig_ttl: u32,
    expiration: u32,
    inception: u32,
    keytag: u16,
    signer: String,
}

fn rrsig_signed_data(f: &RrsigFields, rrs: &[&Rr]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&f.type_covered.to_be_bytes());
    msg.push(f.algorithm);
    msg.push(f.labels);
    msg.extend_from_slice(&f.orig_ttl.to_be_bytes());
    msg.extend_from_slice(&f.expiration.to_be_bytes());
    msg.extend_from_slice(&f.inception.to_be_bytes());
    msg.extend_from_slice(&f.keytag.to_be_bytes());
    msg.extend_from_slice(&name_wire(&f.signer));

    let mut sorted: Vec<&&Rr> = rrs.iter().collect();
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

// ---------- zone RDATA helpers ----------

fn soa_rdata(mname: &str, rname: &str, serial: u32, refresh: u32, retry: u32,
             expire: u32, minimum: u32) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&name_wire(mname));
    r.extend_from_slice(&name_wire(rname));
    r.extend_from_slice(&serial.to_be_bytes());
    r.extend_from_slice(&refresh.to_be_bytes());
    r.extend_from_slice(&retry.to_be_bytes());
    r.extend_from_slice(&expire.to_be_bytes());
    r.extend_from_slice(&minimum.to_be_bytes());
    r
}

fn txt_rdata(text: &str) -> Vec<u8> {
    let mut r = Vec::new();
    for chunk in text.as_bytes().chunks(255) {
        r.push(chunk.len() as u8);
        r.extend_from_slice(chunk);
    }
    r
}

fn nsec_rdata(next_name: &str, types: &[u16]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&name_wire(next_name));
    let mut bitmap = [0u8; 32]; // 256 bits for type 0–255
    for &t in types {
        let byte = (t / 8) as usize;
        let bit = 7 - (t % 8);
        if byte < 32 { bitmap[byte] |= 1 << bit; }
    }
    let last = (0..32).rev().find(|&i| bitmap[i] != 0).unwrap_or(0);
    r.push(0); // window block 0
    r.push((last + 1) as u8);
    r.extend_from_slice(&bitmap[..=last]);
    r
}

// ---------- presentation ----------

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A", 2 => "NS", 6 => "SOA", 16 => "TXT", 48 => "DNSKEY", 47 => "NSEC", 46 => "RRSIG",
        _ => unreachable!(),
    }
}

fn name_unwire(data: &[u8]) -> String {
    let mut pos = 0;
    let mut labels: Vec<&str> = Vec::new();
    while pos < data.len() && data[pos] != 0 {
        let len = data[pos] as usize;
        pos += 1;
        labels.push(std::str::from_utf8(&data[pos..pos+len]).unwrap());
        pos += len;
    }
    format!("{}.", labels.join("."))
}

fn soa_presentation(rdata: &[u8]) -> String {
    let mname = name_unwire(rdata);
    let off1 = rdata.iter().position(|&b| b == 0).unwrap() + 1;
    let rname = name_unwire(&rdata[off1..]);
    let off2 = off1 + rdata[off1..].iter().position(|&b| b == 0).unwrap() + 1;
    let nums = &rdata[off2..];
    let serial = u32::from_be_bytes(nums[0..4].try_into().unwrap());
    let refresh = u32::from_be_bytes(nums[4..8].try_into().unwrap());
    let retry = u32::from_be_bytes(nums[8..12].try_into().unwrap());
    let expire = u32::from_be_bytes(nums[12..16].try_into().unwrap());
    let min = u32::from_be_bytes(nums[16..20].try_into().unwrap());
    format!("{mname} {rname} {serial} {refresh} {retry} {expire} {min}")
}

fn dnskey_presentation(rdata: &[u8]) -> String {
    let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
    let proto = rdata[2];
    let algo = rdata[3];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&rdata[4..]);
    format!("{flags} {proto} {algo} {key_b64}")
}

fn rrsig_presentation(f: &RrsigFields, sig: &[u8]) -> String {
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    format!(
        "{} 3600 IN RRSIG {} {} {} {} {} {} {} {} {}",
        f.signer, type_name(f.type_covered), f.algorithm, f.labels,
        f.orig_ttl, f.expiration, f.inception, f.keytag, f.signer, sig_b64
    )
}

fn nsec_presentation(rdata: &[u8]) -> String {
    let next = name_unwire(rdata);
    let i = rdata.iter().position(|&b| b == 0).unwrap() + 1;
    let rest = &rdata[i..];
    let window = rest[0];
    let bitmap_len = rest[1] as usize;
    let bitmap = &rest[2..2+bitmap_len];
    let mut types = Vec::new();
    for (bi, &b) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if b & (1 << (7 - bit)) != 0 {
                types.push(window as u16 * 256 + (bi as u16 * 8 + bit as u16));
            }
        }
    }
    let ts: Vec<&str> = types.iter().map(|&t| type_name(t)).collect();
    format!("{next} {}", ts.join(" "))
}

// ---------- sign + verify ----------

fn sign_rrset(
    sk: &fips204::ml_dsa_44::PrivateKey,
    rrs: &[&Rr],
    type_covered: u16,
    labels: u8,
    orig_ttl: u32,
    inception: u32,
    expiration: u32,
    keytag: u16,
    signer: &str,
) -> (RrsigFields, Vec<u8>) {
    let f = RrsigFields {
        type_covered,
        algorithm: 18,
        labels,
        orig_ttl,
        expiration,
        inception,
        keytag,
        signer: signer.to_string(),
    };
    let msg = rrsig_signed_data(&f, rrs);
    let sig = sk.try_sign_with_seed(&[0u8; 32], &msg, &[])
        .expect("deterministic sign ");
    (f, sig.to_vec())
}

fn verify_rrset(
    pk: &fips204::ml_dsa_44::PublicKey,
    f: &RrsigFields,
    sig: &[u8],
    rrs: &[&Rr],
    label: &str,
) -> io::Result<()> {
    let msg = rrsig_signed_data(f, rrs);
    let sig_arr: [u8; 2420] = sig.try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{label}: sig not 2420 bytes")))?;
    if pk.verify(&msg, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, format!("{label}: RRSIG verification FAILED")))
    }
}

// ---------- main ----------

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut seed_file: Option<PathBuf> = None;
    let mut out_file: Option<PathBuf> = None;
    let mut zone_origin = "pq.resolutionscope.com.".to_string();
    let mut serial = 2026083001u32;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed-file" => { i += 1; seed_file = Some(PathBuf::from(&args[i])); }
            "--out" => { i += 1; out_file = Some(PathBuf::from(&args[i])); }
            "--origin" => { i += 1; zone_origin = args[i].clone(); }
            "--serial" => { i += 1; serial = args[i].parse().unwrap(); }
            _ => { eprintln!("unknown flag: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    let seed_file = seed_file.expect("--seed-file required");
    let zone_origin = if zone_origin.ends_with('.') { zone_origin } else { format!("{zone_origin}.") };

    // Read seed
    let seed_bytes = fs::read(&seed_file)?;
    assert_eq!(seed_bytes.len(), 32, "seed must be 32 bytes, got {}", seed_bytes.len());
    let seed: [u8; 32] = seed_bytes.try_into().unwrap();

    // Keygen
    let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&seed);
    let pk_bytes = pk.into_bytes().to_vec();

    // DNSKEY + DS
    let dnskey_rd = dnskey_rdata(257, 3, 18, &pk_bytes);
    let kt = keytag(&dnskey_rd);
    let ds = ds_sha256(&zone_origin, &dnskey_rd);

    // RRSIG timestamps
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let inception = (now - 3600) as u32;
    let expiration = (now + 30 * 86400) as u32;
    let labels = zone_origin.trim_end_matches('.').split('.').count() as u8;

    // Build RRsets (apex-only zone per SPEC §3)
    let soa_rd = soa_rdata(&zone_origin, "hostmaster.resolutionscope.com.", serial, 3600, 900, 604800, 300);
    let soa_rr = Rr { owner: zone_origin.clone(), class: 1, rdata: soa_rd.clone() };

    let ns_rd = name_wire("pqns.resolutionscope.com.");
    let ns_rr = Rr { owner: zone_origin.clone(), class: 1, rdata: ns_rd };

    let txt_str = "v=pqexperiment1; domain=pq.resolutionscope.com; algorithm=18; algorithm-name=ML-DSA-44; draft=draft-westerbaan-dnssec-mldsa-04; purpose=fields-specimen-only; corpus-excluded=YES; dual-sign=NO; label=EXPERIMENT-NOT-PRODUCTION; contact=carey.balboa@it-help.tech";
    let txt_rd = txt_rdata(txt_str);
    let txt_rr = Rr { owner: zone_origin.clone(), class: 1, rdata: txt_rd };

    let dnskey_rr = Rr { owner: zone_origin.clone(), class: 1, rdata: dnskey_rd.clone() };

    // NSEC: apex-only, self-pointing, bitmap covers A NS SOA TXT DNSKEY NSEC RRSIG
    let nsec_rd = nsec_rdata(&zone_origin, &[1, 2, 6, 16, 48, 47, 46]);
    let nsec_rr = Rr { owner: zone_origin.clone(), class: 1, rdata: nsec_rd.clone() };

    let soa_set = vec![&soa_rr];
    let ns_set = vec![&ns_rr];
    let txt_set = vec![&txt_rr];
    let dnskey_set = vec![&dnskey_rr];
    let nsec_set = vec![&nsec_rr];

    // Sign each RRset
    let (soa_f, soa_sig) = sign_rrset(&sk, &soa_set, 6, labels, 3600, inception, expiration, kt, &zone_origin);
    let (ns_f, ns_sig) = sign_rrset(&sk, &ns_set, 2, labels, 3600, inception, expiration, kt, &zone_origin);
    let (txt_f, txt_sig) = sign_rrset(&sk, &txt_set, 16, labels, 3600, inception, expiration, kt, &zone_origin);
    let (dnskey_f, dnskey_sig) = sign_rrset(&sk, &dnskey_set, 48, labels, 3600, inception, expiration, kt, &zone_origin);
    let (nsec_f, nsec_sig) = sign_rrset(&sk, &nsec_set, 47, labels, 3600, inception, expiration, kt, &zone_origin);

    // Self-verify
    let pk2 = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_bytes.clone().try_into().unwrap()).unwrap();
    verify_rrset(&pk2, &soa_f, &soa_sig, &soa_set, "SOA")?;
    verify_rrset(&pk2, &ns_f, &ns_sig, &ns_set, "NS")?;
    verify_rrset(&pk2, &txt_f, &txt_sig, &txt_set, "TXT")?;
    verify_rrset(&pk2, &dnskey_f, &dnskey_sig, &dnskey_set, "DNSKEY")?;
    verify_rrset(&pk2, &nsec_f, &nsec_sig, &nsec_set, "NSEC")?;
    eprintln!("self-verify: all 5 RRSIGs verified OK");

    // Emit zone file
    let mut out: Box<dyn Write> = if let Some(ref p) = out_file {
        Box::new(fs::File::create(p)?)
    } else {
        Box::new(io::stdout().lock())
    };

    writeln!(out, "; pq.resolutionscope.com — ML-DSA-44 algorithm-18 signed zone")?;
    writeln!(out, "; DNSKEY keytag={kt} DS={}", hex::encode(ds))?;
    writeln!(out)?;

    writeln!(out, "{zone_origin} 3600 IN SOA {}", soa_presentation(&soa_rd))?;
    writeln!(out, "{}", rrsig_presentation(&soa_f, &soa_sig))?;
    writeln!(out, "{zone_origin} 3600 IN NS pqns.resolutionscope.com.")?;
    writeln!(out, "{}", rrsig_presentation(&ns_f, &ns_sig))?;
    writeln!(out, "{zone_origin} 3600 IN TXT \"{txt_str}\"")?;
    writeln!(out, "{}", rrsig_presentation(&txt_f, &txt_sig))?;
    writeln!(out, "{zone_origin} 3600 IN DNSKEY {}", dnskey_presentation(&dnskey_rd))?;
    writeln!(out, "{}", rrsig_presentation(&dnskey_f, &dnskey_sig))?;
    writeln!(out, "{zone_origin} 3600 IN NSEC {}", nsec_presentation(&nsec_rd))?;
    writeln!(out, "{}", rrsig_presentation(&nsec_f, &nsec_sig))?;

    Ok(())
}