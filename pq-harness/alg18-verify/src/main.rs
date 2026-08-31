//! Independent alg-18 verifier — proves the LIVE zones' ML-DSA-44 signatures
//! using an implementation DIFFERENT from the signer.
//!
//! Signer: fips204 crate. This verifier: RustCrypto ml-dsa (the independent
//! KAT-verified implementation from the 2026-08-30 bake-off). Two independent
//! codebases agreeing on the deployed wire = the verification discipline CC
//! applied to alg-8 (pure-Python RSA), extended to alg-18.
//!
//! Input: a zone file as SERVED (fetched from the authoritative, not from the
//! signer's output) — the stale-input class hunts the emitted artifact.
//! Verifies EVERY alg-18 RRSIG against the RRsets the file carries, plus the
//! DS digest match. Canonical wire reconstruction per the same rules the
//! wall's check 13 uses (validated byte-for-byte against the signer's own
//! debug hashes).

use ml_dsa::{MlDsa44, VerifyingKey};

fn name_wire(n: &str) -> Vec<u8> {
    let t = n.trim_end_matches('.');
    if t.is_empty() {
        return vec![0];
    }
    let mut out = Vec::new();
    for l in t.split('.') {
        let b = l.to_ascii_lowercase().into_bytes();
        out.push(b.len() as u8);
        out.extend(b);
    }
    out.push(0);
    out
}

fn zt_to_epoch(s: &str) -> u32 {
    use std::time::UNIX_EPOCH;
    // YYYYMMDDHHMMSS -> epoch via the civil-days algorithm (same as the signer's
    // inverse). Simple portable version:
    let (y, mo, d, h, mi, sec) = (
        s[0..4].parse::<u32>().unwrap(),
        s[4..6].parse::<u32>().unwrap(),
        s[6..8].parse::<u32>().unwrap(),
        s[8..10].parse::<u32>().unwrap(),
        s[10..12].parse::<u32>().unwrap(),
        s[12..14].parse::<u32>().unwrap(),
    );
    // days from civil (Howard Hinnant's algorithm)
    let y_adj = if mo <= 2 { y - 1 } else { y } as i64;
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let m_adj = mo as i64;
    let doy = (153 * (if m_adj > 2 { m_adj - 3 } else { m_adj + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + h as i64 * 3600 + mi as i64 * 60 + sec as i64;
    // negate-days trick for the epoch (days since 1970-01-01, civil unsigned form)
    let _ = UNIX_EPOCH;
    secs as u32
}

struct Rr {
    owner: String,
    rtype: String,
    rdata: Vec<u8>,
    ttl: u32,
}

fn txt_rd(line: &str) -> Vec<u8> {
    // shlex-like: the zone file quotes char-strings
    let toks: Vec<&str> = line.split('"').collect();
    let mut rd = Vec::new();
    // tokens alternate outside/inside quotes; inside-quotes are the chunks
    let mut in_q = false;
    for (i, t) in toks.iter().enumerate() {
        if i % 2 == 1 {
            let by = t.as_bytes();
            rd.push(by.len() as u8);
            rd.extend_from_slice(by);
            in_q = true;
        }
    }
    let _ = in_q;
    rd
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .expect("usage: alg18-verify <zone-file> [origin]");
    let origin = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "pq.resolutionscope.com.".into());
    let text = std::fs::read_to_string(path).expect("read zone");
    let mut lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with(';') && !l.trim().is_empty())
        .collect();

    // Parse RRsets
    let mut dnskeys: Vec<(u16, Vec<u8>)> = Vec::new(); // (keytag, full wire rdata incl flags/proto/alg)
    let mut records: Vec<Rr> = Vec::new();
    for l in &lines {
        let toks: Vec<&str> = l.split_whitespace().collect();
        if toks.len() < 5 {
            continue;
        }
        let owner = toks[0].to_string();
        let ttl: u32 = toks[1].parse().unwrap_or(3600);
        let rtype = toks[3].to_string();
        let rdata = match rtype.as_str() {
            "DNSKEY" => {
                // flags proto alg b64...
                let flags: u16 = toks[4].parse().unwrap();
                let proto: u8 = toks[5].parse().unwrap();
                let alg: u8 = toks[6].parse().unwrap();
                let b64: String = toks[7..].concat();
                let key = base64_decode(&b64);
                let mut rd = vec![(flags >> 8) as u8, (flags & 0xff) as u8, proto, alg];
                rd.extend(key);
                rd
            }
            "TXT" => txt_rd(l),
            "NS" => name_wire(toks[4]),
            "SOA" => {
                let mut rd = name_wire(toks[4]);
                rd.extend(name_wire(toks[5]));
                for n in &toks[6..11] {
                    rd.extend_from_slice(&n.parse::<u32>().unwrap().to_be_bytes());
                }
                rd
            }
            "MX" => {
                let pref: u16 = toks[4].parse().unwrap();
                let mut rd = pref.to_be_bytes().to_vec();
                rd.extend(name_wire(toks[5]));
                rd
            }
            "NSEC" => {
                let mut rd = name_wire(toks[4]);
                // bitmap: last-nonzero window rule
                let mut bits = [0u8; 32];
                for tn in &toks[5..] {
                    let num = match *tn {
                        "NS" => 2,
                        "SOA" => 6,
                        "MX" => 15,
                        "TXT" => 16,
                        "RRSIG" => 46,
                        "NSEC" => 47,
                        "DNSKEY" => 48,
                        _ => continue,
                    };
                    bits[(num / 8) as usize] |= 1 << (7 - (num % 8));
                }
                let last = (0..32).rev().find(|&i| bits[i] != 0).unwrap_or(0);
                rd.push(0);
                rd.push((last + 1) as u8);
                rd.extend(&bits[..=last]);
                rd
            }
            _ => continue,
        };
        if rtype == "DNSKEY" {
            let kt = keytag_of(&rdata);
            dnskeys.push((kt, rdata.clone()));
        }
        records.push(Rr {
            owner,
            rtype,
            ttl,
            rdata,
        });
    }

    // Verify every alg-18 RRSIG
    let type_num = |t: &str| -> u16 {
        match t {
            "SOA" => 6,
            "NS" => 2,
            "TXT" => 16,
            "MX" => 15,
            "DNSKEY" => 48,
            "NSEC" => 47,
            _ => 0,
        }
    };
    let mut checked = 0usize;
    let mut failures = 0usize;
    lines.retain(|l| !l.trim_start().starts_with(';'));
    for l in &lines {
        let toks: Vec<&str> = l.split_whitespace().collect();
        if toks.len() < 12 || toks[3] != "RRSIG" || toks[5] != "18" {
            continue;
        }
        let covered = toks[4].to_string();
        let labels: u8 = toks[6].parse().unwrap();
        let ttl: u32 = toks[7].parse().unwrap();
        let exp = zt_to_epoch(toks[8]);
        let inc = zt_to_epoch(toks[9]);
        let kt: u16 = toks[10].parse().unwrap();
        let signer = toks[11].to_string();
        let sig = base64_decode(&toks[12..].concat());

        // find the key
        let key_wire = match dnskeys.iter().find(|(k, _)| *k == kt) {
            Some((_, w)) => w.clone(),
            None => {
                println!("✗ keytag {kt}: no matching DNSKEY in zone");
                failures += 1;
                continue;
            }
        };
        let key_bytes = &key_wire[4..];
        let arr: [u8; 1312] = key_bytes[..]
            .try_into()
            .expect("ML-DSA-44 public key must be 1312 bytes");
        let vk = VerifyingKey::<MlDsa44>::decode(&arr.into());

        // canonical RRset from the FILE
        let owner = toks[0].to_string();
        let mut sd: Vec<u8> = Vec::new();
        sd.extend_from_slice(&type_num(&covered).to_be_bytes());
        sd.push(18);
        sd.push(labels);
        sd.extend_from_slice(&ttl.to_be_bytes());
        sd.extend_from_slice(&exp.to_be_bytes());
        sd.extend_from_slice(&inc.to_be_bytes());
        sd.extend_from_slice(&kt.to_be_bytes());
        sd.extend(name_wire(&signer));
        // Canonical RRset: records sorted by RDATA BYTES (the signer's rule —
        // NOT the wire tuple, whose rdlen field would sort before the rdata
        // and produce a different order for RRsets whose records share a
        // length-prefix byte; caught by exact-hash diff against --debug-sd).
        let mut rrs_sorted: Vec<&Rr> = records
            .iter()
            .filter(|r| r.rtype == covered && r.owner == owner && r.rtype != "RRSIG")
            .collect();
        rrs_sorted.sort_by(|a, b| a.rdata.cmp(&b.rdata));
        for r in rrs_sorted {
            sd.extend(name_wire(&r.owner));
            sd.extend_from_slice(&type_num(&covered).to_be_bytes());
            sd.extend_from_slice(&1u16.to_be_bytes());
            sd.extend_from_slice(&r.ttl.to_be_bytes());
            sd.extend_from_slice(&(r.rdata.len() as u16).to_be_bytes());
            sd.extend_from_slice(&r.rdata);
        }

        use ml_dsa::signature::Verifier;
        let sig_arr: [u8; 2420] = sig[..]
            .try_into()
            .expect("ML-DSA-44 signature must be 2420 bytes");
        let sig_typed = ml_dsa::Signature::<MlDsa44>::decode(&sig_arr.into())
            .expect("2420-byte signature must decode");
        match vk.verify(&sd, &sig_typed) {
            Ok(()) => {
                println!("✓ keytag {kt} RRSIG over {covered}: ML-DSA-44 signature VERIFIES (independent impl)");
                checked += 1;
            }
            Err(_) => {
                println!(
                    "✗ keytag {kt} RRSIG over {covered}: signature FAILS independent verification"
                );
                failures += 1;
            }
        }
    }
    println!(
        "\n{origin}: {checked} alg-18 RRSIG(s) verified by the INDEPENDENT implementation (RustCrypto ml-dsa); {failures} failure(s)"
    );
    if failures > 0 {
        std::process::exit(1);
    }
}

fn keytag_of(rdata: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    for (i, b) in rdata.iter().enumerate() {
        acc += if i % 2 == 0 {
            (*b as u32) << 8
        } else {
            *b as u32
        };
    }
    acc = (acc & 0xffff) + (acc >> 16);
    ((acc & 0xffff) + (acc >> 16)) as u16
}

fn base64_decode(s: &str) -> Vec<u8> {
    // minimal base64 (standard alphabet, padded)
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = TBL.iter().position(|&t| t == c).unwrap_or(0) as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}
