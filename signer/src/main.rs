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
        ac += if i & 1 == 1 {
            b as u32
        } else {
            (b as u32) << 8
        };
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

#[derive(Clone)]
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

#[derive(Clone)]
struct SigningContext {
    labels: u8,
    orig_ttl: u32,
    inception: u32,
    expiration: u32,
    keytag: u16,
    signer: String,
}

impl SigningContext {
    fn fields_for(&self, type_covered: u16) -> RrsigFields {
        RrsigFields {
            type_covered,
            algorithm: 18,
            labels: self.labels,
            orig_ttl: self.orig_ttl,
            expiration: self.expiration,
            inception: self.inception,
            keytag: self.keytag,
            signer: self.signer.clone(),
        }
    }
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

fn soa_rdata(
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
) -> Vec<u8> {
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

/// Split a TXT payload into DNS char-strings (≤255 bytes each).
///
/// Rule (routed by claude-code @533d92e, proven byte-identical @0b01277):
/// cut at the LAST SPACE within the 255-byte window, RETAINING the space at
/// the tail of the chunk — prose always reads word-whole in `dig` output.
/// The 255 limit is a maximum, not a mandated cut point.
/// Escape clause: if the window holds NO space (a >255-byte token, e.g. a
/// future sidecar carrying base64), fall back to a hard 255-byte cut for
/// that span only; the boundary is reported as hard-cut so wall.sh can
/// exempt exactly those spans from its word-boundary check.
/// Byte-identity invariant: concatenating the chunks reproduces the input
/// exactly — chunking moves the cut, never a byte.
/// Mirror lives in pq-harness/wall.sh §4b (keep the two in sync).
fn txt_chunks(text: &str) -> Vec<(String, bool)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < b.len() {
        if b.len() - start <= 255 {
            out.push((text[start..].to_string(), false));
            break;
        }
        match b[start..start + 255].iter().rposition(|&c| c == b' ') {
            Some(i) => {
                // retain the space at the chunk tail
                out.push((text[start..start + i + 1].to_string(), false));
                start += i + 1;
            }
            None => {
                out.push((text[start..start + 255].to_string(), true));
                start += 255;
            }
        }
    }
    out
}

fn txt_rdata(text: &str) -> Vec<u8> {
    let mut r = Vec::new();
    for (chunk, _hard) in txt_chunks(text) {
        let cb = chunk.as_bytes();
        r.push(cb.len() as u8);
        r.extend_from_slice(cb);
    }
    r
}

fn txt_presentation(text: &str) -> String {
    txt_chunks(text)
        .into_iter()
        .map(|(chunk, _hard)| format!("\"{chunk}\""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&preference.to_be_bytes());
    r.extend_from_slice(&name_wire(exchange));
    r
}

fn mx_presentation(rdata: &[u8]) -> String {
    let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
    format!("{pref} {}", name_unwire(&rdata[2..]))
}

fn nsec_rdata(next_name: &str, types: &[u16]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&name_wire(next_name));
    let mut bitmap = [0u8; 32]; // 256 bits for type 0–255
    for &t in types {
        let byte = (t / 8) as usize;
        let bit = 7 - (t % 8);
        if byte < 32 {
            bitmap[byte] |= 1 << bit;
        }
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
        1 => "A",
        2 => "NS",
        6 => "SOA",
        15 => "MX",
        16 => "TXT",
        48 => "DNSKEY",
        47 => "NSEC",
        46 => "RRSIG",
        _ => unreachable!(),
    }
}

fn name_unwire(data: &[u8]) -> String {
    let mut pos = 0;
    let mut labels: Vec<&str> = Vec::new();
    while pos < data.len() && data[pos] != 0 {
        let len = data[pos] as usize;
        pos += 1;
        labels.push(std::str::from_utf8(&data[pos..pos + len]).unwrap());
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

/// Epoch seconds → YYYYMMDDHHMMSS (UTC), the RRSIG time presentation every
/// serving daemon accepts (NSD rejects bare epoch integers; the records spec §3.2 — README.md citation map
/// allows both, but zone files must be written for the strictest parser).
fn epoch_to_zone_time(epoch: u32) -> String {
    // civil-from-days (Howard Hinnant's algorithm), days since 1970-01-01
    let days = (epoch / 86400) as i64;
    let secs = (epoch % 86400) as i64;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0,399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}{m:02}{d:02}{:02}{:02}{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn rrsig_presentation(f: &RrsigFields, sig: &[u8]) -> String {
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    format!(
        "{} 3600 IN RRSIG {} {} {} {} {} {} {} {} {}",
        f.signer,
        type_name(f.type_covered),
        f.algorithm,
        f.labels,
        f.orig_ttl,
        epoch_to_zone_time(f.expiration),
        epoch_to_zone_time(f.inception),
        f.keytag,
        f.signer,
        sig_b64
    )
}

fn nsec_presentation(rdata: &[u8]) -> String {
    let next = name_unwire(rdata);
    let i = rdata.iter().position(|&b| b == 0).unwrap() + 1;
    let rest = &rdata[i..];
    let window = rest[0];
    let bitmap_len = rest[1] as usize;
    let bitmap = &rest[2..2 + bitmap_len];
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

/// Zone content — single source of truth, shared by --preview (unsigned
/// placeholder) and the production signing run. Schema per SPEC §3.
const TXT_DECLARATION: &str = "v=pqexperiment2; alg=18; alg-name=ML-DSA-44; keytag=33846; keybytes=1312; iana-assigned-between=2026-08-04..2026-08-11; ref=draft-westerbaan-dnssec-mldsa-04; purpose=field-specimen-only; corpus-excluded=YES; dual-sign=NO; contact=security@it-help.tech";

/// No-mail fixture lock (family standard, WHOIS/mail doctrine 2026-08-21):
/// null MX declares "accepts no mail" (null-MX spec — README.md citation map), SPF -all declares no
/// authorized sender. The fixture cannot be spoofed FROM.
const TXT_SPF: &str = "v=spf1 -all";

/// Carey's words (fixture doctrine: ASCII-only, word-boundary chunking).
const TXT_POEM: &str = "Come home to the data, stay spooky at a distance on that sidewalk with a foundation that is better than concrete, seek logic and reason, mathematical validation not con-firmation -- that is just social media likes, not the tour -- that is just applause, great talk now back to the lab! Decide to mathematically, logically work for the future. One less champagne lobster dinner is a lot more science. Immutable reality checks and mathematical validation my love that is the data we come home to.";

// ---------- sign + verify ----------

fn sign_rrset(
    sk: &fips204::ml_dsa_44::PrivateKey,
    rrs: &[&Rr],
    type_covered: u16,
    ctx: &SigningContext,
) -> (RrsigFields, Vec<u8>) {
    let f = ctx.fields_for(type_covered);
    let msg = rrsig_signed_data(&f, rrs);
    let sig = sk
        .try_sign_with_seed(&[0u8; 32], &msg, &[])
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
    let sig_arr: [u8; 2420] = sig.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label}: sig not 2420 bytes"),
        )
    })?;
    if pk.verify(&msg, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label}: RRSIG verification FAILED"),
        ))
    }
}

// ---------- main ----------

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut seed_file: Option<PathBuf> = None;
    let mut out_file: Option<PathBuf> = None;
    let mut zone_origin = "pq.resolutionscope.com.".to_string();
    let mut serial = 2026083001u32;
    let mut preview = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed-file" => {
                i += 1;
                seed_file = Some(PathBuf::from(&args[i]));
            }
            "--out" => {
                i += 1;
                out_file = Some(PathBuf::from(&args[i]));
            }
            "--origin" => {
                i += 1;
                zone_origin = args[i].clone();
            }
            "--serial" => {
                i += 1;
                serial = args[i].parse().unwrap();
            }
            "--preview" => {
                preview = true;
            }
            _ => {
                eprintln!("unknown flag: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // ---------- preview mode: UNSIGNED placeholder zone ----------
    // The pre-signing box must serve zone content produced by THIS binary too
    // (process rule @533d92e: zones are signer output, never hand-edited).
    // Emits exactly the placeholder shape: SOA + NS + declaration TXT + poem
    // TXT. No DNSKEY, no NSEC, no RRSIGs — the island window stays shut.
    if preview {
        assert!(seed_file.is_none(), "--preview takes no --seed-file");
        let soa_rd = soa_rdata(
            &zone_origin,
            "hostmaster.resolutionscope.com.",
            serial,
            3600,
            900,
            604800,
            300,
        );
        let txt_str = TXT_DECLARATION;
        let poem = TXT_POEM;
        let mut out: Box<dyn Write> = if let Some(ref p) = out_file {
            Box::new(fs::File::create(p)?)
        } else {
            Box::new(io::stdout().lock())
        };
        writeln!(
            out,
            "; pq.resolutionscope.com — UNSIGNED preview (island window shut)"
        )?;
        writeln!(out, "; generated by pq-signer --preview — do not hand-edit")?;
        writeln!(out)?;
        writeln!(
            out,
            "{zone_origin} 3600 IN SOA {}",
            soa_presentation(&soa_rd)
        )?;
        writeln!(out, "{zone_origin} 3600 IN NS pqns.resolutionscope.com.")?;
        writeln!(
            out,
            "{zone_origin} 3600 IN TXT {}",
            txt_presentation(txt_str)
        )?;
        writeln!(out, "{zone_origin} 3600 IN TXT {}", txt_presentation(poem))?;
        eprintln!("preview: unsigned zone emitted (serial {serial})");
        return Ok(());
    }

    let seed_file = seed_file.expect("--seed-file required");
    let zone_origin = if zone_origin.ends_with('.') {
        zone_origin
    } else {
        format!("{zone_origin}.")
    };

    // Read seed
    let seed_bytes = fs::read(&seed_file)?;
    assert_eq!(
        seed_bytes.len(),
        32,
        "seed must be 32 bytes, got {}",
        seed_bytes.len()
    );
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
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let inception = (now - 3600) as u32;
    let expiration = (now + 30 * 86400) as u32;
    let labels = zone_origin.trim_end_matches('.').split('.').count() as u8;

    // Build RRsets (apex-only zone per SPEC §3)
    let soa_rd = soa_rdata(
        &zone_origin,
        "hostmaster.resolutionscope.com.",
        serial,
        3600,
        900,
        604800,
        300,
    );
    let soa_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: soa_rd.clone(),
    };

    let ns_rd = name_wire("pqns.resolutionscope.com.");
    let ns_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: ns_rd,
    };

    // Single source of truth for zone content (process rule @533d92e: zones
    // are signer OUTPUT, never hand-edited on the box). Schema per SPEC §3;
    // contact is the role address (WHOIS doctrine 2026-08-23); poem is
    // Carey's words, ASCII-only by fixture doctrine.
    let txt_str = TXT_DECLARATION;
    let poem = TXT_POEM;
    let txt_rd = txt_rdata(txt_str);
    let poem_rd = txt_rdata(poem);
    let spf_rd = txt_rdata(TXT_SPF);
    let txt_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: txt_rd,
    };
    let poem_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: poem_rd,
    };
    let spf_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: spf_rd,
    };
    // Null MX (null-MX spec, README.md citation map): declares this fixture accepts no mail at all.
    let mx_rd = mx_rdata(0, ".");
    let mx_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: mx_rd.clone(),
    };

    let dnskey_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: dnskey_rd.clone(),
    };

    // NSEC: apex-only, self-pointing, bitmap covers NS SOA MX TXT DNSKEY NSEC RRSIG.
    // Do not claim A here: pqns.resolutionscope.com lives in the parent zone, not this child zone.
    let nsec_rd = nsec_rdata(&zone_origin, &[2, 6, 15, 16, 48, 47, 46]);
    let nsec_rr = Rr {
        owner: zone_origin.clone(),
        class: 1,
        rdata: nsec_rd.clone(),
    };

    let soa_set = vec![&soa_rr];
    let ns_set = vec![&ns_rr];
    let txt_set = vec![&txt_rr, &poem_rr, &spf_rr];
    let mx_set = vec![&mx_rr];
    let dnskey_set = vec![&dnskey_rr];
    let nsec_set = vec![&nsec_rr];

    // Sign each RRset
    let signing_ctx = SigningContext {
        labels,
        orig_ttl: 3600,
        inception,
        expiration,
        keytag: kt,
        signer: zone_origin.clone(),
    };
    let (soa_f, soa_sig) = sign_rrset(&sk, &soa_set, 6, &signing_ctx);
    let (ns_f, ns_sig) = sign_rrset(&sk, &ns_set, 2, &signing_ctx);
    let (txt_f, txt_sig) = sign_rrset(&sk, &txt_set, 16, &signing_ctx);
    let (mx_f, mx_sig) = sign_rrset(&sk, &mx_set, 15, &signing_ctx);
    let (dnskey_f, dnskey_sig) = sign_rrset(&sk, &dnskey_set, 48, &signing_ctx);
    let (nsec_f, nsec_sig) = sign_rrset(&sk, &nsec_set, 47, &signing_ctx);

    // Self-verify
    let pk2 = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_bytes.clone().try_into().unwrap())
        .unwrap();
    verify_rrset(&pk2, &soa_f, &soa_sig, &soa_set, "SOA")?;
    verify_rrset(&pk2, &ns_f, &ns_sig, &ns_set, "NS")?;
    verify_rrset(&pk2, &txt_f, &txt_sig, &txt_set, "TXT")?;
    verify_rrset(&pk2, &mx_f, &mx_sig, &mx_set, "MX")?;
    verify_rrset(&pk2, &dnskey_f, &dnskey_sig, &dnskey_set, "DNSKEY")?;
    verify_rrset(&pk2, &nsec_f, &nsec_sig, &nsec_set, "NSEC")?;
    eprintln!("self-verify: all 6 RRSIGs verified OK");

    // Emit zone file
    let mut out: Box<dyn Write> = if let Some(ref p) = out_file {
        Box::new(fs::File::create(p)?)
    } else {
        Box::new(io::stdout().lock())
    };

    writeln!(
        out,
        "; pq.resolutionscope.com — ML-DSA-44 algorithm-18 signed zone"
    )?;
    writeln!(out, "; DNSKEY keytag={kt} DS={}", hex::encode(ds))?;
    writeln!(out)?;

    writeln!(
        out,
        "{zone_origin} 3600 IN SOA {}",
        soa_presentation(&soa_rd)
    )?;
    writeln!(out, "{}", rrsig_presentation(&soa_f, &soa_sig))?;
    writeln!(out, "{zone_origin} 3600 IN NS pqns.resolutionscope.com.")?;
    writeln!(out, "{}", rrsig_presentation(&ns_f, &ns_sig))?;
    writeln!(
        out,
        "{zone_origin} 3600 IN TXT {}",
        txt_presentation(txt_str)
    )?;
    writeln!(out, "{zone_origin} 3600 IN TXT {}", txt_presentation(poem))?;
    writeln!(
        out,
        "{zone_origin} 3600 IN TXT {}",
        txt_presentation(TXT_SPF)
    )?;
    writeln!(out, "{}", rrsig_presentation(&txt_f, &txt_sig))?;
    writeln!(out, "{zone_origin} 3600 IN MX {}", mx_presentation(&mx_rd))?;
    writeln!(out, "{}", rrsig_presentation(&mx_f, &mx_sig))?;
    writeln!(
        out,
        "{zone_origin} 3600 IN DNSKEY {}",
        dnskey_presentation(&dnskey_rd)
    )?;
    writeln!(out, "{}", rrsig_presentation(&dnskey_f, &dnskey_sig))?;
    writeln!(
        out,
        "{zone_origin} 3600 IN NSEC {}",
        nsec_presentation(&nsec_rd)
    )?;
    writeln!(out, "{}", rrsig_presentation(&nsec_f, &nsec_sig))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte-identity invariant: chunking moves the cut, never a byte.
    fn assert_roundtrip(text: &str) {
        let chunks = txt_chunks(text);
        let concat: String = chunks.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(concat, text, "chunk concatenation must reproduce input");
        for (c, _) in &chunks {
            assert!(c.len() <= 255, "char-string exceeds 255 bytes");
            assert!(!c.is_empty(), "empty char-string is hostile to parsers");
        }
    }

    #[test]
    fn poem_splits_on_word_boundary_retaining_space() {
        let poem = TXT_POEM;
        let chunks = txt_chunks(poem);
        assert_eq!(chunks.len(), 2, "494-byte poem -> exactly two char-strings");
        assert_eq!(chunks[0].0.len(), 254, "cut lands on the space at byte 254");
        assert!(chunks[0].0.ends_with(' '), "space retained at chunk tail");
        assert!(
            chunks[0].0.ends_with("applause, "),
            "no mid-word cut: chunk 1"
        );
        assert!(
            chunks[1].0.starts_with("great talk"),
            "no mid-word cut: chunk 2"
        );
        // every chunk that IS NOT the final one must end on its space
        // (a word-boundary cut retains the space; the final chunk simply
        // ends with the text — it has no boundary to satisfy)
        for (c, hard) in &chunks[..chunks.len() - 1] {
            assert!(!hard, "poem has spaces; no hard cuts expected");
            assert!(c.ends_with(' '), "non-final chunk must end on its space");
        }
        assert_roundtrip(poem);
    }

    #[test]
    fn spaceless_blob_falls_back_to_hard_cuts() {
        let blob = "a".repeat(600);
        let chunks = txt_chunks(&blob);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0.len(), 255);
        assert_eq!(chunks[1].0.len(), 255);
        assert_eq!(chunks[2].0.len(), 90);
        assert!(chunks[0].1 && chunks[1].1, "mid-stream spans hard-cut");
        assert_roundtrip(&blob);
    }

    #[test]
    fn mixed_prose_and_giant_token() {
        let text = format!("lead-in {} tail words here", "b".repeat(300));
        assert_roundtrip(&text);
        let chunks = txt_chunks(&text);
        // the 300-byte token forces at least one hard-cut span, but the
        // trailing prose must still land on word boundaries
        assert!(chunks.iter().any(|(_, hard)| *hard));
        let last = chunks.last().unwrap();
        assert!(!last.1, "trailing prose should be a word-boundary span");
    }

    #[test]
    fn single_chunk_under_cap_is_never_split() {
        let text = "x y z ".repeat(40); // 240 bytes, spaces throughout
        assert_eq!(txt_chunks(&text).len(), 1);
        assert_roundtrip(&text);
    }

    /// Synthetic >255-byte space-retention test — independent of whatever the
    /// zone currently carries (relay finding: a short poem removes the live
    /// test surface for the word-boundary chunker; the check must not depend
    /// on zone content existing that happens to be long).
    #[test]
    fn chunker_is_word_boundary_synthetic() {
        // 60 words of varied length, ~420 bytes — forces multiple cuts
        let text: String = (0..60)
            .map(|i| format!("{}{} ", "probe", i))
            .collect();
        assert!(text.len() > 255, "test must exceed one char-string");
        let chunks = txt_chunks(&text);
        assert!(chunks.len() >= 2);
        for (c, hard) in &chunks[..chunks.len() - 1] {
            assert!(!hard, "prose with spaces must never hard-cut");
            assert!(c.ends_with(' '), "every non-final chunk retains its space");
            assert!(!c.trim_end().is_empty());
        }
        assert_roundtrip(&text);
        // and the rendered form splits exactly at those boundaries
        let rendered = txt_presentation(&text);
        assert_eq!(rendered.matches("\" \"").count() + 1, chunks.len());
    }

    #[test]
    fn presentation_matches_wire_chunking() {
        let poem = "word ".repeat(80); // 400 bytes
        let rendered = txt_presentation(&poem);
        assert!(
            rendered.contains("\" \""),
            "long TXT must render as multiple quoted strings"
        );
        let inner: Vec<&str> = rendered.split("\" \"").collect();
        assert_eq!(inner.len(), txt_chunks(&poem).len());
        assert_roundtrip(&poem);
    }

    #[test]
    fn declaration_is_a_single_chunk() {
        let decl = TXT_DECLARATION;
        assert!(decl.len() <= 255);
        assert_eq!(txt_chunks(decl).len(), 1);
    }

    #[test]
    fn nsec_bitmap_does_not_claim_parent_zone_a_record() {
        let rdata = nsec_rdata("pq.resolutionscope.com.", &[2, 6, 15, 16, 48, 47, 46]);
        let rendered = nsec_presentation(&rdata);
        assert!(
            !format!(" {rendered} ").contains(" A "),
            "child-zone NSEC must not claim A"
        );
        assert!(rendered.contains("NS"));
        assert!(rendered.contains("SOA"));
        assert!(rendered.contains("MX"));
        assert!(rendered.contains("TXT"));
        assert!(rendered.contains("DNSKEY"));
        assert!(rendered.contains("RRSIG"));
        assert!(rendered.contains("NSEC"));
    }

    /// Known-answer test for epoch_to_zone_time, oracle = `date -u -r <epoch>`.
    /// A silent off-by-one here shifts every RRSIG validity window — the
    /// civil-from-days algorithm gets pinned, not trusted.
    #[test]
    fn epoch_to_zone_time_known_answers() {
        assert_eq!(epoch_to_zone_time(0), "19700101000000");
        assert_eq!(epoch_to_zone_time(951782400), "20000229000000"); // leap day
        assert_eq!(epoch_to_zone_time(1788072388), "20260830064628");
        assert_eq!(epoch_to_zone_time(1790667988), "20260929074628");
        assert_eq!(epoch_to_zone_time(4102444799), "20991231235959");
    }

    #[test]
    fn rrsig_presentation_uses_zone_time_not_epoch() {
        let f = RrsigFields {
            type_covered: 6,
            algorithm: 18,
            labels: 3,
            orig_ttl: 3600,
            expiration: 1790667988,
            inception: 1788072388,
            keytag: 33846,
            signer: "pq.resolutionscope.com.".to_string(),
        };
        let line = rrsig_presentation(&f, &[0u8; 2420]);
        assert!(
            line.contains(" 20260929074628 20260830064628 "),
            "RRSIG dates must be YYYYMMDDHHMMSS (NSD rejects epoch): {line}"
        );
        assert!(
            !line.contains("1790667988"),
            "no bare epoch integers in zone presentation"
        );
    }
}
