//! DANE specimen receiver — the known-ground-truth half of the DANE fixture.
//!
//! Contract (phase 1, see policy/LANES.md 2026-08-30):
//!   * Listens on :25. SMTP banner -> EHLO -> STARTTLS -> TLS handshake.
//!   * Presents the certificate whose SPKI SHA-256 digest is published at
//!     `_25._tcp.mx.dane.resolutionscope.com TLSA 3 1 1` (selector = SPKI,
//!     matching = SHA-256, usage = domain-issued).
//!   * NEVER accepts a message: after the handshake it says so and closes.
//!     No DATA, no mailbox, no queue — the specimen is the CONNECTION.
//!   * Fail-closed on itself: at startup it hashes the loaded SPKI and refuses
//!     to listen unless it equals the pinned digest in this file, so the box
//!     can never present a cert the zone does not vouch for.
//!   * One connection at a time; every connection logs one receipt line:
//!     peer | ehlo | starttls=completed | spki=<digest> | tls=<version/cipher>.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};

/// Published TLSA RDATA (hex, no separators): usage 3, selector 1, matching 1.
const PINNED_SPKI_SHA256_HEX: &str =
    "754901f439238c97dbbfb0e5c0ed2ecdfd9a91786b96fea45484f824f6e57613";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let listen = flag(&args, "--listen", "0.0.0.0:25");
    let cert_path = flag(&args, "--cert", "/etc/dane-rx/cert.pem");
    let key_path = flag(&args, "--key", "/etc/dane-rx/key.pem");

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&cert_path)?))
            .collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(&key_path)?))?
            .ok_or("no private key found in key pem")?;

    // Fail closed: the loaded SPKI digest must equal the zone-published pin.
    let spki_digest = spki_sha256_hex(&certs)?;
    if spki_digest != PINNED_SPKI_SHA256_HEX {
        eprintln!(
            "FATAL: loaded SPKI digest {spki_digest} != zone pin {PINNED_SPKI_SHA256_HEX} \
             — refusing to serve a certificate the zone does not vouch for"
        );
        std::process::exit(1);
    }

    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("bad cert/key pair: {e}"))?,
    );

    let listener = TcpListener::bind(&listen)?;
    println!(
        "dane-rx listening on {listen} | spki sha256 {spki_digest} | \
         mail acceptance: NEVER (specimen receiver)"
    );

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        match handle(stream, config.clone()) {
            Ok((ehlo, starttls, tls_desc)) => {
                let ehlo_name = ehlo.as_deref().unwrap_or("-");
                println!("{peer} | ehlo={ehlo_name} | starttls={starttls} | {tls_desc}");
            }
            Err(e) => println!("{peer} | error: {e}"),
        }
    }
    Ok(())
}

fn handle(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<(Option<String>, bool, String), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut w = stream;

    write_resp(
        &mut w,
        "220 mx.dane.resolutionscope.com dane-specimen ESMTP (never accepts mail)",
    )?;

    let mut ehlo: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok((ehlo, false, "closed before STARTTLS".into()));
        }
        let upper = line.trim_end().to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            ehlo = Some(line.trim().to_string());
            write_resp(
                &mut w,
                "250-mx.dane.resolutionscope.com\r\n250-STARTTLS\r\n250 OK",
            )?;
        } else if upper.starts_with("STARTTLS") {
            write_resp(&mut w, "220 Ready to start TLS")?;
            // Handshake over the same socket. The buffered reader may hold
            // pipelined bytes; for the specimen, any pre-STARTTLS pipelining is
            // a protocol violation we accept losing (senders issue STARTTLS
            // on a fresh packet).
            let conn = ServerConnection::new(config).map_err(|e| format!("tls session: {e}"))?;
            let mut tls = StreamOwned::new(conn, reader.into_inner());
            // The Read/Write impls on StreamOwned drive the handshake
            // implicitly; a single zero-length write flushes any pending
            // handshake flight. Force it by writing nothing.
            use std::io::Write as _;
            let _ = tls.flush();
            // Blocking handshake: read until the session reports a protocol.
            let mut scratch = [0u8; 1024];
            while tls.conn.is_handshaking() {
                use std::io::Read as _;
                let n = tls.read(&mut scratch).map_err(|e| format!("handshake read: {e}"))?;
                let _ = n;
            }
            let proto = format!(
                "tls={:?}",
                tls.conn.protocol_version().map(|v| format!("{v:?}")).unwrap_or_else(|| "?".into())
            );
            // Never accept a message: say so inside TLS, then close.
            tls.write_all(
                b"250 STARTTLS complete - specimen receiver: this fixture never accepts mail\r\n",
            )
            .and_then(|_| tls.flush())
            .ok();
            return Ok((ehlo, true, proto));
        } else if upper.starts_with("QUIT") {
            write_resp(&mut w, "221 Bye")?;
            return Ok((ehlo, false, "quit before STARTTLS".into()));
        } else {
            write_resp(
                &mut w,
                "502 Specimen receiver: command not part of the fixture",
            )?;
        }
    }
}

fn write_resp<W: Write>(w: &mut W, msg: &str) -> std::io::Result<()> {
    w.write_all(msg.as_bytes())?;
    w.write_all(b"\r\n")?;
    w.flush()
}

fn flag(args: &[String], name: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

/// SHA-256 over the certificate's SubjectPublicKeyInfo, as the zone pin does.
fn spki_sha256_hex(
    certs: &[CertificateDer<'static>],
) -> Result<String, Box<dyn std::error::Error>> {
    let leaf = certs.first().ok_or("no certificates in pem")?;
    let (_rem, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())?;
    let spki_der = parsed.public_key().raw;
    let digest = Sha256::digest(spki_der);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}
