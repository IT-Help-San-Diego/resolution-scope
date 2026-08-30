# SPEC — DANE specimen fixture (phase 1, shipped 2026-08-30)

## Purpose
A DANE deployment whose **both ends we own**, so the DNSSEC→DNS→TLS chain can
be verified end-to-end with known ground truth — the dns-evil-* philosophy
applied to RFC 7672 (DANE for SMTP). The specimen is the CONNECTION: the
receiver never accepts a message, so there is no mail flow, no mailbox, no
spam surface — only the measurable handshake.

## Architecture (Science-corrected)
- `dane.resolutionscope.com MX 10 mx.dane.resolutionscope.com` — the recipient
  subdomain. The apex null-MX (`resolutionscope.com MX 0 .`) is UNTOUCHED:
  null MX is a property of the owner name, not inherited (RFC 7505), so mail
  routing to the subdomain consults the SUBDOMAIN's MX RRset only.
- `mx.dane.resolutionscope.com A 54.208.160.233` (the dane-rx box).
- `_25._tcp.mx.dane.resolutionscope.com TLSA 3 1 1 7549…7613` — usage 3
  (domain-issued), selector 1 (SPKI), matching 1 (SHA-256).
- All records live in the signed `resolutionscope.com` zone → every RRset
  (MX, A, TLSA) carries an RRSIG; a validating resolver proves the pin.

## Receiver (this crate, `dane-rx/`)
- Rust, rustls (ring backend), built ON the box (t4g.nano 406 MB + 2 GB swap
  — the constrained-hardware vector is part of the fixture's story).
- SMTP banner → EHLO → STARTTLS → TLS 1.3 handshake → states it never accepts
  mail → closes. **No DATA command exists in the state machine.**
- **Fail-closed on itself**: at startup it hashes the loaded SPKI and refuses
  to serve unless it equals `PINNED_SPKI_SHA256_HEX`. The box can never
  present a certificate the zone does not vouch for.
- One receipt line per connection: `peer | ehlo | starttls | tls=…`.
- systemd unit `dane-rx.service`, Restart=always. Private key at
  `/etc/dane-rx/key.pem` (root-only) — generated on the box, never left it.

## Network posture
- SG `dane-rx-sg`: port 22 from Carey's IP only; **port 25 from the three
  probe-fleet IPs only** (Paris 76.13.61.227, measure-us-east 32.194.114.146,
  measure-sg 52.76.139.32). Not world-open at phase 1.

## End-to-end receipt (Paris probe, 2026-08-30 21:01 UTC)
1. `dig TLSA _25._tcp.mx.dane.resolutionscope.com @1.1.1.1 +dnssec`
   → `flags: qr rd ra ad` (validated chain), TLSA `3 1 1 754901F4…F6E57613`,
   RRSIG TLSA by keytag 6990 visible.
2. `openssl s_client -starttls smtp` → TLSv1.3, TLS_AES_256_GCM_SHA384,
   subject CN=mx.dane.resolutionscope.com.
3. Live SPKI digest: `754901f439238c97dbbfb0e5c0ed2ecdfd9a91786b96fea45484f824f6e57613`
   — **byte-identical to the zone pin**. Chain closes.
4. Receiver log line: `76.13.61.227 | ehlo=EHLO mail.example.com |
   starttls=true | tls="TLSv1_3"`.

## Phase 2 (gated on the ~Sep 5 freeze lift)
TLSA inside the PQ zone (alg-18-signed) = post-quantum DANE. Requires a
re-sign of `pq.resolutionscope.com` → gated on the decay-observation window.
Prior-art check against mldsa.huque.com / kochen-specker.info before any
"first" claim.

## Non-goals
- No production mail (it-help.tech stays Google Workspace).
- No open inbound 25 (probe-fleet-only until a deliberate phase-2 ruling).
- The receiver is a specimen, not an MTA: no queue, no DATA, no 8BITMIME.
