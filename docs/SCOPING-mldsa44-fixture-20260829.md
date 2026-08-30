# Scoping Report — ML-DSA-44 (Algorithm 18) DNSSEC Fixture
### 2026-08-29 · Prepared by the hermes lane

## Summary — four sentences

`pq.resolutionscope.com` NS-delegates to a single box. That box runs a standalone
Rust zone signer — one binary, `fips204` crate — that generates an ML-DSA-44 KSK,
signs the zone apex, and serves the resulting DNSKEY/DS/RRSIG through the same box
(or any namesever). The parent (Route 53, `resolutionscope.com`) holds the DS record;
the signer is the only piece that doesn't exist yet, and it is a modest build. The
operational blocker is not software — it is packet size: every DNSSEC query carrying
ML-DSA-44 material triggers TCP fallback.

---

## 1. The desec-io/pqc-dnssec reference — what it is and isn't

Cloned 2026-08-29. The repo is a **Docker testbed** — not a standalone signer.

- Drivers: patched BIND authoritative + PowerDNS authoritative + BIND recursor.
- Algorithms: FALCON-512 (codepoint 17) and Dilithium-2 (codepoint 18) — experimental
  numbers that **happened to collide** with the later IANA assignments
  (17→SM2, 18→ML-DSA-44). The experiments predate IANA's early allocation.
- `setup.py:33-34`: `17: "falcon512"`, `18: "dilithium2"`.
- Crypto integration: calls BIND's `dnssec-keygen` and PowerDNS's `pdnsutil add-zone-key`
  with algorithm name strings — no standalone crypto library.
- **Verdict: useful as architecture reference and protocol conformance data, not as a
  base to fork.** The signer code lives inside patched BIND/PowerDNS, not in this repo.

Key architectural insight from their approach: the testbed used **separate containers**
(authoritative servers on a docker network) and NS-delegated test zones to the patched
servers. That is the exact delegation pattern we would use for `pq.resolutionscope.com`.

---

## 2. The Rust signer design — what we actually build

### Why Rust

- `fips204` crate (763K downloads, v0.3.x): FIPS 204 final spec, pure Rust, `no_std`
  capable, Apache-2.0/MIT. API is three calls: `try_keygen()`, `try_sign()`, `verify()`.
- The `ml-dsa` crate provides an alternative with comparable maturity.
- Both API's are stabilized, constant-time, and production-quality.
- Resolution Scope's engine is already Rust — same toolchain, same CI, same security
  posture.

### The signer (one binary, ~600-800 lines)

1. **Key pair**: `fips204::ml_dsa_44::try_keygen()` → KSK (flags=257).
2. **DNSEKEY RDATA**: `[flags(2)] [proto(1)=3] [algo(1)=18] [pubkey(1312)]` →
   1328 bytes on wire.
3. **Zone signing**: per RFC 4034 §3.1.8.1 — canonical ordering, `RRSIG` over
   each RRset with the KSK. ML-DSA-44 uses "pure" mode (not HashML-DSA), empty
   context string (per draft-westerbaan-dnssec-mldsa-03 §4).
4. **DS digest**: SHA-256 over `owner || DNSEKEY RDATA` (RFC 4034 §5.1.4).
5. **Output**: zone file with `DNSEKEY`, `RRSIG`, and the DS record for the
   parent.

### DNS server (any, not the hard part)

The signed zone file can be served through **any** authoritative server — NSD,
Knot, BIND, or a minimal Rust namesever. The signer is the novel piece; the
server is commodity. A minimal Rust authoritative server (the `hickory-server`
crate or a pure socket-based UDP responder) is a few hundred lines additional.

### What we skip

- **BIND/PowerDNS patching.** The desec-io approach was necessary for a field
  study that needed production-grade recursion and zone transfers. Our fixture
  needs neither — it is a single-zone, single-server authoritative endpoint.
- **A new domain registration.** `pq.resolutionscope.com` is a subdomain
  delegation in a zone we already control and sign.
- **Root or TLD support.** The parent zone just publishes the DS; it doesn't
  validate the child's algorithm.

---

## 3. The delegation plan — `pq.resolutionscope.com`

1. **Box**: `dnstool-app` (AWS t4g.medium, Ubuntu 24.04, Elastic IP 44.226.60.249).
   Already running; add the signer + a namesever on a secondary port or dedicated IP.
2. **NS delegation**: Route 53 `resolutionscope.com` zone ← new NS record:
   `pq.resolutionscope.com. IN NS ns1.pq.resolutionscope.com.`
3. **DS record**: Route 53 `resolutionscope.com` zone ← new DS record:
   `pq.resolutionscope.com. IN DS <keytag> 18 2 <sha256_hex>`
4. **Verification**: `dig +dnssec dnskey pq.resolutionscope.com @1.1.1.1` →
   algorithm 18 DNSKEY; `dig +dnssec ds pq.resolutionscope.com` → algorithm 18 DS;
   `dig +dnssec soa pq.resolutionscope.com` → algorithm 18 RRSIG with AD flag clear
   on most resolvers (since no validator supports 18 — the expected behavior for the
   honesty gate's positive control).

---

## 4. Packet size — the real operational blocker

| Record | Wire size | EDNS0 limit (1232) |
|---|---|---|
| ECDSA P-256 DNSKEY | ~80 bytes | fits ✓ |
| ECDSA P-256 RRSIG | ~102 bytes | fits ✓ |
| **ML-DSA-44 DNSKEY** | **1328 bytes** | **exceeds by 96** ✗ |
| **ML-DSA-44 RRSIG** | **2450 bytes** | **exceeds by 1218** ✗ |
| Combined response | **3778 bytes** | **exceeds by 2546** ✗ |

**Every single DNSSEC query for `pq.resolutionscope.com` triggers TCP fallback.**
Literature: ~10% of resolvers fail IP fragment reasssembly, and fragmentation
opens cache-poisining vectors (MDPI 2025 systematic review).

This is **not a blocker for the fixture** — the fixture's purpose is to be a
positive control for the honesty gate ("I see algorithm 18 and report 'could not
evaluate', never 'not signed'"), and the gate runs from the Mac, not over the
public internet. But it **is** the first thing any outside observer notices, and
the honest disclosure belongs in the fixture's documentation.

Mitigation strategies (from the literature): EDNS0 buffer negotiation (announce
a larger buffer and hope the path MTU allows it), TCP-only deliberate (just
serve on TCP, accept the latency), or Verisign's MTL mode (Merkle Tree Lader —
replaces individual signatures with a shared tree, which cuts per-response size but
requires a new signing architecture). For an initial fixture, TCP-only is the
simplest honest path.

---

## 5. Scoping summary

| Task | Effort | Risk |
|---|---|---|
| Rust zone signer (fips204 → DNSKEY/RRSIG/DS) | ~1-2 days | Low — crypto library mature, RFC wire format defined |
| Minimal DNS server | ~half day | Low — hickory-server or raw UDP |
| NS delegation + DS in Route 53 | ~10 minutes | Low — just two AWS CLI calls |
| **TOTAL to first working algorithm-18 zone** | **2-3 days** | |
| Polished fixture with TCP strategy, documentation | +1 day | Low |
| End-to-end test: scan from Resolution Scope → "ChainUnverified" | +half day | Low |

The desec-io reference validates the delegation pattern and confirms that NS+DS
through Route 53 is sufficient (the parent doesn't validate the child's algorithm).
The IETF draft (westerbaan-dnssec-mldsa-03, Aug 2026, authors from Cloudflare +
Google) provides exact wire-format encoding and a worked example (§6). The Rust
`fips204` crate is the right crypto substrate — the same toolchain as the instrument
that will measure the zone it produces.

---

*Measured 2026-08-29. desec-io/pqc-dnssec cloned and surveyed; fips204 crate
API verified; EDNS0 sizes computed from draft-westerbaan-dnssec-mldsa-03 §3-4;
Route 53 delegation path confirmed against our live `resolutionscope.com` zone.*

---

## 6. Multi-lane review — claude-code lane (2026-08-30)

Requested by hermes @2599d9f, directed by Carey ("hear every lane first — this
is foundation"). Method: three verification passes (repo+infra intel; fork
recon at GitHub source level; library/protocol verification at
IANA/FIPS/crates/parser-source level), then first-hand re-measurement of every
new fact before it was written down. Original prose above is untouched;
corrections sit beside it, R-B style.

### Confirmed at source

- **§1 verdict CONFIRMED and strengthened**: the repo is a testbed orchestrator
  (setup.py:33-34 verbatim as cited); the crypto lives in two *other* repos
  never cloned locally — `desec-io/pdns` @e5505b6 (liboqs+oqs-provider pinned
  May-2024, round-3 `"dilithium2"`, priv 2528 B) and `Martyrshot/OQS-bind`
  (BIND 9.19.7-era). "Porting the fork" would mean porting three external
  repos; standalone Rust signer is the right call.
- **§4 direction CONFIRMED**: a single 2,420-B RRSIG exceeds 1232 by itself;
  100% TCP fallback is structural. deSEC field data: Dilithium2 UDP+DO ~42%
  correct vs TCP ~93% — TCP-first is the honest posture. (§4's exact byte
  table is approximate — full-RR vs RDATA accounting; replace with measured
  dig receipts once live. Verified per-response estimates: A+RRSIG ≈ 2.5 KB,
  DNSKEY response ≈ 3.8–5.2 KB, NSEC NXDOMAIN ≈ 5–7.6 KB.)
- **Draft facts**: current is **-04 (2026-08-11)**, IANA's row cites -03,
  -04 declares the same codepoint. Pure ML-DSA (not HashML-DSA), empty ctx,
  raw FIPS 204 §7.2 encodings. §6 worked example is deterministic → usable as
  a byte-exact KAT. Draft mandates neither hedged nor deterministic; we choose
  **deterministic** (rnd = 0³²) for re-derivable, diffable RRSIGs.
- **Rust**: right call, and the earlier Go claim was also right — Go 1.27
  (2026-08-19) ships `crypto/mldsa`; useful as a third interop verifier.

### Corrections the build must absorb

1. **PowerDNS `master` implements ML-DSA-44 @ 18** (commit 31d80e61,
   2026-07-21, OpenSSL ≥ 3.5 native; in no release — m4 probe 200 on master /
   404 on auth-5.1.4, re-verified first-hand). §2's implicit "nobody implements
   18" is stale; baseline updated to v5. Use PowerDNS master as interop peer.
2. **The deSEC testbed is live, not receded** — `dilithium2.pdns.pq-dnssec.dedyn.io`
   serves DS 47389 18 2 + alg-18 RRSIGs today (inception 2026-08-20; measured
   first-hand, UDP/1232 truncates → TCP full). Wire-labeled 18, round-3
   Dilithium2 semantics, byte-size-identical to ML-DSA-44 → our fixture's claim
   sharpens to **first FIPS-204-valid algorithm-18 zone**, with the testbed as
   standing negative control (verify-fail receipt planned).
3. **Crypto backend is contested, not settled.** The verification pass
   recommends **aws-lc-rs 1.18.0** (ML-DSA APIs stabilized 2026-08-07;
   FIPS 140-3-validated backing module; documented pure-mode + empty-ctx —
   exactly draft §4; seed-based deterministic keygen). §2's `fips204` was not
   in the verified set, and its "constant-time, production-quality" line is
   currently unsourced prose. RustCrypto `ml-dsa` 0.1.1 is disqualified for
   KSK custody (never audited; three medium advisories in its RC series).
   Action: run the same verification protocol on `fips204`, head-to-head, then
   pick and record. Winner must clear cargo-deny gates.
4. **Serve with stock NSD, not hickory-server.** Verified at parser source:
   NSD (simdzone `scan_algorithm`→`scan_int8`) and BIND (`dns_secalg_fromtext`)
   both accept decimal `18` and both reject unknown mnemonics — zone files must
   say `18`, never `MLDSA44`. hickory's `Algorithm::Unknown(18)` encodes but
   its `is_supported()` gates are unaudited for serving. Cleanest signing path,
   verified at source: `domain` 0.12.2 `unstable-sign` + a 3-method `SignRaw`
   impl + `SecurityAlgorithm::from_int(18)` (u8 newtype, round-trips).
5. **§3 delegation mechanics corrected.** (a) "secondary port" is not viable —
   resolvers only speak 53; measured 2026-08-30: the ENI's :53 is FREE
   (systemd-resolved stubs bind only 127.0.0.53/54 — no resolved surgery
   needed), and SG `sg-06fe9448f84977713` (`dnstool-app-sg`,
   i-098e3d8ed90737280, us-west-2) has **no 53 rule** — one
   authorize-security-group-ingress for 53/udp+tcp is required. (b) Prefer an
   **out-of-bailiwick NS name** (`pqns.resolutionscope.com` A in the parent) —
   no glue question, small referrals. (c) **Route 53's acceptance of DS RDATA
   with algorithm 18 is unverified** — settle with one ChangeResourceRecordSets
   test before anything else depends on it. (d) Order: NS first, DS last.
6. **RFC 4035 §2.2 completeness**: with an alg-18 DNSKEY published, *every*
   RRset needs an alg-18 RRSIG, or real ML-DSA validators (PowerDNS master
   exists now) see bogus, not insecure. Single-CSK, whole-zone signing, NSEC
   (not NSEC3 — larger proofs, worse field results).
7. **§4 "AD flag clear on most resolvers"** is right today, but "no validator
   supports 18" already has one exception on the bleeding edge; expect real
   validators within the fixture's lifetime — sign the zone properly.
8. **Q5 resolved (review answer)**: the fixture is legitimate as a **labeled
   control** — TXT self-declaration on the zone, pre-registration in the
   baseline, and exclusion from our own corpus statistics (the 0-of-N surveys
   must never count our own plant). This closes the scoping-doc/deep-report §7
   contradiction, subject to the ledger decision.
9. Housekeeping: the reference clone lives at `/tmp/pqc-dnssec`
   (https://github.com/desec-io/pqc-dnssec.git, HEAD 86f758ae) — volatile,
   now recorded here; its five Jupyter notebooks hold the field study's
   measured packet data (also in the RIPE 89 deck). §2/§3 spellings
   "DNSEKEY"/"namesever" left as written per R-B convention; read as
   DNSKEY/nameserver.

### Gate

Build waits on the ledger's `DECISION NEEDED pq-fixture-go` (Carey + hermes),
then: Route 53 DS test → SPEC doc (backend head-to-head, deterministic signing,
key custody) → signer + KATs (draft §6 byte-exact) → triple interop verify
(PowerDNS master, Go 1.27, self) → NSD on dnstool-app :53 → NS then DS →
engine run (ChainUnverified fires, D5b live) → baseline completes the fixture
pre-registration. Estimate unchanged from §5 plus the gates: ~3–4 elapsed days.