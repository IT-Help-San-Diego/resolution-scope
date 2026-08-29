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