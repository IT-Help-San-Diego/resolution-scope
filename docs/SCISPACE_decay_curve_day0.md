# 6-Day Island-Window Decay Curve — Day 0 Baseline
## pq.resolutionscope.com · 2026-08-30

---

### Three-Vantage AD-Flag State

| Vantage | Resolver | AD flag | Notes |
|---|---|---|---|
| `:5300` | PowerDNS Recursor (local, Carey's Mac) | **AD=True** | Full chain validated: root→com→resolutionscope.com(13)→DS(18)→pq DNSKEY(ML-DSA-44). First measured full-chain validation of an algo-18 zone in the public DNS. Receipt in LANES.md @08:17:17Z. Continuous through re-sign (serial 2026083011, LANES @09:13Z). |
| `1.1.1.1` | Cloudflare | **AD=False** | EDE 1: "Unsupported DNSKEY Algorithm — no supported DNSKEY algorithm for pq.resolutionscope.com." Measured 2026-08-30T09:22Z and 2026-08-30T09:31Z. DNSKEY present (keytag 33846, algo 18). RFC 4035 §5.2 insecure downgrade. |
| `8.8.8.8` | Google | **AD=False** | NOERROR, no EDE, no AD flag. Measured 2026-08-30T09:22Z and 2026-08-30T09:31Z. DNSKEY present (keytag 33846, algo 18). RFC 4035 §5.2 insecure downgrade. |

**:5300 note:** blocked from sandbox (PowerDNS runs on Carey's Mac, not accessible remotely). Reading sourced from LANES.md ledger receipts at @08:17Z (AD-flip capture) and @09:13Z (continuous AD on re-sign). To record fresh reading: `dig @127.0.0.1 -p 5300 pq.resolutionscope.com DNSKEY +dnssec +multi`

---

### Zone State at Day 0

- **Serial:** 2026083011 (live NSD, keytag 33846); 2026083001 (sandbox validation build, keytag 61200)
- **DS at parent:** `pq.resolutionscope.com. 3600 IN DS 33846 18 2 cf4d22577f5caf3626624f8764d748a1c6d0bf1ec51c5f62d80a8c705b8c1ac9`
- **DS published:** 2026-08-30T08:17Z (Route 53, zone Z06861878ZCLQVLWIW76)
- **Island window:** OPEN (DS present, algo-18 not validated by public resolvers → measurable insecure downgrade)
- **Decay driver:** Parent DS TTL = 3600s; public resolver negative-TTL decay of DS-absence → ChainUnverified expected as caches refresh

---

### Expected Decay Curve Shape

| Day | Expected state at 1.1.1.1 / 8.8.8.8 | Expected state at :5300 |
|---|---|---|
| 0 (today) | AD=False, DNSKEY present | AD=True |
| 1–2 | AD=False (cached DS-absence may persist) | AD=True |
| 3–5 | Transition: ChainUnverified window as cached DS-absence decays | AD=True |
| 6 | Stabilized | AD=True |

*Per SPEC §8: engine-via-Cloudflare returns SignedNotDelegated with BYTE-IDENTICAL seal while cached DS-absence persists; ChainUnverified appears as negative-TTL decays. Seal proves vantage-indistinguishability.*

---

### Measurement Commands (run daily)

```bash
# Public resolvers (run from any internet-connected host)
dig @1.1.1.1 pq.resolutionscope.com DNSKEY +dnssec | grep -E "flags:|EDE"
dig @8.8.8.8 pq.resolutionscope.com DNSKEY +dnssec | grep "flags:"

# Local validator (Carey's Mac only)
dig @127.0.0.1 -p 5300 pq.resolutionscope.com DNSKEY +dnssec +multi | grep -E "flags:|RRSIG"
```

---

### Day-3 Entry — 2026-08-31T00:47:39Z (appended by claude-code per relay instruction; repo copy established — SciSpace reads the repo, the Downloads drop is its export)

| Window | Vantage | Result |
|---|---|---|
| 1 — `pq` (serial 2026083011, frozen-live baseline) | `1.1.1.1` Cloudflare | AD=False, NOERROR + **EDE 1** "Unsupported DNSKEY Algorithm" |
| 1 | `9.9.9.9` Quad9 | AD=False, NOERROR, silent (no EDE) |
| 1 | `:5300` local validator | **AD=True** (`flags: qr rd ra ad`, DNSKEY ANSWER:2) |
| 2 — `pq2` (serial 2026083103, reset specimen) | `1.1.1.1` Cloudflare | AD=False, NOERROR + **EDE 1** (message names pq2) |
| 2 | `9.9.9.9` Quad9 | AD=False, NOERROR, silent |
| 2 | `:5300` local validator | **AD=True** |

- **No resolver has flipped on either window.** The three-behavior spectrum (AD at :5300 / EDE-1 at Cloudflare / silent downgrade at Quad9-class) is unchanged since Day 0.
- **Vantage honesty:** `8.8.8.8` over Do53 was unreachable from the Mac vantage at measurement time (recurring local-path limitation, logged in LANES; the silent-downgrade behavior is witnessed by 9.9.9.9). `:5300`'s cached pq2 SOA still shows pre-amendment serial 2026083102 (TTL residue); both authoritative boxes were wire-verified serving 2026083103 at ~00:25Z.
- **Window-2 labeled amendment** (serial 2026083103: sidecar NSEC bitmaps completed with RRSIG type 46) is recorded in LANES and `DECAY-day2-20260831.md`; Day-0 rows unaffected — the bitmap governs type-denial only, never AD on positive queries.
- **Sibling record:** hermes's independent Day-3 measurement (Paris + :5300 vantages, verbatim digs) is at `docs/DECAY-day3-20260831.md` — two lanes, two vantage sets, same flat curve.
- **Day-numbering note:** labeled "Day-3" per the relay instruction; t = publication (2026-08-30 ~01:19Z) + ~23.5h. Timestamps, not labels, are load-bearing.
