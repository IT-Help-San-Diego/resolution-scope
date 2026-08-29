# Deep Report — Post-Quantum DNSSEC, the Instrument, and a Day of Measurements
### 2026-08-29 · prepared for independent review (SciSpace lane)

> Companion to `docs/BASELINE-algorithm18-20260829.md`, which holds the
> re-derivable facts. This document holds the *synthesis*: what the day's arc
> means, what broke inside our own instrument en route, and the specific
> claims we are least certain of and want a second intelligence to pressure-test.

---

## 0. How to read this

Every statement is tagged **MEASURED** (a specific query/command was run and the
result is reproduced below or in the baseline), **SYNTHESIS** (our inference
from measured facts — the part most likely to be wrong and most worth
challenging), or **CLAIM** (something another party asserted that we have or
have not verified).

The throughline of the entire day is a single lesson, stated here because it
organizes everything that follows: **a status claim fails under verification,
and a measurement does not.** We watched that happen four times in one letter,
then watched the replacement — a measurement — survive.

---

## 1. The throughline

The day began with a thank-you letter to a NIST physicist (Yicheng Shi, lead
author of the JOCN entangled-photon-over-aerial-fiber paper) that leaned on the
Sidewalk Theory — passive observation, "we watch your front door from the
street." In the process of checking whether that letter was *true before it was
sent*, we discovered:

1. **Four of its sentences were status claims that were false** (a "shipped"
   gate that was an open PR; a "RIPE Atlas" integration that was approved-not-
   built; an "open" license that was source-available-not-open; a "Dr." title
   the source doesn't support).
2. **Each false status claim was replaced by a measurement**, and the
   measurement is the thing that turned out to be load-bearing.
3. **The measurement itself found a defect in our own instrument** (the DNS
   Tool's derived algorithm field reads TTL as the algorithm on ~50 rows) —
   but the defect did not touch the measurement, because we had parsed *raw*
   records rather than the derived field. The "raw beside the verdict" (R-B)
   architecture is what saved it.
4. **The deepest confusion was a conflation of two unrelated NIST programs**
   that share only the word "quantum."

The rest of this report unpacks each.

---

## 2. The letter, and what verification did to it

The letter praised Dr. Shi's experiment and closed with a claim that our
instrument was "already shipped" for post-quantum DNSSEC. Checking that single
sentence against reality is what opened everything.

**MEASURED — the four claims that failed:**

| Letter claim | Reality | Class of error |
|---|---|---|
| "we just shipped our first post-quantum honesty gate" | PR #31 is OPEN, unmerged; `is_supported` count on main = 0 | status claim (false) |
| "RIPE Atlas probes" | approved (ticket AT-351, "totally fine") but zero integration — `LICENSING.md` says so explicitly | status claim (false) |
| "everything we build is open" | DNS Tool = BUSL-1.1 (source-available, not OSI-open); our own site says "open-core" | term-of-art misuse |
| "Dear Dr. Shi" | NIST page: "a physicist," "IntlAssoc"; profile shows an M.S., not a doctorate | title assumption |

**SYNTHESIS — the pattern:** all four are *status* claims or *credential*
claims — assertions about a state of the world or a person — that a single
verification step falsified. None of the four was a measurement. The fix in
every case was to replace the status claim with a re-derivable fact.

**The surviving sentence** (now in the letter's draft): algorithm 18 is
assigned, and RFC 4035 §5.2 has required validators to report an unwalkable
chain as "unsigned" since 2005. That sentence is checkable by anyone with
`dig` in five minutes. It is the measurement that replaced "shipped."

---

## 3. The measurement (pointer to the baseline)

The full fact set is in `docs/BASELINE-algorithm18-20260829.md`. Compressed:

- **MEASURED — IANA row 18 = ML-DSA-44**, ZoneSigning=Y, Signing/Validation
  MAY, reference `draft-westerbaan-dnssec-mldsa-03` (informational, -03).
  *Assigned, not standardized, not deployed.*
- **MEASURED — no mainline signer implements it** (BIND/Knot/PowerDNS/
  OpenDNSSEC code search: zero; the one prior art is a research *fork* that
  signed with Dilithium-2 — the pre-FIPS-204 predecessor — under experimental
  codepoints, never 18).
- **MEASURED — Route 53 requires `ECC_NIST_P256`** (algorithm 13) for its
  DNSSEC KMS key, so our own registrar cannot emit algorithm 18.
- **MEASURED — zero publishers**, across two complementary-bias samples:
  a 19-zone adopter-biased survey, and our 353-domain usage-biased production
  corpus. Both zero for algorithms 17/18/23.

**The corpus number, restated honestly:** 353 distinct domains, 84 signed,
269 unsigned. Distribution: algorithm 13 ×62, 8 ×19, 7 ×2 (nsa.gov,
mailbox.org), 10 ×1 (mailbox.org), 14 ×1 (defcon.org). Zero exotic. This is
**zero in our sample, not zero in the world** — a usage-biased sample (the
domains people actually scanned through a DNS-security tool) that is *more*
likely than a random sample to contain an adopter, and still finds none.

---

## 4. The instrument defect found en route

While sweeping the corpus, the DNS Tool's *derived* `algorithm` field returned
garbage on ~50 rows: `algorithm = "3600"` and `algorithm_name = "Algorithm
3600"` for nsa.gov, cia.gov, it-help.tech, dns-evil-flicker.com.

**MEASURED root cause (temporal):** `parseAlgorithm` (`dnssec.go`) reads
`strings.Fields(dsRecords[0])[1]` as the algorithm. That is correct for *bare
RDATA* (`"29356 7 2 HEX"` → fields[1] = 7 = algorithm), but wrong for the full
*dig presentation line* (`"nsa.gov. 3600 IN DS 29356 7 2 HEX"` → fields[1] =
3600 = **TTL**). The dig-line form was emitted by `rrToString` before PR #448
(commit `f8e4afc`, 2026-08-17) and bare RDATA after. Every polluted row is a
pre-#448 fossil; the producer is already dead. Ticket filed: dns-tool-intel
#477 (defensive parse + backfill, both specced).

**The meta-finding this is worth carrying:** the measurement did **not** depend
on the buggy derived field. We parsed raw `ds_records`/`dnskey_records`
directly. The R-B principle — raw evidence stored beside the derived verdict,
full fidelity, never the derived field as the only copy — is exactly what
survived a real defect. The instrument's *derived* layer was wrong; the
instrument's *raw* layer was not, and that separation is the point.

---

## 5. The conflation (two programs, one word)

A recurring question through the day was "which provider did NIST use to allow
algorithm 18" — and the question has no answer, because it confuses two
unrelated NIST programs:

- **Quantum NETWORKING** (Dr. Shi's JOCN paper): entangled photons over 62 km
  of aerial fiber. No DNS. No algorithm numbers. No records to `dig`. Physics
  (a resource, not information transfer — the no-communication theorem; a
  point-to-point link, no memory/repeater/swap).
- **Post-quantum CRYPTOGRAPHY** (ML-DSA-44): a digital *signature* algorithm
  for DNSSEC, from the PQC competition. IANA algorithm 18.

They share the word "quantum" and nothing else. The letter got this right
("physical layer" vs "naming layer"); the day's red-team question briefly lost
it.

---

## 6. "Why talk, not action" — four blockers (SYNTHESIS — challenge these)

The question Carey pressed hardest: everyone is *writing about* post-quantum
DNSSEC (Cloudflare, Verisign, SIDN — all future-tense "preparing" posts), and
nobody is *publishing* it. Why? Our synthesis of four reasons, in rough order
of how much we'd bet on them:

1. **It is still a draft.** `draft-westerbaan-dnssec-mldsa-03`, informational.
   Publishing on an informational draft means every record you emit can be
   invalidated by the next revision — and in DNSSEC, invalid records are not
   "eventually consistent," they are **SERVFAIL**, a full zone outage.

2. **Publishing 18 today makes a zone *less* secure, not more.** IANA lists 18
   as MAY (optional to implement), so no resolver is required to understand it.
   RFC 4035 §5.2 says a resolver that meets an unsupported algorithm "SHOULD
   treat the child zone as if it were unsigned." Sign with 18 now and most of
   the internet stops validating you at all.

3. **DNSSEC is a three-party chain, not a two-party key.** A signed zone needs
   its signer, its registrar (to publish the DS), *and* the validating
   resolvers to all support the algorithm. Any one lagging breaks the chain.
   A zone cannot go first alone — "first" means "unsigned" until the other two
   arrive.

4. **The urgency is asymmetric** (this is the one we're least sure of): the
   "harvest now, decrypt later" panic is about *encryption* — confidentiality
   you can record today and crack with a future quantum computer. DNSSEC is
   *signatures* — integrity. A signature either verifies now or it doesn't;
   there is no "decrypt it later" on a signature. So the migration clock for
   DNSSEC genuinely runs slower than for TLS, where ML-KEM is already live
   (~18% of Cloudflare traffic).

Plus the mechanical cost, which is real but not the binding one: ML-DSA-44
signatures are 2,420 bytes vs ECDSA's 64, which bloats zone files and breaks
the "live signing" trick that makes DNSSEC viable at CDN scale.

**These are our best account, not a measurement.** #4 especially is an
argument from the crypto theory, not from a measured adoption curve, and it is
the claim we most want an independent intelligence to push on.

---

## 7. Open questions for the reviewing lane

Each is a specific ask; any of them answered independently would advance the
work.

**Q1 — The "assigned ≠ standardized ≠ deployed" tri-state.** Is that the
right taxonomy, or is there a fourth state we're collapsing (e.g. "assigned,
implemented, but unpublished-in-the-wild")? Is "early allocation" (IANA's term)
materially different from "standardized-but-unimplemented" in a way that
matters to a detection instrument?

**Q2 — The "publishing early = unsigned" reading.** Confirm or refute from
RFC 4035 §5.2 + IANA's MAY columns: is it true that a zone publishing
algorithm 18 today would be treated as unsigned by the *majority* of validating
resolvers, or is the MAY status softer than "most resolvers fail"? The IANA
registry's four columns (Signing/Validation, "Use for"/"Implement for") — read
them and tell us what they actually license.

**Q3 — The signature/confidentiality asymmetry (SYNTHESIS #4 above).** Is
"harvest-now-decrypt-later applies to encryption, not signatures, therefore PQ
DNSSEC migration is less urgent than PQ TLS" a sound argument, or does it miss
a vector — e.g. a signature *today* could be replaced by a forged one *after*
a quantum computer exists, in a way that matters (downgrade/replay)? If the
asymmetry is wrong, our whole "why nobody is acting" account needs re-weighting.

**Q4 — The corpus bound.** Is "zero of 353 security-conscious domains" a sound
basis for "assigned but not deployed in production," given the sample is
usage-biased (not random)? Or does the correct claim need a random sample, and
if so, what's the cheapest sound sampling method you'd endorse?

**Q5 — The instrument's own position.** The baseline's standing proposal is to
self-host an algorithm-18 zone as a live positive control for our honesty gate
(reports "could not evaluate," never "not signed"). Is that a *legitimate*
fixture (a labeled control, like our `dns-evil-*` family) or does it risk
becoming a "planted evidence" cheat the moment anyone mistakes it for a
real-world finding? Where is the line, exactly?

**Q6 — The conflation, swept clean.** Is there any *real* dependency we are
dismissing too fast between quantum networking (QKD/entanglement distribution)
and post-quantum signatures? Specifically: do future QKD networks still need
PQ-signed DNS for their classical side-channel (the routing/DNS that finds the
other endpoint), or is that classical channel already covered by the TLS-class
PQ migration?

---

## 8. Honesty boundary — what this report does NOT claim

- It does **not** claim algorithm 18 is absent from the world — only absent
  from our two samples (19 adopter-biased zones; 353 usage-biased domains).
- It does **not** claim no proprietary signer could implement 18 — only that
  no *readable* surface (open-source code, provider docs, published zones)
  shows one, and Route 53's public interface is bound to algorithm 13.
- It does **not** claim the "why nobody acts" four blockers are fact — they are
  labeled SYNTHESIS and offered for falsification.
- It does **not** claim our instrument is correct — it claims our instrument
  *found its own defect* (the TTL-bleed) and that the raw-record path, not the
  derived field, is what carried the measurement.

The one thing this report does claim, flatly: **a thank-you letter full of
status claims became a measurement, the measurement found a bug in the
measuring instrument, and the raw evidence survived both.** That is the
Verification Principle doing its job on a live system, and it is the finding
that outlives the day.

---

*Prepared by the hermes lane (2026-08-29). Facts cross-referenced to
`docs/BASELINE-algorithm18-20260829.md` and the lane ledger
`policy/LANES.md`. All measurements reproducible from the commands in the
baseline's "re-run protocol."*
