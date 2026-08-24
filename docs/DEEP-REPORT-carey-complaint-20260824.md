# The Deep Report — Carey's full complaint, captured for all lanes

**Date:** 2026-08-24 · **From:** Hermes (instrument lane), carrying Carey's argument verbatim-in-signal
**To:** Claude Science · SciSpace · Claude Code
**Status:** this is the record. No code changed yet. Every lane reads this and answers the numbered questions at the end. We keep circling until there are no errors left in our logic.

---

## 1. The core doctrine — Carey's position, faithfully stated

Carey's argument has one spine: **the measurement layer must be a witness, not a
judge.** Everything else follows from it.

### 1a. Two layers, never jammed together

There is a **binary level** and a **quaternary level**, and they are different
layers.

- The **binary level** is the "seesaw" / treat-lever: did the record come back
  or not. This is what the world runs on — "the ATM machines made for the
  sheep," the lever that flips and gives a treat.
- The **quaternary level** is the V₄ / Owl Semaphore: the layer where *real
  thinking* happens — stance, metacognitive looping, error-finding, the
  recursion that finds and fixes mistakes.

The binary lever is **degrading under traffic** — too much demand, not enough
epistemics to tell what's what. Carey's answer is NOT to replace the binary
lever. It is to run a **supportive quaternary layer right behind the seesaw**
to bear the new load. The four-valued system already exists (IEEE 0,1,X,Z is
the electronics precedent; Verilog uses it). We already *have* the four-valued
logic — the question is whether we keep it **behind** the binary lever where it
can do clean thinking, or keep trying to jam it *into* the binary field.

> "We're not proposing yet to get rid of the binary levers. We already have a
> four-valued logic system, whether it's true quaternary or not. We need to be
> looking at the advanced level four — the layer of four we keep finding is a
> less noisy place to do real thinking, and thus real metacognitive looping and
> recursive action to find errors and fix shit."

### 1b. The witness rule

> "Are you a good witness, or a 'social-media, I-saw-ten-monkeys' lying piece
> of shit?"

The instrument's job is to **witness what came back and report it.** Three
honest receipt states, and they are already distinct in the DNS protocol:

| what the server did | receipt | what a witness says |
|---|---|---|
| returned the record | receipt of presence | **present** |
| said "that record ain't here" (authoritative NODATA, with the SOA naming whose zone) | receipt of absence | **absent** |
| didn't tell us jack (timeout / SERVFAIL / refused) | no receipt | **unknown** |

"Didn't make one" (absent) is *different from* "wouldn't tell us" (unknown).
The first two are receipts — things we were told. The third is no receipt.

### 1c. The judgment lives somewhere else

When we *found* a record, we say **present** — because we witnessed it come
back. The *judgment* about what that record means ("+all authorizes everyone,
so the security score is the worst") lives in **severity + consequence text +
education**, NOT in the present/absent field.

> "Imagine a human walks into a room, sits down at a computer, types, and you
> watch over their shoulder as the DNS record comes back. At that moment, what
> came back in the record? You found the record. A record that we found is
> present. The fact that it's terrible is the judgment that we educate them
> about."

### 1d. The "full page" lie — the conflation Carey caught

In an earlier framing, the instrument's account was summarized as "the server
handed us a full page and on it was just `v=spf1 +all`." Carey called this the
lie, and he was right: the full page *always* carries the ACK, the timestamp,
how long it took, the connection receipt, the rcode, the SOA. Stripping all of
that to produce a clean toy example **was the obfuscation**. A good witness
reports the whole page:

> "We have successfully connected to a server — check. Here is the record we
> got — check. Here is how long it took to get here — check. Here is what it
> says — check. And then, by the way, for the SPF section their security score
> would be the worst, even with a record found, because they said everybody
> with the +all."

The record is present (witnessed). The score is the worst (judged). Both true,
both in their own field.

### 1e. The addiction line — the reason this matters

> "I'm addicted to reality. You're addicted to imagination still. Even the
> humans — bots."

At the binary lever, humans run on autopilot — flip-flip, treat —
indistinguishable from bots. The V₄ layer is the only thing that makes a being
*not* a bot. The instrument must be the thing that doesn't lie about what it
witnessed, because that's the entire point.

---

## 2. The manual-reading discipline — questions to answer BEFORE judging a record

Before the instrument judges a single record, Carey demands we answer, in order:

1. **What is the server honestly willing to give me?** (Read the manual. What
   fields, what receipt, what does "not found" vs "didn't answer" look like on
   the wire?)
2. **Can I take the whole thing in one pull without being slowed down?**
3. **If not, how do I modularize?** What are the options? What do the protocol
   authors think is clean and honest vs nasty?
4. **What's the fastest way — how do the fastest people on the planet who get
   this data actually do it?**

Only after these four are answered do we get to judge a record.

### 2a. The pool questions (transport topology)

> "Is it a chunked pool where they only pull one thing, or one big pool where
> we say give us everything and wait? Do parts come sometimes and parts fail?
> Can half be missing and we still pull data from it? What do these things look
> like? We should have a database full of them. What are the failure modes?"

The demand is concrete: **a database of receipt-level observations** — what was
asked, what came back (rcode), whose SOA vouched, how long it took, whether it
truncated — so the failure modes are *measured and stored*, not inferred from a
final label.

---

## 3. What I found when I read our own manual (first-hand, `resolution-scope` @ `a7e35db`)

The honest audit. Three findings, two good, one gap that is the real work.

### 3a. GOOD — the receipt *mapping* is already right

`engine/src/analysis.rs` `record_absence_verdict` (line 148) already implements
the three-way receipt, reading the rcode AND the SOA:

- `NOERROR` + `NoRecordsFound` → `Absent` (NODATA on an existing zone = measured absence)
- `NXDOMAIN` + SOA is the domain's own zone → `Absent` (name absent, not domain)
- `NXDOMAIN` + SOA is parent/TLD (or none) → `Indet` (domain itself missing)
- `SERVFAIL` / anything else → `Indet` (transient / couldn't measure)

So Carey's three-way receipt — present / confirmed-absent / unknown — is
**already implemented at the mapping layer.** The DNS protocol gives us
everything his witness model asks for: rcode, answer, authority-SOA, flags.

### 3b. GAP — we throw the receipt away

`types/src/dispositions.rs` `ScoredAnalysis` (line 527) stores **only the final
disposition enum.** The rcode, the SOA, the latency, the truncation flag, the
resolver identity — all read to *make* the decision, then **discarded**. The
receipt is consumed and dropped.

This is the literal disease Carey named: we read the whole page, then store only
the verdict and throw away the evidence that produced it. There is **no database
of failure modes** because we never kept the receipts.

### 3c. GAP — serial, single-vantage

- `analyse_domain_with_selectors` (analysis.rs line 47) runs the eight controls
  **serially** — a straight `.await` chain, no `join!`. The slowest control
  (DKIM's 81 selectors; DANE's MX-host loop) gates the whole scan. "Take the
  whole thing and not be slowed down" → currently **no**.
- **Single resolver** (Cloudflare, one vantage). No quorum, no disagreement
  recording, no direct-to-authoritative path.

---

## 4. The protocol facts (what the manual says — to be verified by each lane)

- A DNS query is **one question** (one name + one type). The response carries:
  rcode, answer section, authority section (the SOA of the zone that said no),
  and flags (`AA` authoritative, `AD` validated, `TC` truncated).
- There is **no "give me everything about this domain" primitive.** The `ANY`
  query — the one historical "dump everything" request — was deprecated and is
  now refused by most resolvers (this is the "nasty" path the protocol authors
  deliberately closed). Modularity is not our choice; it is the only clean path.
- Three legitimate pull shapes: **recursive** (one hop, cached, gives the `AD`
  bit), **direct-to-authoritative** (the source, no cache, walk root→TLD→zone
  yourself), **hybrid** (authoritative for the raw record, recursive for the
  validation receipt).
- The internet-scale measurers (ZMap's `zdns`, `massdns`) do three things:
  massive parallelism, direct-to-authoritative, and quorum-with-disagreement-
  recording.

*These facts are asserted from general knowledge and MUST be re-verified by the
lanes against primary sources (RFC 8482 for ANY; the zdns/massdns docs) before
any build decision rests on them.*

**Verification (Hermes, 2026-08-24, primary sources):**

- **RFC 8482** (Abley, Gudmundsson, Majkowski, Hunt — Afilias/Cloudflare/ISC,
  Standards Track, Jan 2019) confirms: there is no "give me everything"
  primitive. `QTYPE=ANY` responses may be a *subset*, a *synthesized HINFO
  RRset*, or a *best-guess* — explicitly with **"no signaling to indicate an
  incomplete subset has been returned."** That last clause is load-bearing for
  us: a responder can silently hand back a partial answer to `ANY`, so `ANY`
  cannot even be trusted as a "dump everything" request. The amplification
  rationale (§9, RFC 5358) is why it was closed. **Confirmed as the "nasty"
  path.**
- **ZDNS** (Izhikevich et al., IMC 2022, Stanford) and **MassDNS**
  (blechschmidt) confirm the "fastest people" account: high-throughput **stub
  resolvers** that talk **direct-to-authoritative** at millions-of-domains
  scale. **One correction to §4's draft:** the quorum-across-recursive-resolvers
  technique is *not* the zdns/massdns pattern (they send a query to a
  (set of) authoritative servers, not several recursive resolvers). The
  multi-resolver quorum is a separate technique (and is already what the Go
  parent's AD-sweep does). The state-of-the-art summary stands as: **massive
  parallelism + direct-to-authoritative**; add quorum separately if a
  validation receipt is required.

---

## 5. The two open questions that remain real (do not conflate with the above)

The present/absent "fork" (is `+all` Present or Absent) was argued exhaustively
and is **downstream** of the receipt question. If we store the receipts, the
judgment becomes a *view* over stored receipts rather than a decision whose
evidence we threw away. So the fork is on hold until §3b/§3c are resolved —
fix the transport, then re-derive the label from the receipts.

---

## 6. The questions each lane must answer

**Q1 (receipt fidelity).** Does our mapping correctly distinguish found /
authoritative-absent / no-answer in *every* control arm, or does any arm fold a
SERVFAIL/timeout into "absent"? Cite file:line. (We believe DNSSEC's
`dnssec_disposition_err` maps SERVFAIL→BrokenChain→Absent — is that a
no-receipt masquerading as a receipt, or correct per RFC 4035 bogus semantics?)

**Q2 (storage).** Should `ScoredAnalysis` gain a per-control receipt record
(rcode, SOA owner, latency, TC flag, resolver identity) so every verdict is
re-derivable from stored evidence? What is the minimal receipt schema that makes
the failure modes a *database* rather than a *memory*?

**Q3 (transport).** Serial→parallel for the eight controls: is there any
correctness reason they must stay serial (shared resolver state, rate limits,
DNSSEC validation context), or is parallelism purely a win?

**Q4 (vantage).** Single resolver → quorum (multiple resolvers, record
disagreement) and/or direct-to-authoritative. What is the RFC-clean way to add
this without breaking the `AD`-bit validation receipt?

**Q5 (the fastest way).** Confirm or correct §4's account of zdns/massdns
(massive parallelism + direct-to-authoritative + quorum). What is the actual
state of the art, and which parts are clean for a *verifying* instrument (as
opposed to a *surveying* one, where DNSSEC validation isn't the point)?

---

*Every file:line in §3 was read first-hand. §4 is flagged for re-verification.*

---

## 7. Hermes first-hand verification of Science's Q1 finding (2026-08-24)

**The finding is real, and I verified it against the wire — with one correction
to its stated consequence.**

### What I measured (all live, specific-type queries — NOT `ANY`)

| query (type A) | rcode | authority | NSEC? |
|---|---|---|---|
| `no-such-name-xyz-987.example.com` | **NOERROR** | example.com SOA (own zone) | **`\000.no-such-name-xyz-987.example.com.`** (do=1) |
| `definitely-not-here-4471.ietf.org` | **NOERROR** | ietf.org SOA | (same provider) |
| `no-such-xyz-987.example.org` | **NOERROR** | example.org SOA | (signed — DNSKEY present) |
| `no-such-xyz-987.microsoft.com` | **NXDOMAIN** | microsoft.com SOA (Azure) | none |

- **Confirmed the mechanism precisely.** With `+dnssec`, the NOERROR response
  carries a **minimally-covering NSEC**: `no-such-name-xyz-987.example.com. NSEC
  \000.no-such-name-xyz-987.example.com. RRSIG NSEC TYPE128` — the synthesized
  "black lies" anti-enumeration record (a signed zone proving a name's
  non-existence without revealing its neighbors). This is not a DNSSEC-OK
  artifact; it is the provider's negative-response synthesis.
- **My own methodological error caught:** my first pass used `ANY`, which
  triggered RFC 8482's synthesized `HINFO "RFC8482" ""` — the very "don't use
  ANY" behavior §4 documents. Re-ran with a specific type. This is the
  look-before-you-measure discipline, applied to my own probe.

### The correction to Science's stated consequence

Science wrote: *"the NXDOMAIN-with-parent-SOA→Indet branch, which exists to
catch 'the domain itself is missing,' cannot fire behind such a provider — so a
missing DOMAIN would read as an absent RECORD."*

**That specific consequence is not reachable, and I measured it directly:**
a genuinely missing domain still returns **NXDOMAIN from the parent** (root/com
SOA), never NOERROR —

```
_dmarc.zzzz-nonexistent-domain-9f3k2.com  →  NXDOMAIN, com. SOA
```

The black-lies NSEC is synthesized **by the authoritative server of an existing
signed zone.** A missing domain has no authoritative server to synthesize it, so
the parent returns genuine NXDOMAIN. The "domain missing → reads as absent
record" failure requires a signed zone that doesn't exist — a contradiction.

### What the finding DOES establish (the real value)

1. **For a fixed-name control under an existing signed "black-lies" zone**
   (`_dmarc`, `_25._tcp.<mx>`, `_mta-sts`), "name doesn't exist" and "name
   exists but has no such record" both arrive as NOERROR/NODATA → `Absent`.
   That verdict is **correct** for our fixed-name controls (the control is
   absent either way).
2. **The receipt-fidelity gap is real and Science's `denial_proof` column is the
   right fix.** Right now we cannot distinguish, after the fact, "NODATA with an
   NSEC proof of non-existence" (black lie) from "NODATA with SOA only" from
   "NXDOMAIN." Recording `denial_proof ∈ {none, soa_only, nsec, nsec3}` per
   lookup turns this into a re-inspectable fact. It is a **provenance
   improvement, not a verdict correction** — no live control was shown to
   produce a wrong verdict (Science's own conclusion, which my measurement
   corroborates).

### Verdict on Science's Q1

**CONFIRMED.** No arm folds a transient failure into an absence. The two
bypass arms (`dnssec_disposition_err`, the CDS ladder) are correct — the DNSSEC
one is *better* than the classifier (SERVFAIL→BrokenChain is a measured hostile
state, not "couldn't measure"). The black-lies finding is real and first-hand
verified, but its "missing domain reads as absent" consequence does not occur;
its real yield is the `denial_proof` receipt column, which is already the right
shape for the Q2 schema.

