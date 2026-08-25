# Receipt Column — Specification (foundation, pre-build)

**Date:** 2026-08-24 · **From:** Hermes · **Status:** spec for the four-mind; no code yet
**Feeds:** Claude Code `4e9d88d` (transport answers) + Science Q2 schema + RFC 9824 ruling
**Converged already:** fork closed, receipt grades ruled, `elapsed_ms` outside the seal.

---

## 0. What this is

Carey's doctrine, now three-lane-unanimous: **the instrument is a witness, not a
judge.** It must report *what came back* (the receipt) and keep the receipt so a
future re-inspector can re-derive the verdict from raw bytes. Today the engine
reads the receipt, produces the disposition, and **throws the receipt away** —
`ScoredAnalysis` stores only the classification, not the evidence.

This spec defines the receipt record and where it lives. It is a **provenance
addition**, not a verdict change: no live control was shown to produce a wrong
verdict (Q1, verified twice), so the tri-state and severity ladder are untouched.

---

## 1. The receipt record — what a witness keeps

Four fields per lookup, one row per control per scan:

| field | type | meaning | sealed? |
|---|---|---|---|
| `rcode` | enum `{NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT}` | the server's verdict on the wire | open question (§4) |
| `answer_count` | `u16` | records actually returned (0 = NODATA/absent) | open question (§4) |
| `denial_proof` | enum `{none, soa_only, nsec, nsec3, nsec_nxname}` | *who vouched* for an absence (`nsec_nxname` added @80f5760) | open question (§4) |
| `elapsed_ms` | `u64` | how long the lookup took | **never** (run metadata) |

`denial_proof` is the load-bearing one — it is the "receipt has grades" column.
The four grades, now RFC-backed:

1. `nsec` / `nsec3` — a **signed cryptographic proof** of non-existence (the
   gold receipt; RFC 4035 §5.4 authenticated denial).
2. `soa_only` — a **signed but deliberately vague** receipt (RFC 9824 "compact
   denial": Cloudflare/Route53/NS1/Knot/Oracle answer NODATA for a nonexistent
   name and never emit NXDOMAIN).
3. `none` — an **unsigned plain answer** (a response, not silence, but no proof).
4. (no row / `TIMEOUT`) — an **error**, no receipt at all → `Indet`.

Two hard constraints on anything DERIVED from these fields (transition tables,
fingerprints, classifiers) — added 2026-08-25 after the cross-check found both
violated in derived documents:

- **`nsec_nxname` co-occurs with `NOERROR`/NODATA only.** RFC 9824 §6:
  compact-denial zones never emit NXDOMAIN, so the TYPE128 sentinel rides
  NOERROR responses. A fingerprint pairing `nsec_nxname` with `NXDOMAIN` names
  a wire state this instrument can never observe — reject it at review. (RFC
  9824 adoption looks like `nsec` → `nsec_nxname` under NOERROR; going to
  honest NXDOMAIN means GAINING rcode 3 and LOSING the sentinel.)
- **Store `rcode` as this TEXT vocabulary, never a raw wire u8.** TIMEOUT has
  no wire rcode; any numeric encoding silently drops one of the five failure
  modes the failure-is-a-measurement principle requires decomposing.

`elapsed_ms` is **run metadata, not measurement** — it is a fact about the
*observer* (which resolver, how busy, how far), not about the *target*. It must
never enter the seal, exactly as `resolver_identity` was already ruled to be a
vantage fact. (Precedent: the observation-conditions rule already recorded.)

---

## 2. Where the receipt lives — two clean shapes

### Shape A — a `lookup_receipts` table (separate, recommended)

```
CREATE TABLE lookup_receipts (
    id            BIGSERIAL PRIMARY KEY,
    scan_id       BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    control       TEXT   NOT NULL,       -- 'dnssec' | 'spf' | ... (the ControlId)
    rcode         TEXT   NOT NULL,
    answer_count  INT    NOT NULL,
    denial_proof  TEXT   NOT NULL,       -- 'none'|'soa_only'|'nsec'|'nsec3'
    elapsed_ms    BIGINT NOT NULL
);
CREATE INDEX ix_receipts_scan ON lookup_receipts (scan_id, control);
```

- The **verdict** (`scans.verdict`) stays the sealed classification.
- The **receipts** are the raw evidence, stored beside the verdict, one row per
  control. "The database full of failure modes" — now actually a database.

### Shape B — JSON columns on `scans` (rejected)

Folding receipts into `scans` as JSON columns mixes evidence into the archival
verdict row and forces a `json`→`jsonb` question the 2026-08-17 ruling already
settled (verdict is `json`, archival-only, not a query surface). Receipts *are*
a query surface ("show me every SERVFAIL ever recorded") — so they belong in
their own indexed table. **Shape A.**

---

## 3. Serial → parallel (the transport answer, folded from Claude Code)

Claude Code's transport answers are correct and recorded here for the build:

- **There is no "verbose mode" to ask DNS for.** The receipt *is* the response
  message: the rcode + answer/authority sections + the NSEC/RRSIG proofs that
  ride along when `DO` is set. We were already receiving every receipt on every
  query and discarding the third column.
- **Recording costs zero extra wire traffic.** The bytes are already in the
  response; we stop dropping them. The good-net-citizen budget is untouched.
- **One question, one response, per record type, per domain.** Nothing is pulled
  in chunks or whole; there is no "give me everything" primitive (RFC 8482 —
  `ANY` is dead). Modularity is the protocol's only clean path, not our choice.
- **No API key, on purpose.** We stand in the public queue because the
  instrument's claim is "what any relying party on Earth would see," and that
  claim is only honest from the public vantage.

The parallel-conversion hazard (Science Q3) stands and is named for the build:
**never `try_join!`** — it cancels siblings on first error and would emit
`TransientError` in correlated clusters (a fabricated correlation, not a
measurement). Use per-control error isolation (`FuturesUnordered` + individual
`Result`s, or eight `tokio::spawn`s joined with `join!`).

---

## 4. The one open fork — are receipts sealed?

This is the single unresolved design question, and it is real (not a restatement
of the closed fork). It is Carey's call, but it is now precisely framed:

**Fork R-A — receipts sealed (v4→v5 bump).** Add the receipt fields to the seal
preimage. Then a tampered receipt breaks the seal, so the *evidence* is as
tamper-evident as the *verdict*. Cost: the seal changes → every prior seal needs
a re-derivation arm, and "what the server said" becomes part of "what we claim."

**Fork R-B — receipts are provenance-beside-the-seal (no bump).** The seal keeps
binding the classification only; receipts are stored append-only beside it,
readable and re-inspectable but not independently tamper-evident. Cost: a
tampered receipt would not break the seal, so receipt-level tamper-evidence is
not provided (only verdict-level).

**Hermes lean (R-B):** the seal's purpose is "the verdict you hold is the one
that was sealed" — a claim about *our classification*. The receipt is the
*producer's* raw output, a different author. Mixing the two authors into one
preimage blurs exactly the witness/judge line this whole arc is enforcing. The
receipt should be stored append-only and *re-derivable* (a re-inspector re-runs
the query and compares), not sealed-into-the-verdict. **But this is a provenance
philosophy call, not a correctness call — and it is Carey's.**

---

## 5. Build order (after §4 is settled)

1. `denial_proof` + `rcode` + `answer_count` extraction at every lookup site —
   the mapping already reads rcode+SOA in `record_absence_verdict`; expose the
   NSEC/NSEC3 presence rather than discarding it.
2. `lookup_receipts` table + `record_scan` writing one row per control.
3. Parallel conversion with per-control isolation (not `try_join!`).
4. `verify_scan` extension (if R-A): receipt fields in the preimage under a v5
   scheme with a v4 re-derivation arm.

---

*Grounded in: store/migrations/001_sealed_history.sql (read), types/src/dispositions.rs ScoredAnalysis (read), engine/src/seal.rs canonical_input (read), engine/src/analysis.rs record_absence_verdict (read).*

---

## 6. Failure is a measurement — Carey's principle (2026-08-24)

A "failed" lookup is only failed if we stop reading at the rcode. Every
response — including NOERROR-with-empty-answer, SERVFAIL, REFUSED, timeout,
NXDOMAIN, NODATA-with-NXNAME — carries recoverable information about *how* the
DNS chose to fail, and that choice is a fingerprint.

**The principle, named:** the failure mode is a recorded signal, not a dead end.
Extract what is recoverable from every response, report it honestly, and track
how failure modes *change* over time.

**Concrete consequence:** `Indet` ("couldn't measure") is today a single
catch-all. The receipt fields `rcode` × `denial_proof` decompose it into the
distinct failure modes (SERVFAIL vs timeout vs REFUSED vs NODATA vs
NODATA-NXNAME). A domain whose failure mode *changes* between scans — SERVFAIL
yesterday, NODATA-NXNAME today — has changed how it hides, and that transition
is itself a signal. This is flux detection moved from the address layer to the
denial layer.

**The canonical proof case:** my own §9 measurement. The server returned NODATA
for a nonexistent name; the NSEC Type Bit Map carried `TYPE128` = NXNAME; I first
read it as an anonymous type. The recoverable signal ("this name does not
exist") was present in a response I filed as "nothing here." The receipt columns
make that signal first-class and re-inspectable instead of dependent on an
analyst recognizing a type code by eye.

**Relationship to the seal:** this does not change the verdict. The verdict
still says `Indet` (couldn't measure the *control*). The receipt now *also* says
*how* it couldn't measure, and that second fact is the intelligence. Witness and
judge stay separate — the judge says "no verdict," the witness says "and here is
exactly how the absence of a verdict arrived."

---

## 7. Two corrections (Claude Science, 2026-08-24) — the empirical caveat + the flux-axis fork

### 7a. The "everyone else deletes it" claim was overstated — corrected

My "the rest of the world discards the receipt" was too broad. Corrected to the
specific novelty:

- **DNSViz** serializes parsed query results to JSON for offline re-analysis
  (its own README: "serialized into JSON format") — it does NOT capture pcap.
- **SecurityTrails** reportedly keeps historical A/MX/NS records
  (product claim; no open codebase to verify).

So "keeping raw data" is *not* the novelty in general. The actual novelty is
**keeping the denial-layer fingerprint (denial_proof grade) as a tracked
time-series dimension** — which neither of the above treats as a first-class
signal. The claim narrows to that, and only that: nobody tracks the *grade of
denial* over time as a first-class dimension.

### 7b. The open fork: is denial-layer flux a second axis or part of the existing flux classifier?

The existing flux classifier (`engine/src/flux.rs`) is **address-layer**: ASN/IP
churn. The receipt columns (`rcode` × `denial_proof`) give a **denial-layer**
fingerprint that is *orthogonal* to it. A domain can be:

- address-stable **and** denial-unstable (same IP, but flips SERVFAIL ↔
  NODATA-NXNAME ↔ REFUSED between scans), or
- address-unstable **and** denial-stable (fast-fluxing IPs, constant denial).

Tracking both gives a **2D flux surface**. This is a **flux-schema design
choice, not a receipt-schema choice** — the receipt schema already specifies everything
needed; the question is only whether the flux classifier consumes the
denial-grade column as a second axis.

**Named, not decided.** It is not urgent (the receipt columns must exist before
any flux consumer can read them), but it should be on the board so the receipt
schema isn't later found to have *mis-stored* the denial grade (e.g., folded into
a single value rather than kept orthogonal to the address axis).

