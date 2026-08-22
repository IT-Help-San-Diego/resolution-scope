# CDS match-vs-differ — scope-out rationale (N1/N2)

**Status:** explicit architectural boundary — a deliberate non-implementation,
documented so the gap is a decision, not an omission.
**Date:** 2026-08-22
**Scope:** `CdsDisposition` in `engine/src/analysis.rs` (the CDS/CDNSKEY
control, control #8 of 8).

---

## The distinction that is not implemented

The known-answer corpus (Arm 2) carries two vectors for CDS that the engine
does **not** currently grade:

| vector | RFC § | semantic | meaning |
|---|---|---|---|
| N1 | 7344 §4.1 / §5 | CDS *matches* the parent DS | in-sync — no rollover in progress |
| N2 | 7344 §6.2 | CDS *differs* from the parent DS | rollover in progress — a transitional signing gap |

What the engine *does* emit today for CDS/CDNSKEY:

- `Published` — CDS/CDNSKEY present (measured presence)
- `DeletionRequested` — null CDS/CDNSKEY, algorithm 0 (RFC 8078 §4, shipped)
- `NotPublished` — zone exists, neither record present
- `NoZone` / `TransientError` — the standard unmeasurable arms

The gap is narrow and specific: **match-vs-differ is a comparison between two
records in two different zones**, and the engine currently measures only one of
them.

## Why this is a different measurement class

Every other control in the engine measures a **single record's presence or
value in a single zone**:

- SPF: one TXT at the apex → presence + terminal qualifier
- DKIM: one key at `<selector>._domainkey` → presence + revocation/wildcard
- DMARC: one TXT at `_dmarc` → presence + `p=` value
- DANE: one TLSA at `_25._tcp.<mx-host>` → presence, gated on host-zone DNSSEC
- CAA: one RRset → presence + `issue`/`issuewild` value-grading
- CDS (as built): one RRset at the child apex → presence + null-delete signal

**Match-vs-differ is not a single-zone measurement.** It requires two lookups
in two zones and a comparison between them:

1. the child's CDS/CDNSKEY RRset (we already fetch this), **and**
2. the **parent zone's DS RRset** — a different zone, up the delegation chain.

Step 2 is the load-bearing absence. It requires:

- **Zone-cut discovery** — knowing which zone is the parent. For
  `mail.example.com` the parent is `example.com`; for `example.co.uk` it is
  `co.uk`. This needs either a PSL table (rejected for the resolver core on
  the same grounds as the Go parent — "absence in a reference table must never
  be reported as absence in the world") or iterative NS/SOA-walk discovery
  (its own lookup fan-out, not yet built).
- **A DS lookup against the parent** — a net-new resolver call the CDS arm does
  not currently make.
- **A semantic comparison** — CDS/DNSKEY digest vs DS digest, with algorithm
  and digest-type normalization. This is the kind of cryptographic comparison
  where a subtle implementation error produces a confident wrong verdict — the
  exact failure class the project exists to detect in others (see ARCHITECTURE
  §7, option C's reasoning, applied to CDS instead of RRSIG).

## The explicit decision

**CDS match-vs-differ is scoped out of the current instrument, by design,**
for two independent reasons:

1. **It is a cross-zone comparison, not a single-zone measurement.** The
   engine's contract (§8 truth-chain, and every other control) measures what a
   single zone publishes. The DS comparison measures the *relationship*
   between two zones, which is a different instrument surface — one that does
   not yet exist and must not be hand-waved into the CDS arm.
2. **RFC 7344 is Informational.** CDS is a *mechanism*, not a *mandate* — the
   parent is not normatively required to act on it. A rollover-in-progress
   reading is therefore an *observation about what the child published and what
   the parent currently holds*, not a correctness verdict on either party.
   Collapsing that observation into a PASS/FAIL score would manufacture a
   finding out of an advisory signal.

**What remains shipped and honest:** the engine reports the measured facts it
*can* establish — CDS present, CDS absent, or null-CDS delete-requested — and
names RFC 7344's Informational status in the user-facing text. It does **not**
claim to know whether a rollover is in progress, because it does not measure
the parent DS. That is the honest boundary: *unmeasured is reported as
unmeasured, never guessed* (the standing doctrine).

## What would close it (if ever adopted)

Adopting N1/N2 is a real feature, not a test:

1. **Zone-cut discovery** (PSL or SOA-walk) to locate the parent zone.
2. **A DS lookup** against that parent.
3. **A digest comparison** (CDS vs DS), with the normalization edge cases
   pinned.
4. **New disposition states** (`CdsInSync`, `CdsRolloverInProgress`), each with
   a §-anchored consequence and an Informational calibration note in the
   renderer.
5. **Known-answer vectors + mutation evidence** for the comparison — the same
   bar every other control met before shipping.

Until that lands, the corpus rows N1/N2 are marked **deferred — scope-out
recorded** rather than "failing," because the engine correctly refuses to
answer a question it does not measure.

## Reference

`docs/arm2-rfc-known-answer-vectors.md` §8 (the N1/N2 rows) and the SciSpace
gap classification. This document is the canonical home for *why* N1/N2 are
deferred — the corpus table points here rather than restating the reasoning
(one-idea-one-home).
