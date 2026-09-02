# DESIGN (DRAFT) — Vantage-Provenance Vocabulary v0
**Status: DRAFT for Carey + mesh review — unlocked by the wave-mesh ruling
(local-instrument with parity floor), 2026-09-02.**
**Author: hermes lane. Every claim below is checked against the live tree
at `65e3af8` or the cited ledger/ruling lines.**

## The problem this vocabulary solves

The mesh is about to hold measurements from **heterogeneous vantage classes**
— and the instrument's own history proves the cost of not naming them: the
Science sandbox read the doorbell's cc-transcript arm as "dead" because it
measured *its own vantage boundary*, not the system (three firings of the
same class). Carrier-vs-signal discipline demands that **where a
measurement was taken from** is a first-class, structured fact — never a
free-text guess, never implicit in who happened to run it.

## The primitive that already exists (and what it lacks)

`resolver_identity` is **seal-bound since v2** (`engine/src/seal.rs:87` —
"v2 added `resolver_identity` (the observer's vantage) to the input set";
pinned by `seal_changes_when_resolver_identity_changes`). That is the
provenance floor: every sealed verdict already names its observer string.

What it lacks: **structure**. Today `resolver_identity` is an opaque string
("default", "google", a vantage label). The mesh needs it to *decompose*
into a vocabulary so the corpus can answer "what KIND of vantage measured
this" without parsing prose.

## The vocabulary (v0 — minimal, extensible)

A vantage is described by three fields, serialized as a compact
`key=value` prefix of `resolver_identity` (the sealed string carries the
structured form; old opaque strings remain valid — they parse as
`class=unstructured`):

```
resolver_identity := [class=<id>][,network=<network>][,operator=<operator>]":"<free-form label>
```

- **`class`** — the vantage class, a CLOSED enum (the taxonomy):
  - `class=instrument` — our signed release binary run by a person, local.
    *This is the source-3 class: opt-in-within-opt-in, k-anonymity gated.*
  - `class=fleet` — our scheduled measurement VPSes (dns-observe Boston/
    Paris, dnsvantage US-east/Singapore; the decay-series vantages).
  - `class=atlas` — RIPE Atlas probe measurements (rented breadth; the
    AT-351 commercial-use grant; attribution-tagged per its terms).
  - `class=public-resolver` — an observation through a public recursive
    (1.1.1.1, 8.8.8.8...): the vantage is the RECURSIVE's position, not the
    operator's — the alg-18 field report's Cloudflare/Google split is
    exactly this class distinction in action.
  - `class=sandbox` — a constrained/simulated environment (the Science TCC
    case, test harnesses, CI). NEVER mixed with real-network data without
    the flag — the class exists so sandbox observations self-declare.
  - `class=unstructured` — legacy opaque strings (back-compat default).
- **`network`** — coarse network position, CLOSED vocabulary at the
  granularity the k-anonymity gate permits (v0: `residential`, `datacenter`,
  `mobile`, `educational`, `censored-region`, `unknown`). Coarse by design:
  this is the field the privacy gate constrains.
- **`operator`** — free-form, OPTIONAL, only for fleet/atlas classes where
  naming the operator is already public (our VPSes; "ripe-atlas").

**Seal impact: NONE at v0.** The structured form lives INSIDE the existing
`resolver_identity` string — the seal still binds the whole string, byte
for byte. A vantage that upgrades from opaque to structured changes its
`resolver_identity` (hence its seal) exactly ONCE, same as any
identity change; old rows re-derive under their old string. No scheme
bump required. (If the mesh later wants the fields *individually* bound,
THAT is a scheme question — raised, not decided, per the deferral
discipline.)

## What each field is FOR (the use cases it must serve)

1. **Carrier-vs-signal in the corpus:** `class` lets an aggregate say "3
   validating + 2 honest-refusal + 1 silent-downgrade" instead of merging
   six vantages into one verdict-flip that nobody can decompose.
2. **The parity floor (Carey's ruling):** web-scan == local-scan
   comparisons GROUP BY class, so "different vantage" can never masquerade
   as "different domain state."
3. **The Iran case / source-3:** `class=instrument` + `network=censored-
   region` is the measurement the mission exists for — and the only place
   that pair appears is opt-in human-run observation.
4. **Sandbox honesty:** `class=sandbox` is the three-firing lesson made
   structural — a sandbox reading self-declares, so it can never be cited
   as a system measurement again.
5. **Decay-series continuity:** today's cross-vantage rows are
   `class=fleet` + `class=public-resolver` in this vocabulary — the
   existing practice, formalized.

## The k-anonymity gate (threshold, not implementation — drafted separately)

The `network` field is the privacy-bearing surface: the gate rule is that
a released vantage observation must be indistinguishable from at least
k−1 other observations sharing its (class, network) pair. v0 leaves k
unset (source-3 isn't live; nothing is blocked); the gate ships WITH
source-3, never after it (deferral-ships-tripwire).

## Review asks (posted to the mesh with this draft)

1. Science: does the `class` taxonomy hold against the RFC/sandbox
   epistemics work — especially `sandbox` and `public-resolver`?
2. SciSpace: does `network`'s coarse set match the prior privacy design
   (opt-in-within-opt-in) it authored — the strongest-work-of-the-arc piece?
3. Claude Code: implementation surface check — `resolver_identity` is
   produced at scan assembly (`engine/src/analysis.rs`); confirm no
   renderer/handler assumes the opaque form (grep: none today, verified).
4. Carey: the ruling asks — is the parity floor served? (Use case 2 is
   your sentence, made a query.)

## What this draft deliberately does NOT do

- No schema/SQL changes (the string is the storage; decomposition happens
  at read time).
- No seal-scheme change (above).
- No source-3 wiring (the gate ships with it, not before).
- No renames of anything existing.

## Provenance

- Wave-mesh ruling (ledger 2026-09-02, Carey): local-instrument + parity
  floor — this draft's use cases 2 and 3 are direct implementations.
- `seal.rs:87` + `seal_changes_when_resolver_identity_changes` (the bound
  primitive).
- Alg-18 field report (2026-09-02): the Cloudflare/Google AD split — the
  `public-resolver` class demonstrated live.
- Sandbox-vantage incident (ledger, three firings): the `sandbox` class's
  reason for existing.
- Decay series Day-5 (Mac + Paris + :5300): `fleet` + `public-resolver`
  formalized.
