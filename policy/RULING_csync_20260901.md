# RULING (DRAFT) — CSYNC absence weight (2026-09-01): ZERO BAND

**Status: DRAFT — awaiting Carey's signature.** Science sound-off: CONCUR
(`csync-soundoff-weight-zero.md`, Science lane, 2026-09-01T01:13–01:17Z).
The zero band is the code's current behavior — signing this changes no code.
Drafted by hermes; every claim below independently re-verified at source
before this document was written (RFC text from rfc-editor.org, enum and
call site at PR #36 tip `3d4f0de`, sweep re-run dual-vantage at drafting
time).

## The question (asked three times; measured once, 2026-09-01)

When CSYNC (RFC 7477, child-to-parent delegation synchronization) is absent
on a domain, what does that absence weigh in the Risk-Weighted Score —
nothing (zero band: measured, shown, excluded from the denominator), or Low
(weight 1, counted and docked)?

## The ruling: zero band

The ruling rests on the specification first and the measurement second —
Science's re-anchoring, adopted, because the prevalence number cannot carry
the ruling and the spec text cannot be overturned by a future sweep.

**1. RFC 7477 §4.5 ("Removal of the CSYNC Records") makes CSYNC transient
by design.** Verbatim: *"Children MAY remove the CSYNC record upon noticing
that the parent zone has published the required records … By removing the
CSYNC record from the child zone, the parental agent will only need to
perform the query for the CSYNC record and can stop processing when it
finds it missing."* The spec's own operational model is publish → parent
processes → remove. At-rest absence is the **prescribed** state — the
ask's "risk window and publish window coincide" argument is not an
inference, it is §4.5. A consequence for evidence discipline: an at-rest
sweep cannot distinguish "nobody uses CSYNC" from "everybody who uses it
removes it per §4.5" — so prevalence **corroborates** this ruling but can
never carry it, and no future sweep catching a zone mid-change overturns it.

**2. RFC 7477 §5 bars CSYNC from the security domain by construction.**
Verbatim: *"this specification was not designed to synchronize DNSSEC
security records, such as DS pointers, or the CSYNC record itself. Thus,
implementations of this protocol MUST NOT use it to synchronize DS records,
DNSKEY materials, CDS records, CDNSKEY records, or CSYNC records."* CSYNC
synchronizes NS, A, and AAAA — reachability, not authentication. §5 names
no adversary defeated by publishing CSYNC and no harm from omitting it;
the words "absence"/"absent" do not appear in §5 at all (verified against
the RFC text). A record the spec forbids from carrying security material
cannot have its absence scored as a security deficiency. This is the
argument that makes weight 0 principled rather than conventional — not
"nobody does it" but "the spec excludes it from the domain the score
measures."

**3. The real delegation-automation risk is already carried, at the right
address.** CDS absent ranks Low, weight 1 — and CDS-Low is load-bearing:
stale-DS SERVFAIL on the zone's own key change is a named availability
failure with a concrete instance (Carey's AWS Route 53 does not support
CDS). CSYNC has no equivalent failure story. Docking CSYNC-absent would
hide the real risk (CDS) under a fake one — the CDS ruling's rejected
option (a), the same defect shape.

## The measurement (corroboration, with its limits stated)

- **Original (2026-09-01T01:08Z, ledger `6d04916`):** 0/20 zones publish
  apex CSYNC — `dig` CSYNC+CDS `@1.1.1.1`, six CDS-publishing elites, ten
  further top-tier operators, Carey's four signed zones.
- **Science, independent (01:13–01:17Z):** 0/24, two resolvers, CDS
  discriminator 8/24, zero resolver disagreement.
- **Confirmation at drafting time:** 0/22 on two independent vantages
  (wire `dig TYPE62 @1.1.1.1` + Google DoH JSON `type=62`), all 44 CSYNC
  responses NOERROR, CDS visible on 9/22 zones in the same sweep. The zero
  is measured absence, not instrument blindness.
- **Instrument trap, pinned for the next re-measurer (verified first-hand
  2026-09-01):** the Google DoH JSON API returns **HTTP 400** for
  `type=CSYNC` (mnemonic unrecognized) and 200 for `type=62`; Cloudflare's
  DoH accepts both; `dig` is immune (it compiles the mnemonic to wire type
  62 locally). Errors read as "not published" produce 0/N **regardless of
  the truth** — Science's first sweep produced exactly this false zero.
  Any future CSYNC sweep must carry an in-sweep discriminator (query CDS at
  the same names) so its zero is falsifiable. Vantage note: UDP/53 to
  `8.8.8.8` was dark from the measuring Mac at drafting time; the Google
  vantage was reached via DoH instead — six timeout lines miscounted as six
  answers is the same trap class, caught by the google.com row (a zone that
  publishes no CDS "answering" 6).

## Why Low/weight 1 is specifically wrong

- **CDS symmetry fails on the risk story.** CDS-Low prices a named
  availability failure; a CSYNC-Low would price nothing — no named harm
  exists in the spec or in any measured operator behavior.
- **It docks spec compliance.** §4.5 prescribes at-rest absence; Low turns
  the prescribed state into an arithmetic penalty — the "penalty with words
  denying it" shape the CDS ruling rejected.
- **It converts a labelling defect into a wrong-party scoring defect.** §5
  verbatim: *"Clients deploying CSYNC MUST ensure their zones are signed,
  current and properly linked to the parent zone with a DS record…"* — on
  an unsigned zone CSYNC is not unused but **unusable**. Under the zero
  band, mislabelling that zone "Absent" is wrong but costless; under Low,
  the zone enters the denominator and is docked for something the spec bars
  it from deploying (the NoMx/DANE wrong-party class).

## The independent defect (ship regardless of this ruling, as its own PR)

`CsyncDisposition` has no not-applicable path. Verified at `3d4f0de`: five
variants (Published, RecordAbsent, NoZone, TransientError, PolicyInvalid);
an unsigned zone gets `RecordAbsent → Absent`. The precedent sits five
dispositions away in the same file: `DaneDisposition::DnssecRequired →
NotApplicable`. CSYNC carries the identical §5 prerequisite and lacks the
variant. Fix: `CsyncDisposition::DnssecRequired → TriState::NotApplicable`,
gated on the domain's apex signedness — which `score_csync(resolver,
domain, receipt)` cannot currently see (no signedness input at the call
site; the signal already exists in the run via the DNSSEC control and must
be plumbed in). Because the new variant adds a `seal_disposition` string
under seal v5 and touches the receipts store, it lands as its **own PR
after #36 merges** — never slipped into the open PR. Under the zero band
the defect is labelling-only in the meantime; that the zero band keeps an
existing defect harmless is an independent reason to prefer it.

## What this ruling does not establish

- **The supply side is unmeasured.** RFC 7477 §4.4 says parental agents
  supporting CSYNC SHOULD publicly document that support; no registry or
  registrar was checked for such documentation. "No parent consumes it"
  remains a third sufficient explanation for 0/N.
- **Sweeps are one moment, few vantages.** Per §4.5 that cannot be
  improved for this question — which is why the ruling rests on the spec.
- **TLS-RPT's weight is not ruled here.** It landed in the same ten-control
  commit with its own derivation pin (#36 punch-list item 2) and has had no
  equivalent spec reading; if questioned, it gets its own measurement and
  document, not an analogy to this one.

## Signature

Ruled: ____________ (Carey) — date: ____________

On signature: strike DRAFT from the title, record the ruling on the ledger,
and card the `DnssecRequired` follow-up PR. No code changes under this
ruling.
