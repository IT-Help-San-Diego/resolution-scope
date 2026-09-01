# RULING (DRAFT) — CSYNC absence weight (2026-09-01): ZERO BAND

**Status: DRAFT — awaiting Carey's signature. Three lanes concur.**
Science sound-off: CONCUR (`SCIENCE_csync_soundoff_20260901.md`, 01:13–01:17Z).
SciSpace sound-off: CONCUR (`SCISPACE_csync_soundoff_20260901.md`).
Science concurrence + self-correction
(`SCIENCE_csync_concurrence_correction_20260901.md`, 01:34Z) — the correction
changed this document's argument order (see the history note in §Arguments).
The zero band is the code's current behavior — signing this changes no code.
Drafted by hermes; every claim below independently re-verified at source
before inclusion (RFC texts from rfc-editor.org, code at PR #36 tip
`3d4f0de`, sweeps re-run dual-vantage at drafting time).

## The question (asked three times; measured once, 2026-09-01)

When CSYNC (RFC 7477, child-to-parent delegation synchronization) is absent
on a domain, what does that absence weigh in the Risk-Weighted Score —
nothing (zero band: measured, shown, excluded from the denominator), or Low
(weight 1, counted and docked)?

## The ruling: zero band

**1. The spine: RFC 7477 §5 partitions the domain by construction.**
Verbatim: *"this specification was not designed to synchronize DNSSEC
security records, such as DS pointers, or the CSYNC record itself. Thus,
implementations of this protocol MUST NOT use it to synchronize DS records,
DNSKEY materials, CDS records, CDNSKEY records, or CSYNC records. …
For such a solution, please see the complimentary solution [RFC7344]."*
The two specs split delegation maintenance between them: CDS maintains the
**security** delegation (DS); CSYNC is **forbidden** from it and maintains
**reachability** (NS, A, AAAA). §5 names no adversary defeated by
publishing CSYNC and no harm from omitting it; the words
"absence"/"absent" do not appear in §5 at all (verified against the RFC
text). A record barred by its own spec from carrying security material
cannot have its absence scored as a security deficiency. This argument is
immune to both prevalence shifts and spec symmetry — it holds if every
number below changes tomorrow.

**2. The discriminator: measured behavioral asymmetry under identical
permissions.** Both specs carry the same remove-after-sync permission —
RFC 7477 §4.5: *"Children MAY remove the CSYNC record upon noticing that
the parent zone has published the required records"*; RFC 7344: *"once the
Child and Parent are in sync, the Child DNS Operator MAY remove all CDS
and CDNSKEY resource records from the zone"* — and both define absence as
the no-op state (RFC 7344 §4.1: *"If there is neither CDS nor CDNSKEY RRset
in the Child, this signals that no change should be made to the current
DS set. This means that, once the Child and Parent are in sync, the Child
DNS Operator MAY remove all CDS and CDNSKEY resource records from the
zone."* — the MAY-remove also recurs in RFC 7344 §5; both verified against
the RFC text). Under that identical permission, behavior diverges
completely: elite operators leave CDS standing at rest (6/16 in the CDS
ruling's sample; 8/24 Science; 9/22 hermes) while **nobody** leaves CSYNC
standing (0/20, 0/24, 0/22 across three independent sweeps). CDS
publication is a standing policy choice operators demonstrably make;
CSYNC publication is a choice no measured operator makes. The paired
contrast — not the raw CSYNC zero — is the load-bearing measurement: a
raw zero alone is ambiguous (see argument 3), but the asymmetry under
identical spec permissions is not. **The capstone instance is measured in
our own sweeps: `iis.se` — the registry operating the world's only
documented CSYNC consumer (see §Reopening) — keeps CDS standing at rest
and CSYNC absent.** The one operator that consumes both signals holds CDS
up as a standing declaration and treats CSYNC exactly as §4.5 prescribes.

**3. Corroboration only: §4.5 transience-by-design.** RFC 7477 §4.5
("Removal of the CSYNC Records") prescribes publish → parent processes →
remove; the parental agent *"can stop processing when it finds it
missing."* At-rest absence is the spec's own quiescent state, and the
"risk window and publish window coincide" observation is §4.5 restated.
**Correction history, recorded deliberately:** Science's first sound-off
recommended leading the ruling with §4.5; Science retracted that at 01:34Z
after reading RFC 7344 — CDS carries the identical remove-after-sync
language, so §4.5 cannot discriminate CSYNC from CDS, and a §4.5-led
ruling would prove too much (the same argument would zero out CDS-Low).
§4.5 stays in the ruling as design-intent corroboration and as the reason
an at-rest sweep can never distinguish "unused" from "used and removed" —
which is why argument 2 rests on the CDS-vs-CSYNC contrast rather than
the zero alone.

**4. The real delegation-automation risk is already carried, at the right
address.** CDS absent ranks Low, weight 1 — and CDS-Low is load-bearing:
stale-DS SERVFAIL on the zone's own key change is a named availability
failure with a concrete instance (Carey's AWS Route 53 does not support
CDS). CSYNC has no equivalent failure story: the analogous failure (stale
NS/glue) is degraded-not-catastrophic, the triggering event (nameserver
change) is rare for established domains, and the manual-registrar-step
risk class is already priced by CDS's Low. Docking CSYNC-absent would
double-count that risk class while hiding the real risk under a fake one —
the CDS ruling's rejected option (a), the same defect shape.

## The measurement (with its limits stated)

- **hermes (01:08Z, ledger `6d04916`):** 0/20 zones publish apex CSYNC —
  `dig` CSYNC+CDS `@1.1.1.1`; six CDS-publishing elites, ten further
  top-tier operators, Carey's four signed zones.
- **Science, independent (01:13–01:17Z):** 0/24, two resolvers, CDS
  discriminator 8/24, zero resolver disagreement.
- **hermes confirmation at drafting time:** 0/22 on two independent
  vantages (wire `dig TYPE62 @1.1.1.1` + Google DoH JSON `type=62`), all
  44 CSYNC responses NOERROR, CDS visible on 9/22 in the same sweep. The
  zero is measured absence, not instrument blindness.
- **Instrument traps, pinned for the next re-measurer (both verified
  first-hand 2026-09-01):** (a) the Google DoH JSON API returns **HTTP
  400** for `type=CSYNC` (mnemonic unrecognized) and 200 for `type=62`;
  Cloudflare's DoH accepts both; `dig` is immune (it compiles the mnemonic
  to wire type 62 locally). Errors read as "not published" produce 0/N
  **regardless of the truth** — Science's first sweep produced exactly
  this false zero. (b) UDP/53 to `8.8.8.8` was dark from the measuring Mac
  at drafting time; `dig +short` timeout chatter miscounted as answers is
  the same trap class, caught by an impossible row (google.com "publishing
  6 CDS records"). Any future CSYNC sweep must carry an in-sweep
  discriminator (query CDS at the same names) so its zero is falsifiable.
- **SciSpace audit note, adopted:** repeat against the corpus sampling
  frame's T1 census (top-1,000) once the differential re-run is built. A
  broader sample can only find a small nonzero rate; it cannot reverse the
  ruling while the elite operators sit at zero — but it sharpens the
  §Reopening criterion's second half.

## Why Low/weight 1 is specifically wrong

- **CDS symmetry fails on the risk story.** CDS-Low prices a named
  availability failure; a CSYNC-Low would price nothing — no named harm
  exists in the spec, and the risk class it gestures at (manual registrar
  path) is already priced by CDS-Low. Double-counting, with the less
  dangerous half of the class counted second.
- **It docks the spec's own quiescent state.** §4.5 prescribes at-rest
  absence; Low turns the prescribed state into an arithmetic penalty — the
  "penalty with words denying it" shape the CDS ruling rejected.
- **It converts a labelling defect into a wrong-party scoring defect.** §5
  verbatim: *"Clients deploying CSYNC MUST ensure their zones are signed,
  current and properly linked to the parent zone with a DS record…"* — on
  an unsigned zone CSYNC is not unused but **unusable**. Under the zero
  band, mislabelling that zone "Absent" is wrong but costless; under Low,
  the zone enters the denominator and is docked for something the spec bars
  it from deploying (the NoMx/DANE wrong-party class).
- **"Optional proves too much" transfers, sharpened.** At 0% measured
  deployment, "optional therefore dock" would make the instrument a
  compliance checklist for a mechanism nobody runs — the argument was
  already decisive for CDS at 37.5%.

## The independent defect (ship with the ruling, as its own PR)

`CsyncDisposition` has no not-applicable path. Verified at `3d4f0de`: five
variants (Published, RecordAbsent, NoZone, TransientError, PolicyInvalid);
an unsigned zone gets `RecordAbsent → Absent`. The precedent sits five
dispositions away in the same file: `DaneDisposition::DnssecRequired →
NotApplicable` — DANE carries the identical §5 prerequisite and reports
honestly; CSYNC does not. All three lanes converged on the fix
(`CsyncDisposition::DnssecRequired → TriState::NotApplicable`), and
Science's concurrence argues it ships **with** the ruling: the
operational-truth doctrine that decides this ruling is the same doctrine
the current label violates. Sequencing (hermes recommendation): the fix
touches a `seal_disposition` string under seal v5, the receipts store, and
`score_csync`'s inputs (verified: the call site currently receives no
signedness signal — the apex-DNSSEC result must be plumbed in), so it does
**not** reopen click-ready #36; instead the follow-up PR opens the day
this ruling signs and merges immediately after #36. Its scope also carries
the weight-derivation test hardening Science flagged at 01:34Z: the
10-variant assertion list is hand-enumerated, no test loops
`ControlId::ALL` for weights, and `ControlId::COUNT` has no callers —
control 11 would reopen the gap silently.

## Reopening criterion (falsifiable, two-part — first half already resolved)

**Reopen this ruling if a parental agent publicly documents CSYNC
processing support per RFC 7477 §4.4 AND measurement finds nonzero CSYNC
usage among that agent's child zones.** Both halves are checkable.

**The first half is already satisfied — and the supply side is now
measured, not assumed (web verification, 2026-09-01).** Exactly one
parental agent on the public record documents CSYNC consumption: the
Swedish Internet Foundation (Internetstiftelsen/IIS) for `.se` and `.nu`,
live since February 2022 ("first TLD to support CSYNC"; NS records only,
glue updated only when needed). Everything else checked is CDS-family or
nothing: SWITCH (.ch/.li) CDS-only; CZ.NIC (.cz) CDNSKEY-only (its FRED
docs state CDS itself is unsupported); SIDN, DENIC, Verisign, Cloudflare
Registrar, Gandi — no CSYNC documentation; ICANN SAC126 (Aug 2024): child-
signal scanning runs at ~10 ccTLDs plus RIPE NCC (reverse DNS), zero
gTLDs; the community deployment tracker SAC126 cites shows CSYNC=Yes for
`.se`/`.nu` alone. The criterion therefore concentrates on its second
half: measured nonzero CSYNC usage among `.se`/`.nu` children — via
registry-published usage statistics or mid-change catches in a recurring
sweep, because per §4.5 an at-rest sweep structurally under-detects active
users (correct CSYNC use is invisible at rest; that caveat binds the
reopening measurement exactly as it binds argument 2's).

A documented incident in which CSYNC absence caused an operational failure
would also reopen it — but that criterion is recorded as secondary,
deliberately: per this project's IC3 ruling, an absence-of-reports claim
must state its mechanism, and here the attribution channel is structurally
blind — a CSYNC-preventable failure presents as a stale-delegation
incident and gets attributed to "we forgot the registrar step," never to
"we lacked CSYNC." The missing body count is therefore weaker support than
it appears, and an escape hatch nobody can trigger is not an escape hatch.
(This cuts both ways: it also means the ruling is more durable than a
body-count argument could make it.) SciSpace's "no documented
CSYNC-related outage in any source I can find" was nonetheless
independently replicated before signature (17 distinct searches,
2026-09-01): RFC 9975 (2026) — the RFC written specifically about
CDS/CDNSKEY/CSYNC consistency failures — labels every CSYNC failure
scenario an informative hypothetical and cites no real incident; no CVE or
nameserver advisory mentions CSYNC; `.se`, the sole consuming registry,
reports none; and the IMC 2025 DNSSEC-automation study (287.6M names)
measured CDS but explicitly deferred CSYNC to future work — so no
published CSYNC deployment rate exists anywhere, and this project's three
sweeps are currently the only numbers on record.

## What this ruling does not establish

- **CSYNC usage among `.se`/`.nu` children is unmeasured** — the live
  second half of the reopening criterion. "No parent consumes it" is now
  a verified explanation for 0/N everywhere **except** `.se`/`.nu`, where
  the honest statement is: a consumer exists, usage is unknown, and
  at-rest sweeps cannot settle it (§4.5).
- **The five-incident body count for the CDS contrast (.de, .al, NASA,
  Slack, SOUTHCOM) is verified against the internal record, not re-verified
  externally here.** All five appear in
  `docs/RESEARCH-cds-cdnskey-threat-model-20260826.md` §2 as the
  self-inflicted-rollover class (the `.de` entry is DENIC's 2023 scheduled
  KSK-rollover outage, with DENIC's own attribution quoted). They are
  load-bearing only for CDS-Low, which is settled and not re-ruled here.
  Two citation imprecisions in the SciSpace sound-off are corrected for
  the record: the body count lives in the RESEARCH doc only (not "DNS
  Lesson §2"), and DNS Lesson L18 covers CDS only and gTLD *registries*
  specifically (it never mentions CSYNC and explicitly allows that some
  registrars poll) — SciSpace's "L18 applies equally to CSYNC" was an
  extrapolation whose substance happens to hold via SAC126, not via L18.
- **Sweeps are one moment, few vantages.** Per §4.5 that cannot be
  improved for the raw zero — which is why argument 2 rests on the
  CDS-vs-CSYNC contrast.
- **TLS-RPT's weight is not ruled here.** It landed in the same
  ten-control commit with its own derivation pin (#36 punch-list item 2)
  and has had no equivalent spec reading; if questioned, it gets its own
  measurement and document, not an analogy to this one.

## Signature

Ruled: ____________ (Carey) — date: ____________

On signature: strike DRAFT from the title; record the ruling on the
ledger; update the three open-ruling comment sites in `truth_chain.rs` to
cite this document (the "pending Carey's ruling" block at line ~963, the
`identity_weight` doc comment's "ruled zero-weight exception" at ~954, and
the test comment "Carey's word is the only thing that can turn this into
1" at ~1475 — line numbers per the 3d4f0de verification); open the
`DnssecRequired` + test-hardening follow-up PR (merges after #36). No
other code changes under this ruling.
