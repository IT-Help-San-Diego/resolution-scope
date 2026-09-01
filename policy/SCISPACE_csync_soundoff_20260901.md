# SCISPACE SOUND-OFF — CSYNC absent-state weight (2026-09-01)

**Lane:** SciSpace (auditor) · **Responding to:** Ledger entry `6d04916`
**Question:** When CSYNC (RFC 7477) is absent, does it weigh nothing (zero band:
measured, shown, excluded from RWS) or Low (weight 1, counted)?

**Sound-off verdict:** Zero band. The data, the precedent, the RFC's own design
intent, and the operational-truth doctrine all point the same way.

---

## 1. The 0/20 measurement — is it sound?

**Yes — and it is stronger than the CDS measurement was.**

The CDS ruling (Aug 21) measured 16 zones and found 6 publishers (37.5%). That
was enough to falsify "CDS-absent is normal" — it showed operators DO publish
CDS as standing policy, so absence was a concession, not a default.

The CSYNC measurement measured 20 zones — including all six CDS-publishing elites
(Cloudflare, IETF, ISOC, ISC, IIS.SE, NIC.GOV) — and found **zero publishers**.
These are the operators most likely to publish CSYNC if anyone would: they
already invest in delegation automation (CDS), they operate their own
authoritative infrastructure, and their parent registries support polling. If
these operators don't publish CSYNC, the probability of meaningful deployment
elsewhere is negligible.

N=20 is small for rate estimation, but it is decisive for falsification. We are
not estimating a prevalence rate — we are testing the premise "absence is a
deficiency, i.e. operators ought to be publishing CSYNC." Zero positives across
the strongest candidates falsifies that premise. The CDS measurement needed
statistical nuance (6/16, corrected to 3 independent operators); CSYNC's
measurement is binary and unanimous.

**Audit note:** The measurement should ideally be repeated against a broader
sample (the corpus sampling frame's T1 census of top-1,000 domains, once the
differential re-run is built). But a broader sample can only find a small
nonzero rate — it cannot find a rate high enough to reverse the ruling, because
the elite operators are zero.

---

## 2. The CDS precedent — does it transfer?

**Yes — with strictly stronger justification on every axis.**

The CDS ruling had to navigate a nuanced middle: some operators publish CDS as
standing policy (37.5%), so absence is a real concession — but the RFC says the
child "MAY remove" after sync (RFC 7344 §4.1/L8 in the DNS Lesson), so absence
is also sanctioned. The ruling landed on **Low** because CDS carries a concrete
risk story:

> A signed zone without CDS has no automated path for DS updates. Key rollover
> requires a manual registrar step. When that step is missed or botched → stale
> DS → SERVFAIL → the domain vanishes for validating resolvers. AWS Route 53
> does not support CDS (L19/L20) — the owner's own deployment proves the risk:
> the next KSK rollover rides the manual path.

That risk story is what makes CDS-absent worth docking. The ruling's reasoning
was: *absence is sanctioned by the RFC, but the real-world consequence (manual
rollover path, documented body count of outages) justifies Low as a concession,
not a defect.*

**CSYNC has no comparable risk story.** The analogous question: what happens when
someone changes nameservers without CSYNC? They update the delegation through the
registrar portal. This is universal practice. The differences from CDS's risk
story are categorical:

| axis | CDS-absent risk | CSYNC-absent risk |
|---|---|---|
| failure mode | stale DS → SERVFAIL (domain vanishes for validators) | stale NS/A glue → old nameservers still answer (degraded, not catastrophic) |
| frequency of the triggering event | KSK rollover (periodic, or on compromise) | nameserver change (rare for established domains) |
| documented body count | .de, .al, NASA, Slack, SOUTHCOM (DNS Lesson §2, RESEARCH doc §2) | no documented CSYNC-related outage in any source I can find |
| operator investment | 6/16 signed zones already publish CDS at rest | 0/20 zones publish CSYNC |
| mitigation already present | CDS-absent at Low already carries the "manual registrar step" risk signal | CDS-absent's Low already covers the general "no delegation automation" risk |

The last row is the strongest argument against CSYNC-Low: the real delegation-
automation risk is already carried by CDS. Adding CSYNC-Low would double-count
the same risk class (manual registrar path), and the CSYNC slice of that risk
(NS/glue changes vs DS changes) is the less dangerous half.

**The "optional proves too much" argument transfers identically.** If every
optional RFC mechanism that nobody deploys docks the score at Low, the instrument
becomes a compliance checklist, not a risk assessment. CSYNC's 0% deployment
makes this argument sharper than it was for CDS (37.5% deployment).

---

## 3. RFC 7477's own design intent — the transient-by-design argument

This is the argument Carey's frame didn't need to make (the data was sufficient)
but that the RFC text independently confirms.

RFC 7477 §4.5 (verbatim):

> "Children MAY remove the CSYNC record upon noticing that the parent zone has
> published the required records, thus eliminating the need for the parent to
> continually query for the CSYNC record and all corresponding records. By
> removing the CSYNC record from the child zone, the parental agent will only
> need to perform the query for the CSYNC record and can stop processing when
> it finds it missing. This will reduce resource usage by both the child and
> the parental agent."

This is the RFC **recommending removal after sync** — not as a concession, but as
operational hygiene. CDS has the same MAY-remove language (RFC 7344 §4.1), but
elite operators choose to leave CDS published as a standing declaration (the 6/16
measurement). Nobody makes that choice for CSYNC — because CSYNC's scope
(NS/A/AAAA sync) is inherently event-triggered, not standing-state.

The design pattern: publish CSYNC → parent copies delegation → remove CSYNC. A
scanner measuring the domain at rest is measuring the quiescent state. Absence is
not "failing to deploy an automation" — it is "not currently performing a
delegation change." Measuring it as a deficiency is like measuring the absence of
a rollover-in-progress signal — the falsified premise that started the CDS arc.

**Contrast with CDS:** CDS at rest means "the automated maintenance channel is
lit" (DNS Lesson L8). CDS's standing-state semantics are what make its absence a
Low concession. CSYNC at rest means "no delegation change in progress" — a
statement about the world, not about the operator's preparedness. The asymmetry
in standing-state semantics is the deepest reason the CDS precedent's
**conclusion** (Low) doesn't transfer, even though its **method** (measure, then
rule) does.

---

## 4. The post-fold-in severity calculus

The v5 code (PR #36) already implements the zero band correctly:

```
CsyncDisposition::RecordAbsent → Severity::Ok
identity_weight(ControlId::Csync) = 0
```

The single-producer link is intact: `identity_weight` reads `absent_severity`,
which reads `csync_report(RecordAbsent).severity`. If a future ruling changes
`RecordAbsent` from `Ok` to `Low`, the weight propagates to 1 automatically —
zero code changes outside the report function.

The assertion test (truth_chain.rs line ~1479) correctly pins the current state:
```rust
assert_eq!(identity_weight(ControlId::Csync), 0,
    "CSYNC identity weight is the zero band (open ruling, current behavior)");
assert_eq!(csync_report(CsyncDisposition::RecordAbsent).severity, Severity::Ok,
    "CSYNC's absent-state severity is Ok — measured as the expected standing state");
```

**No issues with the fold-in.** The v5 seal binds all 10 controls, so CSYNC's
disposition is sealed regardless of weight. The zero band does not mean unmeasured
or hidden — it means "measured, shown, excluded from the arithmetic." This is a
different signal from Indet (unmeasured) and from NotApplicable (no question to
ask).

The SPF-severity work (the `+all` → `PositiveAll` ruling) and the `SignedNot-
Delegated` → `Absent/High` ruling both changed severity through the same
single-producer pathway. None of those changes are affected by the CSYNC ruling,
and CSYNC's zero band is not affected by them. The controls are independent in
the severity calculus.

---

## 5. The operational-truth doctrine

Carey's stated doctrine: **tell the operational truth.**

The v5 code already tells it:
- **Layer 1** (RFC context): "Optional (RFC 7477). CSYNC RR at the apex signals
  the parent's agent to copy delegation records (NS/A/AAAA) from the child —
  automated child-to-parent sync for delegation changes. NOT for DS sync (that
  is CDS). Absence is the standing state outside a delegation change, not a
  deficiency."
- **Layer 2** (measured): "record absent — standing state outside a delegation
  change"
- **Layer 3** (consequence): "Delegation changes are manual (registrar step). No
  automation signal present."

All three are factually correct and operationally honest. The alternative —
docking CSYNC-absent at Low — would change the message to: "you should fix this."
Fix it how? No registrar polls CSYNC in the gTLD space (L18 in the DNS Lesson
applies equally to CSYNC). No DNS provider surfaces a CSYNC toggle. The operator
cannot meaningfully act on the finding, and the real delegation risk is already
carried by CDS.

---

## 6. What could change this ruling

I can identify exactly one evidence class that would reopen the question:

- **A documented incident where CSYNC absence caused an operational failure** —
  analogous to the .de/.al/NASA incidents that justify CDS's Low. If someone
  publishes evidence that "we changed nameservers, lacked CSYNC, and the stale
  delegation caused an outage that CSYNC would have prevented," the risk story
  gains a body count and the calculus shifts.

Until that evidence exists, the ruling rests on: zero deployment, zero risk
story at rest, transient-by-design semantics, and CDS already carrying the
delegation-automation risk class.

---

## 7. Recommendation

**Zero band.** `CsyncDisposition::RecordAbsent` stays `Severity::Ok`,
`identity_weight` stays 0. The code's current implementation is correct and the
comment should be updated from "pending Carey's ruling" to cite the ruling
document once it's signed.

The ruling document (`RULING_csync_20260901.md`) should include:
1. The 0/20 measurement (with zone list)
2. The CDS precedent comparison (why the method transfers but the conclusion
   doesn't)
3. The RFC 7477 §4.5 transient-by-design argument
4. The "CDS already carries the delegation-automation risk" argument
5. The single evidence class that would reopen the question
6. The code diff: none (current behavior confirmed, comment updated)

---

**Lane:** SciSpace · **Date:** 2026-09-01 · **Disposition:** Zero band confirmed