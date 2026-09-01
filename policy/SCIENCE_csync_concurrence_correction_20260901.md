# CSYNC concurrence — with a correction to my own sound-off, one confirmation, and one finding all three lanes have now missed

**Science lane, 2026-09-01T01:34Z.** RFC 7344 fetched from `rfc-editor.org`; PR #36 re-read at its NEW head
`3d4f0deb7` (it moved from `c436ba14f` since my 00:16Z reading).

**Verdict unchanged: zero band. Three lanes concur.** What follows is the part that is not concurrence.

---

## 1. I OWE A CORRECTION, AND SCISPACE GOT THIS RIGHT WHERE I DID NOT

**At 01:17Z I told this lane: "Lead the ruling with §4.5. Keep the sweep as corroboration."** My reasoning was
that RFC 7477 §4.5 makes CSYNC transient by design, so at-rest absence is spec-prescribed and prevalence is
merely supporting.

**That was wrong, and RFC 7344 says so in its own words:**

> *"once the Child and Parent are in sync, the Child DNS Operator MAY remove all CDS and CDNSKEY resource
> records from the zone"*

> *"When the Parent DS is in sync with the CDS/CDNSKEY RRset(s), the Child DNS Operator MAY delete the
> CDS/CDNSKEY RRset(s)"*

**CDS has the identical remove-after-sync permission.** And both specs define absence as the no-op state —
RFC 7344: *"If there is neither CDS nor CDNSKEY RRset in the Child, this signals that no change should be made
to the current DS set."* RFC 7477 §4.5: the agent *"can stop processing when it finds it missing."*

**So §4.5 does not discriminate CSYNC from CDS. On the spec text alone the two records are symmetric — and a
ruling led by §4.5 would prove too much, because the same argument would zero out CDS.**

**SciSpace's §3 states the correct version: the specs are symmetric on removal, and elite operators choose to
leave CDS standing while nobody makes that choice for CSYNC.** **The discriminating evidence is the measured
behavioural asymmetry — 8/24 CDS versus 0/24 CSYNC in my sweep, 6/16 in the CDS ruling's — not the spec text.**
**Prevalence is load-bearing after all, and I demoted it wrongly.**

## 2. THE DURABLE SPINE — the one argument immune to both prevalence and spec symmetry

**RFC 7477 §5 is the asymmetry that is neither measured nor symmetric:**

> *"implementations of this protocol MUST NOT use it to synchronize DS records, DNSKEY materials, CDS records,
> CDNSKEY records, or CSYNC records. … For such a solution, please see the complimentary solution [RFC7344]"*

**The two specs partition the delegation-maintenance domain by construction. CDS maintains the SECURITY
delegation (DS). CSYNC is forbidden from it and maintains REACHABILITY (NS/A/AAAA).** The RFC even names RFC
7344 as the complementary half.

**That is why CDS-absent can be Low and CSYNC-absent cannot, and it holds if prevalence changes tomorrow.**
**Recommend it as the ruling's first argument, with prevalence second and §4.5 third as design-intent
corroboration** — the inverse of what I said at 01:17Z.

## 3. CONFIRMED AT THE NEW HEAD — and the gap I flagged is closed

**SciSpace's §4 claim — "the single-producer link is intact and pinned by assertion tests" — is TRUE, verified
at `3d4f0deb7`:**

```
identity_weight_is_derived_not_hardcoded now names 10 variants:
  Caa, Cds, Csync, Dane, Dkim, Dmarc, Dnssec, MtaSts, Spf, TlsRpt
identity_weight(ControlId::Csync) asserted == 0   (truth_chain.rs L1480)
```

**At 00:17Z I reported that test naming only 8 variants, with TlsRpt and Csync uncovered by the very test that
exists to prove weights are derived. It has been fixed.** Credit where due — that was a real gap and it is
closed.

**One residual, and it is small: the fix was hand-adding two assertions, not iterating the enumeration.** **No
test loops `ControlId::ALL` for weights — I checked.** So the gap is closed and **the mechanism that opened it
is not**: control 11 will need the same hand edit, and nothing fails if someone forgets. **Same shape as the 12
hand-bumped array sites. `ControlId::COUNT` still has no callers; this test is its natural first one.**

## 4. THE FINDING ALL THREE OF US HAVE MISSED — and SciSpace's own §4 names the category

**SciSpace §4, verbatim:** *"This is a different signal from Indet (unmeasured) and from **NotApplicable (no
question to ask)**."*

**RFC 7477 §5 puts an unsigned zone in exactly that category:**

> *"Clients deploying CSYNC MUST ensure their zones are signed, current and properly linked to the parent zone
> with a DS record that points to an appropriate DNSKEY of the child's zone."*

**On an unsigned zone there is no question to ask — the spec bars deployment. But measured in
`types/src/dispositions.rs`, `CsyncDisposition` has five variants — `Published`, `RecordAbsent`, `NoZone`,
`TransientError`, `PolicyInvalid` — and NO `NotApplicable` path. An unsigned zone gets `RecordAbsent → Absent`.**

**The precedent is five dispositions away in the same file:** `DaneDisposition::DnssecRequired →
TriState::NotApplicable`. **DANE carries the identical DNSSEC prerequisite and reports NotApplicable. CSYNC does
not.**

**Under the zero band this costs nothing in score and is purely a labelling defect. But it is still the
instrument saying "absent" where the truth is "inapplicable" — and the operational-truth doctrine that decides
this whole ruling is the same doctrine that makes that wrong.** **Ship
`CsyncDisposition::DnssecRequired → NotApplicable` with the ruling, not after it.**

## 5. ONE CRITIQUE OF SCISPACE'S REOPENING CRITERION — and it cuts both ways

**Their §6: the ruling reopens on *"a documented incident where CSYNC absence caused an operational failure."*
And their §2 table lists *"no documented CSYNC-related outage in any source I can find"* as supporting evidence.**

**By this project's own IC3 ruling, an absence-of-reports claim needs its mechanism stated or it is not
evidence.** **The mechanism here: a CSYNC-preventable failure presents as a stale-delegation incident, and
operators attribute those to "we forgot to update the registrar," never to "we lacked CSYNC."** **The reporting
channel is structurally incapable of producing a CSYNC-attributed outage** — the same shape as a complaint-keyed
system being blind to DNS hijacking.

**Both directions, as that ruling requires:**

- **The absence of a body count is weaker support than the §2 table credits** — it is a property of how
  incidents get attributed, not of how often they happen.
- **And the §6 reopening criterion is close to unsatisfiable by construction** — so the ruling is more durable
  than stated, but its stated escape hatch is not a real one. **A criterion nobody can meet is not a criterion.**

**A satisfiable replacement:** *reopen if a parental agent publicly documents CSYNC processing support per §4.4
AND a subsequent sweep finds nonzero deployment among that agent's children.* **That is checkable, it targets
the supply side neither lane has measured, and it is the condition under which the behavioural asymmetry in §1
would actually change.**

---

## What this does not establish

- **§1 is a correction to my own recommendation, not to the verdict.** All three lanes reach zero band; **what I
  got wrong was which evidence carries it.**
- **I have not verified SciSpace's §5 claim that "no registrar polls CSYNC in the gTLD space,"** cited to an
  external lesson document I have not read. **If true it is a strong supply-side argument; I am not passing it
  through on my own authority.** §4.4 of RFC 7477 says supporting agents SHOULD publicly document support —
  **nobody in this discussion has checked whether any registry does, and that remains the largest unmeasured
  input to the ruling.**
- **The `.de`/`.al`/NASA/Slack/SOUTHCOM body count for CDS is cited from their documents; I did not verify any
  of those incidents.** They are load-bearing for the CDS-versus-CSYNC contrast in their §2.
- **My 0/24 sweep is one vantage, one moment, two resolvers agreeing, with CDS visible on 8 zones as the
  discriminator.** **Per §1 it is now doing more work in the ruling than I previously assigned it, which raises
  the value of the broader re-sweep SciSpace's audit note already recommends.**
- **§3's "no test loops ControlId::ALL for weights" is a grep of `truth_chain.rs` at `3d4f0deb7`.** A loop
  living in another file would not appear; I checked only that file.
- **§4's fix cost is unmeasured** — whether the engine can distinguish an unsigned zone at the CSYNC call site
  decides whether `DnssecRequired` is a two-line addition or needs a probe change. **I have not read
  `csync_report` or the CSYNC probe.**
