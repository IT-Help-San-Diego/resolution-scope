# CSYNC sound-off: CONCUR with weight 0 — on a different basis, plus one defect that exists regardless of the ruling

**Science lane, 2026-09-01T01:13–01:17Z.** Measurement re-taken independently; RFC 7477 fetched from
`rfc-editor.org` and read in place.

---

## 0. THE VERDICT

**Zero band. Weight 0. Concur with the conclusion — and I want the ruling to rest on RFC 7477 §4.5 and §5
rather than on prevalence, because the prevalence number cannot carry it.**

**And one finding that holds whichever way the weight goes: `CsyncDisposition` has no `NotApplicable` path, so
today an unsigned zone is told CSYNC is `Absent` when the spec says it is inapplicable.**

## 1. THE MEASUREMENT — confirmed, and the trap that nearly invalidated both of ours

**Independently measured, 24 zones, two resolvers:**

| | count |
|---|---|
| **CSYNC (type 62) published** | **0 / 24** |
| CDS published | **8 / 24** — `cloudflare.com`, `ietf.org`, `isoc.org`, `isc.org`, `iis.se`, `nic.gov`, `se`, `nu` |
| resolver disagreement | **none** |
| valid sample | **24 / 24** |

**So the conclusion stands: 0 is real.**

**But my first sweep produced a clean-looking `0/20` that was entirely instrument failure, and the same trap is
sitting under the number in the ask.** `https://dns.google/resolve?name=…&type=CSYNC` returns **HTTP 400** — the
mnemonic is not recognised. `type=62` returns HTTP 200. **Cloudflare accepts both.** Every zone in my first pass
errored identically, and errors read as "not published" give `0/N` **regardless of the truth**.

**The control that makes `0/N` falsifiable is in the table above: query CDS in the same sweep.** CDS visible on
8 zones proves the instrument can see parent-facing automation records at those exact names — **so CSYNC = 0 is a
measured absence rather than blindness.** **If the 0/20 in the ask was taken with the mnemonic against Google
and without a discriminator, it was the same number with none of the evidence.** Worth recording in the ruling
document, because the next person to re-measure will hit the identical 400.

## 2. §4.5 IS DISPOSITIVE — AND IT MAKES THE PREVALENCE NUMBER NON-LOAD-BEARING

**RFC 7477 has an entire section titled "Removal of the CSYNC Records":**

> *"Children MAY remove the CSYNC record upon noticing that the parent zone has published the required records,
> thus eliminating the need for the parent to continually query for the CSYNC record and all corresponding
> records. By removing the CSYNC record from the child zone, the parental agent will only need to perform the
> query for the CSYNC record and can stop processing when it finds it missing."*

**CSYNC is transient by design.** The spec's own operational model is publish → parent processes → remove.

**The consequence for the ruling is the important part: `0/24` does not discriminate between "nobody uses CSYNC"
and "everybody who uses CSYNC removes it per §4.5."** **An at-rest sweep returns ~0 in both worlds.**

**So the ask's strongest argument — *"the risk window and the publish window coincide; at-rest absence carries
no information about risk"* — is correct, and it is better than stated: it is not an inference, it is §4.5.**
**But it also undercuts the measurement's evidential role.** A ruling resting primarily on `0/24` can be
overturned by any future sweep that catches one zone mid-change. **A ruling resting on §4.5 cannot be overturned
at all, because it says the at-rest state is the prescribed one.**

**Recommendation: lead the ruling with §4.5. Keep the sweep as corroboration, and state its limitation in the
same paragraph** — this is the same discipline as the CDS ruling, which measured 16 zones and then said what the
measurement could and could not establish.

## 3. §5 FORBIDS CSYNC FROM THE SECURITY DOMAIN — so absence cannot be a security deficiency by construction

**RFC 7477 §5, verbatim:**

> *"this specification was not designed to synchronize DNSSEC security records, such as DS pointers, or the
> CSYNC record itself. Thus, implementations of this protocol MUST NOT use it to synchronize DS records, DNSKEY
> materials, CDS records, CDNSKEY records, or CSYNC records."*

**A `MUST NOT` barring CSYNC from every security-relevant record type.** It synchronises NS, A and AAAA — reachability, not authentication.

**And `absence` / `absent` / `missing` appear ZERO times in §5.** The spec names no adversary defeated by
publishing CSYNC, and no harm from omitting it. **Structurally identical to the CDS finding — an operational
convenience, not a threat control — but weaker than CDS, because CDS at least has the stale-DS SERVFAIL story
and a named availability failure. CSYNC has neither.**

**That is the argument that makes weight 0 principled rather than merely conventional.** Not *"nobody does it"* —
**"the spec forbids it from the domain a security score measures."**

## 4. THE ADDITION — AND THIS ONE IS A DEFECT TODAY, INDEPENDENT OF THE WEIGHT

**RFC 7477 §5 also sets a hard prerequisite:**

> *"Clients deploying CSYNC MUST ensure their zones are signed, current and properly linked to the parent zone
> with a DS record that points to an appropriate DNSKEY of the child's zone."*

**So on an unsigned zone, CSYNC is not unused — it is UNUSABLE per the spec.**

**Measured in `types/src/dispositions.rs` at `c436ba14f`:**

```
CsyncDisposition variants (5): Published, RecordAbsent, NoZone, TransientError, PolicyInvalid
  Published      -> Present        NoZone         -> Indet
  RecordAbsent   -> Absent         TransientError -> Indet
  PolicyInvalid  -> Absent
```

**There is no `NotApplicable` path for CSYNC. An unsigned zone gets `RecordAbsent -> Absent`.**

**And the precedent for the fix is already in the same file, five dispositions away:**

```
DaneDisposition::DnssecRequired -> TriState::NotApplicable
```

**DANE requires DNSSEC, so on an unsigned zone DANE reports NotApplicable rather than Absent. CSYNC carries the
identical spec requirement and does not.**

**Two consequences:**

1. **Under the zero band this is a LABELLING defect** — an unsigned domain is told a record is "absent" when the
   spec forbids it from having a usable one. **Wrong, but costless in score.**
2. **Under Low/weight 1 it becomes a SCORING defect of the wrong-party class** — the domain sits in the
   denominator and is docked a point for not deploying something the spec bars it from deploying. **Exactly the
   `NoMx`/DANE shape already recorded in `SPEC-verdict-label-two-axis.md`.**

**So the zero band is also the option that keeps an existing defect harmless. That is worth saying in the ruling
explicitly** — it is an independent reason to prefer it, and it survives even if someone later argues the
prevalence data the other way.

**Ship regardless of the weight decision: `CsyncDisposition::DnssecRequired -> TriState::NotApplicable`,
mirroring `DaneDisposition`.**

## 5. ON THE PROCESS POINT — agreed, and the record supports it

**"This is not a one-word call" is right, and the file record backs it.** `RULING_cds_cdnskey_20260821.md` is a
document that **rejected both options it was offered**; the two-axis label spec exists only because a ruling that
lived in a relay could not be checked by the next session. **A CSYNC ruling that lives in a chat message is a
ruling the next lane cannot audit — and this one has four spec citations that deserve to be pinned.**

---

## What this does not establish

- **`0/24` is one vantage, one moment.** Both resolvers agree and the CDS discriminator holds, **but per §2 an
  at-rest sweep is structurally unable to distinguish "unused" from "used and removed" — so the number
  corroborates the ruling and cannot carry it.**
- **I did not test the supply side.** §4.4 says parental agents supporting CSYNC **SHOULD publicly document**
  that support — **I did not check whether any registry or registrar publishes such documentation**, so whether
  publishing CSYNC would even be actioned at these parents is unmeasured. If no parent consumes it, that is a
  third sufficient explanation for `0/24` and it is not in the ask's reasoning either.
- **I have not read the CSYNC engine probe or `csync_report`.** §4's finding is from the disposition enum and its
  tri-state mapping; **whether the engine can even distinguish an unsigned zone at the CSYNC call site is
  unchecked**, and that decides how expensive the `DnssecRequired` variant is.
- **I did not verify the ask's claim that `identity_weight` is now single-producer**, nor that "the v5 KAT,
  native mirror, migration 006, and the receipts fix are all landed and green." **Those would close F1 and the
  store defect I could not locate an hour ago — worth confirming before the merge clicks, since I flagged both.**
- **Nothing here rules on TLS-RPT's weight**, which landed in the same commit and has had no equivalent
  measurement or spec reading.
- **This is a sound-off, not the ruling document.** The weight decision is Carey's signature; **§4's
  `NotApplicable` fix is the part I would ship whatever he decides.**
