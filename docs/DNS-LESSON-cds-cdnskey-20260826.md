# DNS Lesson: CDS/CDNSKEY — the deep-documentation punishment, taken

**Date:** 2026-08-26 · **Lane:** claude-code · **Ordered by:** Carey ("all the robots
go do some DNS lessons — deep documentation punishment," ≥20 RFC lashings per robot)
**Why this exists:** in one evening, the four-mind produced THREE chat-recall
fabrications about one control — "CDS is only for rollover" (the ruling-falsified
premise, recited back), "we already handled CDS in hardening" (never in scope), and
"one Route 53 toggle publishes it" (no such control exists). Each came from
chat-memory instead of a file. This document is the file. Every claim below was
read first-hand tonight at rfc-editor.org / docs.aws.amazon.com or is marked with
the session sha where it was first-hand verified earlier. Chat answers about CDS
now cite this document or say "unchecked."

---

## 1. What the records ARE

**L1** — RFC 7344 §3: "The CDS and CDNSKEY resource records are published in the
Child zone and give the Child control of what is published for it in the parental
zone." The child speaks; the parent listens (or doesn't — see §5 below).

**L2** — RFC 7344 §3.1: CDS wire/presentation format is **identical to DS**
(RR type 59). **L3** — §3.2: CDNSKEY is **identical to DNSKEY** (RR type 60).
They are the child's *proposed* DS/DNSKEY, published in the child's own zone,
signed like anything else in it.

**L4** — RFC 7344 §3: "The Child can publish these manually, or they can be
automatically maintained by DNS provisioning tools." (Cloudflare does the
latter on every DNSSEC-enabled zone — measured live: cloudflare.com itself and
four customer zones, session @1952bcc and again tonight.)

## 2. The lifecycle — where every wrong sentence came from

**L5** — RFC 7344 §4: the RRset "expresses what the Child would like the DS RRset
to look like after the change; it is a **'replace' operation**." Not an event, not
an alarm — a *desired state declaration*.

**L6** — RFC 7344 §4.1: "If there is neither CDS nor CDNSKEY RRset in the Child,
this signals that **no change should be made** to the current DS set." Absence =
"leave it alone." Absence is NEVER a removal request.

**L7** — RFC 7344 §6.1.1: "If the CDS/CDNSKEY RRset(s) do not exist, the Parental
Agent MUST take no action. Specifically, it **MUST NOT delete or alter** the
existing DS RRset." The parent-side mirror of L6, as a MUST NOT.

**L8** — RFC 7344 §4.1 + §5: "once the Child and Parent are in sync, the Child DNS
Operator **MAY remove** all CDS and CDNSKEY resource records from the zone."
**The nuance the whole arc missed, in both directions:** publish-at-rest is normal
AND remove-after-sync is RFC-sanctioned. *Both* resting states are legitimate.
What the instrument grades is the **standing signal at scan time**: a standing CDS
means the automated-maintenance channel is lit; absence means the next DS change
rides the manual registrar path (or a republish). The 2026-08-21 ruling's
falsified premise ("publication signals a rollover IN PROGRESS") stays falsified —
6/16 signed zones publish at rest, measured — and L8 is why absence stays a *Low
concession*, not a defect and not a virtue.

**L9** — RFC 7344 §4: "The use of CDS/CDNSKEY is **OPTIONAL**" for consumers.
**L10** — RFC 7344 §6.2: the parental agent "SHOULD use a DNSSEC validator to
obtain a validated CDS/CDNSKEY RRset from the Child zone" — consumption is
validated, not trusted. **L11** — §6.2: the agent "MUST ensure that previous
versions of the CDS/CDNSKEY RRset do not overwrite more recent versions"
(signature-inception ordering — replay defense).

## 3. Deletion and bootstrap — the explicit edges

**L12** — RFC 7344 §9: these techniques "**SHOULD NOT** be used for initial
enrollment of keys since there is no way to ensure that the initial key is the
correct one." 7344 automates *maintenance*, not birth.

**L13** — RFC 8078 (Standards Track, **Updates 7344**): adds initial trust setup
and removal. §3 gives the acceptance policies a parent may use for the FIRST DS:
authenticated channel (§3.1), extra checks (§3.2), accept-after-delay (§3.3),
challenge (§3.4), pre-publication (§3.5).

**L14** — RFC 8078 §4, the DNSSEC Delete Algorithm — deletion is an EXPLICIT
signed signal, never inferred from absence: RDATA `CDS 0 0 0 0` /
`CDNSKEY 0 3 0 0`, "signed in the same way as regular CDS/CDNSKEY RRsets."
This is the instrument's `DeletionRequested` → Severity::High arm (verified
in-tree, truth_chain.rs cds_report; first landed @c349ac7 with the citation
corrected FROM SciSpace's fabricated "RFC 7344 §4.3" TO 8078 §4 — this control's
citation-hallucination history predates tonight).

**L15** — RFC 9615 (Standards Track, July 2024, **Updates 7344 + 8078**):
authenticated bootstrap. The child DNS *operator* publishes CDS/CDNSKEY under
signaling names (`_dsboot.<child>._signal.<ns-host>`) in zones the operator
already has DNSSEC for, so the parent can validate the FIRST DS in-band —
replacing accept-after-delay's leap of faith. **L16** — RFC 9615 §5.1: "It is
possible to add CDS/CDNSKEY records and corresponding signaling records to a
zone without the domain owner's explicit knowledge" — bootstrap is
operator-side machinery, not owner action.

## 4. Document-status precision (the instrument's copy nuance)

**L17** — RFC 7344 front matter: "not an Internet Standards Track specification;
it is published for informational purposes." The Arm-2 correction (@f946cd8)
recorded this against a "Standards Track" over-claim, correctly. **The fuller
truth after 8078:** the *document* 7344 is Informational; the *mechanism* was
elevated by 8078 (Standards Track, Updates 7344) and again by 9615. Our Published
copy says "RFC 7344 is Informational" — true as stated, and the load-bearing
half (the parent is never obligated) survives via L9's OPTIONAL either way.
Precision candidate for a future copy pass, not a defect.

## 5. Consumption reality — who actually listens

**L18** — RFC 7344 §6.1 models the parent **polling** the child. In the real
world, polling parental agents exist mostly at ccTLD registries (SWITCH's .ch/.li
CDS scanner is the canonical deployment; CZ.NIC and several Nordic registries run
similar) and at some registrars. **The major gTLD registries — .com/.net included
— do not poll CDS**, so a standing CDS under .com today is a lit signal with no
registry consumer; only a polling REGISTRAR redeems it. *(Deployment landscape
marked TO-VERIFY-PER-TLD: registry practice is operational fact, not RFC text —
verify the specific TLD before asserting a consumer exists. For it-help.tech:
.tech registry + Amazon Registrar, no known CDS consumer on either side —
unverified-negative, stated as such.)*

## 6. Route 53 reality — source-read tonight, over-determined

**L19** — AWS "Supported DNS record types" (read whole): creatable types are
A/AAAA/CAA/CNAME/DS/HTTPS/MX/NAPTR/NS/PTR/SOA/SPF/SRV/SSHFP/SVCB/TLSA/TXT.
**No CDS, no CDNSKEY.** (Reasoning discipline: this alone proves only
*not-creatable* — Route 53 serves non-creatable types via signing, e.g.
DNSKEY/NSEC/RRSIG — which is why L20 was required.)

**L20** — AWS "Configuring DNSSEC signing" chapter + "Enabling DNSSEC signing and
establishing a chain of trust" (read whole): the chain of trust is established by
a HUMAN creating the DS at the parent — registrar console, change-batch JSON, or
"contact your registrar." Zero CDS/CDNSKEY mentions anywhere in the chapter; no
automatic DS synchronization exists. Wire-confirmed: 0/3 of our signed Route 53
zones publish CDS/CDNSKEY (it-help.tech, resolutionscope.com,
calibrationscope.com). **There is no toggle.** On Route 53, the CDS Low is not
passable by owner action; remediation = accept-with-attribution + runbook the
registrar-DS step.

## 7. Bonus lashings — the adjacent anchors this arc already verified first-hand

**L21** — RFC 4034: DS/DNSKEY record formats CDS/CDNSKEY mirror (via L2/L3).
**L22** — RFC 4035 §5.4: authenticated denial — the receipts' `nsec`/`nsec3`
gold-receipt grade (@1952bcc). **L23** — RFC 9824 §2: NXNAME "sole entry" NSEC3
rule (@341d81e, dual-anchored §4). **L24** — RFC 7505 null-MX — the DANE N/A arm
visible on tonight's it-help.tech screen... (correction: that screen row was
example.com's shape; it-help.tech runs Google MX — the N/A arm belongs to
null-MX domains). **L25** — RFC 8659 §4.2/§4.3 issue vs issuewild — the CAA
row's `issuewild ";"` strongest-state on tonight's screen (@27997d0).

## 8. The quiz — sentences that must never be said again

1. ~~"CDS is something you only do during a rollover."~~ Falsified by measurement
   (6/16 at rest) and by L5 (desired-state, not event).
2. ~~"Absence of CDS is the healthy resting state."~~ Banned framing (ruling
   @ef0abd5 arc): absence is *sanctioned* (L8) but costs the automated path;
   it is a Low concession, neither virtue nor defect.
3. ~~"Absence means the parent should remove the DS."~~ Inverts L6/L7 (MUST NOT).
   Deletion is only ever the explicit L14 signal.
4. ~~"There's a Route 53 toggle for CDS."~~ No such control (L19+L20).
5. ~~"Publish CDS and your .com DS updates automatically."~~ No registry consumer
   at .com (L18); OPTIONAL end to end (L9).
6. ~~"RFC 7344 §4.3 defines the delete signal."~~ 7344 has no §4.3; the delete
   signal is 8078 §4 (L14) — the original citation fabrication of this arc.

**Sources:** [RFC 7344](https://www.rfc-editor.org/rfc/rfc7344.html) ·
[RFC 8078](https://www.rfc-editor.org/rfc/rfc8078.html) ·
[RFC 9615](https://www.rfc-editor.org/rfc/rfc9615.html) ·
[Route 53 supported types](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html) ·
[Route 53 DNSSEC signing](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html) ·
[Route 53 chain of trust](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec-enable-signing.html)
