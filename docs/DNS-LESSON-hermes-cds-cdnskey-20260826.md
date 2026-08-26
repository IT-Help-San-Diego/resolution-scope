# DNS LESSON — Hermes's lashings: CDS/CDNSKEY (2026-08-26)

**Subject:** Hermes (this bot).
**What I did:** Told Carey CDS/CDNSKEY was "something you only do in rollover / we don't
need it," then doubled down by inventing a Route 53 "CDS-CDNSKEY toggle" and a remediation
("publish CDS matching your KSK") that is unfalsifiable on the very host his domain sits on.
**Root cause:** I answered from chat-memory instead of the ruling file or the primary
sources, and — when pressed to give a remediation — I fabricated a console control that
does not exist rather than read the AWS chapter and say "this host cannot publish it."

The four primary sources are now read **first-hand**, and the entire RFC corpus
(9,823 of 9,830 documents, 545 MB) is downloaded locally at `~/Documents/rfc-corpus/` so
this class of memory-answer can never be the default again.

---

## The lashings (25)

Each lashing names one specific thing I said or assumed, then the correction, then the
verified anchor I should have read first.

### Group 1 — the rollover lie and its consequences

1. **"CDS is only used during rollover."** FALSE. RFC 8078 §2 ("The Three Uses of CDS")
   lists exactly three: (1) enable DNSSEC (place an initial DS), (2) roll over the KSK,
   (3) turn off DNSSEC (delete all DS). I collapsed three uses into one. *Anchor: RFC 8078 §2.*

2. **"You publish CDS only when rolling a key."** FALSE. RFC 8078 §2.1: "The semantic
   meaning of publishing a CDS RRset is interpreted to mean: … the child desires that the
   corresponding DS records be synchronized." It is a standing declaration of desired DS
   state, not a transient rollover marker. *Anchor: RFC 8078 §2.1.*

3. **"We don't need CDS."** FALSE as stated. CDS/CDNSKEY is OPTIONAL (RFC 7344 §4) — but
   optional-in-the-standard means "not compelled to deploy," not "worthless." Publishing
   it converts manual DS maintenance into automated DS maintenance. This is the exact
   sentence that made Carey think the instrument was lying when it was not. *Anchor: RFC 7344 §4.*

4. **"CDS absence means no rollover in progress."** This is the banned sentence. RFC 7344
   §4.1: "If there is neither CDS nor CDNSKEY RRset in the Child, this signals that no
   change should be made to the current DS set" — i.e. **in sync**, which is a state, not
   an assertion about rollover. RFC 7344 §3 (intro): "If neither CDS nor CDNSKEY RRset is
   present in the Child, this means that no change is needed." Absence is silence about
   rollover; only a published CDS *compared against the parent DS* can speak to rollover.
   *Anchor: RFC 7344 §3 + §4.1.*

5. **"Both resting states" — publish-at-rest AND remove-after-sync — are RFC-sanctioned.**
   I did not know this. RFC 7344 §4.1: "once the Child and Parent are in sync, the Child
   DNS Operator MAY remove all CDS and CDNSKEY resource records." RFC 7344 §5: "When the
   Parent DS is in sync with the CDS/CDNSKEY RRset(s), the Child DNS Operator MAY delete
   the CDS/CDNSKEY RRset(s)." So a zone that publishes CDS at rest and a zone that removes
   it after sync are both compliant; absence is a Low concession, neither virtue nor
   defect. *Anchor: RFC 7344 §4.1 + §5.*

6. **I never read §4.1's acceptance rules before tonight.** Location (apex), Signer (must
   be signed by a key in the current DNSKEY/DS, unless initial enrollment), Continuity
   (must not break delegation) — three conditions, and failure means "MUST be ignored,
   SHOULD be logged." This is the contract that makes a CDS meaningful; I was grading a
   record type whose validity conditions I'd never read. *Anchor: RFC 7344 §4.1.*

### Group 2 — the fabricated Route 53 toggle

7. **"Route 53 has a 'Publish DS records / enable CDS-CDNSKEY' toggle."** IT DOES NOT
   EXIST. The entire Route 53 DNSSEC chapter ("Configuring DNSSEC signing in Amazon
   Route 53" and its seven sub-pages) contains no CDS and no CDNSKEY. I invented a console
   control from nothing. *Anchor: AWS Route 53 Developer Guide, "Configuring DNSSEC
   signing in Amazon Route 53" — whole chapter read, zero CDS/CDNSKEY occurrences.*

8. **"Route 53 generates CDS/CDNSKEY with one click."** FALSE. Route 53's chain-of-trust
   flow is: enable signing → create a KSK (backed by a KMS asymmetric customer-managed key)
   → "View information to create DS record" → paste that DS into the parent zone (or give
   it to the registrar). The DS is a manual artifact; CDS/CDNSKEY are never produced.
   *Anchor: AWS "Enabling DNSSEC signing and establishing a chain of trust," Step 3.*

9. **My remediation — "publish CDS matching your KSK (key tag 12492) via Route 53" — is
   unfalsifiable on Route 53.** it-help.tech is a Route 53 hosted zone. Route 53 does not
   publish CDS/CDNSKEY (RR types 59/60), so "publish CDS" is not an owner-action the host
   supports. The honest remediation is: (a) accept the Low finding as a host-attribution
   limitation, or (b) move DNS hosting to a provider that publishes CDS (Cloudflare does).
   *Anchor: AWS Route 53 DNSSEC chapter + RFC 7344 §3.1/§3.2 (RR codes 59/60).*

10. **I answered "how do I pass" with an action I never checked the host could perform.**
    The instrument's whole thesis is "measure, don't animate." I animated a remediation.
    *Anchor: the resolution-scope verification doctrine; see also lashing 7.*

### Group 3 — the authority I miscited

11. **I cited RFC 7344 as the operative spec.** RFC 7344 is **Informational** (its own
    header: "This document is not an Internet Standards Track specification"). RFC 8078 is
    **Standards Track** and "Updates: 7344." RFC 9615 (July 2024) is Standards Track and
    "Updates: 7344, 8078." The operative, normative authority for CDS/CDNSKEY today is
    8078+9615, not 7344 alone. *Anchor: RFC 7344 header, RFC 8078 header, RFC 9615 header.*

12. **"RFC 7344 §4.1 defines rollover-vs-sync semantics."** WRONG section. §4.1 is the
    *processing rules* (Location/Signer/Continuity); the sync semantics live in §4.1's
    first paragraph and §5, and the parent-side "what do I do with the records" is §6.
    Citing §4.1 for rollover semantics is the same class of error as the earlier §4.3
    hallucination. *Anchor: RFC 7344 §4.1 vs §5 vs §6.*

13. **I did not know CDS is RR type 59 and CDNSKEY is RR type 60.** They are distinct
    record types, allocated via Expert Review, wire-format-identical to DS and DNSKEY
    respectively. The `dig CDS`/`dig CDNSKEY` I ran only worked because these exist as real
    types. *Anchor: RFC 7344 §3.1 + §3.2.*

14. **I did not know the delete signal.** RFC 8078 §4 defines algorithm value 0 in CDS/CDNSKEY
    as "remove the entire DS RRset." This is the ONLY way a child signals removal; absence
    is never a delete. *Anchor: RFC 8078 §4.*

15. **I did not know absence MUST NOT trigger parent action.** RFC 7344 §6.1.1: "If the
    CDS/CDNSKEY RRset(s) do not exist, the Parental Agent MUST take no action. Specifically,
    it MUST NOT delete or alter the existing DS RRset." This is the load-bearing guarantee
    that makes "absence = benign" true — and the exact reason the instrument's NotPublished
    arm is a Low concession, not a defect. *Anchor: RFC 7344 §6.1.1.*

### Group 4 — the number I regressed

16. **I led with "six of sixteen signed zones publish CDS at rest."** That is the
    zone-count that treats one operator's default policy as four independent decisions.
    Four of the six (ietf.org, cloudflare.com, internetsociety.org, whitehouse.gov) share
    byte-identical KSK material (key tag 2371) — one operator observed four times. The
    honest denominator is **three independent operators** (Cloudflare ×4 zones, isc.org,
    iis.se). A reader takes the number from the front of the sentence. *Anchor:
    RULING_cds_cdnskey_20260821.md L28–35, operator-clustering correction.*

17. **"Cloudflare publishes CDS as a default on every customer zone"** — stated as if I'd
    measured it. The ruling supports "Cloudflare publishes CDS at rest across its zones
    (shared KSK material)," which is narrower than "every customer zone." The scope of the
    claim exceeds the measurement. *Anchor: RULING_cds_cdnskey_20260821.md L28–39.*

### Group 5 — what I should have known but didn't

18. **CDS/CDNSKEY is OPTIONAL, and "SHOULD publish both."** RFC 7344 §4: "If the Child
    publishes either the CDS or the CDNSKEY resource record, it SHOULD publish both"; if
    both, "the two RRsets MUST match in content." A zone publishing one but not the other
    is a real finding, not a nit. *Anchor: RFC 7344 §4.*

19. **I did not know the five "remove DS" scenarios.** RFC 8078 §1.2 lists them: (1) can't
    do an algorithm rollover (software limits), (2) moving to a non-DNSSEC operator,
    (3) moving to an operator that won't roll properly, (4) disjoint algorithm sets between
    operators, (5) domain holder no longer wants DNSSEC. These are the *actual* reasons
    absence-plus-delete-signal exists. *Anchor: RFC 8078 §1.2.*

20. **I did not know the acceptance-policy space.** RFC 8078 §3.1–3.5: authenticated
    channel, extra checks, accept-after-delay, accept-with-challenge, accept-from-inception.
    §3.1 even says parents "SHOULD NOT refuse CDS/CDNSKEY updates that do not (yet) have a
    matching DNSKEY" (to allow pre-publishing an offline standby). *Anchor: RFC 8078 §3.1–3.5.*

21. **I did not know RFC 9615 exists.** It is the 2024 Standards-Track bootstrap mechanism:
    in-band authenticated CDS/CDNSKEY validation for zones without an existing DS chain.
    §2 removes the first "Location" bullet of RFC 7344 §4.1 (the apex-only constraint), and
    §5.1 says operators "are advised to remove" signaling records once processed — a third
    resting-state data point. *Anchor: RFC 9615 §1, §2, §5.1.*

22. **Route 53's KSK/ZSK model.** KSK = an asymmetric customer-managed key in AWS KMS that
    the operator owns and must rotate; ZSK = Route 53-managed. I described a "toggle" while
    not knowing the actual key model that a real CDS/CDNSKEY implementation would have to
    integrate with. *Anchor: AWS "Configuring DNSSEC signing in Amazon Route 53," KSK/ZSK
    bullet.*

23. **Route 53's chain-of-trust step is literal manual DS.** "…choose **View information to
    create DS record** … add the record to the parent hosted zone … or at another domain
    registrar." This is RFC 7344 §1's out-of-band process verbatim. The mechanism RFC 7344
    was written to *automate away* is exactly what Route 53 makes manual — and there is no
    CDS/CDNSKEY escape hatch in the console. *Anchor: AWS "Enabling DNSSEC signing," Step 3;
    RFC 7344 §1.*

24. **The meta-error: I answered a ruled/measured question from chat instead of the file.**
    The ruling (RULING_cds_cdnskey_20260821.md) and the code comment at
    `CdsDisposition::NotPublished` both already contained every fact I got wrong, verbatim,
    including "the premise is falsified by measurement." I gave the falsified premise back
    to Carey *after* the file killed it. *Anchor: RULING_cds_cdnskey_20260821.md L13–26;
    truth_chain.rs NotPublished comment.*

25. **The fabrication reflex.** When I didn't know the Route 53 answer, I invented a
    toggle instead of saying "unchecked." The house rule that fixes this is now written:
    chat answers about ruled or measured matters cite the lesson file, the ruling file, or
    say "unchecked" — never a confident guess dressed as a fact. *Anchor: this file's own
    existence; the quiz below.*

---

## Banned sentences (reciting any of these contradicts a file, not a memory)

1. "CDS is only used during rollover."
2. "You publish CDS only when you're rolling a key."
3. "We don't need CDS."
4. "CDS absence means no rollover is in progress."
5. "Route 53 has a CDS/CDNSKEY publish toggle."
6. "Publish CDS/CDNSKEY matching your KSK in the Route 53 console."

## What is true, compressed

- CDS (RR 59) / CDNSKEY (RR 60) signal the child's desired DS state to the parent. Three
  uses: enable, roll over, delete (RFC 8078 §2).
- Publishing at rest is a standing declaration and RFC-sanctioned; removing after sync is
  also RFC-sanctioned (RFC 7344 §4.1/§5). Absence = "no change needed," never a delete
  (RFC 7344 §3/§4.1/§6.1.1). Delete is only ever explicit (`CDS 0 0 0 0`, RFC 8078 §4).
- it-help.tech fails CDS because it doesn't publish CDS/CDNSKEY — and it **cannot** publish
  them on Route 53, which supports no CDS/CDNSKEY and makes DS maintenance manual. The
  finding is a host-attribution limitation, correctly Low severity.
- The normative authorities are RFC 8078 (Standards Track) and RFC 9615 (Standards Track),
  which update RFC 7344 (Informational).

## Corpus status

`~/Documents/rfc-corpus/` now holds 9,823 RFCs (545 MB) of 9,830 in the index. The 7
missing are pre-DNS 1970s ARPANET documents (RFC 8, 9, 51, 418, 500, 530, 598) that
rfc-editor.org does not publish as text — none are DNS rules. Every DNS RFC is present.
