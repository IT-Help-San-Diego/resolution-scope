# RESEARCH — CDS/CDNSKEY: what it actually protects, who does it, and why Amazon doesn't (2026-08-26)

**Question (Carey):** is CDS/CDNSKEY a real threat vector like the unsigned-DNSSEC
"Apple situation" — with an APT/nation-state ranking, real incidents, real RFCs, real
blogs — or is it something the whole industry is ignoring? And if it matters, why doesn't
Amazon Route 53 do it — is that our first flag of "Amazon stupidity"?

**Verdict up front:** CDS/CDNSKEY is **not** the Apple situation. It is a different
class of risk — **operational resilience, not active attack** — and its correct severity
is **Low**. But it is real, it has a documented body count (self-inflicted outages, not
intrusions), and the industry is indeed largely ignoring it — for a **structural
(two-party) reason**, not laziness. Amazon lags, but so does nearly the whole gTLD
ecosystem; Cloudflare and the European ccTLD registries are the exceptions.

All RFC citations read first-hand from the local corpus (`~/Documents/rfc-corpus/`); all
incident/adoption facts web-verified 2026-08-26.

---

## 1. The threat model — read from the RFCs' own words

CDS/CDNSKEY is not itself a security control. It is the **automation layer for the real
control (DNSSEC)**. Its entire stated purpose (RFC 7344 §9, verbatim):

> "By automating the maintenance of the DNSSEC key information (and removing humans
> from the process), we expect to **decrease the number of DNSSEC related outages**,
> which should increase DNSSEC deployment."

The concrete harms CDS mitigates are two, both about DNSSEC's key lifecycle:

1. **Rollover outages.** RFC 6781 §4.1: "key rollovers are a fact of life when using
   DNSSEC." A KSK must roll when it's compromised, when the algorithm is deprecated, or
   on a rotation schedule — and the KSK rollover is the one that requires changing the DS
   at the parent (a registrar step). Get it wrong or forget it → broken chain → SERVFAIL
   → the domain vanishes for validating resolvers. RFC 7344 §1: "Any manual process is
   susceptible to mistakes and/or errors. In addition, due to the annoyance factor of the
   process, Operators may avoid changing keys or skip needed steps to publish the new DS
   at the Parent."

2. **Crypto rot.** The operator who dreads the manual registrar step simply never rolls
   the key — so a key that gets quietly compromised stays compromised indefinitely, or
   the domain accumulates expired signatures (see incidents below).

What CDS is **not**: an active exposure. A signed zone with a valid DS and no CDS
published is **fully secure right now**. That is the entire difference from the Apple
finding (unsigned mail path → DANE impossible → active MITM surface). CDS absence is
"your rollover procedure is manual and will probably break when you finally need it,"
not "you are exposed today."

The RFCs also bound CDS's *own* attack surface honestly (RFC 7344 §9): a compromised
signing server could publish malicious CDS/CDNSKEY to extend an attack's life — mitigated
by hold-down/delay before the parent acts; and CDS "SHOULD NOT be used for initial
enrollment" without a challenge mechanism (the gap RFC 9615 later closes). And a
compromised *registrar account* is not mitigated at all ("the 'new Registrant' can delete
or modify the DS records at will").

## 2. Real incidents (the "real things that have happened")

The failure CDS exists to prevent is **self-inflicted DNSSEC outage at rollover time**,
and it is well documented:

- **.de TLD (DENIC), 2023** — a *routine, scheduled KSK rollover* broke every `.de`
  domain for hours; validating resolvers (incl. 1.1.1.1) returned SERVFAIL across
  millions of domains. DENIC's own words: "The outage is linked to a routine, scheduled
  key rollover. As a precautionary measure, future rollovers have been suspended until
  the exact technical causes have been identified." (Cloudflare, "When DNSSEC goes wrong:
  how we responded to the .de TLD outage.")
- **.AL TLD** — a broken rollover took down the .al TLD; Cloudflare deployed a Negative
  Trust Anchor to keep sites reachable.
- **NASA.gov, 2012** — DNSSEC validation failure (Comcast published a detailed analysis;
  Comcast's validating resolvers were "correctly responding with a failure and blocking
  access to the site").
- **slack.com** — "the third unsuccessful attempt to enable DNSSEC" (IANIX).
- **gov.zm** — expired signatures; **ofda.gov / nlrb.gov** — RRSIGs 3,642 days expired;
  **southcom.mil** — a 35-hour DNSSEC outage overlapping a 31-day one at a child
  (jiatfs.southcom.mil). (IANIX "DNSSEC Downtime: List of Outages & Validation Failures.")

Every one of these is the rollover/maintenance failure class — the class CDS/CDNSKEY
automation exists to remove.

## 3. Who actually does it (the "only Cloudflare?" answer)

CDS/CDNSKEY is a **two-party mechanism**: the *child* (DNS host) publishes; the *parent*
(registry or registrar) must *consume*. Both halves matter.

**Publishers (child side):**
- **Cloudflare** publishes CDS/CDNSKEY at rest by default on every signed zone
  (Cloudflare DNS docs: "When you enable DNSSEC, Cloudflare automatically publishes CDS
  and CDNSKEY records in your zone"). This is the outlier.
- **Amazon Route 53** does **not** publish CDS/CDNSKEY (AWS DNSSEC chapter read whole —
  no CDS/CDNSKEY anywhere; independently confirmed by third-party writeups).
- (Google Cloud DNS / Azure DNS not independently verified this turn — left unclaimed.)

**Consumers (parent side):**
- **European ccTLD registries lead**: SWITCH (`.ch`/`.li` — the APNIC "CDS/CDNSKEY in the
  real world" walkthrough is literally a `.ch` zone; SWITCH runs two CDS-scanning
  robots), SIDN (`.nl` — "DS record updating can now be fully automated using CDNSKEY
  and/or CDS records"), `.cz` (the first registry to announce CDS/CDNSKEY support, per
  Chung et al., Duke, 2017), plus `.se`/`.no`.
- **Cloudflare Registrar** consumes its own CDS/CDNSKEY ("One-Click DNSSEC": "When
  Cloudflare is your registrar, we can automatically apply DNSSEC through our support for
  CDS and CDNSKEY… Cloudflare Registrar automatically scans available DS records").
- **The gTLDs do not.** No generic CDS-scanning service exists at `.com` (Verisign) — I
  found none, and the Chung et al. finding ("only the .cz registry" among major
  registries) plus Cloudflare's own "registrars *that support* RFC 8078" qualifier both
  point the same way. This is the **bottleneck**.

## 4. The Dutch / internet.nl answer

- **internet.nl is run by SIDN** (the `.nl` registry).
- **internet.nl's public test does not score CDS/CDNSKEY.** Its DNSSEC FAQ lists only
  RFC 4033/4034/4035, 8624, 9276 as the relevant specs — no RFC 7344/8078/9615. Its "why
  DNSSEC" section cites cache-poisoning incidents (Brazilian bank, Eircom, Brazilian
  malware campaigns) — the threat DNSSEC itself exists to stop, not the automation layer.
- **But SIDN (the org behind internet.nl) consumes CDS/CDNSKEY at the registry level for
  `.nl`.** So the Dutch are ahead on the *consumer* side (like they are on DANE), while
  their public test still doesn't demand the *child* publish CDS.

## 5. Why doesn't Amazon do it — is it "Amazon stupidity"?

Not uniquely. Three layers, none of which reduce to "Amazon is dumb":

1. **The mechanism is two-party, and the gTLD parent doesn't consume it.** Publishing CDS
   on a Route 53 zone for a `.com` domain would be shouting into a void — Verisign doesn't
   run a CDS scanner. Cloudflare "gets away with" CDS-at-rest because it is *vertically
   integrated*: it is both the DNS host AND a registrar that consumes its own CDS. Amazon
   Registrar could consume CDS for domains registered at Amazon, but most of the .com
   world sits on a parent that never scans.
2. **Amazon's DNSSEC model is deliberately manual-DS.** The KSK lives in AWS KMS as a
   customer-managed key; the chain-of-trust step is "paste this DS at your registrar."
   That's a product design choice, not an unfinished feature — but it is the pre-7344
   manual process, frozen in place.
3. **It's ecosystem immaturity, concentrated in the gTLD world.** The leaders are the
   European ccTLDs (registry-side) and Cloudflare (publisher-side, because vertical
   integration). Amazon lags on the *publish* side (it doesn't even emit CDS at rest,
   which costs nothing and works whenever a parent *does* scan), but the bigger gap is
   the gTLD registries that consume nothing.

So: **not a flag of Amazon stupidity — a flag of gTLD-ecosystem immaturity, with Amazon
one step behind Cloudflare on the child side too.** If anything, the "stupidity" signal
is that Amazon doesn't *publish* CDS/CDNSKEY at rest, which is free and future-proofs
every zone the moment a parent starts scanning.

## 6. The honest bottom line for it-help.tech

- it-help.tech is a signed, validly-delegated zone. It is **secure right now**.
- Its CDS "not published" is a **Low** severity operational-resilience finding: when the
  KSK eventually rolls, the DS update is a manual registrar step that can break the chain
  — the exact failure class behind the .de/.al/NASA/slack incidents.
- **It cannot be fixed on Route 53 today** (no CDS/CDNSKEY emission, and the `.com`
  parent wouldn't consume it anyway). The correct remediation is: (a) accept with
  attribution, and (b) runbook the registrar-DS step for any future KSK change — or move
  to a CDS-publishing host, disproportionate for a Low alone.

## 7. Design implication (the thing this surfaces, unexecuted)

The instrument already carries host-attribution for DANE (`tlsa_zone` — "your MX host is
unsigned, not your fault"). CDS is the same attribution class: a `NotPublished` Low is
often a *host-capability* fact (Route 53 can't publish it), not an operator's negligence.
A `cds_host_capability` observation — derived from NS-set inspection of who the DNS host
is, gated on whether that host emits CDS — would make the CDS verdict measurably honest
the way DANE already is. Carded, not built; would need the same "how do we measure host
identity honestly and does it enter the seal" discipline as tlsa_zone.
