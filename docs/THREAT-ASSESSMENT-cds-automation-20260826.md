# Threat Assessment: CDS/CDNSKEY automation — the Apple-situation treatment

**Date:** 2026-08-26 · **Lane:** claude-code · **Companion:** DNS-LESSON-cds-cdnskey-20260826.md
**The question (Carey):** is CDS-absence a ranked, real-world threat — APT-class or not,
who ignores it, what do the DANE-forward Dutch think, and is Amazon's absence
negligence or engineering? Same discipline as the industry-DNSSEC-posture
cross-check (the Apple decision, docs/industry-dnssec-posture-crosscheck-20260823.md):
rank honestly, attribute precisely, never inflate.

---

## 1. The honest reframe before any ranking

CDS is **not** an interception-class control. DNSSEC/DANE defend against an
in-path attacker; CDS automates the **trust-anchor lifecycle** — how the DS at
the parent stays correct as the child's keys are born, roll, and die. Its threat
model is therefore three *different* surfaces, each ranked separately below.
Selling CDS as APT defense would be an over-claim; dismissing the DS layer as
boring ignores that nation-states demonstrably operate there (§2-T3).

## 2. The threat model, ranked

### T1 — Self-inflicted bogus zone (availability). REAL, RECURRING, DOCUMENTED.

The canonical incident: **slack.com, 2021-09-30** — DNSSEC enablement attempt,
panic withdrawal, but validating resolvers had the DS cached for up to 24h with
no keys left to validate against → hard validation failure, ~24 hours, with
Slack's own postmortem published. The trigger deepening the failure was **a
Route 53 NSEC type-bitmap bug on wildcard names** — the resolver-side denial
territory our receipt column now records per scan. The ianix DNSSEC-outage
catalog documents this as a recurring *class* (bad rollovers, expired
signatures, desynced DS), not a one-off.

**This is exactly the class CDS + RFC 8078 §4 exist to close:** coordinated DS
introduction, maintenance, and — the Slack step that went wrong — *coordinated
withdrawal* via the explicit signed delete signal instead of a panic pull.
**Ranking: high-frequency class, self-DoS severity, no attacker required.**
The operator is the threat actor, and everyone is that operator eventually.

### T2 — Industry-scale adoption suppression. THE DEEPEST ONE.

The manual registrar-DS step is the measured bottleneck of DNSSEC deployment
(the registrar-role research literature — Chung et al.; SIDN's own finding that
none of the biggest internet services run DNSSEC). Every chain that breaks in a
manual rollover teaches a thousand operators not to sign at all. So the
system-level threat CDS addresses is not "you get hacked without it" — it is
**"the ecosystem stays unsigned because touching the trust anchor by hand
breaks things."** The instrument's whole mission (measured, sealed truth about
what's deployed) lives downstream of this: automation is how the denominator
grows. **Ranking: strategic, ecosystem-scale, slow — the reason the RFCs exist.**

### T3 — The nation-state layer this is NOT the control for. NAMED HONESTLY.

**Sea Turtle** (Cisco Talos, 2017–2020): state-sponsored compromise of
registrars, registries, and ccTLD operators — ~40 organizations, 13 countries —
altering DNS records to man-in-the-middle email/VPN of intelligence, military,
foreign-ministry, and energy targets, with stolen legitimate TLS certificates.
This proves the registrar/DS layer is APT-contested territory. **But CDS does
not defend it** — an attacker with registrar/EPP credentials bypasses child-zone
signals entirely. The controls for T3 are **registry lock + MFA** (Talos's own
recommendation). Boundary sentence for any public copy: *CDS automates honest
lifecycle; registry lock defends against hostile takeover; they are orthogonal,
and a domain wants both.*

## 3. Who actually does what — the industry map (measured/sourced tonight)

**Consuming registries (the scanner side):** `.cz` and `.se` for years; `.ch/.li`
(SWITCH's two-robot scanner: weekly sweep of insecure domains, then every 3h for
72h on CDS discovery, daily once secured — the reference deployment);
**CentralNic-backend TLDs** (multi-TLD gTLD backend, opt-in CDS scanning);
RIPE reverse zones. **Not consuming:** the root (SIDN's stated blocker for
TLD-level automation), **.nl — SIDN has no plans** (the DANE-forward Dutch are
*behind* on this one; internet.nl does not test CDS), and the big gTLD
registries — **.com does not poll.**

**Publishing DNS operators (the speaker side):** Cloudflare (automatic on every
DNSSEC zone — the 6/16-at-rest measurement's majority), deSEC, DNSimple (since
2019), and any self-hosted BIND/Knot with modern dnssec-policy. **Not
publishing: Amazon Route 53** — cannot create the types, signing doesn't emit
them (source-read whole, lesson L19–L20).

**Verdict on "is the whole industry ignoring it":** no — it is a **two-sided
market with adoption on both sides but rarely at the same domain.** European
ccTLD registries and the automation-first DNS operators each built their half;
the US-centric mainstream (.com, Route 53) built neither half.

## 4. it-help.tech specifically — the bitter timeline

- Route 53 cannot speak CDS (over-determined, lesson §6).
- `.tech`'s registry backend was **CentralNic — a CDS scanner operator — until
  November 2025**, when Radix migrated its portfolio to **Tucows Registry**
  (current CDS posture: TO-VERIFY, fresh migration).
- So for years, the registry side of your domain could plausibly consume the
  signal your DNS host is incapable of emitting. The gap is not yours and never
  was: **capability-tier, attributed to the operator** — the exact Apple
  parallel. Apple's unsigned mail path made DANE structurally impossible for
  them; Route 53 makes CDS structurally impossible for you.

## 5. The Amazon question, answered without the easy word

Not stupidity — **deliberate minimalism, with the costs parked at the worst
moments.** Route 53's DNSSEC model freezes the anchor rather than automating
it: customer-managed KMS KSK, no automatic KSK rotation, manual DS at the
registrar, no CDS. That genuinely minimizes DS-churn risk on quiet days — you
can't desync a DS you never change. The costs all land at the lifecycle
*events*: bootstrap (fully manual), algorithm/KSK rolls (white-knuckle manual),
and emergency withdrawal — **which is precisely where Slack burned, on Route 53,
with Route 53's own NSEC bug deepening the hole.** The fair one-line verdict:
Route 53 ships minimum-viable DNSSEC, safe until the day you must touch the
anchor, and the industry's automation answer to that day is the part they
haven't built. First flag of a *pattern*, not proof of stupidity — and the
pattern has a measured incident attached.

## 6. What this means for the instrument

- **Severity Low for NotPublished STANDS.** T1 is availability-class and
  RFC-sanctions both resting states (lesson L8); nothing here justifies
  promotion to the interception tier. The concession stays a concession.
- **The attribution enrichment gets its justification** (design card @4aee867):
  "your DNS host cannot emit this" (measurable) and "your registry does/does not
  consume it" (per-TLD table — a natural receipts/mesh-era data product) are the
  two facts that turn this Low from a scold into a map.
- **Public-copy boundary sentences** (T3 honesty): never present CDS as APT
  defense; always pair it with registry lock when the audience is
  takeover-threat-modeling.

## 7. Sources

[Slack's DNSSEC rollout postmortem](https://slack.engineering/what-happened-during-slacks-dnssec-rollout/) ·
[ianix DNSSEC outage catalog](https://ianix.com/pub/dnssec-outages.html) ·
[slack.com bogus, dns-operations](https://lists.dns-oarc.net/pipermail/dns-operations/2021-September/021340.html) ·
[Talos: Sea Turtle keeps swimming](https://blog.talosintelligence.com/sea-turtle-keeps-on-swimming/) ·
[APNIC: CDS/CDNSKEY provisioning in the real world](https://blog.apnic.net/2021/11/02/dnssec-provisioning-automation-with-cds-cdnskey-in-the-real-world/) ·
[CentralNic: Automated DNSSEC (CDS scanning)](https://centralnic.support/hc/en-gb/articles/5957742209309-Automated-DNSSEC-Configuration-CDS-scanning) ·
[SIDN: one change at a time (no .nl CDS plans)](https://www.sidn.nl/en/news-and-blogs/make-one-change-at-a-time-dont-rush-it-and-maintain-control-throughout) ·
[SIDN: biggest services not DNSSEC-enabled](https://www.sidn.nl/en/news-and-blogs/none-of-the-biggest-internet-services-are-dnssec-enabled) ·
[Cloudflare: expanding DNSSEC adoption](https://blog.cloudflare.com/automatically-provision-and-maintain-dnssec/) ·
[DNSimple: CDS/CDNSKEY support](https://blog.dnsimple.com/2019/02/cds_cdnskey/) ·
[Chung et al.: registrars in DNSSEC deployment](https://users.cs.duke.edu/~bmm/assets/pubs/ChungR-DCLMMW17.pdf) ·
[Tucows: Radix backend migration](https://www.tucows.com/news/radix-selects-tucows-registry-as-back-end-registry-services-provider) ·
RFC 7344 / 8078 / 9615 (first-hand, see the lesson doc)
