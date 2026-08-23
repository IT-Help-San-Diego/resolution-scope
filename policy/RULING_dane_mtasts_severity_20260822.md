# RULING — DANE / MTA-STS severity + the "sane maximum" doctrine

**Date:** 2026-08-22 · **Decided by:** Carey · **Recorded by:** Hermes · **Repo:** resolution-scope
**Status:** RULED (closes the spec §5 sub-decision)

---

## 1. The decision (three parts)

1. **MTA-STS and DANE are the same protection.** Both guard the mail-in-transit hop against
   interception/downgrade. They differ only in trust anchor — MTA-STS trusts the CA/Web-PKI
   system, DANE trusts DNSSEC and pins the exact certificate (TLSA). Same threat, same level,
   so they must carry the **same severity**: both **Medium**.

2. **The dollar-dominant threat is spoofing, not interception.** FBI IC3: BEC = $55.5B exposed
   (2013–2023), the "The $55 Billion Scam" — and that's *impersonation → wire fraud*, owned by
   SPF/DKIM/DMARC. In-transit interception is real but covert and unmeasured (no clean dollar
   figure — which is itself a truth we disclose, not a gap we paper over). So:

   | Severity | Weight | Controls | Threat class |
   |---|---|---|---|
   | High | 3 | DNSSEC, SPF, DKIM, DMARC | spoofing / forgery (the $55B surface) |
   | Medium | 2 | MTA-STS, DANE | in-transit interception |
   | Low | 1 | CAA, CDS/CDNSKEY | hardening / hygiene |

3. **Deployability is a different axis than severity.** DANE is structurally unavailable on
   Google Workspace — the TLSA record lives in Google's MX-host zone (`_25._tcp.smtp.google.com`),
   which the domain owner cannot write. That is a **disposition** fact (can-you-deploy-it), not a
   **severity** fact (how-bad-is-the-threat). The prior High/Low split was *availability wearing a
   severity costume* — exactly the conflation identity-weighting exists to kill.

## 2. The "sane maximum" doctrine (Carey's framing, verbatim logic)

> "As much as I would love to do it just to be able to show the Americans what perfection looks
> like, I think it's also important to show what perfection looks like as far as you can go when
> the world around you won't allow you to do better."

Two kinds of perfection, and the instrument must teach BOTH:

- **Perfection you can reach** — the "sane maximum" within your provider's constraints. For a
  Google Workspace domain this is genuinely excellent: DMARC reject, SPF hard-fail, DKIM,
  DNSSEC, MTA-STS enforce, TLS-RPT.
- **Perfection the world blocks** — DANE on Google, full stop. Not a failure, a ceiling.

The report must say it honestly and attribute it correctly: *"your score is one rung lower here,
but this one's not on you — Google doesn't publish TLSA, Microsoft now does, and here's why it
matters."* Educate, don't penalize. This is the same "no drama, explain yourself" rule applied to
a user's own mail stack.

## 3. Consequences (what this ruling changes)

- **Severity re-ruling** (weights follow automatically — derived from Severity, never hardcoded):
  MTA-STS 3→2, DANE 1→2. Max denominator **unchanged at 18** (net zero: MTA-STS −1, DANE +1).
- **NEW engine feature (carded, NOT this ruling's scope):** a **"provider-gated" disposition**
  for DANE on non-DANE-publishing MX hosts (Google and the like), so a Google user's report reads
  "not deployable through your provider" instead of "absent." Same family as the existing
  `DnssecRequired` disposition — a measured third state between "absent" and "unmeasured."
- **The mail-gateway path is recorded as real and legitimate, but NOT executed.** Rolling your own
  MX gateway (inbound + outbound) gains DANE on top of Workspace — the one path where DANE lives
  at *your* MX host, not Google's. Carey's choice: demonstrate the sane maximum rather than own a
  permanent always-on mail server (a SPOF + a hardening job that never ends). The option stays
  documented so the ceiling is *explained*, not *hidden*.

## 4. Provider reality (measured 2026-08-22, sources on record)

| Provider | Inbound DANE | Note |
|---|---|---|
| Google (Gmail/Workspace) | ❌ No | `smtp.google.com` publishes no TLSA; Google support thread literally titled "DNSSEC: Not fulfilled, DANE: Not fulfilled" |
| Microsoft (Exchange Online) | ✅ GA (shipped) | learn.microsoft.com "How SMTP DANE works" — preview May 2024, GA end-2024 |
| Proton | ✅ Yes (2019) | proton.me security blog |

The line is **Google vs Microsoft**, not "Europe vs America." Microsoft already crossed it;
Google is the specific DANE-less holdout (and it's a *huge* chunk of the American mailbox pie).
