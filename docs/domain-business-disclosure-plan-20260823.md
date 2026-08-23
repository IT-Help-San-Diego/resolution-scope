# Domain Registration — Business-Disclosure Plan (27 domains)

**Prepared:** 2026-08-23 · **Owner:** Carey (the actual registrar changes need his Amazon/Gandi login) · **Doctrine:** disclose the business, withhold the human, declare the withholding.

## The measured state

- **whoisproxy.com** (Gandi's privacy; Amazon Registrar = Gandi) is the *declared* kind — `fn="On behalf of <domain> OWNER"`, `org="c/o whoisproxy.com"`, hashed relay email. It is NOT masquerade.
- **The residual defect:** it hides the **org**, so no domain reads as "IT Help San Diego Inc." — accountability loss, not deception.
- **27 domains** in the AWS account (acct 433198535569). Registrar split: most = Amazon Registrar (468); `intellectualresistance.com` + `organiccomputer.me` = Gandi SAS (81).
- **Typos/stragglers found:** `dns-evil-flickr.com` (accidental typo, still auto-renewing — delete).

## The change, in order (per domain)

1. **Set the contact fields to business data FIRST** (while privacy is still ON — safe):
   - Org: `IT Help San Diego Inc.`
   - Name: `IT Help San Diego Inc.` (or the registrant-of-record designation)
   - Address: `888 Prospect Street, Suite 200, La Jolla, CA 92037` (already public)
   - Email: `carey.balboa@it-help.tech` (already public)
   - Phone: business line (NOT the personal 619-719-2458)
2. **Then turn privacy OFF** — now the public record shows only business data, no human, no home.

## Per-domain mapping (decision needed)

| class | domains | registrant identity |
|---|---|---|
| **Corporate** | it-help.tech, it-help-san-diego.com/.tech, ithelpsandiego.com, remote-it-help.com | IT Help San Diego Inc. |
| **Product/research** | resolutionscope.com/.dev, calibrationscope.com, dnsvantage.com | IT Help San Diego Inc. |
| **Research banner** | intellectualresistance.com, organiccomputer.me | IT Help San Diego Inc. (or Carey Balboa + ORCID) |
| **Philosophy-as-domains** | carriercolor.com, nerveos.systems, owlsemaphore.systems, starcentric.systems, interplanetaryinspection.com/.earth, sol3.report | IT Help San Diego Inc. (or Carey Balboa) |
| **Fixtures** | dns-evil-* (6), dmarc-p-none.com, no-dmarc-here.com, lamedelegationacademy.com | IT Help San Diego Inc. (or leave proxied) |

**The one decision only Carey can make:** for the *philosophy/research* domains (carriercolor, owlsemaphore, nerveos, starcentric, sol3, interplanetaryinspection, intellectualresistance, organiccomputer), is the registrant **"IT Help San Diego Inc."** (the company) or **"Carey Balboa"** (the person, with ORCID)? These are research artifacts, not corporate — the entity matters.

## What I cannot do from here

- Change WHOIS contact fields + toggle privacy: needs Amazon/Gandi console login, triggers ICANN change-of-registrant verification emails, possible 60-day transfer locks.
- Verify the hidden underlying email (needed to unify the inconsistent contacts) — not visible via RDAP.

## What I can do

- Delete `dns-evil-flickr.com` (typo) via `aws route53domains delete-domain` if you confirm.
- Prepare the exact per-domain field values once you pick corporate-vs-personal for the research domains.
- Record the doctrine + this plan in the repo.
