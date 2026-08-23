# The Registration-Data Disclosure Vector

**Status:** measured 2026-08-23 from primary sources. Every claim below carries its source. This is the "what changed in our world" vector opened when a redaction observation in a DNS poll was chased to its root.

**Why this belongs in the instrument's record:** the Resolution Scope engine consumes registration data (registrar, lifecycle, RDAP/WHOIS state) and must distinguish three things that naive tooling collapses into one:

1. **Absent** — the field genuinely has no value in the zone/registry.
2. **Withheld / redacted** — the field HAS a value, and the operator declares it withheld.
3. **Undisclosed-by-policy** — the operator does not publish this class at all, as a standing rule.

A control that reads "missing" where the registry says "withheld" fabricates an absence. This document records the landscape that makes that distinction load-bearing.

---

## The two parallel shifts

Registration-data disclosure changed along two axes at once, and confusing them is the error class this vector exists to prevent.

### 1. Redaction became *structured* (the protocol gained a word for "withheld")

- **RFC 9537**, "Redacted Fields in the Registration Data Access Protocol (RDAP) Response" — Standards Track, March 2024, authored by Verisign and GoDaddy. [datatracker.ietf.org/doc/rfc9537/](https://datatracker.ietf.org/doc/rfc9537/)
- It defines a JSONPath-based extension that lets a server **identify** redacted fields and name the redaction **method** (removal, empty value, partial value, replacement value).
- Before it, a redacted field and an absent field were byte-identical to a parser. RFC 7483 (2015) mentions redaction twice; RFC 9083 (2021) three times — all in passing, no representation.

**The engineering meaning:** "redacted" entered DNS/registration lookups as a *first-class, parseable field* only in the last ~two years. The word's appearance is a protocol capability arriving, not a policy changing.

### 2. The data moved from query-time to published bulk files

- ICANN's **Registration Data Policy** (GNSO consensus policy, effective **21 Aug 2025**) makes GDPR-driven redaction permanent and contractual. [icann.org registration-data-policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
  - §9.2 "Redaction Requirements": redact is *defined* as "MUST NOT include the value AND MUST indicate that the value is redacted." Registrant Name/Street/Email/Phone, Tech contacts, and Registry IDs are all redactable; consent-to-publish lets a holder opt back in.
- The prior state was the **Temporary Specification for gTLD Registration Data** (May 2018), rushed in to keep WHOIS alive under GDPR ("Calzone" model, Hamilton memoranda). The 2025 policy is that temporary fix made permanent.
- **Measured signal — RDAP query volume collapsed 60% in eight months:** ~122 billion monthly queries in Jan 2025 → ~49 billion by Aug 2025. [IETF, "The current state of RDAP"](https://www.ietf.org/blog/current-state-of-rdap/)
  - The registry side is moving disclosure from per-query responses to **versioned, checksummable bulk files** — the same pattern the `.gov` registry uses (its full-frame CSV in git, sha256-frozen, citable to a commit).

**The engineering meaning:** for a sovereignty instrument, the published-file model is strictly better — a frozen file is citable and re-derivable, where a live query is a point-in-time read that can be bot-blocked, rate-limited, or policy-masked (see `.gov` RDAP returning 403 "Error 1010" to automated clients).

---

## The authoritative timeline (primary sources)

| date | event | source |
|---|---|---|
| May 2018 | Temporary Specification for gTLD Registration Data (GDPR emergency) | ICANN |
| Mar 2024 | **RFC 9537** — redaction becomes structured | IETF / rfc-editor |
| Aug 2025 | **Registration Data Policy** — temporary spec made permanent consensus policy | ICANN |
| 2025 | RDAP query volume −60% (122B → 49B) | IETF blog |

**The highest-authority bodies on this vector:** IETF REGEXT (the RDAP specification body — [datatracker.ietf.org/wg/regext/](https://datatracker.ietf.org/wg/regext/about/)) and ICANN / GNSO (the governance layer).

---

## The opposition landscape (who does *not* think like us)

This vector has no cartoon villain; it is a collision of two legitimate goods, and naming both is the point.

1. **Privacy regulators (GDPR as counter-force).** The entire redaction shift is GDPR compliance — a *good* force (protects individuals) that *also* degrades public ownership accountability. The tension is real and non-resolvable to one side; it is a seesaw, not a verdict.
2. **Data brokers / WHOIS resellers.** Their product is the now-redacted data; they fight redaction because it kills their commodity, not out of principle.
3. **Privacy/proxy services** (GoDaddy, Namecheap proxying). A *second* redaction layer on top of the registry's own — replaces the holder's data with a forwarding proxy contact.
4. **Bulk collectors** (passive DNS, CT logs, zone-file accumulation). Their appetite is indifferent to redaction — they get the data through another door, so redaction punishes the *legitimate* analyst while leaving the bulk collector untouched.

---

## Mapping to engine doctrine

The engine already enforces the distinction this landscape demands:

- `absent` ≠ `withheld` ≠ `undisclosed` — three measurements, three different claims.
- A CISA default contact (`.gov` ADR 0020) is **the registrant of record by design**, not a redaction artifact — must not be read as the holder's own contact.
- A missing contact is **undisclosed by policy**, not absent — and the same field can be redacted-by-law in one TLD (`.de`, GDPR) and published in another (`.io`, `.us`), so no single "does the field exist" test is valid across the corpus.

**Consequence for any control consuming registration data:** treat "missing" as *possibly-withheld*, never *absent*, until the registry's publication policy (readable, because the major registries publish it) says otherwise.

---

## Open items → lane assignments

| item | lane | why |
|---|---|---|
| `.gov` disclosure documentation pass (CISA registrar policy, ADR 0020, the `_disclose_fields` code) | Claude Science | already has the frozen frame + the morning's RDAP 403 evidence |
| Independent cloud-side re-verification of the RFC 9537 timeline + `.gov` disclosure mechanism | SciSpace (cloud-only) | zero local access → clean corroboration path |
| Risk-Weighted Score rendering (TUI/HTML/site specimen recapture) | Claude Code | frontend lane, already queued |
