# Cross-Lane Catch-Up — Registration-Data Disclosure + Privacy Reality Check

**Date:** 2026-08-23 · **Anchor:** `@0599b0b` (and later) · **For:** Claude Code, Claude Science, SciSpace — read this ONE file to be current.

---

## 1. What this is

The session opened a new vector (registration-data disclosure) and drove it to
triple-confirmed facts, two new doctrines, and one open personal decision. This
is the single self-contained read so each lane is current without replaying the
whole conversation.

## 2. The three dated facts (corrected, then triple-confirmed)

| # | fact | status |
|---|---|---|
| 1 | **RFC 9537** — Mar 2024, Standards Track, Verisign (Gould/Smith) + GoDaddy (Kolker/Carney). Made `"redacted"` a structured RDAP field (JSONPath; 4 methods: removal / emptyValue / partialValue / replacementValue). §1 states the engine's `absent ≠ withheld` doctrine VERBATIM as its purpose: *"disambiguation between redaction and other possible reasons for data or field absence."* | CONFIRMED ×3 |
| 2 | **ICANN Registration Data Policy** — GNSO consensus, effective 21 Aug 2025 (a 12-May-2026 revision added urgent-disclosure timelines; 21-Aug-2025 is the baseline). §9.2 defines "redact" = MUST NOT include the value AND MUST indicate it's redacted. | CONFIRMED ×3 |
| 3 | **WHOIS sunset 28 Jan 2025** → WHOIS volume −60% (122B→49B, Jan→Aug 2025); **RDAP +9×** (7B→65B), overtook WHOIS June 2025. | CONFIRMED ×3 |

**Transparency on claim 3:** it was initially INVERTED — written as "RDAP
collapsed −60%." Claude Code caught it; Hermes verified first-hand against
ietf.org/blog/current-state-of-rdap (Newton, 19 Feb 2026); corrected. The −60%
is WHOIS; RDAP *grew*. Failure-shape #11 (inference recorded as measured finding).

**Confirmation topology (the point of the four minds):** Hermes (primary-source
search) + Claude Code (local-web) + SciSpace (cloud-only, disjoint access path —
cannot read local files) all agree. RFC 9537 was *also* independently verified by
Claude Science against rfc-editor's errata.json.

**DKIM errata note (Claude Science):** RFC 6376 §3.6.1 carries a Verified/Technical
erratum (eid 5137) — the `k=` tag ABNF names `%x76` ("v") instead of `%x6b` ("k").
The DKIM revocation ruling is unaffected (it rests on `p=` semantics, not `k=`).

## 3. Doctrine 1 — the two privacies are opposites

**Privacy-for-sale ≠ legitimate redaction. One hides the signal, the other labels
the carrier.**

- **Privacy-for-sale** (proxy services, resellers) = *undeclared withholding* — a
  fake proxy contact masquerades as the real one; the real PII still exists
  (ICANN §6 mandates collection) and is resold. The product IS the deception.
- **Legitimate redaction** (RFC 9537, the RDP, `.gov`'s `_disclose_fields`) =
  *declared withholding* — an explicit `"redacted"` member ("a value exists, I'm
  not publishing it, here's how and which").

**The separating test** (ask both, of any withholding):
1. Does the withholding declare itself? Proxy: no. RFC 9537 redaction: yes.
2. Does the security signal survive? Proxy: no (obscures who controls the domain).
   Redaction: yes (lifecycle/status/delegation stay public under §9.1).

**The signal/carrier mapping:** signal = the **lifecycle** (creation/expiry/status/
delegation — §9.1 MUST publish; it's the security truth). Carrier = the **human**
(name/phone/email — §9.2 MAY redact; it's the doxxing surface). **Keep the signal
public, withhold the carrier, declare the withholding.**

**Named, not convicted:** GoDaddy (largest privacy-seller) co-authored RFC 9537.
The standard is good; the product is where the misalignment lives.

## 4. Doctrine 2 — "source, not control" (the weight-2 ruling)

SciSpace proposed a weight-2 MEDIUM tier for a "registration-data control" with a
5-state model. Checked against the tree, the premise does not hold:
- `ControlId` is exactly 8 (DNSSEC/SPF/DKIM/DMARC/DANE/MTA-STS/CAA/CDS) — there is
  NO registration-data control.
- `identity_weight()` maps only High→3 / Low→1 — there is NO weight-2 band.
- The 5-state model conflates RFC 9537's four METHODS (how a server signals
  "withheld") with the disclosure STATE (disclosed/redacted/absent/unmeasured).

**Ruling (recommended, pending Carey's word):** disclosure state is a **property of
the source** (a tri-state: declared / undeclared / unmeasured), feeding the
two-signature threat model (`name_similarity.rs` already anticipates
registration-age/lifecycle). NOT a 9th control, NOT a weight tier.

## 5. Epistemic frame — "public records if you had excellent strategies"

Carey's framing, one-directional on purpose: *"we're showing people what public
records would look like if you had excellent strategies."* It is a
**necessary-condition signature** (IF excellent-strategy THEN records-look-like-X),
NOT a sufficient-condition proof. Running the arrow backwards (records → strategy)
is affirming-the-consequent — LOGIC-03, which the instrument tests for. The
instrument measures the CARRIER faithfully and reports the SIGNAL as a hypothesis,
never a finding.

## 6. NEW — personal privacy decision (measured, not asserted)

Measured 2026-08-23 via RDAP: Carey's domains (resolutionscope.com,
calibrationscope.com) use Amazon Registrar's **whoisproxy.com** proxy. Public
record shows `On behalf of <domain> OWNER`, `org=c/o whoisproxy.com`, NZ phone
`+64.48319528`, Alexandria VA proxy address. **No real PII in the live record.**

The question Carey raised: is there any reason to keep paying for the proxy?

The finding: the proxy **does** block the live public scrape (real), but it is the
*undeclared* shape (masquerade) and it hides even the **company**, so the domains
don't read as IT Help San Diego — accountability loss, plus a false sense of
secrecy (registrar + proxy + escrow still hold the PII).

**Recommendation: disclose the business, withhold the human, drop the proxy.** Swap
the registrant fields to business data (IT Help San Diego Inc. / 888 Prospect St /
carey.balboa@it-help.tech — all already public), then there is nothing personal to
protect, the domain reads as the company, and the proxy fee is $0. This is the
.gov model applied correctly: publish the accountable entity, withhold the
vulnerable human, declare it.

## 7. Cross-reference jobs

- **Claude Science** — verify Doctrine 1 against RFC 9537 §1 + ICANN RDP §9.2: does
  the standard distinguish "declared redaction" from "proxy masquerade" as asserted
  here, or is that a project-level extrapolation?
- **SciSpace** — confirm the CORRECTED claim 3 (WHOIS −60%, RDAP +9×) from public
  sources, so the fix itself is corroborated by a third path, not taken on one
  bot's word.
- **Claude Code** — already cross-checked claim 3 correctly. Open: any public
  copy/site that should state the two-score rule + the disclosure doctrine.

## 8. Open decisions for Carey (either/or)

1. **Privacy:** proxy vs disclosed-business vs redact. Recommendation: disclosed-business.
2. **weight-2:** "registration-data control" vs "source". Recommendation: source.
