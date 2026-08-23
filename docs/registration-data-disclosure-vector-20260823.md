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

**The engine's own doctrine, stated verbatim by the RFC as its purpose** (RFC 9537 §1, Introduction):

> "Because an RDAP response may exclude a field due to either the lack of data or the lack of RDAP client privileges, this extension is used to explicitly specify which RDAP fields are not included in the RDAP response due to redaction. It thereby provides a capability for **disambiguation between redaction and other possible reasons for data or field absence**."

That is `absent ≠ withheld ≠ undisclosed` — the exact distinction the engine enforces — written into the protocol's *reason for existing* three years ago. The engine was right before the standard could say the words; the standard now names the same three-way split.

**RFC 9537's four methods are *how a server signals*, not the disclosure *state*.** `removal` / `emptyValue` / `partialValue` / `replacementValue` are four encodings of the same fact ("this field was withheld"), not four distinct states a downstream control reasons about. Do not map the four methods onto the state space — the state space is disclosed / redacted / absent-or-undisclosed / unmeasured, and the method is metadata attached to the *redacted* state.

### 2. The protocol itself was replaced — WHOIS sunset, RDAP took over

- ICANN's **Registration Data Policy** (GNSO consensus policy, effective **21 Aug 2025**) makes GDPR-driven redaction permanent and contractual. [icann.org registration-data-policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
  - §9.2 "Redaction Requirements": redact is *defined* as "MUST NOT include the value AND MUST indicate that the value is redacted." Registrant Name/Street/Email/Phone, Tech contacts, and Registry IDs are all redactable; consent-to-publish lets a holder opt back in.
- The prior state was the **Temporary Specification for gTLD Registration Data** (May 2018), rushed in to keep WHOIS alive under GDPR ("Calzone" model, Hamilton memoranda). The 2025 policy is that temporary fix made permanent.
- **Measured signal — the sunset, not a collapse:** the **WHOIS** contract obligation was removed **28 Jan 2025**, and WHOIS query volume fell ~60% in eight months (~122B/month Jan 2025 → ~49B Aug 2025). **RDAP moved the opposite way** — ~7B/month Jan 2025 → ~65B Aug 2025 (~9×), overtaking WHOIS in June 2025. [IETF, "The current state of RDAP"](https://www.ietf.org/blog/current-state-of-rdap/), Andy Newton (ICANN principal engineer)
  - Source caveat on record: the ICANN monthly aggregate data "previously published contained errors made during analysis … and showed RDAP queries to be much lower than previously stated" — the corrected 65B figure supersedes earlier, lower RDAP numbers.
  - *Retracted (2026-08-23, Claude Code cross-check):* an earlier draft of this doc attributed the −60% to RDAP and claimed disclosure was "moving from query-time to published bulk files." Both were wrong — the −60% is WHOIS volume caused by the sunset, RDAP *grew* ~9×, and the bulk-file causal story was an unsourced generalization of the `.gov` CSV observation. Pulled, not re-sourced.

**The engineering meaning:** the distinction thesis is *strengthened* by the correction, not weakened. The world moved off a protocol with **no slot** for "withheld" (legacy WHOIS printed free text) onto one that **gained the slot** (RDAP + RFC 9537's structured redaction) — and query volume followed the protocol that could say the word. Separately, where a registry *does* publish a frozen bulk file (`.gov`'s full-frame CSV in git, sha256-citable), that file is strictly better for a sovereignty instrument than a live query — citable and re-derivable, where a live query is a point-in-time read that can be bot-blocked, rate-limited, or policy-masked (`.gov` RDAP returning 403 "Error 1010" to automated clients). That preference is about *how we sample*, not a claim that the industry is migrating to files.

---

## The authoritative timeline (primary sources)

| date | event | source |
|---|---|---|
| May 2018 | Temporary Specification for gTLD Registration Data (GDPR emergency) | ICANN |
| Mar 2024 | **RFC 9537** — redaction becomes structured | IETF / rfc-editor |
| 28 Jan 2025 | WHOIS contract obligation removed for gTLDs (sunset) | ICANN |
| Jun 2025 | RDAP query volume overtakes WHOIS | IETF blog (Newton) |
| Aug 2025 | **Registration Data Policy** — temporary spec made permanent consensus policy | ICANN |
| Jan→Aug 2025 | WHOIS volume −60% (122B→49B); RDAP +9× (7B→65B) | IETF blog (Newton) |

**The highest-authority bodies on this vector:** IETF REGEXT (the RDAP specification body — [datatracker.ietf.org/wg/regext/](https://datatracker.ietf.org/wg/regext/about/)) and ICANN / GNSO (the governance layer).

---

## The opposition landscape (who does *not* think like us)

This vector has no cartoon villain; it is a collision of two legitimate goods, and naming both is the point.

1. **Privacy regulators (GDPR as counter-force).** The entire redaction shift is GDPR compliance — a *good* force (protects individuals) that *also* degrades public ownership accountability. The tension is real and non-resolvable to one side; it is a seesaw, not a verdict.
2. **Data brokers / WHOIS resellers.** Their product is the now-redacted data; they fight redaction because it kills their commodity, not out of principle.
3. **Privacy/proxy services** (GoDaddy, Namecheap proxying). A *second* redaction layer on top of the registry's own — replaces the holder's data with a forwarding proxy contact.
4. **Bulk collectors** (passive DNS, CT logs, zone-file accumulation). Their appetite is indifferent to redaction — they get the data through another door, so redaction punishes the *legitimate* analyst while leaving the bulk collector untouched.

### The two privacies are opposites (the reality check)

The opposition landscape above flattens two things that must stay separate. **Privacy-for-sale and legitimate redaction are not the same "privacy" — one hides the signal, the other labels the carrier.**

- **Privacy-for-sale** (proxy services, resellers) = *undeclared withholding.* The field shows a fake proxy contact that masquerades as the real one; the real PII still exists (ICANN §6 mandates collection) and is resold. The product IS the deception.
- **Legitimate redaction** (RFC 9537, the RDP, `.gov`'s `_disclose_fields`) = *declared withholding.* The response carries an explicit `"redacted"` member — "a value exists, I am not publishing it, here is how and which field." The withholding is itself the signal.

**The separating test** (ask both, of any withholding):

1. *Does the withholding declare itself?* Proxy: no. RFC 9537 redaction: yes.
2. *Does the security-relevant signal survive?* Proxy: no (obscures who controls the domain). Redaction: yes (lifecycle/status/delegation stay public under §9.1).

**Incentive structure** (read the revenue model, not the words): the privacy-proxy business requires the data to keep existing and the hiding to stay paid, so it is structurally incentivized to keep collecting and to resell. Legitimate redaction is a uniform policy applied to a class — no extractive incentive. **Named, not convicted:** GoDaddy, the largest seller of privacy-as-a-service, is also a co-author of RFC 9537, the standard for *declaring* redaction. The standard is neutral-good (declaring beats not); the product is where the misalignment lives.

**The signal/carrier mapping** (this vector's load-bearing conclusion): the **signal is the lifecycle** — creation, expiry, status, delegation — and §9.1 *requires* it published because it is the security-relevant truth. The **carrier is the human** — name, phone, email — and §9.2 *allows* it redacted because it is the doxxing/harassment surface. **Keep the signal public, withhold the carrier, declare the withholding.** That is Carrier Color Theory written into registration-data governance, and it is the same distinction as an undeclared denial (deny the question exists, attack the asker) versus a declared withholding (admit a value, say you're withholding) — the metacognitive move.

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
