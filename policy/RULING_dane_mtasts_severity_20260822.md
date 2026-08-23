# RULING — DANE / MTA-STS severity + the "sane maximum" doctrine

**Date:** 2026-08-22 · **Decided by:** Carey · **Recorded by:** Hermes · **Repo:** resolution-scope
**Status:** RULED (closes the spec §5 sub-decision)

---

## 1. The decision (CORRECTED 2026-08-23 — see §8)

1. **MTA-STS and DANE are NOT the same control layer — this was the error.** They guard the same
   *hop* (mail server → mail server) against **two different attacks at two different layers**:
   - **MTA-STS** = the *enforcement* control against **plaintext downgrade** (STARTTLS stripping).
     Unilaterally deployable (CA/Web-PKI, RFC 8461 explicitly does NOT require DNSSEC). Missing it
     leaves a direct, common interception surface → **High**.
   - **DANE** = the *pinning* control against **certificate substitution / rogue-CA** (DigiNotar-
     class). Layered on top of TLS (which STARTTLS/MTA-STS already provides), and gated on DNSSEC.
     Missing it means "TLS but unpinned" — a rarer, higher-bar attack → **Low**.

   The prior draft claimed "same threat, same level, both Medium." That collapsed *enforcement*
   and *hardening* — the exact distinction the severity ladder already encodes (High = "absent
   enforcement with a direct interception surface"; Low = "hardening absent (TLSA) or a
   precondition gap"). **The code's original split (MTA-STS=High, DANE=Low) was correct.**

2. **The dollar-dominant threat is spoofing, not interception.** FBI IC3: BEC = $55.5B exposed
   (2013–2023), the "The $55 Billion Scam" — and that's *impersonation → wire fraud*, owned by
   SPF/DKIM/DMARC. In-transit interception is real but covert and unmeasured (no clean dollar
   figure — which is itself a truth we disclose, not a gap we paper over). So:

   | Severity | Weight | Controls | Threat class |
   |---|---|---|---|
   | High | 3 | DNSSEC, SPF, DKIM, DMARC, **MTA-STS** | spoofing/forgery + in-transit downgrade enforcement |
   | Low | 1 | **DANE**, CAA, CDS/CDNSKEY | pinning / hardening / hygiene |
   | Medium | 2 | *(deployed-but-not-enforcing states, e.g. p=none, mode:testing)* | |

3. **Deployability is a separate axis (unchanged, and it now *agrees* with the severity).** DANE
   is structurally unavailable on Google Workspace — the TLSA record lives in Google's MX-host
   zone. That is a **disposition** fact (can-you-deploy-it), carried by the `tlsa_zone` field, not
   a severity fact. Keeping DANE **Low** in severity means the unfixable gap does not over-penalize
   — which is the same direction as the deployability reality, not against it.

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

- **Severity re-ruling CORRECTED (2026-08-23):** the original "MTA-STS 3→2, DANE 1→2" was
  **wrong and never applied to code**. The code carries (and correctly keeps) **MTA-STS=High (3),
  DANE=Low (1)**. See §8 for the correction. Weights follow automatically from Severity — the code
  was already correct; nothing needed changing.
- **CORRECTED (Claude Science, 2026-08-22) — no `provider-gated` verdict.** The original ruling
  carded a "provider-gated" *disposition*. That was wrong: it would assert a **business
  relationship** (ownership / "a third party is blocking you") that DNS cannot observe. The only
  observable is **whether the TLSA name shares the scanned domain's registrable domain** — a
  name-string fact, not an ownership fact. Ship it as a **field** (`tlsa_zone:
  same_registrable_domain | different_registrable_domain`), never a verdict; the narrative then
  says "the TLSA name lies outside this domain's own zone — DANE requires either that operator
  publishing TLSA or moving MX to a host you control." True without asserting who owns what.
- **The real finding (Claude Science, measured): `dhs.gov` survives the gate.** MX host
  `mxa-00376703.gslb.gpphosted.com`, host zone `gpphosted.com` **IS signed**, so `DnssecRequired`
  never fires — and `dhs.gov` reports a measured DANE absence that **only Proofpoint can fix**.
  Identical "true finding attributed to the wrong party" shape as `it-help.tech`, but invisible to
  the DNSSEC precondition because the precondition is *satisfied*. The discriminating pair is
  `dhs.gov` vs `cia.gov` (both signed, both no TLSA — one is the operator's own choice, one is
  not), and **only the out-of-zone field separates them.** This is the item to card, not the
  gateway.
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

## 5. Site copy vs repository record (Carey, 2026-08-22)

Two tiers, on purpose. **Everything is kept informationally** in the repo (this ruling, the
doctrine docs, the RFC citations) — the long form is the durable record. **The public site gets a
short, honest line, not an essay.** A DANE finding on the report says the one true thing:
"not deployable through your provider (Google publishes no TLSA) — this one's not on you" — and
links to the record for anyone who wants the depth. Doctrine: the site demonstrates; the repo
preserves. Never put the long explanation on the page.

## 6. Carded (future, not executed)

- **"Escape trick" publish-later** — the self-hosted MX + DANE gateway on top of Workspace (the
  inbound/outbound gateway path in §3) is a real, Google-supported technique. Carey floated
  publishing it as a how-to ("everybody wants this, they're paying mail hardeners a fortune —
  here's how to do it yourself"). Carded as a *possible* future article, NOT site content, NOT a
  shipped feature. It is the one legit path to DANE on Google, and it is deliberately not the
  default recommendation (it installs a permanent operational liability).
- **`tlsa_zone` field (engine) — NOT a verdict.** The measured zone-cut comparison. **Final
  shape (converged 2026-08-23 by SciSpace + Claude Science): FOUR values** — `same_zone`
  (MX host's zone apex == domain's zone apex), `descendant_zone` (MX host in a subdomain zone of
  the scanned domain — still under the owner's control, e.g. `amazon.com` → `amazon-smtp.amazon.
  com`), `foreign_zone` (MX host in a zone that is NOT a descendant — someone else's, e.g.
  `microsoft.com` → `protection.outlook.com`), `zone_unmeasured` (the SOA walk failed — honest
  non-classification). Emits a fact the narrative can use, never an ownership claim. This is the
  corrected form of the earlier "provider-gated disposition" (retracted — see §3).
- **dhs.gov out-of-zone attribution (engine)** — the real defect the measurement found. When the
  MX-host zone is signed (so `DnssecRequired` never fires) but the TLSA name sits in a *different*
  registrable domain, the measured DANE absence must be attributed to the mail operator, not the
  scanned domain. Requires the `tlsa_zone` field to be expressible. Discriminating pair:
  `dhs.gov` (Proofpoint — not its choice) vs `cia.gov` (self-hosted — its own choice).

## 7. Seal decision — derived from the seal's foundation (2026-08-23)

**Does `tlsa_zone` enter the seal? YES — SEAL_SCHEME v2 → v3.**

Derived, not preferred. The seal's own contract (seal.rs) sorts every datum into two buckets:
- **Sealed** = primary measurements + the verdicts drawn from them (domain, engine, resolver
  identity, the 8 dispositions + tri-states).
- **Excluded** = run metadata (`session_id`, `timestamp` — about *the run*, unrecoverable by a
  future reader) and derived views (the risk-weighted score — recomputed *from* sealed data).

`tlsa_zone` is neither excluded thing: it is a **primary DNS measurement** (compare
`zone_apex_of(mx_host)` to `zone_apex_of(domain)`), a fact about the domain's mail architecture,
not about the run, and not derived from other sealed fields. Therefore it is sealed, same category
as a disposition.

**Negative proof:** unsealed, `dhs.gov` and `cia.gov` seal byte-identically while their verdicts
mean opposite things (operator's gap vs own gap). Flip the field, the seal doesn't flinch — the
*attribution* becomes silently tamperable, a receipt that can be altered, which is the exact
failure the seal exists to prevent. The seal's purpose (tamper-evidence over verdict *meaning*)
requires the field to be bound.

**Note (field naming, converged 2026-08-23 — SciSpace + Claude Science):** the honest name keys
on what is *measured*, and the measured axis is the **SOA zone-cut hierarchy**, not "registrable
domain." SciSpace's second opinion confirmed RFC 7672 §2.2.3 reinforces the zone-cut (the TLSA
lookup key `_25._tcp.<mx_hostname>` lives in the MX host's zone by delegation — zone-cut directly
answers "who must publish for DANE to work?"), and that "registrable domain" would import the
Mozilla PSL and its multi-level-ccTLD / vanity-gTLD / military-subdomain edge cases. The field is
**four-value**: `same_zone` / `descendant_zone` / `foreign_zone` / `zone_unmeasured` — the
`descendant_zone` split is load-bearing (`amazon.com`'s MX host IS its own zone apex inside
`amazon.com`; a two-value field would call Amazon's own mail host "foreign"). The four enum
variant NAMES enter the seal (same as every disposition — pinned by
`disposition_variant_names_are_stable`).

## 8. CORRECTION — the severity re-ruling was wrong, and never applied (2026-08-23)

**Retracted: "MTA-STS/DANE both Medium." The code was right all along.**

- **What happened:** Carey asked "aren't MTA-STS and DANE the same thing?" I affirmed "yes, same
  threat → same severity," and recorded "both Medium" as a ruling in this file and in the score
  spec §5 — **without ever applying it to code, and without checking the "same thing" premise.**
- **Why the premise was false:** they guard the same *hop* against *different attacks at different
  layers*. MTA-STS = enforcement vs **plaintext downgrade** (common, deployable, RFC 8461 needs no
  DNSSEC). DANE = pinning vs **cert-substitution/rogue-CA** (rare, DNSSEC-gated, layered on top of
  TLS). The severity ladder already distinguishes exactly this: High = "absent enforcement, direct
  interception surface"; Low = "hardening absent (TLSA) / precondition gap."
- **Two independent arguments converge on High/Low:**
  1. *Layer distinction* (above): enforcement ≠ pinning-hardening.
  2. *Attainability* (Claude Science): moving MTA-STS DOWN weakens the one mail-TLS control that is
     unilaterally deployable; moving DANE UP strengthens one most domains structurally cannot
     deploy. Severity must not over-penalize an unfixable gap.
- **Measured on `ef0abd5`:** `MtaStsDisposition::RecordAbsent → Severity::High` (truth_chain.rs:527),
  `DaneDisposition::NotConfigured → Severity::Low` (:471), `DaneDisposition::DnssecRequired →
  Severity::Low` (:495). The code never changed.
- **Failure shape (recorded as #11):** *agent inference recorded as user ruling.* I converted
  Carey's question + my affirmation into "Carey ruled both Medium," then presented it as settled in
  summaries. The control: a ruling requires an explicit "rule it" from Carey, and must be applied to
  code in the same session — a doc edit without a code edit is a contradiction left behind.

**Net:** MTA-STS=High, DANE=Low. Both stay exactly as the code has them. No code change; this file
and the spec §5 are reverted to match. The score is unblocked on the *severity* axis.
