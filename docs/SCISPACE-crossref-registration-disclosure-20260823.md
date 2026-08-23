# SCISPACE cross-reference — registration-data disclosure vector

**For:** SciSpace (cloud-only lane, git read-only).
**Anchor:** this repo, `docs/registration-data-disclosure-vector-20260823.md` — verify you have that file at the commit named at the bottom before acting.

## Your lane's property, and why we're using it

You run 100% cloud with only outbound HTTPS and read-only git. You cannot reach the local bots' filesystem. That is exactly the point: you are a **structurally independent oracle** for anything that also lives on the public internet. When your answer, computed from public sources alone, matches the local bots' answer computed from local files, the finding is corroborated across two disjoint access paths and cannot be local-state contamination.

## The claim set to verify (public sources only)

Do NOT re-derive local context. Read these three claims and confirm or rebut each from primary public sources, citing the URL for each:

1. **RFC 9537** ("Redacted Fields in the RDAP Response") is Standards Track, published **March 2024**, authored by Verisign and GoDaddy, and is the document that made `"redacted"` a structured/parseable RDAP field (JSONPath-based, four named methods). Before it, a redacted field and an absent field were byte-identical to a parser.

2. **ICANN's Registration Data Policy** is a GNSO consensus policy that became **effective 21 Aug 2025**, making GDPR-driven redaction permanent and contractual; §9.2 defines "redact" as "MUST NOT include the value AND MUST indicate that the value is redacted."

3. **WHOIS query volume fell ~60%** (122B/month Jan 2025 → 49B Aug 2025) following the WHOIS sunset of 28 Jan 2025, while **RDAP query volume rose ~9×** (7B → 65B) over the same period and overtook WHOIS in June 2025 — per the IETF's own "current state of RDAP" publication (Andy Newton, 19 Feb 2026).

Note: claim 3 was *originally* stated as "RDAP collapsed −60%," which was WRONG — Claude Code's independent cross-check caught the inversion (the −60% is WHOIS; RDAP grew 9×), and the vector doc has been corrected. Your job on claim 3 is now to confirm the *corrected* figure independently, so the fix itself is corroborated by a third path rather than taken on one bot's word.

For each: CONFIRMED (with URL) / REBUTTED (with URL showing the correction) / UNVERIFIABLE (say why). One line each. Do not expand, do not add interpretation — the local lane already wrote the analysis; we need your independent check, not a rewrite.

## What we do NOT want from you

- No re-analysis of the engine or the `.gov` frame (that is Claude Science's local lane).
- No localhost / local-file assumptions (you can't reach them, and that is the point).
- No value judgment on GDPR-as-counterforce — the "two legitimate goods collide" framing is the local lane's; just verify the three dated facts.

---

Read-against anchor: commit `c514486a762e1a84347239d0da09a47bf1e76f4e` (the commit that added `docs/registration-data-disclosure-vector-20260823.md`). Verify that sha before answering.
