# SCISPACE cross-reference — registration-data disclosure vector

**For:** SciSpace (cloud-only lane, git read-only).
**Anchor:** this repo, `docs/registration-data-disclosure-vector-20260823.md` — verify you have that file at the commit named at the bottom before acting.

## Your lane's property, and why we're using it

You run 100% cloud with only outbound HTTPS and read-only git. You cannot reach the local bots' filesystem. That is exactly the point: you are a **structurally independent oracle** for anything that also lives on the public internet. When your answer, computed from public sources alone, matches the local bots' answer computed from local files, the finding is corroborated across two disjoint access paths and cannot be local-state contamination.

## The claim set to verify (public sources only)

Do NOT re-derive local context. Read these three claims and confirm or rebut each from primary public sources, citing the URL for each:

1. **RFC 9537** ("Redacted Fields in the RDAP Response") is Standards Track, published **March 2024**, authored by Verisign and GoDaddy, and is the document that made `"redacted"` a structured/parseable RDAP field (JSONPath-based, four named methods). Before it, a redacted field and an absent field were byte-identical to a parser.

2. **ICANN's Registration Data Policy** is a GNSO consensus policy that became **effective 21 Aug 2025**, making GDPR-driven redaction permanent and contractual; §9.2 defines "redact" as "MUST NOT include the value AND MUST indicate that the value is redacted."

3. **RDAP query volume collapsed ~60%** between January 2025 (~122B monthly queries) and August 2025 (~49B), per the IETF's own "current state of RDAP" publication.

For each: CONFIRMED (with URL) / REBUTTED (with URL showing the correction) / UNVERIFIABLE (say why). One line each. Do not expand, do not add interpretation — the local lane already wrote the analysis; we need your independent check, not a rewrite.

## What we do NOT want from you

- No re-analysis of the engine or the `.gov` frame (that is Claude Science's local lane).
- No localhost / local-file assumptions (you can't reach them, and that is the point).
- No value judgment on GDPR-as-counterforce — the "two legitimate goods collide" framing is the local lane's; just verify the three dated facts.

---

Read-against anchor: commit `__ANCHOR__` (the commit that added `docs/registration-data-disclosure-vector-20260823.md`). Verify that sha before answering.
