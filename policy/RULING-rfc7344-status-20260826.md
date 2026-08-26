# RULING — RFC 7344 status: PROPOSED STANDARD (settled, four-bounce, do not re-litigate)

**This fact thrashed four times in one session.** It is now settled by three independent
authorities read first-hand. Anyone tempted to change it again must first disprove all
three, not just re-read the frozen header.

## The three authorities (all read first-hand 2026-08-26)

1. **rfc-index.xml `<current-status>` for RFC 7344 = `PROPOSED STANDARD`**
   (`~/Documents/rfc-corpus/rfc-index.xml` — the RFC Editor's machine-readable current
   status, which is the authority Science already ruled "status comes from the index").

2. **IETF Datatracker API** (`https://datatracker.ietf.org/api/v1/doc/document/rfc7344/`):
   `std_level` resolves to `ps` = **Proposed Standard**.

3. **RFC 8078 §6.1, verbatim** (the mechanism, not an inference):
   > "Experience has shown that CDS and CDNSKEY are useful in the deployment of DNSSEC.
   > [RFC7344] was published as Informational; **this document elevates RFC 7344 to
   > Standards Track.**"

## Why the record kept thrashing (the trap, named)

RFC 7344's own **document header** still reads:

> "This document is not an Internet Standards Track specification; it is published for
> informational purposes."

That text is **frozen at publication (2014)**. The RFC Editor never retro-edits a
published RFC's header — so every "Informational" string in the info page and the document
body is that frozen 2014 text, not a statement of current status. Claude Code's
`e9ab562` counter-correction read the frozen header (and the info page's 38 "Informational"
hits) and concluded "current status is Informational, Updates never changes category."

That inference is correct in general but **wrong here**, because RFC 8078 does not merely
"Update" RFC 7344 — it has a dedicated IANA-considerations subsection (§6.1) that
*explicitly elevates it*. The info page's 38 "Informational" hits sit alongside **1
"Proposed Standard"** — the current-status line. Reading the count without the discriminator
is the same "grep the producer, not the representation" failure as `POST`→postgres and
`CDS`→ECDSA.

## The precise, correct statement

- RFC 7344 was **published Informational** (2014).
- RFC 8078 §6.1 (2017) **elevated it to Standards Track** (Proposed Standard maturity).
- RFC 9615 (2024) and RFC 9975 (2026) further update it.
- Current status: **Proposed Standard**.

## The load-bearing fact that is unchanged by any of this

RFC 7344 §6 says the parental agent **SHOULD** use the CDS/CDNSKEY RRset — a SHOULD, not a
MUST. That is what makes publication *non-binding on the parent*, and it is true whether
the document is Informational or Proposed Standard. Every version of this string, correct
or not, agreed on that; it is not the point under dispute and must not drift.

## The rule, sharpened

**An RFC's status is read from the index or the Datatracker — never from the document
header, and never inferred from an "Updates:" relationship.** A frozen header records
status at publication; an explicit elevation (§6.1 of an updater) changes it. When in
doubt, the Datatracker `std_level` field is the single most authoritative signal.
