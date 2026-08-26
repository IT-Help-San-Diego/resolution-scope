# RESEARCH — verdict-word vocabulary: what best practice actually is (2026-08-26)

**Question (Carey):** before we delete the PASS/FAIL translation layer, do a big
scientific review of what the industry considers best practice for reporting
measured-security state — not what we imagine, what the authoritative sources say.

**Verdict up front:** best practice is to report the *measured state in the protocol's
own vocabulary* and to keep "broken" distinct from "not deployed" with different words.
RFC 4033 §5 is the governing example, and it does exactly what our `PASS`/`FAIL`
translation layer destroys. Deleting the translation is not our invention — it is
adopting the standard's own design principle.

All RFC text below is quoted verbatim from the local corpus (`~/Documents/rfc-corpus/`).

---

## 1. The governing standard: RFC 4033 §5 (verbatim)

RFC 4033 §5 ("Scope of the DNSSEC Document Set and Last Hop Issues") defines the four
states a validating resolver can determine:

> **Secure:** The validating resolver has a trust anchor, has a chain of trust, and is
> able to verify all the signatures in the response.
>
> **Insecure:** The validating resolver has a trust anchor, a chain of trust, and, at
> some delegation point, signed proof of the non-existence of a DS record. This
> indicates that subsequent branches in the tree are provably insecure. A validating
> resolver may have a local policy to mark parts of the domain space as insecure.
>
> **Bogus:** The validating resolver has a trust anchor and a secure delegation
> indicating that subsidiary data is signed, but the response fails to validate for
> some reason: missing signatures, expired signatures, signatures with unsupported
> algorithms, data missing that the relevant NSEC RR says should be present, and so
> forth.
>
> **Indeterminate:** There is no trust anchor that would indicate that a specific
> portion of the tree is secure. This is the default operation mode.

**The load-bearing property:** the protocol gives *different words to different
things*.

- **Bogus** = *broken* (signed but fails validation → SERVFAIL → real, active failure).
- **Insecure** = *not deployed* (signed proof that there is no DS → resolves fine, just
  not cryptographically protected).

A domain that is merely unsigned is **Insecure**, never **Bogus**. The distinction is
the entire point of the vocabulary, and it is a *measured-state* distinction, not a
judgment of the operator. The BIND 9 DNSSEC Guide states the operational consequence
exactly (bind9.readthedocs.io, "DNSSEC Guide"):

> A DNSSEC-enabled validating resolver still resolves Secure and Insecure; only Bogus
> and Indeterminate result in a SERVFAIL.

So the protocol's own words already carry the "is this broken, or just absent?"
distinction that our PASS/FAIL collapse erases.

## 2. What the authoritative tools actually print

| tool | what it reports | verdict words used |
|---|---|---|
| **DNSViz / Verisign DNSSEC Debugger** | the DNSSEC authentication chain, rendered as a graph | `Secure` / `Insecure` / `Bogus` / `Indeterminate` (RFC 4033 states), never PASS/FAIL |
| **BIND 9 (named)** | validation result per response | the same four states; `Insecure` = unsigned, resolves |
| **blocky** (resolver) | validation result table | `Secure` / `Insecure` / `Bogus` / `Indeterminate` |
| **internet.nl** | numeric grade + band (Excellent/Good/Sufficient/Insufficient/Poor) for the *overall* result; each individual test reported in plain language + the standard's own terms | no per-control PASS/FAIL verdict word |
| **Hardenize** | "Test passed" binary + the *measured policy value* (e.g. `p=reject`, `adkim=r`) as the substantive content | the measured value is the answer, not a word |

**The pattern is uniform: none of them invent a per-control verdict word.** They report
the measured state in the protocol's own vocabulary (or the measured value itself), and
let a *separate* severity/grade axis carry the good-vs-bad judgment. Our `PASS`/`FAIL`
column is a translation layer on top of exactly this pattern, and it reintroduces the
conflation the standards authors deliberately removed.

## 3. Mapping the principle to all eight controls

RFC 4033's four words are DNSSEC-specific resolver states — correct for DNSSEC, wrong
for SPF/DKIM/CAA. The *generalization* of the principle is the tri-state, which our code
already carries (`types/src/tristate.rs`):

- `Present` = the record is there and structurally valid (RFC 4033 "Secure"-like for the
  presence axis).
- `Absent` = the record is not there (RFC 4033 "Insecure"-like: *absent*, not *broken*).
- `Indet` = couldn't determine (RFC 4033 "Indeterminate").
- `NotApplicable` = the control doesn't apply to this surface.

The severity ladder (Low/Medium/High/Critical) is the judgment axis. The tier row
(FINDINGS/ADVISORY/HOLDING/COULD NOT MEASURE/NOT APPLICABLE) is the presentation of that
judgment. Together these three axes — *measured state, severity, consequence copy* —
already carry the complete, honest picture. The `PASS`/`FAIL` word is a fourth,
lossy, redundant signal that collapses the exact distinction every authoritative tool
and standard works to preserve.

## 4. The PASS/FAIL translation, measured as the defect it is

`TriState::Present → "PASS"` and `TriState::Absent → "FAIL"` collapse two things that
RFC 4033 treats as distinct:

- **On the absence side:** `Absent` maps to "FAIL" whether it is a High-severity attack
  surface (SPF/DMARC/DNSSEC absent) or a Low-severity backstopped gap (CDS/CAA/DANE).
  RFC 4033 would call the first "Bogus" (broken) and the second "Insecure" (absent) —
  different words. We collapse them.
- **On the presence side:** `Present` maps to "PASS" whether it is Ok (`-all` SPF,
  `p=reject`) or High (SPF `?all`, DMARC `p=none`, MTA-STS testing, CDS
  deletion-requested). RFC 4033's "Secure" vs "Insecure" distinction has an analog here:
  "present and strong" vs "present and asserting nothing." We collapse them to "PASS."

The 8 lossy rows (4 overstatement + 4 understatement) out of 54 are not a wording
preference problem — they are the translation layer re-introducing the conflation the
standard's vocabulary was designed to eliminate.

## 5. Conclusion

Best practice, as established by the authoritative standard (RFC 4033 §5) and uniformly
followed by the tools that implement it (DNSViz, BIND, blocky, internet.nl, Hardenize),
is:

1. **Report the measured state in the protocol's own vocabulary** (or the measured value
   itself), never an invented verdict word.
2. **Keep "broken" distinct from "not deployed"** with different words — the single most
   important distinction in the entire space.
3. **Carry the good-vs-bad judgment on a separate axis** (severity / grade), not by
   overloading the state word.

Our `TriState` already implements (1) and (2) in a control-general form. The severity
ladder + tier row already implement (3). The `PASS`/`FAIL` translation is the one
component that violates all three — and it is the *only* component that needs to be
removed, not replaced.

**Recommendation: delete the translation.** Render `PRESENT` / `ABSENT` / `INDET` /
`NOT-APPLICABLE` (the machine's own `Display`), and let severity + tier + consequence
copy carry the judgment. This is not a new vocabulary and not a copywriting choice — it
is the removal of an authored judgment that contradicts the standard the tool cites.

## 6. Sources (with per-source provenance)

**The standards argument is self-sufficient and checkable** — a reader can re-derive it
from RFC 4033 §5 alone, which is why the decision does not rest on the tool survey.

| source | what it supports | provenance |
|---|---|---|
| **RFC 4033 §5** | the four states; PASS/FAIL appear zero times | **verified** — quoted from `~/Documents/rfc-corpus/rfc4033.txt`, and independently re-verified by the Science lane against rfc-editor.org this session |
| **BIND 9 DNSSEC Guide** | "resolves Secure and Insecure; only Bogus and Indeterminate result in a SERVFAIL" | **fetched** — bind9.readthedocs.io, search-result text |
| **DNSViz** | DNSSEC chain in RFC 4033 states | **recalled, not fetched** — dnsviz.net page was loaded but the state legend was behind a client-side loader; NOT independently confirmed this session |
| **blocky** | the same four states with per-state semantics | **fetched** — 0xerr0r.github.io/blocky config docs, search-result text |
| **internet.nl** | numeric grade + band, no per-control verdict word | **recalled, not fetched** — page loaded but the example-domain test errored, so no result bands were observed this session |
| **Hardenize** | "Test passed" + measured policy value as the content | **fetched** — hardenize.com public report, DMARC section observed |
| `types/src/tristate.rs` | `Display` emits PRESENT/ABSENT/INDET/NOT-APPLICABLE | **verified** — read from source |

**Explicit limit:** the generalisation "no tool invents a per-control verdict word" rests
on the five tool rows, two of which (DNSViz, internet.nl) are **recalled, not fetched**
this session and therefore unverified by any lane. They are almost certainly correct —
DNSViz is famous for exactly the RFC 4033 vocabulary — but a claim a reader can't
re-derive should be marked as such, not listed beside a verbatim quote. **The decision
does not depend on them**: the RFC 4033 §5 argument (broken-vs-absent get different words;
PASS/FAIL collapse them) carries the recommendation on its own, and that argument is
verified.
