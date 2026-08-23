# DOCTRINE — "No band-aids" (one principle, two ownership branches)

**Date:** 2026-08-22 · **Stated by:** Carey · **Recorded by:** Hermes · **Repo:** resolution-scope

---

## The apparent contradiction

Two stances that look opposite, side by side in the same mind:

1. **seL4 / verification** — "all code is incomplete until all code is validated, and thus all
   patches are just expensive band-aids until code is complete. At that point you only expand."
   Maximalist: validate everything, prove the foundation, eliminate the black box.
2. **DANE / mail gateway** — "stop before perfection." Don't roll your own MX + DANE gateway on
   top of Google Workspace. Accept Google's ceiling, tell the truth about it.

Carey flagged himself as a hypocrite for holding both. **He is not.** The two stances are one
principle with two branches, split only by ownership.

## The resolution — the single principle is "reject band-aids"

| You… | Completion available? | The anti-band-aid move |
|---|---|---|
| **own the foundation** (your code) | yes | **complete it** — validate/prove, never patch |
| **don't own the foundation** (Google's `smtp.google.com`) | no | **still don't patch it** — name the ceiling, tell the truth |

- seL4: the foundation is yours, completion is reachable, so the alternative to a band-aid is
  **completion** (validation, proof).
- DANE: the foundation is Google's, completion is *not* reachable, so the alternative to a
  band-aid is **truth** (the `provider-gated` disposition).

**The key realization that dissolves the "hypocrisy": the mail gateway was never "perfection" — it
was the band-aid in disguise.** A self-hosted MX gateway is a permanent, expensive patch bolted
onto Google's stack, maintained forever, that becomes redundant the instant Google ships DANE. It
is the *same* expensive-band-aid shape the seL4 discipline refuses — except that on Google's stack
you can't reach "complete," so the refusal takes the form of "stop and tell the truth" rather than
"validate and finish."

## The connection to "justice"

The courtroom is the black box wearing a robe: there is **no system** preventing the horrible
thing — no seal, no re-derivable verdict, no validation, no named ceiling. It calls its output
"justice" and offers no receipt. Everything this project builds — proof, seal, truth-chain,
no-band-aids, provider-gated disposition — is the *system* that was missing there: **justice as a
checkable property, not a mood.**

## Convergences (this doctrine touches the others)

- **Sane maximum** ("show perfection as far as the world lets you go") — the truth branch of
  no-band-aids on a foreign foundation.
- **Identity-weighting / measure-the-breeze** — the measurement branch; a band-aid is what you
  reach for when you'd rather patch than measure.
- **More-fair-than-a-judge** — the seal is the receipt the courtroom never issued.

## Rule of thumb (reusable)

Before adding a workaround, ask: **"is this completing my foundation, or band-aiding someone
else's?"** If mine → validate to completion. If theirs → name the ceiling. Never install a
permanent patch on a foundation I can't finish.
