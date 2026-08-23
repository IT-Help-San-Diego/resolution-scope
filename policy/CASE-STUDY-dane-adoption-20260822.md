# CASE STUDY (tracking) — DANE adoption: the arc into the American mailbox

**Status:** OPEN — deliberately *not* backed off. This is a living tracker, not a snapshot.
**Date opened:** 2026-08-22 · **Recorded by:** Hermes · **Repo:** resolution-scope

---

## Why this is tracked, not closed

DANE is the one control where "the world won't let you go further yet" is *movable*. Unlike a
personal ceiling (a solo operator can't be their own CA), DANE's ceiling is a **vendor choice**,
and vendor choices migrate. The point of the case study is to **watch the migration and tell the
truth about it as it moves** — so the instrument's `provider-gated` verdict is never a static
excuse, but a live reading of an arc in progress.

## The measured arc (2026-08-22 baseline)

| Provider | Inbound DANE | Direction |
|---|---|---|
| Proton | ✅ since 2019 | first mover |
| Microsoft (Exchange Online) | ✅ GA end-2024 | crossed over |
| Google (Gmail/Workspace) | ❌ still absent | the holdout |

The story is not "Europe vs America" — it's **Google vs the rest of the American stack.** The
line to watch is `smtp.google.com` (and Google's DNSSEC signing of its MX hosts, still
incomplete): the day Google publishes a TLSA, the last major American holdout falls and DANE
stops being "provider-gated" for the largest single chunk of the pie.

## What "don't back off" means, mechanically

1. **Track, don't judge.** Re-measure the provider table on a cadence (quarterly is plenty); the
   disposition follows the measurement, never a hand-held list. This is the "absence in a local
   reference table must never be reported as absence in the world" rule — a provider table is a
   snapshot, not a truth.
2. **The `provider-gated` verdict names the *arc*, not the *failure*.** It says "Google doesn't
   publish TLSA *yet* — Microsoft now does" — so the user reads it as a moving frontier, not a
   dead end. That's the education, and it's why the disposition exists.
3. **The escape trick stays documented** (self-hosted MX gateway) as the always-available path —
   so the honest message is "you can have DANE today, it just costs operational ownership; or
   wait, and your provider will likely ship it." Choice, priced, disclosed.

## Check-in with "our boss the future"

The governing question when the present blocks a good thing is not "what's cheap now" but "what
does the future want." The future wants DANE (Microsoft and Proton already crossed; Google's
holdout is a matter of roadmap, not physics). So the instrument's job is to **keep the question
open and true** — record the state, disclose the ceiling, track the arc — rather than to accept
the ceiling as permanent or to pretend it isn't there. That is what "we check in with our boss
the future" cashes out to, here: the boss is the future, and the future wants the truth kept
current.
