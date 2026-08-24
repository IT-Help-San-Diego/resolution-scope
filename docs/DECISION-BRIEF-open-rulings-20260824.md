# DECISION BRIEF — the four open Resolution Scope rulings (2026-08-24)

> **RESOLVED 2026-08-24** — Claude Science ruled both "definitional" questions,
> and both turned out to have measured answers, not values calls. Items 2 and 3
> below are now **RULED AND LANDED**. Item 1 is engineering (build.rs, no
> ruling needed). Item 4 is a scope call to settle by measuring the N2 rate.
> The "cannot be vectored from data" premise in the original brief was half
> wrong — see the correction note at the bottom.

Prepared by Hermes for the four-mind group (Carey + Claude Science + Claude Code
+ SciSpace). Every RFC claim below is cited to the standard, verified first-hand;
every "cannot be vectored from data" claim is tested, not assumed.

The question Carey asked: **which of the four open decisions can be settled by
data/experiment, and which genuinely require a human ruling?** The honest answer
is that they split into three classes, and "these can't be vectored from data"
is only true of two of the four.

---

## The four items

| # | item | what it is | class |
|---|---|---|---|
| 1 | `engine_version()` provenance | seal binds a static `"0.1.0"` instead of the producing build | **data settles it — just build it** |
| 2 | `+all` → `Critical` + `Absent` | SPF `+all` authorizes everyone but scores full SPF credit | **RFC settles the fact; semantics is a values call** |
| 3 | `SignedNotDelegated` severity | signed-but-no-DS chain sits at Medium | **RFC settles the fact; semantics is a values call** |
| 4 | CDS N1/N2 grading | build "CDS matches parent DS" vs "differs" | **data settles the scope — measure, then decide** |

---

## Item 1 — `engine_version()` is fully vectable; no ruling needed

**The defect:** `engine_version()` (`engine/src/seal.rs:191`) returns
`CARGO_PKG_VERSION`, a static `"0.1.0"`. The seal preimage carries
`engine_version` as the field that says *which engine produced this verdict* —
but two different builds that emit different verdicts both stamp `"0.1.0"`, so
the provenance field cannot distinguish them. Its own doc comment promises a
git-derived version and never got one.

**Why this needs no data and no ruling:** provenance best practice is settled,
and the parent project already does it — `dns-tool-intel` derives its version
from git (`scripts/version.sh` → ldflags at build time), the exact pattern this
comment already gestures at. The only "decision" is *when*, which is scope, not
substance. This is a do-it-right task, not a judgment call.

**Best practice:** wire a git-derived version (describe → semver → ldflags),
matching the parent instrument, so the seal provably binds the producing code.

---

## Item 2 — `+all`: the fact is settled, the score semantics is not

**The settled fact (RFC 7208, verified verbatim):**

- §2.6.3 — a "pass" result is "an explicit statement that the client is
  authorized to inject mail with the given identity."
- §8.3 — a pass means the domain "can now, in the sense of reputation, be
  considered responsible for sending the message."

So `+all` does not fail to authorize — it **affirmatively authorizes the entire
internet** and lends the domain's reputation to every spoofer. It is the one
mail-authentication disposition that makes forgery *succeed* rather than merely
go unblocked. (`KeyMismatch → Critical` is the existing precedent for that tier.)

**What data cannot settle:** whether a deployed-but-inverted control counts as
`Present` or `Absent`. This collides with our own §8 doctrine ("score
deployment, not protection"), which was written for the *non-enforcing* class
(SoftFail/Monitor/NotEnforced — deployed AND functioning, just weak). `+all` is
a different class: deployed but the function is *inverted*. `Present` and
`Absent` diverge catastrophically on exactly this one disposition, and which one
is right depends on what we decide the score *means* — a definition, not a
measurement.

**What data CAN inform it:** how often `+all` appears, and whether it is ever
deployed deliberately. Our own corpus can answer this directly (see the
"measurement I can run" note at the end). But prevalence tunes the *framing*,
not the *ruling* — even one deliberate `+all` would still need the semantics
decided.

**Best practice (leaning):** `Critical` severity is close to forced by §8.3; the
genuine open edge is the tri-state. Two coherent positions, both defensible:
- *Functional* — `Absent` (a record authorizing everyone provides no selective
  authorization; functionally identical to no record, which is already Absent).
- *Literal deployment* — `Present` (a record exists; §8 says we score
  deployment).

---

## Item 3 — `SignedNotDelegated`: the fact is settled, the weighting is not

**The settled fact (RFC 4033 §5, verified verbatim):**

> "Insecure: The validating resolver has a trust anchor, a chain of trust, and,
> at some delegation point, signed proof of the non-existence of a DS record."

A signed-but-not-delegated zone publishes DNSKEY at the child but has no DS at
the parent, so no chain can be built — the resolver treats it as **Insecure**,
which is the same state an *unsigned* zone occupies. From a relying party's
view, signed-not-delegated and unsigned are indistinguishable: both provide
zero authenticated protection.

**What data cannot settle:** the *axis* to weight. Two coherent positions:
- *Relying-party protection* — signed-not-delegated **equals unsigned** (both
  Insecure, both "no protection"), so it should leave the "safe" tier and rank
  alongside `Unsigned` (currently `Absent`).
- *Operator false-assurance* — signed-not-delegated is **worse than unsigned**,
  because the operator signed it *believing they were protected*, and they are
  not. Unsigned at least makes no claim; a signed island makes a false one.
  (This is Carrier Color aimed at the operator: the wrapper says "signed," the
  signal says "unprotected.")

This is a values call about what the instrument's severity *condemns* — a
measurement gap, or a false-confidence gap. Data can tell us how common the
state is, not which of those two is the finding.

**Best practice (leaning):** the RFC's own taxonomy puts this squarely in
"Insecure," and our severity ladder already has `Unsigned` mapped. The cleanest,
most defensible move is to stop treating it as a distinct middle rung and score
it with `Unsigned` — *unless* Carey wants the instrument to specifically call
out the false-assurance case, which is a genuinely novel signal no other tool
reports.

---

## Item 4 — CDS N1/N2 grading: measure first, then decide scope

**The settled fact (RFC 7344 §4.1/§5/§6.2):** CDS *matching* the parent DS =
in-sync (no rollover); CDS *differing* = rollover in progress.

**Why this is a scope call, not a ruling:** there is no taxonomy question — the
RFC defines the semantics. The only question is *is it worth building*, and that
is answerable by data: how often does a scanned domain publish CDS that differs
from its parent DS? If the rollover-in-progress signal is rare, the feature has
low immediate value; if common, it is a real detection worth shipping.

**Best practice:** measure the prevalence of "CDS published but ≠ parent DS"
across the corpus before committing build time. This is the one item that is
*fully* vectable from data.

---

## The measurement I can run now

Two of these four can be moved by measuring our own production corpus
(`domain_analyses`): the `+all` prevalence (item 2) and the
"CDS ≠ parent DS" rollover prevalence (item 4). Both are a single query away
and would turn two "open rulings" into one informed ruling and one scope
decision. Say the word and I run them before anyone spends a decision on them.

---

## Summary — what actually needs a human, and what doesn't

| item | needs Carey? | reason |
|---|---|---|
| `engine_version()` | **no** | engineering best practice, precedent in dns-tool-intel |
| CDS N1/N2 | **no (yet)** | measure prevalence first; data picks the scope |
| `+all` tri-state | **yes** | what does `Present`/`Absent` *mean* for an inverted control |
| `SignedNotDelegated` | **yes** | condemn a measurement gap or a false-confidence gap |

Two of the four genuinely cannot be vectored from data — not because the data is
hard to get, but because they are definitions of what the score means, and no
experiment settles a definition. The other two are either already-settled
engineering or a measurement I can run this session.

---

## Correction note (what the original brief got wrong)

The brief framed items 2 and 3 as "definitional — no experiment settles a
definition." **Science falsified that** on both:

- **`SignedNotDelegated` was never a definition question.** RFC 4033 §5 makes a
  resolver reach the *identical* state (Insecure) for unsigned and
  signed-but-undelegated. The code scored them differently
  (`Unsigned`=Absent/High vs `SignedNotDelegated`=Indet/Medium), so signing
  then failing to delegate scored *higher* than never signing — the
  display-vs-state defect in numeric form (Indet removed DNSSEC's weight 3
  from both sums). **Ruled `Absent` + `High`; the false-confidence reading
  ("the operator signed believing they were protected, and they aren't") goes
  in the consequence text, not the tri-state.**

- **`+all` was never a definition question.** RFC 7208 §8.3 is unambiguous
  (pass = "considered responsible for sending the message"). The sharper test
  than §8's "score deployment" doctrine is *does the record authorize
  anything?* — `+all` authorizes everyone, which conveys exactly the
  information of no record. **Ruled `Absent` + `Critical`; `?all` stays
  `Present`/`High` (RFC 7208 §8.2 — neutral is treated like none).**

- **The `engine_version()` mechanism was misdescribed.** It is
  `env!("CARGO_PKG_VERSION")` (seal.rs:192), *not* a hardcoded `"0.1.0"` —
  the real defect is the version was never bumped and there is **zero
  `build.rs`** in the tree. It IS in the seal preimage (pushed third), so it is
  load-bearing on the integrity layer. Fix = a `build.rs` git-version stamp, a
  build-system addition, no ruling needed.

- **One v3→v4 seal bump carried the whole thing.** `+all`'s split adds a new
  disposition *token* to the preimage (construction change → bump).
  `SignedNotDelegated`'s tri change and the `build.rs` version stamp are value
  changes (no bump of their own).

**Landed 2026-08-24:** `SignedNotDelegated → Absent/High`, `+all →
PositiveAll/Absent/Critical` (with `?all`/no-all remaining `OtherPolicy`),
v3→v4 seal bump, golden seal recomputed (byte-exact verified — Python
reproduced the old v3 golden before pinning the v4 value). Still open: the
`build.rs` version stamp (engineering, cross-compile risk — its own careful
change) and CDS N1/N2 (measure the N2 rate among publishers first).
