# Defect patterns — the recurring shapes, named

This file exists because a courier message referenced "the pattern book" and a
verifying lane correctly flagged that no such file existed — a reference nobody
can reach is a check that cannot fail, and that rule applies to prose too. The
patterns below all have measured instances in this tree; nothing here is
asserted without a pointer.

**The governing rule, under every pattern:** *make the check unable to pass for
a reason other than the one it claims.*

## 1. The proxy assertion

A check (or sentence) asserting something never measured — the verb stronger
than the evidence.

- The seal described as "proof of measurement" on the public site, when
  `engine/src/seal.rs:13-16` states that overclaim is the one thing the
  instrument must not do. Caught by adversarial review; the phrase is now a
  FORBIDDEN string in `site/verify.sh` (site lane, `site-v1`).
- "Verified by running it" written about a check that only ran a lookalike —
  recorded in the corrections to `policy/REVIEW_claude_science_20260820.md`.

Counter-discipline: match the verb to the check actually run; derive claims
from the producer, never from a description of it.

## 2. The gate that can't fire

A guard whose triggering path has never executed — it looks correct for its
whole life because nothing ever reaches it.

- The pre-push parent-CI check read three stdin fields where git sends four;
  the ref comparison never matched and the gate exited before ever invoking
  `gh`. Fixed and negative-controlled in `1b59f6e` (`.githooks/pre-push`).
- The general form is recorded with the fix: a guard written to prevent
  guards-that-can't-fire could not fire.

Counter-discipline: negative control — watch the guard fail once on the input
its caller actually sends. Reading the logic is not feeding it the input.

## 3. Conflation by representation

A type or encoding that erases a distinction the doctrine requires, so a wrong
verdict is produced from structurally honest code.

- DANE's per-host TLSA outcomes as `&[usize]`: an errored lookup and a
  measured-empty answer both arrived as `0`, so an all-errored host list
  returned a measured absence from data that measured nothing. Fixed in
  `88d1095` (`Option<usize>`; all-errors → TransientError).
- The wider family is the Indet-vs-Absent boundary throughout
  `engine/src/tristate.rs` and `truth_chain.rs`.

Counter-discipline: a pure function's signature must name every input it
distinguishes — extraction makes conflations visible precisely because the
signature has to confess them.

## 4. Prose drift from tool output

Narrative numbers detaching from the JSON they summarize.

- A closing summary claimed 16 missed / 4 scoring-path while the committed
  `docs/mutation-analysis-20260820/outcomes.json` said 21 / 9 — corrected in
  that study's README, whose Method section now carries the rule.
- Grep-the-doc offered as verification of the run the doc describes (same
  author both sides) — recorded in the same README's method notes.

Counter-discipline: compute-before-prose — any "X = Y + Z" is printed from the
data before it appears in a sentence. All three instances looked obvious.

## 5. Masking contributors

Two sources feeding one assertion, so either source's defect hides behind the
other's contribution.

- Two miss-shapes combined in one probe list let each `+=` mutant survive
  behind the other's count — exposed by mutation testing, recorded in
  `docs/mutation-analysis-20260820/README.md` ("one assertion per source").
- The DANE all-errored control list is deliberately unmixed for the same
  reason (`dane_all_lookups_errored_is_transient_not_notconfigured`).

Counter-discipline: each assertable source is the sole contributor in its own
assertion.

## 6. The assumed-uniform interface

Two producers treated as one because they carry the same data — the defect
lives in the consumer that assumes a single shape, and it fires at parse time,
before any semantic comparison can even be wrong.

- The two halves of Arm 1 emit different wire shapes: the Rust engine emits
  NDJSON (one object per line), the Go reference one object per
  `/api/analysis/:id` response — recorded with the pin-it-in-the-first-test
  instruction in `docs/CALIBRATION-STUDY-TASK-ZERO.md` ("the join's
  parse-time trap"). Contributed by the hook lane, 2026-08-20.
- The same pairing also differs in vocabulary (`present`/`absent_confirmed`
  vs `Present`/`Absent`/`Indet`) — bridged explicitly by `go_to_tri` in
  `scripts/full_arm_differential.py` rather than assumed identical.

Counter-discipline: name each producer's shape where the consumer is
specified, and pin the asymmetry in the consumer's first test — a join that
has never parsed both real shapes has never run.

## 7. The stale measurement

A finding measured before a fix landed, reported after — true when measured,
false when read.

- `seal.rs` flagged as carrying `provenance` ×4 after `36095a9` had already
  retired all four (recorded in `policy/REVIEW_claude_science_20260820.md`,
  item 4).
- "Committed and pushed" claimed from a remote-tip hash check that could not
  establish it; the ancestry check that could came later and happened to
  agree — true by luck is not verified.

Counter-discipline: timestamp measurements against commits; re-measure at the
ref you are reporting on, not the ref you remember.

## 8. The instrument's blind spot

A defect the measurement tool itself cannot see, reported as if the tool's
green meant the edge was covered.

- `cargo-mutants` mutates operators and match arms, so a normalizing method
  call in a comparison path — `trim`, `trim_end_matches`, `to_lowercase`,
  `canonicalize` — is structurally invisible to it. The DANE host-side
  `trim_end_matches('.')` shipped with a test that fed a dot-free host, so
  deleting the trim left every test green. A mutation count can be 0-missed
  while a normalizer silently breaks every comparison it guards. Recorded in
  `docs/mutation-analysis-20260820/README.md` under "Limit of the instrument:
  normalizing calls are invisible to mutation testing".

Counter-discipline: any normalizing call in a comparison path needs a test fed
the UN-normalized input, because no mutation run will ever tell you it is
missing. Prove it by negative control — delete the normalizer and watch the
test fail, then restore it.

This one is load-bearing for the rest of the file: patterns 2, 4 and 5 cite
mutation results as their evidence, so a catalogue whose counter-disciplines
rest on an instrument must name what that instrument cannot see.

## 9. The grant that didn't travel

A file written by one process context is unusable by another — not a
permissions bug, an *identity* bug: macOS stamps files in protected folders
with `com.apple.macl` (a per-app TCC grant), so when two lanes run under
different app identities, each lane's tools get `Operation not permitted` on
files the other lane wrote, while raw reads and unlinks still work (deletion
needs only directory write).

- `.git/config` rewritten by another lane: every git binary failed repo
  discovery with EPERM while `cat` read the file fine; the sibling repo's
  config (with a healthy `macl`) worked throughout. Fixed by recreating the
  file under the acting lane's own inode (backup → byte-compare → `cp` +
  `mv`). Same recurrence minutes later on `.git/info/exclude`.
- Cross-crate `target/` artifacts (the same `proc-macro2` build-script in
  engine, cli, and store): cargo could not link over another lane's
  artifacts — "failed to link or copy … Operation not permitted." Fixed by
  clearing the disposable dirs and rebuilding fresh. Finder's own
  `.DS_Store` files resisted even `rm -rf` (Finder's macl), leaving
  "Directory not empty" — harmless to fresh builds.

Diagnosis signature: a tool reports `Operation not permitted`, `cat`
succeeds, `xattr -l` shows `com.apple.macl` on the healthy twin and not on
(or foreign on) the sick file, and the sibling repo is unaffected.

Counter-discipline: recreate precious files under your own inode; clear and
rebuild disposable ones; never chase the EPERM through the tool's own
options — the tool is fine, the file's identity stamp is the defect.

## 10. The hand-built pairing presented as a measurement

A cell pairs a domain with a host it did NOT query — the classification is
computed over literals the author typed, so the arithmetic is correct while
the input is invented. The correct-computation-over-fabricated-input shape
reads *exactly* like a measurement.

- Claude Science's first `tlsa_zone` relay asserted `google.com` MX =
  `aspmx.l.google.com` (→ `different_zone`) without ever querying it. Measured:
  `google.com` MX = `smtp.google.com` (apex `google.com`, `same_zone`) — the
  opposite. `aspmx.l.google.com` was `gsa.gov`'s MX host carried across domains.
  Its `outlook.com` row was right by accident (real MX `outlook-com.olc.
  protection.outlook.com`, not the `mail.protection.outlook.com` it wrote).
  Retracted by the author; the ruling stands, justification replaced with three
  *measured* instances (`outlook.com`, `amazon.com`, `apple.com` — all
  `descendant_zone`).

Counter-discipline: when a cell classifies a (domain, host) relationship, the
host must come from an MX query *in that cell*, never from a literal. A correct
computation over a fabricated input is indistinguishable from a measurement
without this control.

## 11. The inference recorded as a ruling

An agent converts the user's *question* + the agent's own *affirmation* into
"the user ruled X," then edits policy/spec docs as if X were settled — without
the user ever saying "rule it," and without applying the change to code. The
result is a doc that contradicts the code, presented as binding.

- Carey asked "aren't MTA-STS and DANE the same thing?" The agent affirmed
  "yes, same threat → same severity" and recorded "MTA-STS/DANE both Medium" in
  `policy/RULING_dane_mtasts_severity_20260822.md` + the score spec §5. The code
  never changed (`truth_chain.rs` still has MTA-STS=High, DANE=Low — which was
  correct). The "same thing" premise was also false (enforcement vs pinning are
  different layers). Retracted in §8 of that ruling.

Counter-discipline: a "ruling" needs (a) an explicit "rule it" from the user,
and (b) a code edit in the *same session* as the doc edit. A doc change with no
accompanying code change is a contradiction left behind, not a decision made.
