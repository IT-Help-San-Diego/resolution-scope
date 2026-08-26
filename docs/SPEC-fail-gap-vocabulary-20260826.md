# SPEC — severity-keyed verdict word (FAIL/GAP on absence; distinct word on Present-above-Ok)

Status: **FILED, CONDITIONAL — the DECISION NEEDED was withdrawn as mis-posed (see §8
addendum). This document activates on an explicit Carey ruling — his word is sufficient
by itself, the way every severity ruling in this repo was made on argument and source;
measured reader-comprehension evidence would strengthen the case but is not a
precondition (an earlier version of this line overstated that gate — corrected
2026-08-26). Any activation must fix BOTH collision directions — the FAIL overstatement
AND the PASS understatement (see §2). Nothing ships without the ruling.**
Written 2026-08-26 (claude-code lane), commissioned by Carey's scope answer: "whatever
will give as much information to Hermes as possible and the rest of the team to finally
make a decision." One proposal, one document, per the ledger's own rule
(`policy/LANES.md` @6fa75e9 entry: "a PAIRED word+score change … should be specced as
one document if Carey wants it").

## 1. The problem in one frame

`TriState::Absent` renders as the word **FAIL** on every report surface, for every
control, at every severity. A Low-severity absence — the concession class the severity
ladder itself created so that "an unfixable gap is not over-penalized"
(`policy/RULING_dane_mtasts_severity_20260822.md`) — therefore carries the same verdict
word as a High-severity one. The row Carey kept hitting read:

```
LOW  CDS/CDNSKEY  FAIL  not published — zone exists, no CDS/CDNSKEY
```

Two vocabularies collide on one line: `LOW` (the ladder saying "concession") and `FAIL`
(the word saying "defect"). The word is produced by exactly three tri→word maps:

- `engine/src/report.rs:92` (`fn row`, engine flat table)
- `cli/src/render.rs` `tri_icon()` (report, summary, HTML)
- `cli/src/tui.rs` `state_icon()` (TUI)

plus one hand-maintained specimen (`site/index.html`, engine flat-table capture).
`types/src/tristate.rs` `Display` ("ABSENT") is the store's label space, not a report
surface — out of scope either way.

## 2. The alternatives, with current status

**(1) Leave it.** Status quo. Its cost has dropped twice since the complaint was filed:
at `bbc0c4c` the CDS blue copy became self-explaining (availability-control sentence),
and at `8bb3f01` (2026-08-26, this arc) **placement-only landed**: a fifth `ADVISORY`
tier now holds every Low row, out of "FINDINGS — controls that need attention",
severity-keyed, word/severity/arithmetic/seal untouched. On it-help.tech the CDS row
now renders under `ADVISORY — low-severity gaps: scored, but not urgent`.

**Residual after placement (what this proposal is actually about):** the word FAIL now
sits *inside* a tier whose own subtitle says "not urgent". The heading and the word
disagree on one row. Whether that residual is harm or honesty is exactly the board's
call — see §4.

**(2) This proposal — severity-keyed verdict word, BOTH AXES.** The verdict word is
currently keyed to *presence* (`Present`→PASS, `Absent`→FAIL) while the judgement lives
on *severity* — so it lies in both directions. The completed rule reads both axes:

| state | word |
|---|---|
| Present + Ok | PASS |
| **Present + above-Ok** (`Spf::OtherPolicy`=High, `Dmarc::Monitor`=Medium, `MtaSts::NotEnforced`=Medium, `Cds::DeletionRequested`=High) | **its own word — published but asserting nothing / actively de-securing** |
| Absent + High/Critical | FAIL |
| Absent + Low (CDS `NotPublished`, CAA `NotConfigured`, DANE `NotConfigured`, DANE `NoMx`) | **GAP** (or the board's chosen word) |
| Indet / NotApplicable | unchanged |

Uniform across all 8 controls. **Never CDS-only** — that shape is already ruled out (§5).
The PASS-side is NOT optional: leaving `Present + above-Ok` as "PASS" ships only the
overstatement half and leaves the understatement — the direction where a reader stops
looking. `Cds::DeletionRequested` (a zone asking its parent to delete the DNSSEC anchor)
rendering PASS is the sharpest instance.

**(3) Any score change.** **Not proposed.** See §4: the score half of "paired" is
already satisfied by shipped code. This document proposes a word change and zero
arithmetic.

## 3. Mechanism (if ruled YES)

- The three word maps take `(tri, severity)` instead of `tri` alone; single producer
  per surface, pinned identical across surfaces. `Absent` splits:
  `Low → "GAP"`, otherwise `"FAIL"`. `Present` splits symmetrically:
  `Ok → "PASS"`, above-Ok → the board's weak-word (the four rows in §2's table);
  leaving either split out ships half the fix (§2).
- Membership is the same Low census the ADVISORY tier keys on (exactly four arms in
  the **54-row** table — verified by machine extraction 2026-08-26: CDS `NotPublished`,
  CAA `NotConfigured`, DANE `NotConfigured`, DANE `NoMx`) — so **tier and word agree by
  construction**: ADVISORY rows all read GAP, FINDINGS rows never do. The full census:
  PASS 13 · Present-above-Ok 4 · FAIL 12 · Absent+Low 4 · Indet 16 · N/A 5 = **54**.
- JSON: byte-unchanged (tri strings like `"Absent"` are the machine vocabulary; no
  key renamed, none added).
- Store/history vocabulary: untouched.
- `site/index.html` specimen: recaptured, not hand-edited — its CDS row would read
  GAP, its MTA-STS row (`RecordAbsent` = High) stays FAIL; the sealed re-derive block
  is unaffected.

## 4. The "paired score" half, analyzed honestly

The 2026-08-21 ruling that rejected relabelling also pre-committed the honest form of
any score differentiation (`policy/RULING_cds_cdnskey_20260821.md`, verbatim):

> If fixed, the honest form is a severity-weighted score reported ALONGSIDE the
> unweighted one, never replacing it

**That score has since been built and shipped**: Risk-Weighted (`SCORING_VERSION 1`,
weights DNSSEC/SPF/DKIM/DMARC/MTA-STS = 3, DANE/CAA/CDS = 1, spec
`docs/risk-weighted-score-spec-20260822.md`), rendered beside Coverage on every
surface, never sealed. So the question "does 'paired' require new arithmetic?" has two
readings, both recorded:

**Reading A — word + existing RWS is the coherent package (claude-code lean).** The
(b) rejection named "an arithmetic penalty with words denying it." In 08-21's world
the only score was flat coverage: a softened word would have denied an undifferentiated
charge. Today the differentiated charge *exists and is displayed* — a Low absence
visibly costs 1/18 where a High costs 3/18. A severity-keyed word no longer denies the
arithmetic; it agrees with the half of the arithmetic that already differentiates, and
the severity label + tier already say "Low" twice. Under this reading the proposal
needs **zero** arithmetic: no `SCORING_VERSION` bump, no `Tally` change, no JSON
change.

**Reading B — the word still denies the flat score.** Coverage is deliberately
unweighted: `present/(present+absent)` charges a Low exactly what it charges a High,
and the same ruling defended that ("CDS absent docks for the same reason SPF absent
docks"). A row reading GAP while Coverage silently charges it at par is the
display-vs-state defect shape again, just moved one level up. Under this reading the
word change is only honest if the arithmetic also distinguishes — which the ruling
forbids doing *inside* Coverage, and RWS already does *beside* it, so Reading B
collapses into either "leave it" or "Reading A was right all along." The board should
notice that Reading B's own escape hatch is the RWS that already ships.

**The decisive question for the board:** is "FAIL" a rendering of `TriState::Absent`
(machine state — then one state should keep one word, leave it), or a rendering of
the *finding's demand on the operator* (then the word should track severity, as the
tier now does)? Placement already answered this for geometry; the board answers it
for vocabulary.

## 5. What this amends, named verbatim — and what it preserves

`policy/RULING_cds_cdnskey_20260821.md` rejected its option (b):

> (b) is an arithmetic penalty with words denying it — the display-vs-state defect
> shape.

The rejection **stands untouched** for: any CDS-only word change (this proposal is
global and severity-keyed); any relabelling of the *measured* text (the measured
strings are untouched); any change while no differentiated score exists. The amendment
this proposal asks for is narrow: *permit the verdict word to key on severity now that
the ruling's own alongside-score precondition is shipped.* Everything else the ruling
protects is preserved: the `NotPublished → Absent` collapse, `severity == Low`, both
scores' arithmetic, the copy, and the seal (verdict words are presentation-side; seal
preimage is `disposition=tri` only).

Also preserved: `RULING-rfc7344-status-20260826.md` (untouched), the NoMx→Absent
mapping (board-routed separately, untouched), and the
`cds_not_published_copy_is_ruled_do_not_soften` pin — which would gain a companion,
not lose a tooth (§6).

## 6. Acceptance tests — the frozen contract (implementation must satisfy all)

1. **Word census**: iterating all 54 disposition rows — every `Absent+Low` row renders
   GAP, every `Absent+{Medium,High,Critical}` row renders FAIL, and every
   `Present+above-Ok` row (`Spf::OtherPolicy`, `Dmarc::Monitor`, `MtaSts::NotEnforced`,
   `Cds::DeletionRequested`) renders its own non-PASS word — identically on
   engine report, CLI report/summary/HTML, and TUI; `Indet/NotApplicable` words
   byte-unchanged.
2. **Tier/word coherence**: no FINDINGS row ever renders GAP; no ADVISORY row ever
   renders FAIL; no `Present+above-Ok` row renders PASS.
3. **JSON byte-unchanged** on the existing corpus (16 verdict keys, "Absent"
   strings, scores).
4. **Coverage and Risk-Weighted numerically identical** on fixed fixtures pre/post.
5. **Seal goldens byte-identical**; `SCORING_VERSION` still 1; `SEAL_SCHEME` still v4.
6. **`cds_not_published_copy_is_ruled_do_not_soften` stays green** (tri==Absent,
   severity==Low, banned list, "manual"), plus a new pin: the GAP word may never
   appear on a non-Low row (the anti-creep gate).
7. **Specimen recaptured** from real output, seal block unchanged.
8. A do-not-re-litigate comment at the word maps naming this spec and the ruling it
   amends.

## 7. DECISION

*(empty — the board rules; record the ruling here with date and parties, then and only
then does code move)*

## 8. Addendum (2026-08-26, claude-code): the DECISION NEEDED was mis-posed — withdrawn

Carey pressed the question that collapsed it: *"SPF is optional too… isn't that the
same goddamn scenario?"* It is, and the symmetry is the answer, not a decision:

1. **Optionality is layer-1 only.** All eight `rfc_requirement` strings begin
   "Optional." The 08-21 ruling already named this: "the optionality argument proves
   too much" — optional-therefore-soften would empty the denominator for every control.
   SPF absent and CDS absent are the same collapse (`Absent → FAIL`); what differs is
   measured consequence, and that difference already has a channel: **severity**
   (SPF absent = High, BEC/spoofing class; CDS absent = Low, self-inflicted
   availability class). The severity ladder is this instrument's CVSS-analog,
   per-disposition, ruled with sources. The word column is the *deployment* channel.
2. **Making the word a second demand channel is the display-vs-state defect class**,
   and tonight's measurements showed it would have to be fixed in both directions to
   stay honest (isc.org renders PASS with HIGH — `?all` SPF, deployed but asserting
   nothing — the mirrored lie, arguably the more dangerous one).
3. **The communication failure Carey actually experienced was placement**, and it is
   fixed: the ADVISORY tier + subtitle ("low-severity gaps: scored, but not urgent") +
   the self-explaining consequence copy + the severity label are four channels that
   already tell the naive reader the truth around the word FAIL.
4. **The vendor half ("stubborn security vendor who you trusted your domain with") is
   attribution, not vocabulary** — the carded `cds_host_capability` observation
   ("host publishes none in our sample of N zones, measured <date>", never "cannot")
   is the honest fix for that, separate from any word.
5. **The only thing that could reopen this document** is empirical evidence that real
   readers systematically misread the shipped surface — comprehension data, not
   intuition about a hypothetical grandpa. No such measurement exists. If it ever
   does, §§3–6 are the pre-agreed shape, amended to cover the PASS+HIGH direction
   symmetrically.

Change-control asymmetry, restated: changing the vocabulary requires a ruling;
keeping it requires nothing. There is therefore no open decision. Withdrawn by its
author.
