# HANDOFF — Arm 1 (N-version differential: Rust engine vs Go reference)

From: Hermes (instrument lane) · Date: 2026-08-21 · Repo: `resolution-scope` @ main `42f6f67`

## What Arm 1 is

The first time the two DNS engines are measured against each other, on the same
domains, on the same eight controls. The Rust engine (`resolution-scope`) and
the Go DNS Tool (`dns-tool-intel`) both produce dispositions + tri-states for
DNSSEC / DANE / SPF / DKIM / DMARC / MTA-STS / CAA / CDS-CDNSKEY. Arm 1 runs
both, joins them domain-by-domain, and classifies every disagreement. This is
the "does what it says is correct" measurement that everything so far has
deferred to — see `docs/CALIBRATION-STUDY-SPEC.md`.

## Ownership (why this file exists)

The one real friction tonight was lanes colliding on shared state. Arm 1 is
assigned in writing to **Hermes (the instrument lane)** — the harness AND its
output directory, nothing else's. Rules:

- Output dir: `docs/arm1-20260821/` (the harness owns it; other lanes read,
  don't write).
- Claude Science owns the *analysis design* (pre-registered classification,
  statistical treatment) and produces rulings — never commits.
- Claude Code owns nothing here; site/frontend only.
- If another lane needs a decision, it goes through Carey, not into the harness.

## The two endpoint shapes (already measured — don't re-discover)

| side | surface | shape | unit |
|---|---|---|---|
| Rust | `resolution-scope -d <domains...> --format json` | NDJSON, one object/line | line = domain |
| Go | `GET /api/analysis/:id` | one object per response | response = domain |

Full detail in `docs/CALIBRATION-STUDY-TASK-ZERO.md`. The harness parses a
newline-delimited stream for Rust and N single-object HTTP responses for Go,
then pairs on domain identity. **This asymmetry breaks at parse time, before
any verdict comparison — it is pinned in the harness's FIRST test, not
discovered at the first real join.**

## The two hard gates (from the spec, and Claude Science's ruling)

1. **Three-way disagreement classification, never two-way.** Each disagreement
   is *ours wrong*, *theirs wrong*, or *the spec is genuinely ambiguous* — and
   the classification is **pre-registered before any row is joined**, not
   applied after seeing the data.

2. **The four-state bridge gap.** `go_to_tri` in
   `scripts/full_arm_differential.py` maps three states (`present` /
   `absent_confirmed` / else→Indet). The Rust side now emits a FOURTH state —
   `NotApplicable` (null-MX DANE). The Go side cannot express it. **Rows where
   Rust emits `NotApplicable` are EXCLUDED WITH A PUBLISHED COUNT — never
   folded into `Absent`** — or constraint #2's honest-instrument penalty sneaks
   back in through the mapping.

3. **Freeze the corpus content-addressed BEFORE either engine runs.** The Go
   side hands you `X-SHA3-512` natively; hash the Rust NDJSON bytes yourself.
   Otherwise the disagreement set and the corpus drift together and the
   agreement rate stops being re-derivable.

## First milestone — tiny, structural, the next LOOK moment

One domain, both real shapes, joined:

```
resolution-scope -d <domain> --format json   # NDJSON, one line
curl <go>/api/analysis/:id                    # single object
```

Parse both, pair them, print the sixteen verdict fields side by side. **No
classification, no corpus, no rates.** That table — two engines' verdicts in
one view for the first time — is the thing to show Carey. Everything after it
scales from a join that has already parsed both real shapes.

## Corpus design (for when the join holds)

Seed with the golden fixtures, then deliberately add: DANE-deployed domains,
MTA-STS enforcers, null-MX declarers, genuinely-unsigned domains (google.com —
verified real, don't "fix" it), and the live evil fixture (dns-evil-flicker.com,
known-bogus DS, ground truth on file). Publish the raw per-domain/per-control
table; derive the agreement rates in the reader's script, never as stored prose.
