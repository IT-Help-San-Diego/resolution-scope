#!/usr/bin/env python3
"""Summarize a cargo-mutants outcomes.json into the per-function outcome table.
Deterministic: reads the tool's own output, no prose, no interpretation.

This exists so the mutation claim ("zero survivors in dispersion()") is
re-derivable by anyone who does not trust the reporter: run

    python3 scripts/mutation_summary.py engine/mutants.out/outcomes.json

and compare against docs/mutation-flux-20260820/README.md. The per-function
"missed" column is the number a naive reader cannot get wrong — a function with
missed==0 has every one of its surviving mutants caught by some test.

The five outcome categories below are the tool's own `SummaryOutcome` variants,
mapped verbatim from cargo-mutants 27.1.0 `outcome.rs::summary()`:

    CaughtMutant — mutant whose TEST phase failed (killed).
    MissedMutant — mutant whose TEST phase succeeded (survived). THE survivor
                   counter: "zero survivors" is literally missed==0.
    Timeout      — mutant that timed out (neither caught nor missed).
    Unviable     — mutant whose check/build failed (not compilable).
    Success      — a mutant whose LAST phase succeeded but was not classified
                   caught/missed (both of those require the last phase to be
                   Test). An edge bucket, distinct from MissedMutant.

Note the header's `success` counter and the `Success` *record* in the array are
DIFFERENT things: the record is the unmutated `Scenario::Baseline` run, which
cargo-mutants pushes into `outcomes` but EXCLUDES from every header counter via
the `is_mutant()` guard. Do not conflate them.
"""
import collections
import json
import sys

# All five SummaryOutcome variants, in the order cargo-mutants emits them.
CATEGORIES = ["caught", "missed", "timeout", "unviable", "success"]


def classify(summary: str) -> str:
    s = str(summary)
    if s == "CaughtMutant":
        return "caught"
    if s == "MissedMutant":
        return "missed"
    if s == "Timeout":
        return "timeout"
    if s == "Unviable":
        return "unviable"
    if s == "Success":
        return "success"
    raise AssertionError(f"unrecognized summary outcome: {s!r}")


def main(path: str) -> None:
    d = json.load(open(path))
    assert isinstance(d.get("total_mutants"), int), "not a valid outcomes.json"

    # Per-function tally over MUTANT scenarios only. The Baseline scenario is a
    # bare string (not a {"Mutant": ...} dict) and is skipped — it must not
    # leak into a function's count.
    by_fn = collections.defaultdict(lambda: dict.fromkeys(CATEGORIES, 0))
    for o in d["outcomes"]:
        sc = o.get("scenario")
        if not isinstance(sc, dict):
            continue  # the Baseline
        fn = sc["Mutant"]["function"]["function_name"]
        by_fn[fn][classify(o["summary"])] += 1

    # Recompute totals from the per-record tally, then cross-check against the
    # header. If they disagree, print BOTH so the discrepancy is visible — a
    # header/tally mismatch is itself a finding, never silently hidden.
    recomputed = {c: sum(v[c] for v in by_fn.values()) for c in CATEGORIES}
    header = {c: int(d.get(c, 0)) for c in CATEGORIES}

    print(f"cargo-mutants {d.get('cargo_mutants_version')}")
    print(f"total={d['total_mutants']} " + " ".join(f"{c}={header[c]}" for c in CATEGORIES))
    if recomputed != header:
        print("HEADER/TALLY MISMATCH — header vs recomputed-from-records:")
        print(f"  header:     {header}")
        print(f"  recomputed: {recomputed}")
    print()
    hdr = " ".join(f"{c:>8s}" for c in CATEGORIES)
    print(f"{'function':34s} {hdr}")
    for fn in sorted(by_fn):
        v = by_fn[fn]
        row = " ".join(f"{v[c]:>8d}" for c in CATEGORIES)
        print(f"{fn:34s} {row}")
    # Always exit 0: this is a report, not a gate. It documents, it never blocks.


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: mutation_summary.py <outcomes.json>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
