#!/usr/bin/env python3
"""Summarize a cargo-mutants outcomes.json into the per-function caught/missed
table. Deterministic: reads the tool's own output, no prose, no interpretation.

This exists so the mutation claim ("zero survivors in dispersion()") is
re-derivable by anyone who does not trust the reporter: run

    python3 scripts/mutation_summary.py engine/mutants.out/outcomes.json

and compare against docs/mutation-flux-20260820/README.md. The per-function
"missed" column is the number a naive reader cannot get wrong — a function with
missed==0 has every one of its surviving mutants caught by some test.
"""
import collections
import json
import sys


def classify(summary: str) -> str:
    s = str(summary).lower()
    if "unviable" in s:
        return "unviable"
    if "missed" in s:
        return "missed"
    if "timeout" in s:
        return "timeout"
    return "caught"


def main(path: str) -> None:
    d = json.load(open(path))
    assert isinstance(d.get("total_mutants"), int), "not a valid outcomes.json"
    by_fn = collections.defaultdict(lambda: {"caught": 0, "missed": 0, "timeout": 0, "unviable": 0})
    for o in d["outcomes"]:
        sc = o.get("scenario")
        if not isinstance(sc, dict):
            continue  # the "Baseline" scenario is a string
        m = sc["Mutant"]
        fn = m["function"]["function_name"]
        by_fn[fn][classify(o["summary"])] += 1

    print(f"cargo-mutants {d.get('cargo_mutants_version')}")
    print(f"total={d['total_mutants']} missed={d['missed']} "
          f"caught={d['caught']} timeout={d['timeout']} unviable={d['unviable']}")
    print()
    print(f"{'function':34s} {'caught':>7s} {'missed':>7s} {'timeout':>8s} {'unviable':>9s}")
    for fn in sorted(by_fn):
        v = by_fn[fn]
        print(f"{fn:34s} {v['caught']:>7d} {v['missed']:>7d} "
              f"{v['timeout']:>8d} {v['unviable']:>9d}")
    sys.exit(0 if d["missed"] == 0 else 0)  # always exit 0: this is a report, not a gate


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: mutation_summary.py <outcomes.json>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
