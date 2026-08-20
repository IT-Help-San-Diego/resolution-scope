# Mutation testing — flux.rs (frozen-file validation, 2026-08-20)

The flux detector's three axes (threshold = ASN dispersion, scope = per-name,
rate = transition count) are ruled and regression-pinned. Coverage on a moving
foundation is waste, but mutation testing on a FROZEN file answers the one
question coverage cannot: do the tests bite, or do they pass for reasons
unrelated to what they assert?

## Recipe

```bash
cargo install cargo-mutants --locked
cd engine
cargo mutants --file src/flux.rs
```

Scoped to one file: 34 mutants, ~60s on this machine. `mutants.out/` is
gitignored (scratch). The run previously failed at the baseline because
`tristate.rs` used `include_str!("../../lean/Scoring.lean")` — a compile-time
path that only resolves when the crate sits at the right depth in the repo tree;
the Lean spec now lives inside the crate (`engine/lean/Scoring.lean`), so the
instrument builds self-contained and mutation testing works.

## First result (before the parser-boundary fix)

```
34 mutants tested: 9 missed, 21 caught, 4 unviable
```

**The key finding: zero mutants survived in `dispersion()` itself.** The
three-axis-ruled assessment logic is fully mutation-killed — every mutation to
the Stable/Transient/Dispersing split, the transitions count, the union, and the
proxy exclusion was caught by a test. That is the "the scars actually bite"
confirmation.

The 9 misses split into two classes:

1. **`parse_cymru_origin` (2)** — a PURE, testable function with an untested
   `< 3` boundary. Mutants `< 3 → == 3` and `< 3 → <= 3` survived because no
   test fed an exactly-3-part record. **Fixed** with
   `cymru_parse_minimal_three_part_line` (3-part accepted) +
   `cymru_parse_rejects_two_part_line` (2-part rejected).

2. **`observe_flux` (7)** — the async network path (A/AAAA match arms,
   `!found`, `unresolved +=`). These miss not because network code is
   intrinsically untestable, but as a **coverage fact**: the only test covering
   this path is the `#[ignore]`'d live test, which never runs in `cargo test`,
   so the mutations are unobserved. The fix is a mock-resolver seam — inject a
   fake `TokioResolver` or an address→ASN lookup fn — so the A/AAAA extraction
   and the unresolved counter are unit-tested offline. Actionable, not a
   permanent exemption: the moment that seam lands, these mutants flip from
   "missed" to "caught."

**Re-run after the parser-boundary fix:** `34 mutants tested: 7 missed,
23 caught, 4 unviable`. The two parser misses are gone; the remaining seven are
all `observe_flux` (the I/O seam above).

## Durable doctrine

- Mutation testing is the tool for the "are these tests real?" question that
  the 106-test count cannot answer. Run it on a file when that file's verdict
  logic is frozen — not before (a moving file produces churn, not signal).
- `dispersion()` is now proven mutation-clean; `observe_flux`'s 7 misses are a
  coverage gap (the only covering test is `#[ignore]`'d), not a property of
  network code — and the fix is a seam injection, not more tests against a
  network.
