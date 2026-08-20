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
   `!found`, `unresolved +=`). These missed as a **coverage fact**: the only
   test covering this path was the `#[ignore]`'d live test, which never runs in
   `cargo test`, so the mutations were unobserved. **Fixed** by extracting the
   pure core into `ip_from_rdata` (the A/AAAA match arms) + `observation_from_parts`
   (the found/unresolved/min-TTL assembly), leaving `observe_flux` a thin
   network wrapper. Four unit tests now reach that logic.

**Re-run after the seam landed:** `37 mutants tested: 31 caught, 6 unviable,
0 missed`. Every function is now `missed=0` — the seven `observe_flux` misses
flipped to caught exactly as predicted. The only residual is one unviable
mutant in `observe_flux` itself (the tool could not compile a testable form for
the live-resolver wrapper), which is honest and tiny: the pure core is covered,
the network wrapper is not, and that is stated rather than hidden.

## Durable doctrine

- Mutation testing is the tool for the "are these tests real?" question that
  the 106-test count cannot answer. Run it on a file when that file's verdict
  logic is frozen — not before (a moving file produces churn, not signal).
- `dispersion()` is now proven mutation-clean; `observation_from_parts` and
  `ip_from_rdata` (the `observe_flux` pure core) are also `missed=0` after the
  seam extraction. The only untested code left in the file is the live-resolver
  wrapper itself — a thin shell, one unviable mutant, stated not hidden.
