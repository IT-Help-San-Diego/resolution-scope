# Mutation testing — flux.rs, 2026-08-20 (tool output)

This directory is the **raw, re-derivable evidence** for the flux mutation claim.
It exists because the mutation result is the load-bearing claim of the whole
arc — "the scars actually bite" — and a load-bearing claim must not live only in
a reporter's prose. It is held to the same standard as the seal: **the value has
to be re-derived by someone who does not trust the reporter.**

## The artifact

- `outcomes.json` — `cargo-mutants`'s own output, committed verbatim (61 KB,
  every mutant's scenario + build/test phase results). Not edited, not
  summarized-then-deleted. This is the thing to read if you distrust the
  summary.
- The extractor: `scripts/mutation_summary.py` — a deterministic reader that
  turns `outcomes.json` into the per-function caught/missed table below. It does
  not interpret; it counts.

## Reproduce

```bash
cargo install cargo-mutants --locked          # v27.1.0
cd engine
cargo mutants --file src/flux.rs              # ~60s
python3 ../scripts/mutation_summary.py mutants.out/outcomes.json
```

The committed `outcomes.json` was produced by `cargo-mutants 27.1.0` against
source commit `3c1b73f1075980011fdf50aff068166944f4ffbc` (tree clean; `flux.rs`
unchanged since). Re-running against that commit reproduces the numbers.

## The numbers (from the committed JSON, via the extractor)

```
cargo-mutants 27.1.0
total=34 missed=7 caught=23 timeout=0 unviable=4

function                caught  missed  timeout  unviable
cymru_origin_name            2       0        0         0
dispersion                  13       0        0         1
observation_from_asns        2       0        0         1
observe_flux                 0       7        0         1
parse_cymru_origin           6       0        0         1
```

## What this establishes, and what it does not

**Established (read directly off the table):**

- **Zero mutants survived in `dispersion()`** — 13 caught, 0 missed. The
  three-axis assessment logic (Stable/Transient/Dispersing, the transition
  count, the union, the proxy exclusion) is fully mutation-killed. Every
  mutation to it changed the output enough that a test failed.
- **`parse_cymru_origin` boundary is closed** — 6 caught, 0 missed. The two
  mutants that previously survived (`< 3 → == 3`, `< 3 → <= 3`) are now killed
  by `cymru_parse_minimal_three_part_line` + `cymru_parse_rejects_two_part_line`.
- **The 7 misses are all `observe_flux`** — the async network path, whose only
  covering test is `#[ignore]`'d (a coverage fact, not a property of network
  code). Fix = a mock-resolver seam; the moment it lands, these flip
  missed→caught.

**Not established (stated, not buried):**

- The `unviable` mutants (4) are mutants the tool could not compile into a
  testable form — not "caught" and not "missed," a third category. They are in
  `dispersion`/`observation_from_asns`/`observe_flux`/`parse_cymru_origin`, one
  each, and none is claimed as coverage.
- Mutation testing proves the tests *would catch* the mutants the tool made. It
  does not prove the tests are *complete* — a bug shape the tool does not mutate
  is invisible to it. Same boundary honesty as the seal: tamper-evidence is not
  proof-of-measurement; mutation-clean is not proof-of-correctness.

## Why this file exists separately from `docs/MUTATION-TESTING.md`

`MUTATION-TESTING.md` is the narrative (what we did, what it means). This
directory is the **evidence**. The narrative can be wrong without the numbers
moving; the numbers can be wrong without the narrative knowing. Keeping them
separate is how a reader verifies one against the other instead of trusting
either.
