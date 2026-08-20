# Mutation testing — flux.rs, 2026-08-20 (tool output)

This directory is the **raw, re-derivable evidence** for the flux mutation claim.
It exists because the mutation result is the load-bearing claim of the whole
arc — "the scars actually bite" — and a load-bearing claim must not live only in
a reporter's prose. It is held to the same standard as the seal: **the value has
to be re-derived by someone who does not trust the reporter.**

## The artifact

- `outcomes.json` — `cargo-mutants`'s own output, committed verbatim (every
  mutant's scenario + build/test phase results). Not edited, not
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
source commit `ef770d111ac7e6940462eda3f635ba9420e3d900` (tree clean; `flux.rs`
unchanged since). Re-running against that commit reproduces the numbers.

## The numbers (from the committed JSON, via the extractor)

```
cargo-mutants 27.1.0
total=37 missed=0 caught=31 timeout=0 unviable=6

function                caught  missed  timeout  unviable
cymru_origin_name            2       0        0         0
dispersion                  13       0        0         1
ip_from_rdata                3       0        0         1
observation_from_asns        2       0        0         1
observation_from_parts       5       0        0         1
observe_flux                 0       0        0         1
parse_cymru_origin           6       0        0         1
```

## The progression — from 7 misses to 0

The first run (against `3c1b73f`, recorded in `docs/MUTATION-TESTING.md`) showed
**7 misses, all in `observe_flux`** — the async network path, whose only
covering test was `#[ignore]`'d. That was a coverage fact, not a property of
network code.

The fix was a seam, not more network tests: the A/AAAA match arms were extracted
into pure `ip_from_rdata`, and the assembly (the `found` flag, the unresolved
counter, the min-TTL fold) into pure `observation_from_parts`, leaving
`observe_flux` a thin wrapper that resolves and delegates. Four unit tests now
reach that logic.

**This run — the re-run after the seam landed — shows `missed=0` across every
function.** The seven misses flipped to caught exactly as predicted.

## What this establishes, and what it does not

**Established (read directly off the table):**

- **Zero mutants survived in `dispersion()`** — 13 caught, 0 missed. The
  three-axis assessment logic (Stable/Transient/Dispersing, the transition
  count, the union, the proxy exclusion) is fully mutation-killed.
- **`parse_cymru_origin` boundary is closed** — 6 caught, 0 missed.
- **The `observe_flux` seam is closed** — `ip_from_rdata` 3 caught, 0 missed;
  `observation_from_parts` 5 caught, 0 missed. The A/AAAA extraction and the
  found/unresolved counters are now exercised by unit tests.

**Not established (stated, not buried):**

- The `unviable` mutants (6) are mutants the tool could not compile into a
  testable form — not "caught" and not "missed," a third category. One each in
  `dispersion`/`observation_from_asns`/`observation_from_parts`/`observe_flux`/
  `parse_cymru_origin`/`ip_from_rdata`, and none is claimed as coverage. In
  particular, `observe_flux` shows 0 caught because its only mutation the tool
  could produce was unviable — the live-resolver wrapper itself is still not
  unit-tested, only its pure core is. That residual is honest and tiny.
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
