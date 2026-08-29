# Contributing

This project's first reviewer is the CI. It is strict on purpose: every gate
below exists because of a defect that actually shipped or nearly did
(docs/DEFECT-PATTERNS.md is the catalogue). A PR that fails a gate will not
get human review; a PR that passes them all will.

## Ground rules

1. **Every claim carries a measurement.** A PR description that says "fixes
   the DANE verdict" must say what was measured, on what input, and which
   test now pins it. The PR template asks for exactly this — fill it in or
   the PR is closed.
2. **A check that cannot fail is not a check.** New tests must be shown
   failing on the defect they guard (negative control). "I read the code and
   it looks right" is not evidence; feeding the guard the input that trips it
   is.
3. **Verify at source.** If you claim a file, function, or behavior does or
   does not exist, your evidence is the command you ran against this tree at
   the commit you are changing — not memory, not a description of the code.
4. **Verdict vocabulary is load-bearing.** `Present` / `Absent` /
   `Indeterminate` distinctions (types/src/tristate.rs, engine/src/truth_chain.rs)
   are doctrine, not style. A change that collapses an Indet into an Absent —
   or lets an errored lookup read as a measured empty — will be rejected
   regardless of how clean the code is.

## Layout

Five sibling Rust crates, **no workspace** — each has its own Cargo.toml and
lockfile, and commands run inside the crate directory:

- `engine/` — measurement + verdict core (also holds `lean/Scoring.lean`,
  the machine-checked scoring doctrine, and the only place RFC citations
  may appear in source).
- `cli/` — the `resolution-scope` binary: report, html, json, tui.
- `store/` — sealed verdict history against Postgres.
- `types/` — shared no_std types; pins the seal's variant-name contract.
- `native/` — seL4/LionsOS compartment work; `--lib` is the host contract,
  the `[[bin]]` is bare-metal Phase-2.

Non-crate dirs: `docs/` (evidence and specs), `policy/` (rulings and lane
records), `scripts/` (gates and differentials), `site/`, `infra/`.

## Run the gates before you push

Install the tracked pre-push hook once per clone:

    ./scripts/install-hooks.sh

To reproduce CI fully:

    # per crate (engine, cli, store, types):
    cargo fmt --check && cargo test && cargo clippy --all-targets -- -D warnings

    # native (lib contract + bare-metal check, both clippy-strict):
    cd native && cargo build --lib && cargo test --lib \
      && cargo clippy --lib -- -D warnings \
      && cargo clippy --lib --target aarch64-unknown-none -- -D warnings \
      && cargo check --lib --target aarch64-unknown-none

    # repo-wide:
    bash scripts/check-citation-boundary.sh    # RFC literals stay in engine/
    cargo deny check licenses sources          # per crate, deny-by-default
    cargo deny check advisories                # per crate (audit.yml runs this daily)

    # store integration tests need a real Postgres:
    docker compose up -d
    RS_STORE_TEST_URL=postgres://... cargo test -- --include-ignored

Plain `cargo clippy` is not the gate — `--all-targets -- -D warnings` is
(the lenient form has passed while the strict form was red).

If your change touches scoring semantics, `engine/lean/Scoring.lean` must
still check (`lean engine/lean/Scoring.lean`, toolchain pinned in
`lean-toolchain`). A scoring change that cannot be proved is a scoring
change that does not merge.

## Licensing

The analyzer core is AGPL-3.0. By contributing you agree your contribution
is licensed the same as the crate you touch (check the crate's Cargo.toml).
Dependencies must clear `cargo deny` (crates.io only, allow-listed licenses).

## What to expect

Review happens when the maintainer has time; there is no SLA. First-time
contributors' CI runs require manual approval (GitHub's default), so your
gates may not fire until the PR is noticed. Small, single-claim PRs with
their measurement attached get through fastest; large PRs mixing concerns
will be asked to split.
