# Shared types crate extraction (2026-08-22)

Single-producer extraction: the verdict type surface moved out of the engine and
out of the native mirror into one `resolution-scope-types` no_std crate, so the
hand-kept mirror is deleted and drift is structurally impossible.

## What moved

| Type | From | To |
|---|---|---|
| `TriState` | `engine/src/tristate.rs` + `native/src/tristate.rs` (mirror) | `types/src/tristate.rs` |
| 8 disposition enums + `chain()` + `Display` | `engine/src/analysis.rs` type section | `types/src/dispositions.rs` |
| `ScoredAnalysis` | `engine/src/analysis.rs` + `native/src/types.rs` (mirror) | `types/src/dispositions.rs` |

`types/` is `#![no_std]`; `Display`/`chain()` use `core::fmt` (identical to
`std::fmt`). The enum **variant names** are unchanged — the seal hashes the
`Debug` repr, so byte-identity is the regression contract.

## Why (single-producer rule)

The mirror notice in the old `native/src/types.rs` named the follow-up: a
hand-kept mirror WILL drift, and the golden-seal test only *detects* the drift
after it happens — it cannot prevent it. Extracting the type surface here makes
drift structurally impossible: both consumers compile against the same
definitions. This is SciSpace's "extract the shared crate FIRST" ordering,
ahead of Stage-2 (FFI) wiring.

## Regression pin — still holds

- Engine golden seal / `canonical_input` byte-exact test: **passes** (123 unit
  tests green, 7 network-ignored).
- Native golden seal `seal_versioned(demo_verdict(), "0.1.0") == 9a0b7790…`: **passes**
  (8 tests green) — proving the extracted types are byte-identical.
- `types/` pins the variant-name sets + a couple of `chain()` edges (3 tests).

## `deny_unknown_fields` (SciSpace Ask #2)

`ScoredAnalysis` now carries `#[serde(deny_unknown_fields)]`: a version-skewed
store receiving a newer engine's payload fails LOUDLY instead of silently
dropping fields it does not recognise (the silent-field-drop class the
golden-seal test cannot catch for non-seal-bearing additions).

## CI + guard changes

- `crates` matrix: `[engine, cli, store]` → `[engine, cli, store, types]`.
- `licenses` matrix: + `types`.
- `native-lib` job: + `cargo check --lib --target aarch64-unknown-none` — the
  bare-metal compile gate (catches "compiles on host, breaks on target", e.g. an
  accidental `std::` reference the host `cargo build --lib` would not surface;
  ~30s, no SDK, type-only).
- `scripts/check-citation-boundary.sh`: `types/` is now a licensed citation
  producer (the disposition doc comments carry the RFC citations, which move
  WITH the type so semantics and authority stay colocated). Guard was watched
  flagging `types/` before the exclusion landed, so the exclusion is load-bearing.

## Native Cargo.toml

`serde` (direct) removed from native — the types crate owns the derives now;
native keeps `serde_json` (wire format) + `sha3` (seal) + the new path dep.
