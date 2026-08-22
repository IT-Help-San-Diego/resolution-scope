# SciSpace second-opinion — closure (2026-08-22)

Closed out the seL4-foundation second-opinion (`SCISPACE_second_opinion_sel4_foundation.md`,
read against `2e7984d`). State of every item below.

## Closed in code

| # | Finding | Closure |
|---|---------|---------|
| 2 (deny_unknown_fields) | `ScoredAnalysis` lacked it | `#[serde(deny_unknown_fields)]` now lives on the single producer in `types/src/dispositions.rs` (not just the native mirror — the extraction made it one place). Commit `4826798`. |
| 4 (CI `--lib` only) | bare-metal bin can silently rot | `native-lib` job gained `cargo check --lib --target aarch64-unknown-none` (~30s, no SDK). Commit `4826798`. |
| 2/ordering (extract shared crate FIRST) | mirror drift | `resolution-scope-types` no_std crate created; `native/src/{tristate,types}.rs` mirror DELETED; both engine + native consume the single producer. See `docs/shared-types-crate-extraction-20260822.md`. |
| 1 / 6 (stale `.cdl`) | 11,334-byte hand-written capDL still in tree | **Deleted** `native/capdl/dns_sovereign_compartment.cdl` + the dir (SciSpace's preferred option a). `engine/src/ipc.rs` comment re-pointed at the real authoring artifact `native/microkit/dns_sovereign_compartment.system`. The historical finding docs (`capdl-syntax-finding`, `microkit-sdk-correction`, etc.) remain as dated record. |

## Documented-and-tracked (not yet implemented — deliberate, not forgotten)

These are staged behind Stage 2 (FFI→Microkit wiring) per SciSpace's own ordering, and are
now recorded as a **HARDENING TRACK** in `native/src/ffi.rs` so they cannot silently vanish:

| # | Item | Stage | Shape |
|---|------|-------|-------|
| 1A | monotonic u64 attempt-counter (forensics) | Low/optional | static `AtomicU64` bumped per tamper/parse failure; NULL + caller-logged is already correct, this is additive forensics. |
| 1B | wire format `serde_json` → `postcard` | Stage 3 | DoS-surface (TCB) reduction only — the seal is over `canonical_input`, so JSON cannot cause a silent integrity failure. |
| 1C | allocator strategy invariant | now-documented | bump allocator, `dealloc` no-op, 64 KiB sized for single-verdict-per-boot. Documented in `native/src/main_native.rs` + referenced in the hardening track. |
| 3 | `SEAL_SCHEME` version exchange | Stage 2 | engine sends `produced_by` but not the scheme constant; on v2→v3 skew every verdict NULLs with no skew-vs-tamper diagnostic. Fix (SciSpace option a): carry the scheme over the boundary and assert before re-deriving. |

## Correctly left as-is

- **Finding 5** — `SCISPACE_nostd_dnssec_status.md` + `UPSTREAM-NOSTD-DNSSEC-SCOPE.md` track
  Option A/C revival only, no intersection with the active Option B build. Correctly unmarked.

## Net

Every *soundness* and *soft-hole* item is closed. The four remaining items are explicit
hardening-track entries with their stage, not open questions. Stage 2 (wire the no_std
Rust lib as the store PD via a C shim or libmicrokitco) proceeds on a clean, single-producer
foundation.
