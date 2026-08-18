// =============================================================================
// resolution-scope-native — lib.rs
// =============================================================================
//
// R2 MITIGATION (compile-error regression guard):
//
//   If the "dnssec-ring" feature is absent from the build graph, hickory-dns
//   compiles cleanly but DNSSEC validation is silently disabled.  This guard
//   converts that silent failure into a hard compile error so it is caught at
//   `cargo check` time, not at runtime or in production scoring.
//
//   If you need to build without DNSSEC (e.g. a minimal test harness), you
//   must disable the default "dnssec" feature explicitly:
//
//       cargo test --no-default-features
//
//   and record the architectural justification in a PR description.
//   See: docs/ARCHITECTURE.md
//   See: docs/ARCHITECTURE.md §1
//
#[cfg(not(feature = "dnssec-ring"))]
compile_error!(
    "Feature `dnssec-ring` is required. \
     Building resolution-scope-native without DNSSEC validation silently disables \
     signature verification — all DNSSEC scores will be wrong. \
     Add `dnssec-ring` to the feature set, or use `--no-default-features` \
     only with a recorded architectural justification. \
     See Cargo.toml [features] and docs/ARCHITECTURE.md."
);

// =============================================================================
// Module structure
// =============================================================================

// Phase 1 modules depend on hickory-resolver and tokio, which are absent from
// the Phase 2 (native/Cargo.toml) dependency tree.
// Gate them so Phase 2 builds compile cleanly without modification.
#[cfg(not(feature = "phase2-native"))]
pub mod analysis;
#[cfg(not(feature = "phase2-native"))]
pub mod ipc;
#[cfg(not(feature = "phase2-native"))]
pub mod report;
pub mod tristate;

/// Phase 2 native path: sDDF-to-smoltcp `Device` trait adapter.
///
/// Gated on the `phase2-native` feature so Phase 1 builds (which have no
/// smoltcp dependency) compile cleanly without modification.
///
/// **How to activate for Phase 2**:
/// 1. Add `phase2-native = []` under `[features]` in
///    `native/Cargo.toml`.
/// 2. Add `phase2-native` to the `default` feature list in that manifest.
/// 3. Add `smoltcp` to `[dependencies]` (already present in the native
///    Cargo.toml; not needed in Phase 1's Cargo.toml).
///
/// Phase 2 `[[bin]]` targets (`src/main_native.rs`) may also declare
/// `mod sddf_device;` directly without going through this lib — both paths
/// are valid during the spike.  Once Phase 2 is promoted, the standalone
/// declaration in `main_native.rs` should be removed in favour of this
/// re-export.
#[cfg(feature = "phase2-native")]
pub mod sddf_device;

// Re-export the most-used surface types so callers can write
// `resolution_scope_native::ScoredAnalysis` without a full module path.
#[cfg(not(feature = "phase2-native"))]
pub use analysis::ScoredAnalysis;
pub use tristate::TriState;

// =============================================================================
// TriState — the core scoring primitive
// =============================================================================
//
// (Full implementation lives in tristate.rs; the type is re-exported above.)
//
// TriState encodes the Sensitivity Row Requirement (resolution-scope-native test plan
// Section F): every scored control MUST emit exactly one of three values.
// "Warning" is not a valid output — it maps to Absent (see T1-1 fix note).
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  Present  │ Control exists and is valid                                 │
// │  Absent   │ Control is missing or invalid (counts in denominator)       │
// │  Indet    │ Could not measure (excluded from denominator, shown as "?") │
// └─────────────────────────────────────────────────────────────────────────┘
