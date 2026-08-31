// =============================================================================
// resolution-scope-engine — lib.rs
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
//   See: docs/ARCHITECTURE.md (Resolution Scope architecture record)
//   See: docs/ARCHITECTURE.md §1 (tokio/seL4 boundary)
//
#[cfg(not(feature = "dnssec-ring"))]
compile_error!(
    "Feature `dnssec-ring` is required. \
     Building resolution-scope-engine without DNSSEC validation silently disables \
     signature verification — all DNSSEC scores will be wrong. \
     Add `dnssec-ring` to the feature set, or use `--no-default-features` \
     only with a recorded architectural justification. \
     See Cargo.toml [features] and docs/ARCHITECTURE.md."
);

// =============================================================================
// Module structure
// =============================================================================
//
// The engine crate is Phase 1 ONLY. Phase 2 (no_std + smoltcp + sddf_device)
// lives in the sibling `native/` crate; it does not gate on a `phase2-native`
// feature here. The SciSpace kit's shared-lib.rs carried `#[cfg(feature =
// "phase2-native")]` gates from when both phases shared one lib; the split into
// two crates made them dead (the engine never enables that feature, and
// sddf_device.rs exists only in native/). Removed.

pub mod analysis;
pub mod asn_classification;
pub mod corpus_filter;
pub mod denial_proof;
pub mod flux;
pub mod ipc;
pub mod name_similarity;
pub mod report;
pub mod seal;
pub mod tristate;
pub mod truth_chain;

// Re-export the most-used surface types so callers can write
// `resolution_scope_engine::ScoredAnalysis` without a full module path.
pub use analysis::CaaDisposition;
pub use analysis::CdsDisposition;
pub use analysis::CsyncDisposition;
pub use analysis::DaneDisposition;
pub use analysis::DkimDisposition;
pub use analysis::DmarcDisposition;
pub use analysis::MtaStsDisposition;
pub use analysis::ScoredAnalysis;
pub use analysis::SpfDisposition;
pub use analysis::TlsRptDisposition;
pub use denial_proof::{
    control_from_key, control_key, extract_denial_proof, DenialProof, LookupReceipt, ReceiptRcode,
};
pub use seal::{seal, SEAL_SCHEME};
pub use tristate::TriState;
pub use truth_chain::{
    by_severity, truth_chain, Audience, ControlId, ControlReport, Severity, Tally,
};

// =============================================================================
// TriState — the core scoring primitive
// =============================================================================
//
// (Full implementation lives in tristate.rs; the type is re-exported above.)
//
// TriState encodes the Sensitivity Row Requirement (resolution-scope-engine test plan
// Section F): every scored control MUST emit exactly one of three values.
// "Warning" is not a valid output — it maps to Absent (see T1-1 fix note).
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  Present  │ Control exists and is valid                                 │
// │  Absent   │ Control is missing or invalid (counts in denominator)       │
// │  Indet    │ Could not measure (excluded from denominator, shown as "?") │
// └─────────────────────────────────────────────────────────────────────────┘
