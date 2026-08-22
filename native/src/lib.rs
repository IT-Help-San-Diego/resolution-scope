// =============================================================================
// resolution-scope-native — lib.rs (Option B: report/store receiver)
// =============================================================================
//
// Under Option B (docs/ARCHITECTURE.md §7) the no_std compartment is the
// report/store receiver: it receives a ScoredAnalysis produced by the std
// engine, re-derives the verdict seal (SHA3-512), renders, and writes through
// a granted capability. No network, no resolver, no tokio — no smoltcp, no
// hickory-proto, no ring (the pre-B "DNS engine inside the compartment" shape
// that Option B abandoned; see docs/seL4-demo-state-and-model-drift-20260822.md).
//
// The load-bearing contract is the SEAL: canonical_input + seal_versioned must
// be byte-identical to engine/src/seal.rs. The golden-seal test in seal.rs pins
// this mirror to a value computed from the engine.
//
// The C ABI (ffi.rs) is the seam between the std engine (outside seL4) and this
// no_std store compartment (inside) — the exact Rust↔Microkit boundary.
//
// MIRROR NOTICE — the types (tristate, types) and seal are thin copies of the
// engine's. The correct long-term shape is a shared no_std crate (single-
// producer rule); the header in types.rs names the follow-up.
// =============================================================================

#![no_std]

extern crate alloc;

pub mod ffi;
pub mod fixtures;
pub mod report;
pub mod seal;
pub mod tristate;
pub mod types;

pub use fixtures::demo_verdict;
pub use report::render_text;
pub use seal::{canonical_input, seal_versioned, SEAL_SCHEME};
pub use tristate::TriState;
pub use types::ScoredAnalysis;

/// Verify a claimed seal against the verdict it purports to bind.
///
/// Tamper-evidence (the store's whole job): recompute the seal over the verdict
/// and the producing engine's version, then compare to the claimed seal that
/// crossed the boundary. A mismatch means the verdict was altered after sealing.
pub fn verify_seal(analysis: &ScoredAnalysis, produced_by: &str, claimed: &str) -> bool {
    seal_versioned(analysis, produced_by) == claimed
}
