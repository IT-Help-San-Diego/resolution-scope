// tristate.rs — TriState re-export + the Lean correspondence pin
//
// The TriState type now lives in the shared `resolution-scope-types` crate
// (single producer, shared with native/). This module re-exports it so
// `crate::tristate::TriState` keeps resolving for the renderer (report.rs) and
// the truth-chain model (truth_chain.rs), and keeps the Lean correspondence
// test below — the machine-checked-doctrine guard that pins the Rust variants
// to lean/Scoring.lean.

pub use resolution_scope_types::TriState;

#[cfg(test)]
mod tests {
    use super::TriState;

    /// The Rust TriState variants — the canonical, ordered set. The Lean model
    /// (lean/Scoring.lean, now inside the crate at engine/lean/Scoring.lean)
    /// must declare exactly these four, same names, no
    /// more and no fewer. The proofs bind the LEAN model, not this enum — there
    /// is no extraction, codegen, or FFI — so this test is what keeps the two
    /// from drifting apart silently (the correspondence gap Claude Science
    /// flagged on the machine-checked-doctrine claim). If either side renames,
    /// adds, or removes a state, this fails at build time.
    ///
    /// Scope: this pins NAME correspondence only — that the Lean constructors
    /// and the Rust variants are named identically. It does not pin SEMANTIC
    /// correspondence (that each variant's behavior matches its constructor's
    /// meaning); that residual gap is closed when refinement proofs land.
    #[test]
    fn tri_state_matches_lean_model() {
        const RUST_VARIANTS: [&str; 4] = ["Present", "Absent", "Indet", "NotApplicable"];

        // Sanity on the Rust side: the Debug repr of every variant is its
        // canonical name (catches a rename or an extra variant).
        let debugged = [
            format!("{:?}", TriState::Present),
            format!("{:?}", TriState::Absent),
            format!("{:?}", TriState::Indet),
            format!("{:?}", TriState::NotApplicable),
        ];
        assert_eq!(debugged, RUST_VARIANTS, "Rust TriState variants drifted");

        // The Lean model, read at compile time so removing it breaks the test.
        // Path is relative to this source file and resolves INSIDE the crate
        // (engine/lean/Scoring.lean) — the spec travels with the instrument, so
        // a copy of just the engine crate stays buildable (and the drift-pin
        // stays a drift-pin rather than a path-fragility trap).
        let lean = include_str!("../lean/Scoring.lean");
        let lean_variants = extract_lean_tristate_constructors(lean);
        assert_eq!(
            lean_variants.as_slice(),
            RUST_VARIANTS,
            "Lean TriState constructors drifted from the Rust enum"
        );
    }

    /// Extract the constructor names from the Lean `inductive TriState where`
    /// block — each `| Name` line up to the `deriving` clause.
    fn extract_lean_tristate_constructors(lean: &str) -> Vec<String> {
        let start = lean
            .find("inductive TriState where")
            .expect("lean/Scoring.lean must declare `inductive TriState`");
        let rest = &lean[start..];
        let end = rest
            .find("deriving")
            .expect("lean TriState block must end with `deriving`");
        let block = &rest[..end];
        block
            .lines()
            .filter_map(|line| {
                let t = line.trim();
                let name = t.strip_prefix('|')?.trim();
                if name.is_empty() || name.starts_with("--") {
                    None
                } else {
                    Some(name.to_string())
                }
            })
            .collect()
    }
}
