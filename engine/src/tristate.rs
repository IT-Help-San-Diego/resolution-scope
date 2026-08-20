// tristate.rs — Core scoring primitive
//
// Every scored DNS control emits exactly one TriState variant.
// See docs/TEST-PLAN.md Section F (Sensitivity Row Requirement).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TriState {
    /// Control exists and is cryptographically valid.
    Present = 0,
    /// Control is absent or invalid — counted in the score denominator.
    /// NOTE: "warning" states (e.g. MTA-STS T1-1) MUST map to Absent, not a
    /// fourth value.  See test plan Section F.2d (T1-1 regression test).
    Absent = 1,
    /// Could not measure — excluded from denominator, shown as "?" in the UI.
    Indet = 2,
    /// Measured, and the control does not apply to this domain — e.g. a null MX
    /// (RFC 7505 "MX 0 .") declares "accepts no mail", so SMTP DANE is moot.
    /// Excluded from the denominator like Indet, but it is a POSITIVE
    /// measurement ("we know precisely why it doesn't apply"), not
    /// "couldn't measure". Distinct claim, same arithmetic.
    NotApplicable = 3,
}

impl std::fmt::Display for TriState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriState::Present => write!(f, "PRESENT"),
            TriState::Absent => write!(f, "ABSENT"),
            TriState::Indet => write!(f, "INDET"),
            TriState::NotApplicable => write!(f, "NOT-APPLICABLE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TriState;

    /// The Rust TriState variants — the canonical, ordered set. The Lean model
    /// (lean/Scoring.lean) must declare exactly these four, same names, no
    /// more and no fewer. The proofs bind the LEAN model, not this enum — there
    /// is no extraction, codegen, or FFI — so this test is what keeps the two
    /// from drifting apart silently (the correspondence gap Claude Science
    /// flagged on the machine-checked-doctrine claim). If either side renames,
    /// adds, or removes a state, this fails at build time.
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
        let lean = include_str!("../../lean/Scoring.lean");
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
