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
}

impl std::fmt::Display for TriState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriState::Present => write!(f, "PRESENT"),
            TriState::Absent => write!(f, "ABSENT"),
            TriState::Indet => write!(f, "INDET"),
        }
    }
}
