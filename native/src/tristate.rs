// tristate.rs — Core scoring primitive
//
// MIRROR of engine/src/tristate.rs. The native compartment re-derives the
// verdict seal, and the seal binds the Debug representation of TriState (the
// variant NAME), so these variants must be byte-identical to the engine's.
// Drift is caught by the golden-seal test in seal.rs.
//
// MIRROR NOTICE: temporary thin copy. The correct long-term shape is a shared
// no_std "types" crate that both engine/ and native/ depend on (single-producer
// rule). See the header in types.rs for the follow-up.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TriState {
    /// Control exists and is cryptographically valid.
    Present = 0,
    /// Control is absent or invalid — counted in the score denominator.
    Absent = 1,
    /// Could not measure — excluded from denominator, shown as "?" in the UI.
    Indet = 2,
    /// Measured, and the control does not apply (e.g. null MX) — a POSITIVE
    /// measurement, excluded from the denominator like Indet.
    NotApplicable = 3,
}

impl core::fmt::Display for TriState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TriState::Present => write!(f, "PRESENT"),
            TriState::Absent => write!(f, "ABSENT"),
            TriState::Indet => write!(f, "INDET"),
            TriState::NotApplicable => write!(f, "NOT-APPLICABLE"),
        }
    }
}
