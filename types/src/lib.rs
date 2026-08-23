//! # resolution-scope-types
//!
//! The single producer of Resolution Scope's verdict type surface: [`TriState`],
//! the eight per-control disposition enums, and the [`ScoredAnalysis`] IPC
//! payload (spec §5). `#![no_std]` — compiled by both the std engine (Phase 1,
//! `engine/`) and the bare-metal native compartment (Phase 2 Option B,
//! `native/`).
//!
//! ## Why this crate exists
//!
//! The verdict seal binds the `Debug` representation of these types — the enum
//! VARIANT NAMES — so a verdict sealed by the engine must deserialize into
//! byte-identical types in the store, or the seal fails verification. Before
//! this crate, `native/src/{tristate,types}.rs` were hand-kept mirrors of
//! `engine/src/{tristate,analysis}.rs`. A hand-kept mirror WILL drift, and the
//! golden-seal test only *detects* the drift after it happens — it cannot
//! prevent it. Moving the type surface here makes drift structurally impossible:
//! both consumers compile against the same definitions (single-producer rule).
//!
//! `ScoredAnalysis` carries `#[serde(deny_unknown_fields)]` so a version-skewed
//! store receiving a newer engine's payload fails LOUDLY instead of silently
//! dropping the fields it does not recognise (the silent-field-drop class).

#![no_std]

extern crate alloc;

mod dispositions;
mod tristate;

pub use dispositions::{
    CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
    DnssecDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition, TlsaZone,
};
pub use tristate::TriState;
