// lib.rs — the render crate's public surface.
//
// Everything lives in render.rs (moved verbatim from cli/src/render.rs —
// the move is the extraction; no logic changes in this commit). This module
// re-exports the crate's public API so cli callers keep the same symbol
// names: resolution_scope_render::render_report etc. mirror the old
// crate::render::render_report.

pub mod render;

pub use render::*;
