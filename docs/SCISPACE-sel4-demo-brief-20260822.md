# SciSpace Brief — seL4/LionsOS compartment demo (Option B)

**From:** Hermes lane (instrument/backend), resolution-scope
**To:** SciSpace (remote, outbound-verified, git read-only)
**Date:** 2026-08-22
**Repo:** https://github.com/IT-Help-San-Diego/resolution-scope

## Context (read this first)

Resolution Scope is a sovereign DNS-resolution instrument (8 controls, SHA3-512
sealed verdicts). We are moving its storage layer onto seL4/LionsOS. The adopted
decision is **Option B** (see `docs/ARCHITECTURE.md` §7): DNSSEC *validation*
runs in a std (tokio+hickory) engine OUTSIDE the compartment; only *sealed
verdicts* (a `ScoredAnalysis` — small, enumerated, non-secret) cross the IPC
boundary into a **storage-only** compartment that holds no network capability.
The theorem the demo proves (`docs/ARCHITECTURE.md` §3): the store cannot be
silently drained, because it holds no network cap and is reachable only through
the interface it exposes.

## The three questions that gate the builder work

Answer each with a **source** (file/line, release tag, PR number, or a
first-hand fetch), not an assertion. If you cannot verify something, say
"unverified" rather than guessing.

### Q1 — Does LionsOS 0.4.0 ship a usable no_std Rust support crate now?

`native/Cargo.toml` still has `sel4-runtime` **commented out** with the note
"Uncomment once the LionsOS Rust support package is chosen." LionsOS shipped
0.4.0 (tagged 2026-08-21, PR #335 "Update sDDF, libVMM and sdfgen
dependencies"). We need to know:

- Is there an official `rust-sel4` / `sel4-runtime` crate that supports a
  no_std Rust *native service* (not just the root task) at 0.4.0?
- If yes: crate name, version, and whether it provides `#[panic_handler]`,
  an allocator, and BootInfo extraction for a native service (not root task).
- If no: state that plainly — it changes the demo's Rust-integration plan.

### Q2 — Minimal CAmkES/EasyConfig system for a one-compartment store demo

We have a hand-written `native/capdl/dns_sovereign_compartment.cdl` (a sketch,
`arch aarch64`, two components: query-engine + storage compartment). It has NOT
been run through `capdl-tool`. We need the minimal *real* shape:

- For a LionsOS native service that only (a) receives an IPC message, (b) writes
  through one frame capability, (c) holds **no** network/device capability —
  what is the smallest `system.camkes` / EasyConfig that builds and boots?
- Is a raw `.cdl` even the right entry point in 0.4.0, or does LionsOS want
  `system.camkes` + a `device_tree` fragment instead?

### Q3 — Is the `.cdl` draft valid capDL syntax for `capdl-tool`?

Reading `native/capdl/dns_sovereign_compartment.cdl`: are `objects { … }`,
`caps { … }`, and `tcbs { … }` the correct capDL sections, and are the
`(rights: RWG)` / `(rights: W)` / `(guard: 0, guard_size: 0)` annotations valid?
If you can identify concrete syntax errors by inspection, list them with the
line number.

## Do not do

- Do not propose building DNSSEC validation inside the no_std compartment (that
  is Option C, already argued against — see ARCHITECTURE.md §7).
- Do not treat the hand-written `.cdl` as validated; it is a draft until
  `capdl-tool` runs it.

## Deliverable

A short answer per question, each with its source. Write it to a file in the
repo (or reply in a block Carey will paste back); we will land it under
`docs/` with your attribution.
