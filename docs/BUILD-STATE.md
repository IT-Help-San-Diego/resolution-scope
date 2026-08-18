# Build State — Resolution Scope spike kit (adopted 2026-08-17)

Adopted from the SciSpace second-wave kit with the four corrections verified
against the tree. Two sibling crates, **no workspace** (feature-unification
between a std+tokio crate and a no_std crate is a real hazard).

## Layout

- `engine/` — Phase 1: std + tokio + hickory. **Builds on host.**
  `cargo build` ✅, `cargo test` ✅ (3 pass, 5 ignored live-network).
  `cargo check --no-default-features` **fails as designed** (exit 101) — the
  `dnssec-ring` compile guard fires; negative assertion verified.
- `native/` — Phase 2: no_std + smoltcp + hickory-proto. **Library builds on
  host** (`cargo build --lib` ✅, `cargo test --lib` ✅ 4 pass: tristate +
  sddf_device bounds). The `[[bin]]` (main_native.rs) is bare-metal only:
  `#![no_std]`, custom `#[panic_handler]`, `#[no_mangle] main`.

## Corrections applied at adoption

1. License `MIT OR Apache-2.0` → **AGPL-3.0** (repo is AGPL-from-birth).
2. Repo URL → `IT-Help-San-Diego/resolution-scope` (kit pointed at a
   nonexistent `it-help-tech/dns-tool-sovereign`).
3. Dropped `mdns` from Phase 2 (a posture scanner has no use for multicast).
4. Feature name unified to `dnssec-ring` — the kit's Phase 1 named it
   `dnssec`, which made the compile guard always fire (Phase 1 could never
   have compiled as shipped).

## Version reality (measured, not relayed)

- **hickory `0.26` does not exist on crates.io** — only `0.26.0-alpha.1`.
  Pinned to verified stable **0.25.2** (`cargo build` was the instrument).
- Kit API migrated to 0.25.2: `TokioAsyncResolver` is `Resolver<T>` re-export;
  construction is `builder_with_config(cfg, name_server::TokioConnectionProvider
  ::default()).with_options(opts).build()`; `ResolveErrorKind::NoRecordsFound`
  moved to `ProtoErrorKind` (matched via `ResolveErrorKind::Proto(e)` guard);
  `tls-ring` feature added for `cloudflare_tls()`.

## FINDING — the Phase 2 bare-metal blocker (the spike's first real result)

**hickory-proto 0.25.2's `dnssec-ring` transitively requires `std`.**
`dnssec-ring = ["dep:ring", "__dnssec"]` and `__dnssec = [..., "std"]`, and
`std` pulls `url/std` (percent-encoding) — so `cargo check --target
aarch64-unknown-none` fails in `percent-encoding`, `futures-core`, `getrandom`.
smoltcp's `socket-dns` also pulls `futures` (std).

**There is no no_std DNSSEC path in hickory today.** Options for the seL4
lane, unresolved: (a) upstream-hickory no_std DNSSEC feature request/fork,
(b) DNSSEC validation stays in the std Phase 1 engine and the native crate
only carries verdicts across the compartment boundary, (c) hand-rolled RRSIG
verify against `ring` directly. This is exactly the class of premise the
spike exists to falsify *before* the seL4 builder starts. Recorded here so
the builder is never started against a design that cannot compile.

The bare-metal bin build is therefore **deferred, not abandoned** — the
host-verified library + this finding is the honest spike state.
