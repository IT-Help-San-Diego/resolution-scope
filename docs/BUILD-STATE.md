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

## Version reality (measured twice, corrected once)

- First pass wrongly concluded "hickory 0.26 does not exist on crates.io" —
  that was a **stale local registry index** read as a version fact (Claude
  Science caught it: `cargo search` sees 0.26.1 live while a stale index shows
  only 0.26.0-alpha.1). The kit's `"0.26"` caret pin was valid all along.
- **Resolved to 0.26.1** after `cargo update`. Note: `hickory-client` has NO
  0.26 stable (alpha only) — but it was a **dead dependency** (never imported
  in the kit), so it was removed rather than pinned back.
- API migration at 0.26.1 (verified against the crate sources): `TokioResolver`
  (not `TokioAsyncResolver`); construction is
  `builder_with_config(ResolverConfig::tls(&config::CLOUDFLARE),
  net::runtime::TokioRuntimeProvider::default()).with_options(opts).build()?`;
  "no records" is `NetError::is_no_records_found()` (the nested
  `ResolveErrorKind::Proto(ProtoErrorKind::NoRecordsFound)` match is gone);
  `Lookup.answers()` returns `&[Record]`; `Record.data` is a public field;
  TXT strings are `rec.data`'s `txt_data: Box<[Box<[u8]>]>`.

## FINDING — the Phase 2 bare-metal blocker (verified at BOTH 0.25.2 AND 0.26.1)

**hickory-proto's `dnssec-ring` transitively requires `std` at 0.26.1 too.**
`dnssec-ring = ["dep:ring", "__dnssec"]` and `__dnssec = [..., "std"]` —
identical structure in both versions (the 0.25.2 doubt did not survive
re-measurement). `cargo check --target aarch64-unknown-none` fails in
`percent-encoding` (via `url/std`) and `getrandom`. smoltcp's `socket-dns`
also pulls `futures` (std).

**There is no no_std DNSSEC path in hickory today — now robust across the
current stable.** The strongest form of this claim is the published manifest,
not the compile error: `hickory-proto` 0.26.1 declares
`__dnssec = ["dep:bitflags", "dep:rustls-pki-types", "dep:time", "std"]` with
**`std` as a literal member**, and `dnssec-ring = ["dep:ring", "__dnssec"]` —
so ring DNSSEC enables `std` **by declaration**, not by accident of a
transitive dep. A build error can be a toolchain artifact; a feature
declaration in the published manifest is the crate's own stated contract,
checkable by anyone on crates.io without a cross-compiler. (The bare-metal
`cargo check --target aarch64-unknown-none` failure in `percent-encoding` /
`getrandom` corroborates it but is not the load-bearing evidence.)

The bare-metal bin build is therefore **deferred, not abandoned** — the
host-verified library + this finding is the honest spike state.
