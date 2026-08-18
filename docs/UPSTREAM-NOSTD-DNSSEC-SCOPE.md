# `__dnssec` → no_std scoping (the fix-for-everyone technical core)

Measured against hickory-proto 0.26.1 (crates.io source) on 2026-08-18.
This is the upstream-contribution plan for making DNSSEC validation compile
on bare metal (option A in ARCHITECTURE.md §7).

## The problem, precisely

`hickory-proto 0.26.1` declares:

```
__dnssec = ["dep:bitflags", "dep:rustls-pki-types", "dep:time", "std"]
```

`"std"` is a **literal member**, so enabling ring DNSSEC enables std by
declaration (not by transitive accident). The bare-metal build then fails in
`percent-encoding` (via `url/std`), `getrandom`, and `rand/thread_rng`.

## What actually requires std (measured, not assumed)

The dnssec *code* is already almost entirely no_std-clean. Grep of
`src/dnssec/`:

- `signer.rs` uses `core::time::Duration` ✅ already no_std.
- `rdata/sig.rs`, `rdata/rrsig.rs` use `time::OffsetDateTime` — the `time`
  crate is no_std-capable (`alloc` feature; `std = ["alloc"]`).
- `use std::println` appears **only inside `#[cfg(test)]` modules** ✅.
- **The one std-only production site:** `trust_anchor.rs:21` uses
  `use std::{fs, path::Path}` — file I/O to read a trust-anchor file.

So the blockers are **three feature declarations**, not the code:

| Pin | Current | Fix |
|---|---|---|
| `__dnssec` list | `..., "std"]` | drop `"std"` (or gate it behind a std feature) |
| `ring` | `features = ["std"]` | `default-features = false, features = ["alloc"]` — ring is no_std via `alloc`; `std` only adds OS-entropy `SystemRandom`, which a device supplies itself |
| `time` | default (std) | `default-features = false, features = ["alloc"]` — `time::std = ["alloc"]`, so only `std::time` interop is lost |
| `rustls-pki-types` | default = `alloc` | **already no_std** (`default = ["alloc"]`, `std = ["alloc"]`) — no change |
| `bitflags` | default | **already no_std** (2.x is no_std by default) — no change |

## The transitive std that disappears when `"std"` is dropped

The blanket `std` feature pulls `url/std` (percent-encoding — the bare-metal
hard fail), `rand/std` + `rand/thread_rng` (needs OS entropy), `ring/std`,
`thiserror/std`, `tracing/std`, `data-encoding/std`, `ipnet/std`. Removing
`"std"` from `__dnssec` cuts the whole chain; the no_std build then supplies
a custom RNG via hickory's existing `no-std-rand` feature.

## The one code change: trust_anchor.rs

`std::{fs, path::Path}` reads a trust-anchor file from disk. A no_std target
has no filesystem. Fix: gate the file-reading behind a `std` feature, and
provide an in-memory trust-anchor constructor (a `&[u8]` / pre-parsed
`TrustAnchor` set) for no_std. The Lean/seL4 target already requires the trust
anchor to be capability-granted or embedded, so this aligns with the
architecture.

## Scope of the upstream PR

1. Drop `"std"` from `__dnssec`; make the `__dnssec` std-free path compile
   under `--no-default-features --features "dnssec-ring no-std-rand unstable"`.
2. Switch `ring` to `alloc`-only in the dnssec path.
3. Switch `time` to `alloc`-only.
4. Gate `trust_anchor.rs` file I/O; add an in-memory trust-anchor path.
5. Gate the `__dnssec` code behind the existing `unstable`/`no-std` features
   (matching the #2104 convention).

## Verification the fix is correct (not just compiles)

The acceptance test is fixture-parity: the no_std dnssec path, fed the same
DNSKEY/DS/RRSIG inputs as the std path, must produce **identical validation
verdicts** on the dns-evil-* fixtures and the recaptured golden set. A
no_std path that compiles but validates differently is worse than no path.

## What this does NOT require

No new crypto (ring already implements the algorithms), no new DNS wire logic
(hickory-proto already parses DNSKEY/DS/RRSIG in alloc), no async runtime.
The whole contribution is feature-graph surgery + one gated file-I/O site.
