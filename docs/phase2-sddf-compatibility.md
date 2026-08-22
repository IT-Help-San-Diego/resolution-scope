# Phase 2 sDDF compatibility — LionsOS 0.4.0 impact note

**Date:** 2026-08-22
**Trigger:** LionsOS shipped 0.4.0 (2026-08-21), one day before this note. The
release updated the seL4 Device Driver Framework (sDDF) — the layer the Phase 2
native path binds to.
**Scope:** the `native/` crate's `sddf_device.rs` adapter stub, and the
`native/Cargo.toml` dependency posture.

---

## What was verified (first-hand, not relayed)

| Fact | Evidence |
|---|---|
| LionsOS 0.4.0 is the current release | `gh release list --repo au-ts/lionsos` → `0.4.0 (Latest)`, tagged 2026-08-21 |
| sDDF was updated in the 0.4.0 line | PR #335 "Update sDDF, libVMM and sdfgen dependencies", merged 2026-08-13 (`gh pr view 335 --repo au-ts/lionsos`) |
| The native crate has no sDDF crate dependency yet | `native/Cargo.toml` — `sel4-runtime` is **commented out** with "Uncomment once the LionsOS Rust support package is chosen" |
| The adapter is a stub, abstract by design | `sddf_device.rs` — ring descriptors are our own `SddfRxDescriptor`/`SddfTxDescriptor` (`offset`/`len`), and every real ring-protocol step is a `TODO(sddf)` marker |

---

## The compatibility conclusion: the stub survives the bump

The `sddf_device.rs` adapter was deliberately written **version-agnostic**. It
defines its own abstract ring descriptors (`offset` + `len`) and implements the
`smoltcp::phy::Device` trait against those, NOT against any specific sDDF crate
type. The comments say exactly this:

> `TODO(sddf): replace with the actual sDDF ring descriptor type from the
> LionsOS Rust support crate when it is available.`

Consequently, the LionsOS 0.4.0 sDDF update **does not invalidate the stub**.
It changes *which* Rust support crate and *which* ring-descriptor type the
`TODO(sddf)` markers will eventually bind to — not the `Device`-trait contract
the stub already satisfies on the smoltcp side.

The load-bearing invariants are all upstream of the sDDF version:

- The capability model (`dma_frame_cap` slot 2, `net_tx_ntfn_cap` slot 3) is an
  seL4 fact, independent of sDDF's Rust API.
- The smoltcp `Device` trait (`receive`/`transmit`/`capabilities`) is pinned to
  smoltcp 0.11, not sDDF.
- The `ring`/`hickory-proto` no_std posture is unaffected by sDDF.

## What the 0.4.0 bump actually changes (and the one action it forces)

The one concrete consequence: **when the seL4 builder is provisioned, the
`TODO(sddf)` integration must bind to the 0.4.0-era sDDF Rust bindings, not a
0.3-era snapshot.** The `native/Cargo.toml` already encodes this correctly —
the `sel4-runtime` dependency is held open ("Uncomment once the LionsOS Rust
support package is chosen") rather than pinned to a stale version. That posture
is exactly right and should be preserved: do not pin sDDF until the builder is
real and the 0.4.0 API surface is read directly.

## Not verified (do not assert)

The following came from a peer-lane report and were **not** independently
verified against the sDDF diff. They are recorded as integration-time
checklist items, not facts:

- Whether the sDDF update is a dependency bump vs. a breaking ring-protocol
  redesign (the PR title says "Update … dependencies", but the diff was not
  read).
- The specific `sdfgen` / `libVMM` version deltas.
- Whether the 0.4.0 firewall multi-interface work changes sDDF network
  isolation semantics.

These are the items to confirm when the builder lane opens — they affect
integration cost, not the architecture.

## Net effect on Phase 2 sequencing

**No change to the locked architecture.** Phase 2 remains: abstract
`Device`-trait stub now, real sDDF binding later. The 0.4.0 release is a
*signal that the target platform is still moving*, which is why the stub's
version-agnostic design and the held-open `sel4-runtime` dependency are both
correct and should be kept as-is. The §2 milestone gate (5 concurrent smoltcp
UDP queries with per-query deadlines) is unchanged and still gated on the
builder + the hickory no_std question (see `UPSTREAM-NOSTD-DNSSEC-SCOPE.md`).
