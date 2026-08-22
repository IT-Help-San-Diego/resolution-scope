# seL4 Demo — Native Receiver Milestone (Option B compartment code)

**Date:** 2026-08-22 (overnight session)
**Author:** Hermes lane (instrument/backend)
**Status:** native crate rewritten + bare-metal bin links; LionsOS system build is next

## 1. What changed (supersedes the drift finding's "does not compile" state)

`docs/seL4-demo-state-and-model-drift-20260822.md` recorded that (a) the native
crate modeled the pre-B smoltcp/hickory DNS engine and (b) the bare-metal bin
"does not compile" on the `ring` → `assert.h` cross-compile gap. Both are now
resolved.

The native crate (`native/`) is rewritten as the **Option-B report/store
receiver** — the compartment described in `docs/ARCHITECTURE.md` §7 and the
capDL + spec:

- **receive** `ScoredAnalysis` + producing engine version over `ep_results_in` (STUB)
- **re-derive / verify** the SHA3-512 verdict seal (REAL, host-tested)
- **render** the report (REAL, minimal)
- **write** via `cap_local_report` (STUB)

No smoltcp, no hickory-proto, no ring, no network capability. The stale
`sddf_device.rs` (sDDF→smoltcp adapter) is deleted.

## 2. The ring→assert.h blocker is gone — by removal, not workaround

`ring` 0.17 has C sources that need a bare-metal aarch64 `assert.h`. The
compartment no longer needs ring because it does not do DNSSEC validation (that
stays in the std engine, Option B). The seal uses **sha3** (`sha3` 0.10), which
is pure Rust with zero C sources. Removing smoltcp + hickory-proto + ring
removed the entire cross-compile blocker.

## 3. Verified outcomes (measured, not asserted)

| Check | Result |
|---|---|
| `cargo test --lib` (host) | 5/5 pass, incl. `seal_matches_engine_golden_value` |
| `cargo build --lib --target aarch64-unknown-none` | clean |
| `cargo build --bin --target aarch64-unknown-none --release` | **links** — stripped 82KB statically-linked aarch64 ELF |
| `cargo clippy --lib -- -D warnings` | 0 warnings |
| `scripts/check-citation-boundary.sh` | PASSED (native has no RFC literals) |

The **golden-seal test** is the drift-pin: it asserts the native crate's
`seal_versioned(fixture, "0.1.0")` equals a value computed from the *engine*
(`9a0b7790…3a35`), so the type mirror cannot silently drift from the engine's
seal contract. This is the "two engines, one catalog" pattern applied to the
compartment.

## 4. The seal contract (load-bearing, byte-identical to engine)

```
resolution-scope-sha3-512-v2\n
<domain>\n
<engine version>\n
<resolver identity>\n
dnssec=<DnssecDisposition:?>=<TriState:?>\n   … 8 controls, Debug variant names
```

The types (`tristate.rs`, `types.rs`) mirror the engine's variant names exactly
— the seal binds the `Debug` representation, so a rename on either side breaks
the seal (correctly).

## 5. Still a thin copy (the honest caveat)

The types + seal are still a *mirror* of `engine/`, not a shared crate. The
correct long-term shape is a shared no_std `types` crate both crates depend on
(single-producer rule). The extraction is the follow-up and must ALSO update
`scripts/check-citation-boundary.sh`, because the citation-bearing
`truth_chain.rs` would move out of `engine/` alongside the types. Until then the
golden-seal test pins the mirror so it fails loudly on drift rather than
silently.

## 6. What the demo still needs (the next physical step)

The Rust compartment code now compiles bare-metal, but the *system* is not yet
built. Remaining, in order:

1. **LionsOS SDK checkout** + seL4 kernel + CAmkES + capDL tooling (toolchain is
   installed on the Beelink; the SDK is not yet cloned). **Note (2026-08-22):**
   `repo init -u https://github.com/au-ts/lionsos.git` fails with
   `manifest 'default.xml' not available` — the LionsOS repo structure has
   moved/changed since these docs were written. The current setup command must
   be re-read from the live `lionsos.org/docs/tutorials/gettingstarted/` (the
   site is JS-rendered, so fetch it in a browser or the SciSpace lane, not curl).
   The `repo` tool is already installed at `~/bin/repo` on the Beelink.
2. **capDL validation** — machine-check `native/capdl/dns_sovereign_compartment.cdl`
   with `capdl-tool` (the hand-written draft is a sketch, never machine-checked).
   This is SciSpace gating question #3.
3. **Minimal CAmkES/EasyConfig system** for a one-compartment store demo
   (SciSpace gating question #2) — `engine` (std, outside) → `report`/`store`
   (no_std, inside), no network capability.
4. **no_std Rust support crate** — does LionsOS ship a usable `sel4-runtime`
   (SciSpace gating question #1)? Until then the `[[bin]]`'s `_start`/allocator/
   panic handler are the spike stand-ins for what that crate provides.

## 7. Builder

The Beelink SER10 (`lab-pc`, x86_64, 24 cores, Ubuntu 24.04) is the local seL4
builder, replacing the stopped AWS `c7i.2xlarge`. It has clang 18, lld, ninja,
qemu-system-aarch64 8.2.2, gcc-aarch64-linux-gnu 13.3, gdb-multiarch, and the
`aarch64-unknown-none` rust target. The demo ships as a QEMU aarch64 image
(x86-64 builder cross-compiles to ARM — the world's majority arch).
