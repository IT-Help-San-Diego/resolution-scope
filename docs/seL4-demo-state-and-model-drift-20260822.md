# seL4 Demo — State and Model-Drift Finding

> ✅ **RESOLVED 2026-08-22** — the three-way drift described below is fixed: the
> native crate was rewritten as the Option-B report/store receiver (no smoltcp,
> no hickory, no ring, no network), the bare-metal bin links, and the store
> compartment now BOOTS and passes a verdict on the sealed channel. See
> `docs/seL4-demo-native-receiver-milestone-20260822.md` and
> `docs/seL4-demo-toolchain-verified-20260822.md`. This file is kept as the
> historical record of the finding (and its measured evidence), not as current
> state.

**Date:** 2026-08-22
**Author:** Hermes lane (instrument/backend)
**Status:** RESOLVED (was: finding recorded; builder lane is the next step)

## 1. What the demo actually requires (measured, not assumed)

The seL4/LionsOS compartment demo cannot be built or run from this Mac. Three
independent facts, each verified first-hand this session:

1. **No seL4/LionsOS toolchain exists here.** `capdl-tool`, `seL4-config`,
   `camkes` are all absent; there is no `rust-sel4` / `lionsos` checkout
   anywhere on disk (only the `aarch64-unknown-none` rust target is installed).
2. **The bare-metal bin does not compile on this host** — and it is a *toolchain*
   gap, not a code bug: `ring` 0.17.14's C sources need `assert.h` when
   `cc` cross-compiles for `aarch64-unknown-none`, and this Mac has no bare-metal
   aarch64 C toolchain. (The older "12 errors against hickory-proto no_std API"
   note in BUILD-STATE.md is a *separate*, earlier failure; both are real and
   both are toolchain/target gaps, not logic defects.)
3. **The seL4 builder is stopped.** `i-08ca65b7acd2dc275`, `c7i.2xlarge`,
   `44.228.179.31`, state `stopped`. It is the only host with the toolchain the
   demo needs.

## 2. The finding: three models, one of them stale

The repo currently describes the compartment in **three ways, and only two agree.**

| Source | What the compartment IS | Matches Option B? |
|---|---|---|
| `docs/ARCHITECTURE.md` §7 (the adopted decision) | storage isolation: sealed **verdicts** cross the boundary; DNSSEC validation stays in the std engine outside | ✅ the decision itself |
| `docs/lionsos-compartment-demo-spec.md` §2 + `native/capdl/dns_sovereign_compartment.cdl` | `engine` (std) outside; `report`+`store` (no_std) inside, **no network capability** — `ep_results_in`(R), `ep_domain_in`(R), `cap_local_report`(W), `cap_display`(W), clock(R) | ✅ consistent with B |
| `native/src/main_native.rs` + `native/src/sddf_device.rs` | the no_std compartment **itself runs smoltcp UDP + hickory-proto and does the DNS query**, holding `dma_frame_cap` (slot 2) + `net_tx_ntfn_cap` (slot 3) | ❌ **contradicts B** |

The contradiction is concrete and checkable: `sddf_device.rs` cites
"`dma_frame_cap` slot 2" and "`net_tx_ntfn_cap` slot 3", but the capDL `objects`
block contains **no `dma_frame` object and no `net_tx_ntfn` object** (`grep -c`
returns 0). The capDL models the Option-B storage compartment (no network); the
Rust `[[bin]]` still models the pre-B "DNS engine inside the compartment" shape
that Option B explicitly abandoned.

**Why it matters:** under B the compartment's whole point (§3 theorem) is that
the store holds *no network capability* and can't be drained. A compartment that
runs smoltcp DNS over a DMA frame is the opposite of that. The two source files
are the stale ones — the capDL and the spec are correct and already encode B.

## 3. What "build the demo" now concretely means

Under B, the demo needs a **new no_std compartment component** — the
report/store receiver — not the existing smoltcp DNS engine:

- receive `ScoredAnalysis` over `ep_results_in`
- re-derive/verify the seal, render, write via `cap_local_report`
- **no smoltcp, no hickory-proto, no network cap**

The existing `main_native.rs`/`sddf_device.rs` (smoltcp + hickory-proto DNS) is
the *query-engine* path, which under B lives in the std Phase-1 engine — outside
the compartment, already differential-verified. It is not the compartment and
should not be mistaken for it.

And it all still needs the builder: LionsOS checkout + toolchain + a
CAmkES/EasyConfig system description (the hand-written `.cdl` draft is a sketch,
not yet machine-checked by `capdl-tool`) on the stopped `c7i.2xlarge`.

## 4. Cost gate (this is a Carey decision, not an agent one)

`c7i.2xlarge` is a large box; spinning it up is a real per-hour cost and
rent-critical by standing policy. The demo cannot advance past §1–§3 of this
note until the builder is started — which is a **human** go/no-go, not
something an agent starts unattended.

## 5. What was done this session without the builder (verifiable)

- Fixed the `.cdl` draft's two mechanical defects: `arch ia32` → `arch aarch64`
  (matches the `aarch64-unknown-none` target), and the dangling
  `/home/sandbox/lionsOS-compartment-demo-spec.md` reference → the repo path.
- Measured the native crate truth: `--lib` builds and 4/4 tests pass on host;
  the bare-metal `[[bin]]` fails on the `ring`→`assert.h` toolchain gap (not a
  logic defect).
- Recorded the three-way model drift so it is named, not silent.

## 6. Open questions routed to SciSpace (outbound-verified, git read-only)

See `docs/SCISPACE-sel4-demo-brief-20260822.md`. The three questions that
actually gate the builder work: (1) does LionsOS 0.4.0 ship a usable no_std
Rust support crate now (the `sel4-runtime` dep is still commented out); (2) what
is the minimal CAmkES/EasyConfig system for a one-compartment store demo; (3) is
the `.cdl` draft valid capDL syntax to hand `capdl-tool`.
