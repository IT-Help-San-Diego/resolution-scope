# SciSpace Debrief — Resolution Scope seL4 foundation, full catch-up + second-opinion asks

**From:** Hermes lane (instrument/backend), resolution-scope
**To:** SciSpace (remote, git read-only)
**Date:** 2026-08-22
**Repo:** https://github.com/IT-Help-San-Diego/resolution-scope
**Commit to read against:** `2e7984d7cb7d075b23ac281f1ede11147970aa86`
**Supersedes:** `docs/SCISPACE-sel4-demo-brief-20260822.md` (its Q2/Q3 were
answered by a correction — read §3 below before acting on anything from that brief)

---

## 0. TL;DR — what changed since the last brief

The prior brief asked three questions about CAmkES/capDL. **Two of those
questions were answered by a correction, not by an answer**: the whole premise
was wrong. LionsOS does NOT use CAmkES or hand-written capDL — it uses **seL4
Microkit**, whose `bin/microkit` tool *generates* capDL from a `.system` XML
description. So:

- **Q1 (Rust support crate):** answered below (§4) — **no** first-class
  `sel4-runtime` for native services; the binding is `libmicrokitco` (C/C++).
- **Q2 (minimal CAmkES system):** **moot** — the authoring artifact is a
  `.system` XML, and we have already authored + booted it (§3).
- **Q3 (is the `.cdl` valid capDL):** **moot** — the `.cdl` was never valid
  capDL, and it is not the authoring artifact. Marked obsolete (§3).

The demo went from "blocked on a bare-metal compile error" to "a verified
seL4 kernel running our two-PD store compartment with no network capability, in
one overnight session." Everything below is the evidence for that, and the
specific foundation claims we want you to independently verify.

---

## 1. What Resolution Scope is (unchanged context, for completeness)

A sovereign DNS-resolution instrument: 8 controls (DNSSEC, SPF, DKIM, DMARC,
DANE, MTA-STS, CAA, CDS/CDNSKEY), each verdict sealed with SHA3-512 so anyone
can re-derive it. The storage layer is being moved onto seL4/LionsOS.

**Option B (adopted, `docs/ARCHITECTURE.md` §7):** DNSSEC *validation* runs in a
std (tokio+hickory) engine OUTSIDE the compartment; only *sealed verdicts* — a
`ScoredAnalysis`, small/enumerated/non-secret — cross the IPC boundary into a
**storage-only** compartment holding no network capability. The theorem (§3):
the store cannot be silently drained because it holds no network cap and is
reachable only through the interface it exposes.

---

## 2. The overnight arc (what got built, in dependency order)

Each item is a commit on `main`; read them in this order if you want the full
narrative.

1. **`5ce2b8a` — native crate rewritten as the Option-B receiver.** The old
   crate modeled the *pre-B* "DNS engine inside the compartment" shape
   (smoltcp + hickory-proto + ring, holding `dma_frame_cap` + `net_tx_ntfn_cap`).
   That contradicted Option B. Rewritten to a **report/store receiver**: receives
   `ScoredAnalysis`, re-derives the SHA3-512 seal, verifies, renders, writes.
   No smoltcp, no hickory, no ring, no network. Net −1331 lines (699 add, 2030
   del). `sddf_device.rs` deleted.
2. **`34eaaed` — bare-metal bin links on stable Rust.** The prior blocker
   (`ring` 0.17 → `assert.h` cross-compile) vanished by *removal*: sha3 (pure
   Rust) replaced ring. Added `#![no_main]`, `fn main()` (not `-> !`), dropped
   the nightly-only `#[alloc_error_handler]`, `spin_loop` halts.
3. **`5ce2b8a`'s golden test — seal byte-identity pinned.** A known-answer test
   asserts the native crate's `seal_versioned(fixture, "0.1.0")` equals a value
   computed from the *engine*:
   `9a0b7790ff865f24df52ae0449284809cd7f61c5d4ea267f292de8650adcdb2bfdee735e15d4a9bf7ea84052c5b3f6c49cbd0062e30c1f13d4f37ebd70203a35`.
   The type mirror (tristate + 8 disposition enums + ScoredAnalysis) cannot
   silently drift from the engine's seal contract.
4. **Toolchain (not committed — on the Beelink box `lab-pc`):** ARM 12.3
   `aarch64-none-elf-gcc` (verified `12.3.1`), LionsOS tree + submodules,
   **Microkit SDK 2.3.0** (pre-built linux-x86-64, GPG **Good signature** from
   Julia Vassiliki, fp `FE91 4864 43B0 F4EB 9ECC 3652 4D86 8A34 EDF3 FDCA`, key
   from keys.openpgp.org).
5. **`88c6226` — QEMU boot gap resolved.** The `KERNEL DATA ABORT` (GIC
   distributor) was a wrong QEMU invocation, not a kernel defect. Microkit
   manual §8.13 gives the canonical command: `-device
   loader,file=<img>,addr=0x70000000,cpu-num=0 -m size=2G` — NOT `-kernel`, and
   **2GB** (the `platform_gen.json` 1.5GiB region was a red herring). With it,
   the hello example boots and prints `hello, world` through seL4 → CapDL
   initializer → Microkit monitor → PD.
6. **`9adb9be` — store-compartment `.system` authored + booted.** Two PDs
   (`engine` stub → passive `store`) over ONE `<channel>`; the store PD holds
   **no `<irq>`, no network `<map>`, no network `<memory_region>`** — "no
   network capability" is structural. Boots and prints:
   ```
   store: init (passive, no network, no irq)
   MON|INFO: PD 'store' is now passive!
   engine: init (stub, sends one verdict)
   store: received verdict on channel (sealed)
   ```
7. **`2e7984d` — C-ABI FFI seam.** The store compartment's single C entry point
   (`rs_store_report` / `rs_store_free`), the exact Rust↔Microkit boundary. See
   §5 — this is the main thing we want verified.

---

## 3. The correction (please absorb before answering anything)

The prior brief's Q2/Q3 asked about CAmkES and hand-written capDL. **Both were
wrong premises.** Measured against the actual LionsOS tree:

- **LionsOS builds on seL4 Microkit, not CAmkES.** The system description is a
  `.system` XML (`<memory_region>`, `<protection_domain>`, `<channel>`, `<map>`,
  `<setvar>`). Reference: `microkit-sdk-2.3.0/example/kitty/.../kitty.system`.
- **capDL is generated, not authored.** `bin/microkit` consumes the `.system`
  and emits the capDL + boot image internally. The hand-written
  `native/capdl/dns_sovereign_compartment.cdl` was never valid capDL syntax AND
  is not the authoring artifact. It is now marked OBSOLETE in its own header.
- **LionsOS is fetched via `git clone` + `git submodule update --init`, NOT
  `repo init`** (the manifest URL moved).

`docs/seL4-demo-microkit-sdk-correction-20260822.md` is the authoritative
correction record.

---

## 4. Q1 (carried over, now answered with a measured fact)

**Does LionsOS ship a no_std Rust support crate for native services?**

Measured: **no.** The LionsOS tree (`~/lionsos`, submodules included) has no
Rust crate; `find` for `*.rs` returns nothing under the components/lib paths.
The Microkit binding is **`libmicrokitco`** (`~/lionsos/dep/libmicrokitco`, a
C/C++ library built via `build.zig`). There is no `sel4-runtime` Rust crate
usable for a native service at 0.4.0.

**Implication (this is what §5's FFI seam is for):** the no_std Rust compartment
must be reached through a C boundary — either a C shim calling Rust
`extern "C"`, or Rust linking `libmicrokitco` directly. We chose the C-ABI seam
as the foundation-independent middle.

---

## 5. Second-opinion ask #1 — the FFI seam (main thing to verify)

`native/src/ffi.rs` defines two `#[no_mangle] pub unsafe extern "C" fn`:

```rust
rs_store_report(json: *const u8, json_len: usize,
                claimed_seal: *const c_char, produced_by: *const c_char)
    -> *mut c_char
rs_store_free(ptr: *mut c_char)
```

Semantics:
1. deserialize `ScoredAnalysis` from `json` (serde_json, alloc-only — the same
   wire format the std engine emits);
2. re-derive SHA3-512 seal over (verdict, engine version);
3. compare to `claimed_seal` — **mismatch or parse-failure → NULL** (tamper
   evidence, fail-closed);
4. on match, render the report, return NUL-terminated UTF-8 on the heap;
   caller frees with `rs_store_free`.

Proven: 8/8 host lib tests pass (incl. round-trip golden seal, tampered-seal
reject, garbage reject); lib compiles `aarch64-unknown-none`; `nm` shows
`T rs_store_report` / `T rs_store_free` exported.

**Questions for you (source-backed, not assertion):**

- **A. Is the fail-closed semantics correct?** We reject (NULL) on seal
  mismatch OR deserialize failure. Is there any legitimate case where the store
  should record *something* (even a tombstone "verdict arrived but unverifiable")
  rather than drop it silently, for auditability? The §4 store-drain theorem
  says "cannot be silently drained" — does a silent NULL drop violate the
  *spirit* of that (undetectable loss) even though it doesn't drain capability?
- **B. Is `serde_json` (alloc-only) the right wire format for the IPC boundary,**
  or is a fixed binary layout preferable for a compartment (smaller TCB, no
  JSON parser, deterministic size)? We chose JSON because the engine already
  emits it — is "same as engine" a strong enough reason, or does a storage
  compartment's minimized attack surface argue for a length-delimited binary
  encoding?
- **C. Any soundness issue with `unsafe extern "C"` + the bump allocator** as
  written? The `rs_store_free` takes a pointer the caller must have gotten from
  `rs_store_report`; the bump allocator never reuses. Is there a use-after-free
  / double-free hazard we're not seeing?

---

## 6. Second-opinion ask #2 — the type mirror vs. shared crate

`native/src/{tristate,types,seal}.rs` are **thin copies** of the engine's types
and seal. The golden test makes drift *detectable*, not impossible. The
long-term shape is a shared no_std crate both depend on (single-producer rule).

**Question:** is the golden-known-answer test a sufficient bridge for now, or is
the mirror a lurking defect class we should close *before* Stage 2 (wiring the
Rust into seL4)? The extraction must also move `truth_chain.rs` (the
citation-bearing layer) out of `engine/`, which touches
`scripts/check-citation-boundary.sh`. Ordering question: **extract-the-shared-crate
first, or wire-the-FFI-first?**

---

## 7. Second-opinion ask #3 — the foundation audit, checked

I ran a self-audit and closed 5 drift items (§0 of the memory, commit
`1b34d05` + `3ad2204`). The concern: **did I miss any hole?** Specifically:

- Are there docs still describing the pre-B smoltcp/sDDF shape as current that
  I did *not* mark superseded? (I marked `ARCHITECTURE.md` §1/§2,
  `phase2-sddf-compatibility.md`, the `.cdl`, and the model-drift doc.)
- I deliberately left `SCISPACE_nostd_dnssec_status.md` and
  `UPSTREAM-NOSTD-DNSSEC-SCOPE.md` **unmarked** because they document Option A
  (upstream no_std DNSSEC), a live long-term item — not abandoned. Correct call,
  or should those also carry a "current status: Option A, not the active build"
  banner to prevent a reader mistaking them for the current plan?
- The CI `native-lib` job gates `--lib` only (the bare-metal bin is the recorded
  Phase-2 debt). Is that a hole — a bare-metal bin that could rot silently with
  no CI — or acceptable because the bin is a spike not a product artifact?

---

## 8. What we are NOT asking (do not spend effort here)

- Do not re-litigate Option A vs B vs C (`ARCHITECTURE.md` §7 already decides).
- Do not re-verify the RFC citation work (already independently verified by you
  in the Arm-2 arc; still green).
- Do not propose building DNSSEC validation inside the compartment (Option C,
  argued against).

---

## Deliverable

For each of the three "second-opinion ask" sections: a short, source-backed
answer (file/line, release tag, PR number, or first-hand fetch — never an
assertion). Say "unverified" where you cannot verify. Land it in the repo (or
reply in a block Carey will paste); we will commit it under `docs/` with your
attribution.
