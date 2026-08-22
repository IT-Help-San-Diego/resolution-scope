# seL4 Demo — SDK/Toolchain Correction (supersedes the capDL finding's "next step")

**Date:** 2026-08-22 (overnight session, follow-up)
**Author:** Hermes lane (instrument/backend)
**Status:** the CAmkES path in `capdl-syntax-finding-20260822.md` is CORRECTED below

## 1. The correction

`docs/capdl-syntax-finding-20260822.md` §4 concluded the next step is to
"author the CAmkES/EasyConfig description and let the toolchain emit capDL."
That is **wrong for LionsOS**. Measured against the actual LionsOS tree (cloned
`au-ts/lionsos` + submodules this session):

1. **LionsOS builds on seL4 Microkit, not CAmkES.** The system description is a
   **`.system` XML** file (Microkit's format), not a CAmkES `.camkes` file and
   not a hand-written capDL. See `examples/kitty/board/qemu_virt_aarch64/kitty.system`
   for the canonical reference.
2. **capDL is not in the LionsOS authoring path at all.** Microkit generates the
   boot image directly from `.system`; capDL is a lower-level CAmkES-internal
   artifact that LionsOS does not expose. The hand-written
   `native/capdl/dns_sovereign_compartment.cdl` is therefore doubly obsolete: it
   is neither valid capDL (the syntax finding) nor the artifact LionsOS consumes.

## 2. What the correct authoring path is (measured from the tree)

A LionsOS system is described in a `.system` XML with:

- `<memory_region name="…" size="…" phys_addr="…"/>` — physical memory grants
- `<protection_domain name="…" priority="…" pp="…" passive="…">` — one PD per
  component (the seL4 compartment), containing `<program_image path="X.elf"/>`,
  `<irq irq="N" id="0"/>`, `<map mr="…" vaddr="…" perms="rw"/>`,
  `<setvar symbol="…" region_paddr="…"/>`
- `<channel>` elements connecting PDs (the IPC surface)

The build is Makefile-driven: `MICROKIT_SDK` (and, for LionsOS examples,
`LIONSOS` / `MICROKIT_CONFIG`) env vars, `make` from the example dir, producing
a Microkit `.img` bootable under QEMU.

The mapping to our compartment is direct and *simpler* than the capDL sketch:
our `report`/`store` PD holds **no `<irq>`, no network `<map>`, no network
`<memory_region>`** — only the IPC `<channel>` from the `engine` PD and the
`<memory_region>`/`<map>` for `cap_local_report` (write-only output) and the
clock. "No network capability" is expressed as the *absence* of those elements
in the `.system`, which is exactly the theorem the spec §4 wants.

## 3. Setup actually completed on the Beelink this session

- **ARM toolchain**: `arm-gnu-toolchain-12.3.rel1` `aarch64-none-elf-gcc`
  installed at `/opt/toolchain/…/bin`, verified `12.3.1 20230626`. This is the
  toolchain LionsOS requires (bare-metal `none-elf`, not the apt
  `aarch64-linux-gnu`).
- **LionsOS tree**: `git clone https://github.com/au-ts/lionsos.git` + all
  submodules (`dep/sddf`, `dep/libmicrokitco`, `dep/musllibc`, …) checked out.
- **Correction to the `repo` tool path**: LionsOS is NOT fetched via `repo init`
  (the manifest URL has moved and no longer applies). The current flow is plain
  `git clone` + `git submodule update --init`. The `~/bin/repo` tool installed
  earlier is unused; the older project docs that assumed a manifest are stale.

## 4. Remaining (the real next step, corrected)

1. **Microkit SDK** (`seL4/microkit`) — build it (it builds an seL4 kernel
   instance per platform, the QEMU virt aarch64 platform for our demo). The
   getting-started doc references a prebuilt download or a git build.
2. **Author the `.system` XML** for the one-compartment store demo: `engine`
   PD (std, outside — actually a Linux VM in the first cut) → `report`/`store`
   PD (no_std, inside, no network). This replaces the `.cdl` sketch entirely.
3. **no_std Rust support crate** — does LionsOS ship a usable `sel4-runtime`
   / Microkit Rust binding (SciSpace gating Q1)? Until then the `[[bin]]`'s
   `_start`/allocator/panic handler are the stand-ins.
4. **QEMU run** — boot the `.img` under `qemu-system-aarch64` (installed) and
   verify the compartment receives + seals + renders + writes, with no network.

## 5. Housekeeping

- `native/capdl/dns_sovereign_compartment.cdl` — keep as a *sketch of intent*
  (the capability table), but mark it explicitly "not an authoring artifact;
  see the .system file" to avoid a future lane treating it as build input.
- `docs/seL4-demo-native-receiver-milestone-20260822.md` §6 step 1 and
  `docs/capdl-syntax-finding-20260822.md` §4 both carry the now-corrected
  CAmkES wording; this file is the authoritative correction.
