# capDL Syntax Finding — the hand-written draft is NOT valid capDL

**Date:** 2026-08-22 (overnight session)
**Author:** Hermes lane (instrument/backend)
**Status:** finding recorded; the .cdl draft must be REGENERATED, not hand-fixed

## 1. What was checked

Cloned `seL4/capdl` and compared `native/capdl/dns_sovereign_compartment.cdl`
(the hand-written draft) against the known-good reference specs shipped in the
tool (`capDL-tool/example-aarch64.cdl`, `example.cdl`, and the CAmkES-generated
`camkes-adder-*.cdl` files, each with a `.right` file that is the parser's
expected output). This is a syntax-level comparison against the grammar the
`capdl-tool` parser accepts — answering SciSpace gating question #3.

## 2. Verdict: the draft is NOT valid capDL

It has multiple, specific, enumerable syntax errors. Four are structural:

| # | Draft says | capDL grammar requires | Evidence (example) |
|---|---|---|---|
| 1 | `cnode (12)` / `cnode (8)` | `cnode (N bits)` | `rm_cn = cnode (10 bits)` |
| 2 | `(rights: RWG)` / `(rights: W)` / `(rights: R)` | bare rights `(RWG)` / `(W)` / `(R)`, or `(masked: R)`, or generated `(mask: RWG)` — no `rights:` prefix | `0x12d: timer (G)`, `0x12f: name2 (masked: R)`, generated `(guard_size: 0, guard: 0, mask: RWG)` |
| 3 | a separate `tcbs { … }` block | TCB params go INLINE on the object declaration; `cspace:`/`vspace:` go in the `caps { }` section | `tcb = tcb (addr: 0x15000, ip: 0x00010000, sp: 0x00013000, prio: 42, init:[10,15], fault_ep: 1)` then `rm_tcb { vspace: rm_pd, cspace: rm_cn }` |
| 4 | `priority: 255` | `prio:` (inside the TCB object declaration, not a separate section) | `prio: 254, max_prio: 254` |

Additionally the draft omits the standard `irq maps { … }` and `cdt { … }`
sections that the reference specs carry (the CDT — capability derivation tree —
is where the root task's revocation after init would actually be expressed).

## 3. The deeper finding: capDL is the wrong artifact to hand-write

The `camkes-adder-*.cdl` files are the tell: they are **generated output** —
full of `addr: 0x14b000, ip: 0x17a24, sp: 0x149000, mask: RWG` — all values
that the CAmkES toolchain computes from a system description. Nobody writes
capDL by hand; the standard seL4 / CAmkES / LionsOS workflow is:

1. Write a **CAmkES / EasyConfig system description** (components, connections,
   attributes) — SciSpace gating question #2.
2. The CAmkES toolchain **generates** the capDL from that description.
3. `capdl-tool` consumes the generated capDL to produce the capDL loader.

The `.cdl` draft should therefore be treated as a *sketch of intent* (which
capabilities the compartment should hold), not as input to `capdl-tool`. The
correct next step is to author the CAmkES/EasyConfig description and let the
toolchain emit the capDL — the draft's role is to specify the *capability table*
in `docs/lionsos-compartment-demo-spec.md` §4, which the CAmkES description then
encodes.

## 4. What this means for the demo build

- **Do not fix the .cdl by hand.** Regenerating it by hand would just produce a
  second, larger hand-written file with the same drift risk.
- The CAmkES/EasyConfig description (Q2) is now the front of the queue. Until it
  exists, the .cdl remains a sketch (correctly labeled as such in the drift doc),
  and the seal/verify/Rust code built this session is unaffected — it is the
  *component* code, independent of the *system* description.
- `python-capdl-tool` (the Python module) does not parse .cdl text (it builds
  `Spec` objects programmatically); the .cdl text parser is the Haskell
  `capDL-tool`, which requires a Haskell toolchain to run. The example-comparison
  above is the cheaper, sufficient syntax check for now.

## 5. Reference

- `seL4/capdl` — `capDL-tool/example-aarch64.cdl` (aarch64 reference) and
  `camkes-adder-*.cdl` (CAmkES-generated reference).
- `docs/lionsos-compartment-demo-spec.md` §4 (the capability table the CAmkES
  description must encode) and §7 (boot sequence).
