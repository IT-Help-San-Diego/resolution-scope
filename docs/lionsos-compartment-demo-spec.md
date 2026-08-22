# lionsOS Compartment Demo Spec — Resolution Scope

Status: **draft** — the IPC contract is the load-bearing part; §1–§4 and §6+ are
summarized pointers to the canonical architecture record
(`docs/ARCHITECTURE.md`), which owns the full reasoning. This file exists so
the `ScoredAnalysis` IPC payload has a spec home to mirror — `analysis.rs`
already references `lionsOS-compartment-demo-spec.md §5`; until now that
section did not exist.

One-idea-one-home rule: **this file owns the IPC contract (what crosses the
boundary and why it is safe to trust).** `ARCHITECTURE.md §7` owns the *Option B
decision* (why validation runs outside the compartment). Each points at the
other; neither restates the other's reasoning.

## 1. Purpose

A LionsOS compartment on seL4 that isolates **storage** — the sealed
measurement history — from the analysis engine. The compartment's theorem is
narrow (ARCHITECTURE.md §3): the store cannot be silently drained, because it
holds no network capability and is reachable only through the interface it
exposes.

## 2. Compartments

- **engine** (std, Phase 1): runs DNS validation (hickory dnssec), produces
  verdicts. Runs outside the seL4 compartment for now — see ARCHITECTURE.md §7
  (the no_std DNSSEC decision).
- **report** (no_std): receives a `ScoredAnalysis`, renders the sealed report,
  writes to the path granted by `cap_local_report`. No network, no resolver,
  no tokio — pure synchronous logic.
- **store** (no_std): holds the sealed history; the compartment the §3 theorem
  protects.

## 3. Capabilities

Per the capability manifest (`docs/CAPABILITY-MANIFEST.md`), each compartment
receives only the capabilities its interface requires. `config` — the Go
parent's monolith — is the boundary violation to split, not a compartment to
replicate.

## 4. The store-drain theorem (day-one proof target)

The demo proves the store **cannot be silently drained**: a compromised engine
cannot exfiltrate beyond its granted capabilities. It does **not** prove a pwned
service is confined while the engine runs in a Linux guest — that is an
explicit non-goal (ARCHITECTURE.md §3).

## 5. IPC contract — what crosses the boundary

`ScoredAnalysis` is the payload. It crosses from **engine → report** and
**engine → store**. Its defining property: it is a **small, enumerated,
non-secret value**. Every field is either a domain name, an 8-disposition
verdict, a tri-state score, or an observation condition — nothing a compartment
needs to re-derive to be isolated, and nothing that grants further capability.

### 5.1 The trust-boundary caveat (Option B, verdicts-cross-boundary)

**What crosses the boundary is a verdict, not a validation.** Because DNSSEC
validation runs in the std engine (ARCHITECTURE.md §7, option B), the
compartment receives the *conclusion* of validation, never the proof.

This is an **accepted trust boundary**, stated explicitly so it is never left
implicit:

- **The compartment trusts the IPC channel.** A compromised std engine could
  store a *false* verdict — a well-formed, correctly-sealed, entirely wrong
  measurement. The store would faithfully persist it.
- **This is a different trust boundary than the §4 theorem addresses.** The
  §4 theorem is about *capability confinement* (can the store be drained? no).
  The §5.1 boundary is about *data integrity* (is the stored verdict true? the
  store cannot know).
- **It is accepted by design, not overlooked.** The alternative — hand-rolling
  DNSSEC validation on bare `ring` (option C) — trades this data-integrity
  boundary for the *wrong-verdict* failure class this project exists to detect
  in others (ARCHITECTURE.md §7). A false-verdict risk from a compromised
  engine is preferable to confident-wrong-verdicts from a subtly broken
  in-house validator.

**Consequences to name in any public claim:**

1. "Runs on a verified kernel" does **not** mean "every stored verdict is
   correct." The verified substrate guarantees the store is not *silently
   drained* and the report renderer is *confined*; it does not guarantee the
   verdicts were produced by an uncompromised, correct engine.
2. The seal is **tamper-evidence of the verdict after it crossed**, not proof
   the verdict was right when it crossed. A fabricated verdict can be sealed
   too — the seal binds the bytes, not their truth.
3. The long-term close of this boundary is option A (upstream no_std DNSSEC in
   hickory, ARCHITECTURE.md §7), which would let validation run *inside* a
   compartment. Until then, the boundary is real, documented, and accepted.

## 6. Report renderer — already compartment-shaped

`report.rs` is the model: it reads only a `ScoredAnalysis`, renders from the
single truth-chain producer, and writes through one granted capability. No
network, no resolver, no tokio — so it compiles for a no_std compartment today.
This is the template the store compartment follows.
