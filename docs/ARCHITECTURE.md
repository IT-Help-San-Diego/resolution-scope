# Resolution Scope — Verified-Substrate Architecture Record

The load-bearing claims for the seL4/LionsOS direction, stated in their
measured form. Every claim here is scoped to what was measured; nothing
below asserts beyond the evidence.

## 1. The concurrency claim (measured on the Go parent)

The requirement for a native (no-Linux) engine is **not** a tokio port:

- **The DNS protocol work is synchronous.** Parsing, validation, record
  comparison need no async runtime.
- **The fan-out is ours.** Measured on `dns-tool-intel`:
  - `dnsclient/client.go`: the five-resolver sweep is `go func(ip)` per
    resolver — 6 goroutines, 6 channels, 7 timeout contexts.
  - `analyzer/orchestrator.go`: 4 fan-out goroutines; `dkim.go`: 2;
    `dane.go`: 1.
- **The requirement, stated precisely (PRE-OPTION-B, superseded 2026-08-22):** a
  native service must issue N concurrent UDP queries over the no-std stack
  (smoltcp) with independent per-query deadlines. That is job scheduling, not a
  general-purpose async runtime.

  **SUPERSEDED by Option B (§7):** under the adopted decision, the seL4
  compartment is the report/store RECEIVER — no smoltcp, no network, no
  resolver (see `docs/seL4-demo-native-receiver-milestone-20260822.md`). The
  smoltcp/sDDF fan-out question is therefore not on the compartment's path; it
  remains relevant only to Option A (upstream no_std DNSSEC), which is a
  no-deadline long-term item, not the current build.

A serial sweep is the wrong instrument regardless: the parallel sweep is
what makes cross-resolver disagreement measurable in a single pass — the
tool's entire DNSSEC/consensus story.

## 2. Guest-deletion acceptance criterion

**Milestone gate (PRE-OPTION-B, superseded 2026-08-22):** can a native LionsOS
service issue five concurrent smoltcp UDP queries with independent per-query
deadlines?

- **Yes** → the Linux guest layer is deletable from the architecture.
- **No** → the guest stays, and every public claim narrows to what was
  measured.

  **SUPERSEDED by Option B (§7):** this gate tested the pre-B "DNS engine inside
  the compartment" shape. The adopted shape is storage isolation — the store
  holds no network capability and cannot be drained (the §3 theorem) — so the
  guest-deletion question is decoupled from the smoltcp fan-out. The current
  milestone is the store-compartment boot + verdict-over-channel proof
  (`docs/seL4-demo-toolchain-verified-20260822.md` §4).

The criterion is testable in the spike and is the go/no-go for removing the
nested layer.

## 3. The theorem the demo proves (day one, stated narrowly)

- The store compartment cannot be reached except through the interface it
  exposes, and a compromised engine cannot exfiltrate beyond its granted
  capabilities.
- **The demo proves "the store cannot be silently drained."** It does NOT
  prove "a pwned service is confined" while the engine runs in a Linux
  guest — the kernel's proof says nothing about what happens *within* a
  compartment, and the guest holds every secret in one address space.
- A monolith inside a verified kernel is a monolith. The verified substrate
  rewards a decomposed application; it does not create one.

## 4. The capability manifest (prerequisite, writable before any seL4 work)

The confinement is only as good as the decomposition. Measured on the Go
parent: the server process reads 20 distinct secrets from its environment
(`DATABASE_URL`, `PROBE_API_KEY`, `GOOGLE_CLIENT_SECRET`, `SESSION_SECRET`,
`DISCORD_WEBHOOK_URL` among them) and holds the DB pool and the outbound
probe client in one process — one compromised handler currently has all of
it.

**Action, ahead of the demo:** enumerate which of the secrets each
future compartment needs (scanner: network + `PROBE_*`; filter:
network+storage; store: `DATABASE_URL` only, no network). The generated
manifest with its producing grep lives at
[CAPABILITY-MANIFEST.md](CAPABILITY-MANIFEST.md); its first measured finding
is that `internal/config` reads all 34 env vars, so `config` itself is the
boundary violation to split — fixable today on ordinary Linux.

## 5. Hypervisor honesty (public copy, verbatim)

On a rented instance, seL4 runs as the guest OS of the provider's
hypervisor — that layer is irremovable on virtual hardware. "Runs on a
verified kernel" must not invite the reading that nothing else is
underneath. True bare metal is `.metal` instances or owned hardware.

## 6. Sequencing

spike (local, Rust + hickory dnssec feature) → compartment demo on the
seL4 builder (proves §3) → local compartment tier → cloud box provisioned
seL4-native from birth (fixed-size, separate). Named, unmeasured risks:
sDDF throughput at DNS query rates; LionsOS v0.4 maturity (0.4.0 shipped
2026-08-21 — re-verified 2026-08-22). Neither is asserted without a
benchmark.

## 7. The no_std DNSSEC decision (2026-08-17, measured)

**Decided: verdicts cross the compartment boundary, not the validation.**
hickory's DNSSEC requires `std` (BUILD-STATE.md — declared in the published
feature graph), and `std` does not exist on bare-metal seL4. The seL4
compartment's purpose is **storage isolation, not validation isolation**: the
theorem §3 actually proves — the store holds no network capability and cannot
be drained — holds regardless of where validation runs. What crosses the
boundary is a verdict: a small, enumerated, non-secret value the compartment
does not need to re-derive to be isolated.

- **B (adopted, unblocks the demo):** DNSSEC validation runs in the std
  Phase-1 engine; only sealed verdicts cross into the compartment.
- **A (long-term, no deadline):** upstream no_std DNSSEC in hickory. The
  no_std foundation landed in `hickory-proto` (PRs #2104, #2821, #2806, all
  merged 2025-03); `__dnssec` remains std-gated and unclaimed — re-verified
  2026-08-22 against `main` HEAD and crates.io (see
  `SCISPACE_nostd_dnssec_status.md`).
- **C (argued-against):** hand-rolling RRSIG verification on bare `ring` is
  exactly the surface where a subtle implementation error produces confident
  wrong verdicts — the failure class this project exists to detect in others.
  hickory's DNSSEC layer is valuable precisely because it is not ours to get
  wrong.

**Accepted trust boundary (documented, not implicit):** under B, the seL4
compartment trusts the IPC channel delivering verdicts — a compromised std
engine could store a false verdict. That is a real trust boundary, accepted
by design; it is NOT the trust boundary the §3 theorem addresses, and it is
recorded here so it is never left implicit.

## 8. The truth-chain contract (2026-08-18, governs every renderer)

Every control's verdict is a three-layer chain, and the instrument keeps all
three layers or it degrades into a badge printer:

1. **RFC requirement** — what the standard actually demands, including
   optionality. SPF is optional; if present it must terminate in `-all` or
   `~all`. DMARC `p=none` is a legitimate but inert policy. MTA-STS
   `mode: testing` is a published policy that enforces nothing.
2. **Measured state** — what is actually in DNS, captured precisely by the
   disposition enum (`SpfDisposition::SoftFail`, `DmarcDisposition::Monitor`,
   `MtaStsDisposition::NotEnforced`, …). The disposition is the truth of the
   measurement and nothing else; it collapses to `TriState` only at
   presentation, never inside the engine.
3. **Real-world consequence** — what breaks if the control is absent or
   inert, stated as a measurable exposure: spoofing surface, STARTTLS
   stripping, no CA restriction.

Other scanners collapse this chain into one boolean ("SPF: PASS") and throw
away layers 1 and 3. Here the contract is: **the disposition carries layer 2;
the renderer carries layers 1 and 3.** A renderer that prints a disposition
without its RFC context and consequence is out of contract, for all eight
controls (DNSSEC, DKIM, MTA-STS, DANE, SPF, DMARC, CAA, CDS).

**The enforcement collapse ruling (attached reasoning, do not re-derive):**
score **deployment, not protection** — the three non-enforcing-but-published
states — `SpfDisposition::SoftFail`,
`DmarcDisposition::Monitor`, `MtaStsDisposition::NotEnforced` — all collapse
to `Present`. Before the ruling, states of identical epistemic type collapsed
to opposite `TriState` answers inside one struct. `Present` asserts exactly
what was measured: the control is published. Non-enforcement is a layer-1/3
fact the renderer must state in words; it is not a fact the score is allowed
to erase or to invert into absence. The score never claims more than the
measurement, and the renderer never says less than the truth.
