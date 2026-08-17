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
- **The requirement, stated precisely:** a native service must issue N
  concurrent UDP queries over the no-std stack (smoltcp) with independent
  per-query deadlines. That is job scheduling, not a general-purpose async
  runtime.

A serial sweep is the wrong instrument regardless: the parallel sweep is
what makes cross-resolver disagreement measurable in a single pass — the
tool's entire DNSSEC/consensus story.

## 2. Guest-deletion acceptance criterion

**Milestone gate:** can a native LionsOS service issue five concurrent
smoltcp UDP queries with independent per-query deadlines?

- **Yes** → the Linux guest layer is deletable from the architecture.
- **No** → the guest stays, and every public claim narrows to what was
  measured.

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

**Action, ahead of the demo:** enumerate which of the 20 secrets each
future compartment needs (scanner: network + `PROBE_*`; filter:
network+storage; store: `DATABASE_URL` only, no network). That list IS the
capability manifest, and splitting the probe credential out of the web
process buys real isolation today, on ordinary Linux — the prerequisite
that makes a compartment boundary meaningful later.

## 5. Hypervisor honesty (public copy, verbatim)

On a rented instance, seL4 runs as the guest OS of the provider's
hypervisor — that layer is irremovable on virtual hardware. "Runs on a
verified kernel" must not invite the reading that nothing else is
underneath. True bare metal is `.metal` instances or owned hardware.

## 6. Sequencing

spike (local, Rust + hickory dnssec feature) → compartment demo on the
seL4 builder (proves §3) → local compartment tier → cloud box provisioned
seL4-native from birth (fixed-size, separate). Named, unmeasured risks:
sDDF throughput at DNS query rates; LionsOS v0.3 maturity. Neither is
asserted without a benchmark.
