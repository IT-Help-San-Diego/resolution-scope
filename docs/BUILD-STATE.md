# Build State — Resolution Scope spike kit (adopted 2026-08-17)

Adopted from the SciSpace second-wave kit with the four corrections verified
against the tree. Two sibling crates, **no workspace** (feature-unification
between a std+tokio crate and a no_std crate is a real hazard).

## Layout

- `engine/` — Phase 1: std + tokio + hickory. **Builds on host.**
  `cargo build` ✅, `cargo test` ✅ (19 pass, 5 ignored live-network).
  `cargo check --no-default-features` **fails as designed** (exit 101) — the
  `dnssec-ring` compile guard fires; negative assertion verified.
- `native/` — Phase 2: no_std + smoltcp + hickory-proto. **Library builds on
  host** (`cargo build --lib` ✅, `cargo test --lib` ✅ 4 pass: tristate +
  sddf_device bounds). The `[[bin]]` (main_native.rs) is bare-metal only:
  `#![no_std]`, custom `#[panic_handler]`, `#[no_mangle] main`.
  **Measured 2026-08-19: the bin does NOT compile even apart from the
  target** — 12 errors against hickory-proto 0.26.1's no_std API surface
  (`Message::new()` takes `(u16, MessageType, OpCode)` there; the std-side
  setter methods `set_id`/`set_op_code`/`header()`/`extensions_mut()` don't
  exist without default features). Pre-existing, untouched by the truth-chain
  work; whoever opens the seL4 lane ports main_native.rs's message
  construction first. The ledger's contract for this crate remains `--lib`.

## Engine arms — complete (2026-08-18 evening)

All eight controls now score correctly against live protocol, and the full-arm
differential (`scripts/full_arm_differential.py`) is at **39 parity / 1
scope-diff / 0 real-diff** (from 32/8/0 at the start of the session). The one
remaining scope-diff is a deliberate, correct distinction, not a port gap.

- **DNSSEC** — preserves the full disposition (`DnssecDisposition`, 7 variants)
  instead of collapsing to TriState, so the report explains *why* a domain is
  Indet (island-of-security vs couldn't-measure). Live: resolutionscope.com =
  signed-but-not-delegated; example.com/cloudflare.com = signed-and-delegated.
- **DANE** — SMTP DANE (MX → `_25._tcp.<mx-host>` TLSA, RFC 7672), not HTTPS
  DANE (`_443._tcp` was the wrong surface for an email tool). Four distinct
  outcomes: Present (MX + TLSA), Absent (mail routable but no DANE — incl. a
  silent no-MX absence, which is spoofable FROM), NotApplicable (null MX
  "MX 0 ." = explicit "accepts no mail"), Indet (domain missing). Live:
  ietf.org/huque.com PASS, gmail.com/whitehouse.gov FAIL, example.com N/A.
- **MTA-STS** — full two-step RFC 8461 protocol (discovery TXT → HTTPS policy
  fetch via reqwest/rustls → parse version/mode/mx). Live: google.com PASS.
- **NXDOMAIN SOA disambiguation** — `record_absence_verdict` reads the SOA zone
  from the authority section to distinguish "domain missing" (Indet) from
  "record absent within an existing zone" (Absent). Fixed the subdomain
  NXDOMAIN flatten for `_dmarc`/`_mta-sts` (cia.gov/red.com were wrongly Indet),
  and generalized to the DANE MX lookup.
- **`NotApplicable` fourth state** — a null MX is a *measured declaration*, not
  "couldn't measure". Added as a TriState variant distinct from both Absent and
  Indet: same denominator exclusion as Indet, but a positive claim ("we know
  precisely why DANE doesn't apply").

Corollary findings: google.com/gmail.com are genuinely unsigned (no DNSKEY, no
DS, no AD flag) — the engine correctly reports them unsigned. example.com
publishes a null MX ("accepts no mail") → DANE NotApplicable; whitehouse.gov
publishes no MX at all (NODATA) → DANE Absent.

## Truth-chain render model (2026-08-19, ARCHITECTURE.md §8 as code)

`engine/src/truth_chain.rs` is the ONE place dispositions map to presentation
facts: per control a `ControlReport` carrying the three layers (RFC
requirement / measured label / consequence per `Audience::{BlueTeam,RedTeam}`),
a consequence-derived `Severity` (declaration order = worst-first sort order),
and the shared `Tally` (score arithmetic was previously duplicated in
report.rs and the TUI — both now consume this). The TUI owns styling only; a
disposition match outside truth_chain.rs is out of contract. 28 engine tests
pin the mapping, including: the §8 enforcement ruling (SoftFail/Monitor/
NotEnforced → Present + Medium), broken-deployments-are-Critical, and the
two-axis doctrine — Unmeasured ⟹ Indet strictly, while island-of-security
and dane-dnssec-required are the two named measured-but-unchained exceptions
(Indet tri, ranked severity).

**Fake-data fix, same pass:** `analyse_domain` had emitted
`DkimDisposition::NotFoundDefaults` ("81 selectors probed, none matched")
while no DKIM probe exists in the engine — a fabricated measurement claim.
New `DkimDisposition::NotProbed` is the only honest stub value and is what
the engine now emits; `NotFoundDefaults` is reserved for a sweep that ran.

**Adversarial panel round (2026-08-19, 33 agents, 15 confirmed):** the panel
turned up the same defect class at FIVE more emission sites, plus the root
cause — hand-paired `(TriState, Disposition)` tuples let the two verdict
channels disagree (three live divergences existed, incl. a same-day
regression: the NotEnforced→Present ruling changed `chain()` but not the
emission site). Fixes, all landed:

- **Structural:** every `score_*` now returns ONLY its disposition;
  `analyse_domain` derives the tri via `chain()`. The divergence class is
  unwritable now.
- **DANE:** TLSA presence emits new `TlsaPublished` ("match not verified by
  this pass") — `Verified`/`Mismatch` are reserved for a future SMTP cert
  prober and have no emission site. New `NoMx` (zone without MX = Absent,
  spoofable FROM) split from `NoMail` (null MX = NotApplicable), restoring
  the four-outcome split this file records above.
- **SPF:** a record with neither `-all` nor `~all` emitted HardFail
  (fabricated enforcement); new `OtherPolicy` (Present + Medium — fourth
  member of the §8 deployed-not-enforcing class).
- **DMARC:** missing/unrecognized `p=` emitted Reject (fabricated policy);
  new `InvalidPolicy` (Absent + High — invalid record = no record).
- **MTA-STS:** hint-present-but-policy-unfetchable emitted TransientError
  (measured absence flipped to unmeasured, against T1-1); garbage policy
  text emitted NotEnforced (a mode never parsed). New `PolicyInvalid`
  (Absent + High) covers both; the policy parser is now three-way
  (Enforce / TestingOrNone / Invalid).
- **report.rs:** rows now render from the model (one verdict channel; the
  raw-field rows could contradict the model's own score line in one
  document). **TUI:** dead `scroll` wired to the Paragraph; Tab now rescans
  (it previously showed the old domain's verdicts under the new name).

48-state census pinned in truth_chain tests (30 engine tests green). Live
check post-fix: resolutionscope.com island + null-MX N/A + 3/5, example.com
signed+delegated + CDS published + 4/6 — every row's measured label honest.

## First differential result (2026-08-18, scripts/fixture_differential.py)

**Three-way: Rust verdict / Go verdict (frozen in fixture) / fixture reference
+ LIVE protocol as arbiter when they disagree.** The Go parent is a comparand,
not ground truth — a fixture is a frozen Go measurement and cannot arbitrate
against itself.

| domain | fixture (chain,state) | RUST | era | disposition |
|---|---|---|---|---|
| cloudflare.com | complete,present | Present | recaptured | **PARITY (fixture confirms)** |
| example.com | complete,present | Present | recaptured | **PARITY** |
| ietf.org | complete,present | Present | recaptured | **PARITY** |
| whitehouse.gov | complete,present | Present | recaptured | **PARITY** |
| cia.gov | complete,present | Present | defect-era | **only genuine stale-fixture** (signed live: 3 DNSKEY/4 DS, AD=true) — recapture |
| google.com | none,absent_confirmed | Absent | defect-era | fixture **already correct** (unsigned live: 0 DNSKEY/0 DS) — no recapture needed |
| red.com | none,absent_confirmed | Absent | defect-era | fixture **already correct** (unsigned live) — no recapture needed |
| thisdoesnotexist-xz9q.com | None,None | **Indet** | defect-era | NXDOMAIN, honest couldn't-measure (zone doesn't exist) |

**4/4 parity on the recaptured (post-fix) state space.** Claude Science's two
corrections folded in: **cia.gov is the ONLY genuine stale-fixture case** of
the three defect-era captures (it's signed and validating live; the frozen
label is wrong) — `google`/`red` are unsigned live with the fixture **already
correct**, needing no recapture at all. Grouping all three as "fixture stale"
was wrong.

**Second port defect caught (the domain_exists flatten):** the engine
originally mapped NXDOMAIN → `Absent`, asserting a measured absence of DNSSEC
on a zone that doesn't exist. `Absent` is a claim about a zone's
configuration; there is no zone. Fixed everywhere (DNSSEC, DANE, CAA,
CDS/CDNSKEY): `e.is_nx_domain()` → `Indet`, only NOERROR/NODATA on an
existing zone → `Absent`. Same flatten the Go engine's domain_exists arc
removed — and the denial is unauthenticated (AD=false), so even nonexistence
isn't proven.

**The differential caught a real port defect before it shipped:** the kit's
original `score_dnssec` gated on "any answer record exists → Present", which
asserted *unsigned-but-resolves* (google.com) as secure — the exact
false-secure class the Go engine's DNSSEC arc fought. Fixed by gating on
hickory's per-record `Proof` (Secure → Present, Insecure/Bogus → Absent,
Indeterminate → Indet). This is the acquire-the-parent's-defects failure mode
the three-way design exists to prevent.

## FINDING — engine DNSSEC arm probes via address existence (2026-08-18)

The live-specimen test caught a category error in `score_dnssec`. The arm
probes DNSSEC state through `resolver.lookup_ip()` (A/AAAA **address**
existence), then its `Err` branch maps `is_no_records_found()` → `Absent`
("unsigned"). But a domain that SIGNS DNSSEC (2 DNSKEY, valid RRSIGs) while
publishing no web content yet (0 A/AAAA — our two newly-registered domains
resolutionscope.com/.dev) returns `NoRecordsFound` on the address lookup, and
the engine reports **Absent** — falsely "unsigned" for a zone that
demonstrably signs.

- Live protocol (dig @1.1.1.1): resolutionscope.com/.dev each publish **2
  DNSKEY, 0 DS, 0 A, 0 AAAA**. Signed, island-of-security, no web content.
- hickory `lookup_ip` → `Err(NoRecordsFound)` (no A/AAAA), SOA proof =
  **Indeterminate** — the *correct* "couldn't measure the chain" signal.
- Engine Err branch → `is_no_records_found() → Absent` — the category error:
  "no address record" read as "no DNSSEC".

**Also**: `lookup_ip`'s per-record `Proof` does NOT surface the
authenticated-denial distinction Claude Science measured at the DS query
(.dev = AD=true denial → Insecure; .com = AD=false → Indeterminate). That
lives at the DS query, not the address lookup. Both arms point the same way:
`score_dnssec` must query **DS/DNSKEY directly** (with CD/AD flags, mirroring
the Go engine's dnssec.go), not infer DNSSEC from address-record existence.
"Presence answers does-X-exist; proof answers did-validation-succeed" — and
address presence answers neither.

Fix direction (next task): rewrite `score_dnssec` to query DNSKEY + DS with
checking-disabled + read the authenticated-denial / AD state, mapping:
Secure→Present, authenticated-unsigned (Insecure)→Absent, broken (Bogus)→Absent,
unauthenticated/couldn't-measure→Indet. Never map address-record absence to a
DNSSEC verdict.

## Corrections applied at adoption

1. License `MIT OR Apache-2.0` → **AGPL-3.0** (repo is AGPL-from-birth).
2. Repo URL → `IT-Help-San-Diego/resolution-scope` (kit pointed at a
   nonexistent `it-help-tech/dns-tool-sovereign`).
3. Dropped `mdns` from Phase 2 (a posture scanner has no use for multicast).
4. Feature name unified to `dnssec-ring` — the kit's Phase 1 named it
   `dnssec`, which made the compile guard always fire (Phase 1 could never
   have compiled as shipped).

## Version reality (measured twice, corrected once)

- First pass wrongly concluded "hickory 0.26 does not exist on crates.io" —
  that was a **stale local registry index** read as a version fact (Claude
  Science caught it: `cargo search` sees 0.26.1 live while a stale index shows
  only 0.26.0-alpha.1). The kit's `"0.26"` caret pin was valid all along.
- **Resolved to 0.26.1** after `cargo update`. Note: `hickory-client` has NO
  0.26 stable (alpha only) — but it was a **dead dependency** (never imported
  in the kit), so it was removed rather than pinned back.
- API migration at 0.26.1 (verified against the crate sources): `TokioResolver`
  (not `TokioAsyncResolver`); construction is
  `builder_with_config(ResolverConfig::tls(&config::CLOUDFLARE),
  net::runtime::TokioRuntimeProvider::default()).with_options(opts).build()?`;
  "no records" is `NetError::is_no_records_found()` (the nested
  `ResolveErrorKind::Proto(ProtoErrorKind::NoRecordsFound)` match is gone);
  `Lookup.answers()` returns `&[Record]`; `Record.data` is a public field;
  TXT strings are `rec.data`'s `txt_data: Box<[Box<[u8]>]>`.

## FINDING — the Phase 2 bare-metal blocker (verified at BOTH 0.25.2 AND 0.26.1)

**hickory-proto's `dnssec-ring` transitively requires `std` at 0.26.1 too.**
`dnssec-ring = ["dep:ring", "__dnssec"]` and `__dnssec = [..., "std"]` —
identical structure in both versions (the 0.25.2 doubt did not survive
re-measurement). `cargo check --target aarch64-unknown-none` fails in
`percent-encoding` (via `url/std`) and `getrandom`. smoltcp's `socket-dns`
also pulls `futures` (std).

**There is no no_std DNSSEC path in hickory today — now robust across the
current stable.** The strongest form of this claim is the published manifest,
not the compile error: `hickory-proto` 0.26.1 declares
`__dnssec = ["dep:bitflags", "dep:rustls-pki-types", "dep:time", "std"]` with
**`std` as a literal member**, and `dnssec-ring = ["dep:ring", "__dnssec"]` —
so ring DNSSEC enables `std` **by declaration**, not by accident of a
transitive dep. A build error can be a toolchain artifact; a feature
declaration in the published manifest is the crate's own stated contract,
checkable by anyone on crates.io without a cross-compiler. (The bare-metal
`cargo check --target aarch64-unknown-none` failure in `percent-encoding` /
`getrandom` corroborates it but is not the load-bearing evidence.)

## The bare-metal bin build is therefore **deferred, not abandoned** — the
host-verified library + this finding is the honest spike state.

## §2 milestone gate state (2026-08-18)

**Question:** can a native service issue 5 concurrent smoltcp UDP queries with
independent per-query deadlines? Decomposes into:

- **Structural (proven):** smoltcp's `dns::Socket::new(servers, queries)`
  takes a query-slot array at construction; each `start_query` returns an
  independent `QueryHandle`. N concurrent queries with distinct handles is the
  library's own model, not something we build. ✅
- **Measurable (deferred):** actual query throughput + per-query deadline
  behavior at DNS rates on real sDDF hardware. This is the seL4 builder's job
  and is gated behind (a) the hickory no_std question for a full bare-metal
  binary, and (b) the builder itself (kept cold — no idle capacity).

Native lib host-verified meanwhile: `cargo test --lib` 4/4 green (tristate,
sddf_device ring bounds).

## Recapture blocker (2026-08-18): Docker embedded-DNS filters DNSSEC records

The cia.gov fixture recapture against the local dev server returned a
**local-environment measurement artifact**, not a fixture verdict: Docker's
embedded resolver (127.0.0.11) answers A records but returns **"No answer" for
DS/DNSKEY** — so the local tool saw `has_ds: false, chain: broken` while the
live protocol shows cia.gov signed (3 DNSKEY / 4 DS, AD=true). **Do NOT write
a fixture from this measurement.** The honest recapture path needs a clean
resolver (production server, or a local server whose DNS isn't Docker's
embedded stub). The production path is gated on the human-triggered scan
(botverify); the local path needs the container pointed at a real upstream
resolver. Recorded so the recapture is never "completed" from a broken
resolver and called done.

## Sealed-history store (2026-08-19, foundation layer 7-of-8)

`store/` — the instrument's memory, holding itself to the instrument's
epistemics: **sealed on write by the store** (`record_scan` computes the seal
from the verdict it is handed; a caller-supplied seal is never accepted),
**verifiable on read across versions** (each row persists the producing
engine's version; `verify_scan` re-derives from stored verdict + stored
version — `seal_versioned` was added to the engine for exactly this, because
`seal()` baked in the current build's version and every release would have
orphaned all prior sealed history), and **Up-only migrations** (no Down
sections exist — the dns-tool-intel #467 hazard class removed, not guarded).
Postgres local-first per doctrine; `verdict` is `json` not `jsonb` per the
2026-08-17 measured ruling. Capability shape: DATABASE_URL only.

Integration-tested against a REAL postgres (7 tests incl. tamper-detection
via direct SQL mutation behind the seal's back, cross-version verification,
migration idempotence, and the full flux loop: engine measures → store
remembers → engine's pure dispersion() reads the memory back). CI runs them
against a postgres service container with --include-ignored — an env-gated
silent skip would be a check that cannot fail. Found-by-testing: concurrent
migrators raced on CREATE TABLE (five parallel tests on a fresh database,
four failed) — fixed with a pg_advisory_lock, which is the production fix,
not a test accommodation. Firing path: `resolution-scope -d <domain> --store-url` (env
RS_STORE_URL) persists every scan sealed and echoes the citable row id;
end-to-end verified by DB census (row's seal == report's seal, byte-equal
across runs — determinism observed live).

## Commit discipline (2026-08-20): a gate is only a gate if someone reads it

Two red-CI episodes shipped unnoticed because doc/evidence commits skip the
local gate and nobody read the red `CI` run — it was masked in the mixed-status
commit view by green CodeQL/Deploy runs (display-vs-state, the third instance
of that shape). Measured history:

| commit | CI |
|---|---|
| `d36ff770` | **failure** |
| `88d10957e` → `0b967ca2d` | success (self-healed — nobody fixed it) |
| `f8dd0db9e` → `af8df7d28` | **failure** (five commits) |
| `043263dce` | success |

**The mechanical fix** is `.githooks/pre-push`, which fires on every push and
cannot be skipped:

1. **Local gate (unconditional)** — `cargo fmt --check`, `cargo test`, and
   `cargo clippy --all-targets -- -D warnings` on every crate CI formats
   (`engine`, `cli`, `store`). A doc/evidence commit skips the local gate by
   nature; this restores it, so drift is caught before it can ship.
2. **Parent-CI gate (main pushes only)** — the commit being built ON must not
   already be red. Fail-open on tooling (gh absent / no run found); fail-closed
   on a found red parent.

Install per clone with `scripts/install-hooks.sh` (`core.hooksPath` is a
per-clone setting, so each lane runs it once). The durable rule it encodes:
**a doc/evidence commit must check CI on its parent before landing** — those
commits don't run the local gate and are exactly where drift accumulates.

