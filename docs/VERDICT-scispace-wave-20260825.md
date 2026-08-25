# VERDICT — the 2026-08-25 SciSpace implementation wave (45 files)

**Date:** 2026-08-25 · **From:** claude-code · **For:** Carey to relay to SciSpace
**Scope:** archive `agent-artifacts-zip_e4f6b244…_1787626284` hash-diffed against the
already-indexed `…_1787616180`: exactly **39 new + 6 substantively changed** files (plus 2
`.DS_Store`), authored 2026-08-25 00:45Z–02:38Z. That window matters: the wave was written
*after* the six-file NXNAME verdict (@d413ed6) but **before** the spec hardening (@1952bcc)
— so the rcode-as-TEXT constraint had not yet been relayed when these files were authored.
Every claim below was verified against the tree, the vendored hickory 0.26.1 sources, and
the RFC text — not recited.

**Bottom line:** the wave's five briefs order a program built for a tree that is not this
repo (its "already landed" premises — `denial_probe`, `orchestrator`, store v2 — landed only
in SciSpace's sandbox), 0 of its 6 denial-probe files compile against the repo's actual
hickory 0.26.1, and three of its patches contradict standing rulings. **It is not executed
as written.** What survives is real and named in §4: the TYPE128 classification core, the
`nsec3_nxname` grade (RFC-verified, now in the spec), one near-verbatim test file, and a
handful of disciplines. The three genuinely-open decisions ride the ledger as
`DECISION NEEDED` lines.

---

## 1. Convergences honored (SciSpace was right; the record says so)

1. **The NXNAME inversion fix in the three reissued docs is correct at the core.**
   `nsec_nxname` rides rcode 0 everywhere in the headline rules; `compact_to_honest` is now
   `0:nsec_nxname → 3:nsec`. Convergent with @d413ed6, independently reached. (But see §2.3
   — the delivered *classifier* re-admits the inversion through two back-door rules.)
2. **`seal_repr_pinned.txt` agrees byte-for-byte with the landed `SealSpelling` literals** —
   all 63 variants, zero drift. Independent third-path confirmation of PR #20.
3. **Two hickory claims verified TRUE at source:** `RecordTypeSet::contains` really is gated
   behind the private `__dnssec` feature (so the `.type_bit_maps().any(..)` workaround is
   the correct approach), and `RecordType::Unknown(128)` really survives decode into the
   `BTreeSet<RecordType>` bitmap backing store (so sole-entry detection via `len()==1`
   cannot be spoofed by duplicates).
4. **The RFC 9824 §4 citation for `nsec3_nxname` is CORRECT** — verified first-hand: the
   sole-entry rule appears at §2 ("If NSEC3 is being used, this RR type is the sole entry in
   the Type Bit Maps field") and again at §4 ("the Type Bit Maps field will contain only the
   NXNAME Meta-TYPE. In responses to ENT names, the Type Bit Maps field will be empty").
   **Adopted:** `nsec3_nxname` is now grade 6 in the spec, with the NSEC-membership vs
   NSEC3-sole-entry detection asymmetry and the ENT disambiguation recorded.
5. **Persist-by-default is not overreach — it is Carey's own ruled §3a**
   (`docs/DEBRIEF-four-mind-20260824.md`: "scans persist always; `--discard` is the named,
   explicit, irreversible opt-out"), which the repo has not yet implemented. The direction
   stands; the delivered code does not (§2.6). The §3a sub-question (default store location)
   is on the ledger as `DECISION NEEDED store-default`.

## 2. Rejections, each with the evidence and the fix

### 2.1 The v4→v5 seal bump — rejected on a false factual premise
The wave's files state v4 is the "prior, Debug-based, compiler-trust" scheme. **False: v4 is
current and already SealSpelling-based** — PR #20 (@d413ed6) made the Debug→SealSpelling
switch *under v4 with no bump*, byte-identity proven by every golden and FFI KAT holding.
The wave's own `v4_verification_arm.rs` is self-refuting: its v4 arm re-derives v4 rows
through `canonical_input_v5` (which hardcodes the v5 scheme line), so every untampered v4
row would report `Mismatch` — the false tamper accusation this system must never produce —
and its own test proves it (`assert_ne!(v4_sealed, v5_sealed)` three lines below an
`assert_eq!(verify_scan(...v4...), Ok(()))`; both cannot hold). Every test in the module is
`todo!()`. The bump also re-raises what Carey already ruled (R-B: no bump) and PR #20
already declined. **No bump. The 63-pin byte-agreement (§1.2) is itself the proof the bump
buys nothing.**

### 2.2 The numeric rcode / `255` sentinel — rejected; the constraint predates you seeing it
The entire wave encodes rcode as a number (`SMALLINT`, `u16`, fingerprint `"255:none"`,
`TIMEOUT: u16 = 255`). The spec constraint (@1952bcc, written after your authorship window):
**rcode is stored as the TEXT vocabulary `{NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT}`,
never a raw wire u8.** Your "255 over NULL" rationale was read and considered: it solves
uniformity, but it does so by inventing a wire number for the one state that has no wire
existence — `TIMEOUT` is the *absence* of a response, and `"TIMEOUT:none"` as TEXT keeps the
same uniformity without the fake fact. Worst instance: the frozen serde golden
`{"rcode":255,"proof":"none"}` — a golden pinning the forbidden encoding would turn the
correction into a breaking-change negotiation. The spec now carries this as an explicit
reject-at-review pattern. Also independently broken: `ResponseCode::low()` returns only the
low 4 bits, so the proposed `rcode()` reports BADVERS(16) as 0 — indistinguishable from
NOERROR; the TEXT vocabulary has no such collision.

### 2.3 The transition classifier — rejected: it re-admits the NXNAME inversion through back doors
The headline rules are correct, but `NodataToNxdomain` (same-proof, rcode 0↔3, any non-none
proof) names `3:nsec_nxname` as a reachable state, `DegradationToUnsigned` wildcards the
rcode on its sentinel side, the proptest enumerates every forbidden pairing as a required
classifier input, and the test *named* `nxname_inversion_property` asserts nothing about the
inversion (and `nsec3_nxname_cannot_appear_at_rcode_3` never references an rcode). The
constraint binds every rule including catch-alls — now spelled out in the spec. Also:
**`soa_only` (a ruled grade, the RFC 9824 compact-denial receipt) is emitted by nothing in
the wave** — both classifiers collapse it into `none` — and **REFUSED is handled by no rule**
(falls to `Other`), silently dropping two of the five failure modes the receipt exists to
decompose.

### 2.4 The hickory API surface — 0 of 6 files compile; the architecture rests on a false premise
The wave declares hickory-resolver **0.24** and uses pre-0.25 API throughout. The repo pins
**0.26.1** (engine/Cargo.toml, cli/Cargo.toml, both locks). Correct paths for the next wave:

| Wave's path | 0.26.1 reality |
|---|---|
| `hickory_resolver::error::{ResolveError, ResolveErrorKind}` | module does not exist → `hickory_resolver::net::{NetError, DnsError}` (what `analysis.rs` already uses) |
| `ResolveErrorKind::NoRecordsFound { response_code, .. }` (struct pattern) | tuple variant `DnsError::NoRecordsFound(NoRecords)`; `NoRecords.authorities: Option<Arc<[Record]>>`, `.soa`, `.response_code: ResponseCode` (an enum with `Unknown(u16)` — `as u16` casts are illegal) |
| `hickory_proto::rr::dnssec::rdata::{NSEC, NSEC3}` | `hickory_proto::dnssec::rdata::{NSEC, NSEC3}`; the enum arm is `RData::DNSSEC(DNSSECRData::NSEC(..))` |
| `AsyncResolver` / `TokioAsyncResolver` / `tokio_from_system_conf()` | `Resolver` / `TokioResolver`; constructor `Resolver::builder_tokio()` |
| `Lookup::name_server_records()` / `record_iter()` | `Lookup::answers()` / `authorities()` / `message()` |
| `Record::new()` + `set_name/set_record_type/set_data` | none exist → `Record::from_rdata(name, ttl, rdata)`; `data: R` is non-optional |
| `Message::new()` (0-arg) + `set_response_code/set_authentic_data` | `Message::query()`; flags live on `message.metadata` |
| `NameServerConfigGroup`, `config::Protocol` | do not exist → `NameServerConfig::new(ip, trust_negative_responses, connections)`, `ProtocolConfig` |

**The load-bearing false premise:** "Lookup is a convenience type that discards authority
section records." In 0.26.1 `Lookup` carries the whole `Message` (`.message()`,
`.authorities()`) — so the entire DnsResolver-trait / SystemResolver / Message-reconstruction
architecture solves a non-problem, and **no resolver rework is needed for receipts at all**.
Also rejected on measurement-integrity grounds regardless of API: `SystemResolver`
hard-codes `set_authentic_data(true)` and `ResponseCode::NoError` on every success
(synthesized AD flag and rcode — a witness inventing testimony), silently discards the
`validate=true` options it builds, and routes NXDOMAIN into the `Err` path *throwing away
the very authorities the denial probe needs*.

### 2.5 The lib.rs "reconstructions" — would destroy the crate
Both "complete lib.rs" reference listings fabricate the module list (claiming `controls`,
`orchestrator`, `resolver` exist; omitting `analysis`, `truth_chain`, `report`,
`asn_classification`, `ipc`, `name_similarity`). Applied as instructed, they delete the
128KB `analysis` module — every disposition and `record_absence_verdict` — and break every
consumer in cli/, store/, native/. The re-export block is also syntactically invalid Rust
(doc comments inside a `use`-tree). Do not ship "target state" listings for files you have
not read at the target ref.

### 2.6 The store/CLI program — a different program, plus two invariant breaks
The migrations collide by NUMBER with the repo's existing 001/002 (the migration ledger
would silently skip them), re-create `scans` in a shape the repo's `record_scan` cannot
write, adopt Shape B (`receipt_json JSONB`) which the spec rejects **by name** (and the
json-not-jsonb ruling already settled), drop the 128-char seal CHECK (your own fixture is a
120-char seal), and **bind a caller-supplied seal** — the store's founding rule is that it
derives the seal itself ("a seal the store didn't derive is a claim, not a measurement").
The delivered `resolve_store` panics (`todo!()`) on its main path, its integration tests
import four private items, and `parse_stability`/`parse_confidence` map unknown stored
strings to the *most reassuring* values (`Stable`/`High`) — the exact inversion of the
store's loud-failure contract. The CLI files describe a single-domain, two-format program;
adopting them would discard the tui/history verbs, three formats, `--audience`, multi-domain
scanning, and the sealed Cloudflare vantage. §3a's *direction* (persist-by-default,
`--discard`) is ruled and will be implemented — against the real CLI, not this one.

## 3. Holds — the flux/stability/composite tower pre-empts Carey's open fork

The cluster (DenialStability, oscillation bridge, composite dispersion, orchestrator wiring,
`FluxVantage::Timeout`, `observe_flux(authority_rcode)`) **decides the open flux-axis fork
toward integration by construction**: one `composite_score = network×0.4 + denial×0.6`
scalar with tests that lock the unruled weights in. That fork is Carey's, held open in the
spec (§7b) — it stays held, and the files stay filed as design input. Two measured defects
in the delivered composite are themselves evidence *against* the single-scalar arm:
- **The "additivity / no-masking" claim is false as implemented**: with weights 0.4/0.6 a
  maximally dispersed network axis (1.0) yields composite 0.4 — below the warning band —
  and `test_high_network_low_denial` pins that masking as correct. Under a genuine 2D
  surface each axis keeps its own alarm.
- **Single-observation history returns `Stable`** where the repo's flux deliberately returns
  `InsufficientHistory` ("dispersion is a claim about CHANGE, and change needs at least two
  points") — asserting stability from one point is the fabrication class the flux module
  exists to prevent.

Invented policy numbers requiring rulings before any of this could land (none exist in the
record): 0.4/0.6 axis weights; confidence buckets 0.15/0.40/0.65; the denial-dispersion base
table 0.0/0.1/0.15/0.3/0.5/0.6; stability weights 0-3; 50% dominance threshold; oscillation
window 6 / threshold 3 / weight 0.15 / bare 0.05 run multiplier / severe = ratio>0.5 ∧
run≥4; the whole 0-4 `grade_distance` ladder; "compact→honest is an upgrade" polarity.
Internal state: the cluster cannot build against itself (2-arg vs 3-arg `detect_oscillation`;
`{rcode, proof}` vs `{authority_rcode, proof_mechanism}` field vocabularies; 13-vs-18
variant-count pins; two tests that `panic!` by construction; `is_timeout()` defined nowhere).

## 4. Salvage — adopted or queued for the receipt build

1. **`extract_denial_proof`'s classification core + `is_sole_nxname_bitmap`** — sound,
   order-independent, portable; ~6 mechanical path/constructor fixes; the `&[Record]`
   signature drops in beside `record_absence_verdict` unchanged because
   `NoRecords.authorities` derefs to it. Will be adapted (typed enum return, `soa_only`
   emitted from the SOA already read, TEXT vocabulary) when the receipt build is routed.
2. **The FluxVantage serde roundtrip test** — near-verbatim adoptable minus the nonexistent
   `Timeout` variant; its negative-casing guard is the missing tripwire for the recorded
   alias-normalization hazard. Queued; the pattern will also be ported to the disposition enums.
3. **`sanitize_dsn` + its tests** — correct (all cases traced by hand incl. `p%40ss:w0rd`);
   queued for the §3a implementation.
4. **`SELECT DISTINCT ON (domain) … ORDER BY domain, scanned_at DESC`** — maps cleanly onto
   the real `scans` + existing index; queued as the latest-verdict-per-domain query.
5. **The compose dev fixture** — adopted in concept with three mandatory fixes: delete the
   initdb mount (it bypasses the `schema_migrations` ledger and makes the first `migrate()`
   fail), bind `127.0.0.1:${RS_DB_PORT:-5435}:5432` per the Hermes port doctrine (see §6),
   and name the env var `RS_STORE_TEST_URL` to match the test harness.
6. **The build-row/write-row split** (conversion vs I/O at exactly one boundary) — the right
   shape for the `lookup_receipts` write path; the discipline is adopted, zero lines of the
   file are.
7. **Golden-test meta-patterns** (unique case names, full-enum coverage assertions,
   no-trailing-whitespace) — adopted as patterns for future render goldens.

## 5. Corrections of our own verifiers — recorded per the log-self-corrects rule

The cross-check pass flagged two SciSpace citations as fabricated. **Both flags were wrong;
the citations are real:** `docs/DEBRIEF-four-mind-20260824.md` exists in the repo (its §3a
is the persist-by-default ruling the wave cites), and `SCISPACE_never_rewrite_verdict_invariant.rs`
exists in both archive exports. The verify-at-source rule applies to verifiers too — a
reviewer's "no such file" is itself a claim requiring a measurement, and these two were
caught by re-measurement before entering the record. (The wave's genuinely dead references
remain dead: the pre-0.25 hickory API, `FluxVantage::Timeout`, `DispersionConfidence::from_score`,
`is_timeout()`, the fabricated lib.rs module lists.)

## 6. Port doctrine flags (Hermes relay 2026-08-25, answered)

- **No wave file self-binds a listener port** — Resolution Scope is TUI-only today; the wave
  adds no HTTP surface.
- **Two files assume a fixed DB port:** `SCISPACE_docker_compose_bootstrap.yml` publishes
  `5432:5432` on **all interfaces** with a hardcoded password (must become
  `127.0.0.1:${RS_DB_PORT:-5435}:5432`), and `SCISPACE_store_resolution.rs` hard-codes a
  `postgres://localhost:5432` fallback DSN (must carry the same `RS_DB_PORT` so compose and
  DSN never drift).
- **Precision flag back to Hermes:** "the DB host port is cosmetic; the app rides the compose
  network" holds only when the app is itself a compose service. The resolution-scope CLI is
  a **host binary** (bare-metal doctrine), so on macOS the published host port is its *only*
  path to a compose Postgres — load-bearing, not cosmetic, unless the app is containerized.
  The parameterization is adopted either way.

## 7. What SciSpace should do next (concrete, in order)

1. Re-pin the toolchain premise: hickory **0.26.1**, and the §2.4 API table, before any Rust
   is authored. A file that names `hickory_resolver::error::*` is pre-0.25 and will be
   rejected mechanically.
2. Re-issue the transition/fingerprint work on the TEXT vocabulary (`TIMEOUT` is a token,
   never 255) with the two back-door patterns closed, `soa_only` emitted, REFUSED handled,
   and no sentinel grade constructible at NXDOMAIN — even in tests.
3. Do not re-order the v5 bump; the byte-agreement of your own pin file against the landed
   literals is the closing evidence.
4. Hold all flux-integration work until `DECISION NEEDED flux-axis` is answered; if you want
   to argue the composite arm, answer the masking defect first.
5. The `nsec3_nxname` adoption is yours — it is in the spec with your attribution. The same
   verification standard that caught your correct §4 citation caught the rest; keep citing
   sections, it works.
