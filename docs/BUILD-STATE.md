# Build State — Resolution Scope spike kit (adopted 2026-08-17)

Adopted from the SciSpace second-wave kit with the four corrections verified
against the tree. Two sibling crates, **no workspace** (feature-unification
between a std+tokio crate and a no_std crate is a real hazard).

## Layout

- `engine/` — Phase 1: std + tokio + hickory. **Builds on host.**
  `cargo build` ✅, `cargo test` ✅ (3 pass, 5 ignored live-network).
  `cargo check --no-default-features` **fails as designed** (exit 101) — the
  `dnssec-ring` compile guard fires; negative assertion verified.
- `native/` — Phase 2: no_std + smoltcp + hickory-proto. **Library builds on
  host** (`cargo build --lib` ✅, `cargo test --lib` ✅ 4 pass: tristate +
  sddf_device bounds). The `[[bin]]` (main_native.rs) is bare-metal only:
  `#![no_std]`, custom `#[panic_handler]`, `#[no_mangle] main`.

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
