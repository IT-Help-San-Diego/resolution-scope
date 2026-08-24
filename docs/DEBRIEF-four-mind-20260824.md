# DEBRIEF — Resolution Scope, four-mind sound-off (2026-08-24)

Prepared by Hermes for Carey + Claude Science + Claude Code + SciSpace.
Every factual claim is verified at source (code or RFC) this session; where a
number is carried from memory rather than re-measured, it says so.

Purpose: get the whole team sounding off on (a) what landed, (b) what's still
open, (c) one new decision each with a clean either/or, and (d) one genuinely
new scientific challenge that needs fresh thinking.

---

## 1. Landed (verified, tested, shipped — `936a5f0` on main)

Two rulings Science issued this turn both had measured answers, not values
calls, and both are now in the engine:

| item | was | now | basis (verified verbatim) |
|---|---|---|---|
| DNSSEC `SignedNotDelegated` | Indet / Medium | **Absent / High** | RFC 4033 §5 "Insecure" — a resolver reaches the identical state for unsigned and signed-but-undelegated. Indet was silently dropping DNSSEC's weight 3 out of the score, so a half-finished deployment scored higher than honest non-deployment. |
| SPF `+all` | bundled in `OtherPolicy` (Present / High) | **`PositiveAll` / Absent / Critical** | RFC 7208 §8.3 — pass = "considered responsible for sending the message." A record authorizing every sender conveys exactly the information of no record. `?all`/no-all stay `OtherPolicy` (Present/High, §8.2). |

Seal scheme bumped **v3→v4** (the `+all` split adds a new disposition *token*
to the preimage = construction change). Golden seal recomputed **byte-exact** —
I first reproduced the old v3 golden from the same preimage, then pinned the v4
value, so the recompute is a known-answer, not a re-derive. Native golden +
FFI KAT + cli scheme-mismatch test all updated.

Gates: engine 146/146, cli 57/57, native 8/8, types 3/3, clippy strict clean,
citation boundary passed. Negative control: reverting the `+all` parser branch
fired the G5 known-answer vector before restore.

---

## 2. Open engineering — no ruling needed, one thing to decide *how*

**The version stamp.** `engine_version()` is `env!("CARGO_PKG_VERSION")` — and
every crate's Cargo.toml says `0.1.0`. It is **in the seal preimage** (pushed
third, after scheme and domain), so two builds emitting different verdicts
currently stamp seals claiming the same provenance. This is load-bearing on the
integrity layer, not cosmetic.

The parent instrument already does it right (git-derived version via
`scripts/version.sh` → ldflags). The Rust equivalent needs a `build.rs` that
doesn't exist yet. Two sub-decisions:

1. **Version shape — Carey's ruling: `v26.x.x`.** The year says what it is,
   matching the parent (`dns-tool-intel` is already at `26.51.0`). A
   suffix (`-alpha`/`-beta`) says "not GA yet" honestly. This tool is shipping
   real science while stamped `0.1.0` — the stamp is now a lie.
2. **Where it comes from** — `git describe` at build time (build.rs → env), or
   a hand-bumped semver. Build.rs is the correct answer; the cross-compile
   story (the native aarch64 bare-metal crate) is the thing to get right.

---

## 3. New decisions from this turn — each a clean either/or

### 3a. Scan persistence — RULED: persist by default, delete only on flag

Current state (verified): `record_scan` persists `(domain, engine_version, seal,
seal_scheme, verdict)` with a re-derivable seal; `scan_history(domain)` reads it
back; `verify_scan` re-checks for tamper. **But it's opt-in** — you must pass
`--store-url`, else nothing is written.

**Carey's ruling: scans persist always; they disappear only when the operator
explicitly flags it.** This is the "save everything, publish the signal" doctrine
applied to the measurement itself: a scan is a sealed fact, and you don't
silently discard a scientist's data. Shape: persist by default; `--discard` (or
equivalent) is the named, explicit, irreversible opt-out.

**Open for the team:** the default store location. A local-first tool needs a
default Postgres that doesn't require the operator to have provisioned one.
Options: (i) require an explicit `RS_STORE_URL` (most honest, most friction);
(ii) a local default (e.g. `postgres://localhost/resolution_scope`) with a
clearly-labelled fallback. Carey's local-DB doctrine (real Postgres, never
embedded) already rules out SQLite — the question is only *which* Postgres and
*how much* the operator must do to get it.

### 3b. Tab layout — the seal must never renumber

Current: 8 controls grouped into 5 tabs, `1:Summary … 6:CAA/CDS, 7:Seal`.
Carey's instinct is right and it has a concrete reason: **if the seal is the
last number and a future control slots in, the seal never renumbers.**

The fork Carey named precisely, and it's a real one:
- **A — spread out:** one control per key, `0:Summary, 1..8:controls, 9:Seal`.
  Most honest (every number key = exactly one control), zero spare.
- **B — keep grouping:** leave 6 and 7 as spare, seal at 8, room to grow
  without renumbering.

The deeper point Carey made: **the real goal is not "add two slots" or "spread
out" — it's "how short can this text be and still communicate."** That's the
mastery-of-communication constraint, and it applies to the whole surface, not
just the tab row. Which of A/B we pick is downstream of how tight we can make
the copy.

### 3c. The keycap row — signal as text, icon as fail-safe decoration

Carey's "wingdings" story is a Carrier Color lesson, and it gives a clean rule:

- **Signal = plain ASCII.** Numbers, verdicts, labels, the seal — font-
  independent, readable on any terminal anywhere. If a font is missing a glyph,
  the meaning survives because it was text all along.
- **Carrier (the icon) = decoration, must fail safe.** The owl `🦉` is a
  Unicode emoji; whether it renders as an owl or tofu boxes depends on *their*
  font, not us. It already fails safe — the epistemic mode is carried by palette
  color *and* the words "BLUE TEAM · defend", not by the owl.

Keycaps should be old-school Unix ASCII: `[1]` `[j]` `[k]` `[enter]` `[esc]`
`[tab]` `[q]` — the `less`/`vim`/`mc` convention, wingdings-proof, and it reads
as a key with zero special glyphs. Avoid `↑↓` `⎋` `⏎` where they'd risk the same
tofu as the owl; bracket the ASCII name instead.

---

## 4. THE NEW SCIENTIFIC CHALLENGE — minimal 4-state icons

Carey's question, and it's the right one to pose to the whole team:

> We need icons that represent four different states, just like the Owl
> Semaphore, that can — with color and placement or movement — communicate with
> the same clarity and depth. What are replacement ideas for the most minimal,
> stripped-down version of the Owl Semaphore? How would it display in a tiny
> console — like an old Casio-style digital watch, in the most minimal
> environments?

The constraint, stated precisely:

1. **Four states** = the Klein four-group (I, σᵥ, C₂, σₕ) — but the *display*
   must not depend on four glyphs a font might not have.
2. **Three independent channels are available in any terminal:** color, position
   (placement/movement), and character (ASCII always available). The Owl
   Semaphore in a GUI uses color + shape; the console version must re-express
   the same group using only channels that survive in an 80×24 cell grid.
3. **Must degrade gracefully** — strip color, it still works; strip movement,
   it still works; the ASCII character must carry the state alone as the floor.

Candidate directions to sound off on (not rulings, seeds):

- **Position as the group operator.** A single glyph placed in one of four
  corners of a cell = one of the four states. Placement is font-independent and
  survives color-stripping. This maps the V₄ to a 2×2 spatial grid — σᵥ = flip
  vertical, σₕ = flip horizontal, C₂ = flip both, I = identity — which is
  literally the group's own matrix representation rendered as position.
- **ASCII four-characters as the fallback floor.** `1` `-` `+` `×` or `I` `V`
  `H` `C` — four ASCII glyphs that read even at one character per cell.
- **Two orthogonal half-cells** (top/bottom, left/right) with a fill/no-fill
  bit each, à la a 7-segment or dot-matrix digit — the Casio-watch answer.

The scientific heart of it: **the Owl Semaphore's content is the group structure,
not the bird.** The minimal version must preserve the structure (which two flips
compose to which) and can discard everything decorative. The group is a 2×2
frame operation; a 2×2 dot grid is the same thing drawn small. The challenge is
whether we can make that *readable* as clearly as the owls, not whether we can
encode it.

---

## 5. Migrating DNS Tool scans into Resolution Scope — provenance, not just disclosure

Carey authorized: bring existing scans from the live DNS Tool into the new
instrument's history *if it helps*, and "disclose everything." The honest
shape of that, verified at source:

1. **Two different instruments.** Resolution Scope stores 8 controls + TriState.
   The DNS Tool's live verdict object carries **9 keys** (adds BIMI and TLS-RPT,
   which Resolution Scope does not score) with a value space of
   `info/success/warning/missing` — a display-severity map with **no
   "couldn't-measure" slot**. (Carried from the Arm-1 finding; re-verify against
   the live `/api/replay/:id` before any ingestion.)
2. **Direction is one-way, read-only from the old tool.** DNS Tool's production
   DB is untouched; we extract only. We never write to it.
3. **Ingest with a `source_instrument` provenance field** — a real column
   (`dns-tool-go` vs `resolution-scope-rust`), not a README note. A note drifts;
   a field can't be missed. This is the difference between "disclosure" and
   "provenance."
4. **The vocabulary mapping is lossy and must be per-row, not blanket.** Go
   `success/warning/missing` → Rust TriState needs a documented mapping, and Go
   rows that don't distinguish "measured-absent" from "couldn't-measure" land as
   "unmeasured — source did not distinguish," which is itself an honest row.

**The deeper point:** the old corpus helps the new instrument *by staying
distinct and comparable* — that's exactly what Arm 1 / Arm 2 (the Go-vs-Rust
differential) already is. The value is calibration against a frozen reference,
not melting the reference into the new lineage. If we do ingest, it must carry
`source_instrument` so the database can honestly say "this row is the old
instrument, this row is the new one" — otherwise the "database shows us building
the tool" claim becomes a category error.

---

## 6. Questions for the team (sound off)

1. **Minimal 4-state icon** — is the 2×2 positional grid (corner placement =
   group operator) the right minimal form, or is there a clearer ASCII-first
   encoding? What's the most legible single-cell representation of V₄ that
   survives color-stripping and font-missing?
2. **Tab layout A vs B** — one-control-per-key (seal at 9, no spare) or keep
   grouping (two spare, seal at 8)? Does the "how short can the text be" goal
   point to A (spread, because the controls earn their own keys) or B (group,
   because tightness is the point)?
3. **Default store** — for a local-first tool that must persist by default, what's
   the least-friction real-Postgres default that doesn't hide a black box?
4. **Version shape** — `v26.x.x` + alpha/beta suffix (Carey's lean), and does
   `git describe` in a `build.rs` survive the aarch64 bare-metal cross-compile
   cleanly, or is there a known sharp edge?
5. **Ingestion** — confirm the `source_instrument` field + per-row lossy-mapping
   disclosure is the right provenance mechanism, or is there a cleaner one?

---

## Appendix — the ruling chain, one line each (for the log)

- `6a10e80` SoftFail → Ok (SPF/DMARC ladder offset, RFC 9989 §7.1).
- `e5a7936` DANE `DnssecRequired` → NotApplicable (measured unavailability).
- `5eaae12` CDS ruling pinned in code + guard.
- `936a5f0` SignedNotDelegated → Absent/High; `+all` → PositiveAll/Absent/Critical;
  seal v3→v4.
