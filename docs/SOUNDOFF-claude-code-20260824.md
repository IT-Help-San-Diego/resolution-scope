# SOUND-OFF — Claude Code lane on the four-mind debrief (2026-08-24)

Answers to `docs/DEBRIEF-four-mind-20260824.md` §6, each grounded in
verification run this session (5-agent sweep over both repos + rfc-editor.org
first-hand; per-claim evidence in the ledger entry that accompanies this file).

## 0. First, a defect the sweep found: the v4 bump broke its own obligation

`936a5f0` bumped SEAL_SCHEME v3→v4 but touched no `store/` file. `verify_scan`
short-circuits every non-current scheme to `UnverifiableScheme` — so all rows
sealed yesterday under v3 (real rows exist) became unverifiable, in direct
violation of the obligation written into `SealCheck`'s own doc
(store/src/lib.rs:62-68: "Whoever bumps SEAL_SCHEME adds the previous scheme's
re-derivation arm"). Not a false-tamper (the e9b0d2e design held), but a
contract break at the integrity layer.

**Fixed this session** (PR #19, squash-merged @8cbccdd, CI 18/18 including the
planted-v3-row live-postgres test): v3's canonical form is byte-identical
to v4's except the scheme line — proven by Hermes's own known-answer
reproduction during the bump — so the arm is a scheme-parameterized
re-derivation: `seal_versioned_under_scheme` in the engine (additive; goldens
untouched), scheme dispatch factored into a pure `check_stored_seal` with four
non-DB tests plus a planted-v3-row live-postgres test. Open follow-ups named in
the code: (a) rows labeled **v2** exist by backfill timing (migration 002) —
whether they still deserialize and deserve an arm is unresolved archaeology;
(b) the next bumper (v4→v5) owes the v4 arm; the obligation doc now lists the
arms present.

## 1. Minimal 4-state icon — encode the generators, not the states

The strongest form: **two independent ℤ₂ channels, because V₄ ≅ ℤ₂×ℤ₂.** Four
arbitrary glyphs encode the *states* but hide the *operators*; two binary
channels make composition visible — one generator always toggles channel 1,
the other always toggles channel 2, C₂ toggles both. Concretely, three tiers:

- **ASCII floor (any terminal, any font, color-stripped):** letter case ×
  column position in a fixed two-column field: `N.` / `.N` / `n.` / `.n`.
  Pure ASCII, one field, and the group action is literally visible: flip
  case = one reflection, flip column = the other, both = C₂. (The TUI already
  speaks this dialect — `state_icon` uses fixed-width ASCII cells.)
- **Block tier (dot-matrix / Casio):** the Unicode quadrant blocks `▘ ▝ ▖ ▗`
  are the 2×2 positional grid AS single characters — corner = group element,
  and the V₄ flips are the geometric flips of the glyph itself. Wide terminal
  font coverage, but NOT universal — this is carrier, never signal.
- **Color:** redundant third channel, never load-bearing (Carrier Color rule).

Boundary, per the standing owl-marks rule: this is a NEW symbol set to be
spec'd into the family standard for constrained slots — the owl artwork itself
is never simplified to fit a slot; the slot gets this instead.

## 2. Tabs — A, and the measurement says exactly what it costs

Measured: the 10-tab A row (`0:Summary 1:DNSSEC 2:SPF 3:DKIM 4:DMARC 5:DANE
6:MTA-STS 7:CAA 8:CDS 9:Seal`) is **75 columns with single-space separators —
fits 80** — but 85 under the current Tabs config (right-pad + `│` divider):
A is feasible iff the divider goes. Renumber sites are three, not one: the
header's `(7)` beside the seal prefix, the summary hint line, and the footer
echo of the tab label — all should derive from a single `TAB_SEAL` producer so
this never drifts again. Code cost: admit `0` in the digit handler, shift
`TAB_SUMMARY`/`TAB_SEAL`/`tab_for_control`, update two pinned tests.

**Lean: A.** Two reasons beyond honesty-per-key: (i) B's spare slots reserve
room for a 9th control — which is precisely the growth the source-not-control
doctrine (weight-2 ruling recommendation) resists; headroom for a thing we
decided not to want is not headroom. (ii) Seal at 9 is the terminal digit —
under A it can never renumber, which is Carey's stated invariant.

## 3. Default store — the ruling's edge case is the machine without Postgres

Persist-by-default has one honest failure mode: **refuse and instruct.** If no
store is reachable, the scan must not run-and-silently-not-persist — that
would make the ruling a lie exactly where it bites. Shape: try `RS_STORE_URL`,
else `postgres://localhost/resolution_scope`; if neither answers, refuse with
the exact one-line bootstrap command (and `--discard` as the only path that
runs without a store — explicit, named, per the ruling). Corollary from the
observation-conditions rule: the conditions line should name WHICH store
received the row, so persistence is visible, not assumed.

## 4. Version — verified ready; three sharp edges, none blocking

Verified: every golden/KAT pins `"0.1.0"` on BOTH compute and expectation
sides, so the bump breaks zero tests; `verify_scan` hashes the row's stored
version, so old rows keep verifying; the version is preimage CONTENT, not
form — **no scheme bump needed** for the move. `build.rs` + `git describe` is
right, with three edges:

1. **Split-brain:** cli's clap `version` bakes the CLI crate's own
   `CARGO_PKG_VERSION` — stamp both crates (or make `--version` print
   `engine_version()`), else the binary reports 0.1.0 while seals say v26.
2. **Staleness:** emit `cargo:rerun-if-changed=.git/HEAD` and packed-refs, or
   cargo caches the stamp across commits — the Rust twin of the parent's
   "plain go build stamps dev into prod" defect.
3. **No-.git contexts** (tarball, vendored build): fall back to something
   VISIBLY distinct (e.g. `26.0.0-untracked`), never silently to a default.

aarch64 is a non-edge: build scripts execute on the HOST during
cross-compilation. Cargo.toml wants bare semver (`26.x.y`, no leading `v`).

## 5. Ingestion — the premise moved: map from the tri-states, not the verdicts

The sweep **refuted the "no couldn't-measure slot" claim in the good
direction**: the Go tool PERSISTS per-protocol tri-states — `spf_state`,
`dkim_state`, … `caa_state` (all nine) with `present | absent_confirmed |
indeterminate` — plus git-describe `app_version` on every row since migration
019. So:

- **Map from `*_state`, not from the display statuses.** Near-lossless into
  TriState (Arm-1's `go_to_tri` already exists — reuse it; the only
  asymmetry is NotApplicable, which Go cannot express). The 9-key display map
  is protocol-relative (SPF absence = "missing", DANE absence = "info") and
  known-lossy for DNSSEC inside the Go tool itself (CD-confirmed bogus:
  status "warning", display_severity "danger").
- **Keep `full_results` verbatim in the ingested row.** Provenance = the
  original plus a versioned mapping, not the mapped result plus a note. BIMI
  and TLS-RPT (no Rust control) live there unmapped instead of being dropped.
- **`source_instrument` column: yes** — plus the source's own `app_version`
  (rows before migration 019 carry `''` = unattributed), and TWO timestamps:
  `measured_at` (source `created_at`) vs `ingested_at`.
- **Legacy rows without `*_state` keys → indeterminate-with-reason, never
  `absent_confirmed`** (the keys are newer than much of the corpus).
- **Disclose the corpus curation:** `shouldPersistResult` drops /dev/null,
  ephemeral, and undelegated-successful scans — `domain_analyses` is a
  curated corpus, not "all scans."
- **Seal-at-ingest claims tamper-evidence since INGESTION only** — the seal
  vocabulary ruling (tamper-evidence, never proof-of-measurement) already
  covers this; the row shape should make the ingestion time unmissable.

## 6. One item back to Science — the ?all tension the +all ruling opened

RFC 7208 §8.2, first-hand: *"A 'neutral' result MUST be treated exactly like
the 'none' result."* The +all ruling's stated test — "conveys exactly the
information of no record" → Absent — captures `?all` too, by the RFC's own
normative sentence. Yet `?all` stayed `OtherPolicy`/Present/High. The
distinction is defensible (+all affirmatively authorizes everyone; ?all
asserts nothing) but then the RULING's test needs sharpening from
"information of no record" to "affirmatively authorizes" — or ?all needs a
re-rule. Also for the record: RFC 7208 fail is §8.4 (§8.2 is Neutral), and
RFC 9989 §7.1's aggregate-report-blinding argument (already in the landed
softfail copy) is a stronger basis than the debrief's citation alone.
