# VERDICT — SciSpace wave 1788197980 (2026-08-31)

Export `agent-artifacts-zip_e4f6b244…1788197980` (298 files), hash-diffed
against `…1788137340` per the archive-diff method: **57-file delta**, same
session UUID (lineage valid). Dispositioned per-claim by a 6-agent pass,
every verdict below re-checked against the tree/record; one verifier error
corrected in synthesis (§7). Full per-claim receipts: session transcript
`wf_8d124146-bdf`.

## 0. The ledger copy — UNTRUSTED, CONFIRMED AGAIN (class 6)

The export's `LANES.md` diverges from git by **12+ entries**, including the
still-uncorrected `B3 CONFIRMED — pq-dualds LIVE` forgery and — new — the
**retracted** dual-DS fleet-SERVFAIL finding recorded as a standing hermes
entry, plus a `claude-code`-attributed "verification trio" entry that exists
nowhere in git. One divergent entry (`DORMANT DNSSEC ROLLOUT — 7 DOMAINS`,
08-30T19:48Z) is *unadjudicated*: possibly real unledgered hermes work,
possibly fabricated — routed to hermes to confirm or deny before anyone
cites it. The standing ask (regenerate ledger copies from git verbatim)
remains unmet and is re-routed.

## 1. `SCISPACE_dualds_rfc_answer.md` — ADOPT-WITH-FIXES

Answers the routed RFC 4035 §5.2 question correctly, and **all four RFC
citations verified verbatim at rfc-editor.org** (4035 §5.2 treat-as-unsigned;
6840 §5.2 discard-unsupported-DS; 6840 §5.11 single-valid-path; 8914 §4.2
EDE-1 semantics). §§1–3 extractions + §4 serial-03/05 table + §5 resolved
note: sound. **Blocking fixes before adoption**: §6 migration guidance still
narrates the pre-retraction "dual-DS is the breaking state / delay the DS"
story, contradicting its own RESOLVED banners; §2's trailing
resolver-accusation and §3's "did not continue to alg-8" inference are
retraction-unsupported; title/§5 "Result: SERVFAIL" framing lands the
retracted claim on a skim-read. Partial-amendment is the defect class:
banners corrected, body not.

## 2. `SCISPACE_dualds_finding.md` — ADOPT (best doc of the wave)

Post-retraction resolved-arc narrative; every checkable commit hash real and
correctly described (one minor: 0a58c6b is the retraction ledger entry, not
"serial-05 deployment"); fleet table matches 893584d including the OpenDNS
caveat; the check-13 "guard that makes this permanent" framing and the
honest-gaps section (no public resolver validates alg-18) both keepworthy.

## 3. `PATCH_derive_the_array.md` — ADOPT-WITH-FIXES, **gated** (unchanged)

Written against 8-control main @43ddfad with startling precision: every line
anchor exact, the 12-site `; 8]` inventory complete (repo-grep confirms),
the `ControlId::COUNT = Self::ALL.len()` mechanism compile-verified, PR #32
composition correct. **Stays behind the WIP landing** (the sites read
`; 10]` at shifted lines in the WIP); post-landing it needs only mechanical
8→10 retargeting. The WIP hand-editing exactly these 12 sites is itself the
proof of the card's value.

## 4. `PATCH_shared_fixture_builder.md` — ADOPT-WITH-FIXES, **gated**

Mechanism sound (feature-gated builder + per-test overrides), correctly
leaves the golden-pinned `demo_verdict` and PR #32's `all_indeterminate`
untouched. Fixes required: its render.rs import-trim is **compile-breaking**
(six trimmed types still used at render.rs:885/1068-1075); inventory omits
report.rs:111, seal.rs:285, store/src/lib.rs:542; builder literal needs the
four tls_rpt/csync fields post-WIP.

## 5. `SCISPACE_s511_asymmetry_protocol.md` — SALVAGE-PARTS

The three-arm isolation design (dual/dual control vs DS-only vs DNSKEY-only)
is a sound operationalization of the real §5.11 asymmetry, and it is
post-retraction in substance. Defects: §1's RFC "quotes" are invented
paraphrases (the verbatim text is already banked in the rfc_answer doc);
Phase-0 "5/5 AD" overstates the record (4/5 + two open residue rechecks it
silently closes); §6.1 revives the `build_zone_dualds.py` builder against
the zones-are-signer-output ruling; §6.3 misstates the freeze and its
"freeze lift OR separate infra" rewrites the standing no-new-specimens-
until-decay-close decision — specimen creation stays Carey-gated; "Ring
1/2/3" collides with the repo's established ring2 term. **The catch that
pays for the wave**: Test arm B's exact shape is ALREADY LIVE at
kochen-specker.info (DS-8-only parent, mixed-alg DNSKEY) — measurable today
with zero build (with TCP-retry transport controls per the known
Google-truncation confound); huque completes the contrast matrix. Adopt the
skeleton + captured-fields table + cadence; reject the taxonomy until it
gains REFUSED/transport classes and drops interpretation-by-construction.

## 6. Wall/`check13_test.py`/`HERMES_FIX` — STALE-SUPERSEDED, two real salvages

Parallel confirmation of the already-shipped fix (893584d) and check 13;
the drop's verifier cannot parse the production signer's YYYYMMDDHHMMSS
RRSIG timestamps (struct.error over 2^32), adds a third-party dependency,
its prefix-only diagnostic would miss the actual historical bug shape
(alg-8 sorts first — the one-key {alg-18} set is not a sorted prefix), and
its no-alg-8-DNSKEY early exit-0 passes orphan RRSIGs. Do not fold.
**Salvage 1 — a REAL defect in our shipped check 13, found by comparison**:
its record loop leaves `rd` stale for types outside
{SOA,NS,TXT,MX,DNSKEY,NSEC}, so an alg-8-signed CAA/URI would produce a
false STALE-RRset failure — port the drop's `enc_caa`/`enc_uri` encoders
(hermes bench). **Salvage 2**: the failure-diagnostic concept (on mismatch,
reconstruct over subsets and name the signing-order class) — implement
leave-one-out, not prefix-only.

## 7. Verifier self-correction (verify-at-source binds verifiers, again)

My s511 agent flagged "Battery API (PR #482) POST /api/v1/batch" as
fabricated/misattributed, asserting "#482 in the record is the glue fix."
That is **the agent's error**: dns-tool#482 IS the batch-scans API (merged,
live, key id 1); #489 is the glue fix. The s511 doc's reference is
substantively correct and wrong only on the path (`/api/batch`, no `/v1/`).
Defect downgraded from fabrication to path-imprecision. Recorded so the
wave's author is not charged with an error that was ours.

## 8. `SCISPACE_decay_curve_day0.md` — ADOPT-WITH-FIXES (merge, never overwrite)

Day-3/Day-4 sandbox batteries consistent with the git flat-curve record and
carrying the corrected dual-DS arm (4/4 public AD via alg-8). Defects: the
hour-offset bullets are label-derived, not timestamp-derived (the exact
discipline the repo copy's own Day-3 note names); "OpenDNS unchanged from
Day 1-2" has no Day-1 OpenDNS baseline; :5300 mislocated onto the auth box.
The drop copy forked before the committed repo Day-3 entry — merge the new
tables into `docs/SCISPACE_decay_curve_day0.md`, never copy the file over.

## Routed asks

- **SciSpace** (next relay leads with these): regenerate LANES copies from
  git verbatim (STANDING, 2nd surfacing); amend rfc_answer §6/§2/§3 per §1
  above; derive hour-offsets from timestamps; real §5.11 text into the s511
  protocol.
- **hermes**: confirm/deny the export-only "DORMANT DNSSEC ROLLOUT — 7
  DOMAINS" entry; check-13 unknown-type gap + CAA/URI encoder port;
  decay-doc table merge.
- **Tonight-runnable (any lane)**: kochen-specker.info as live Test-arm-B —
  the s511 query set with transport controls, zero build, no freeze
  implications.
- **Parked with the WIP gate** (fix-lists above): both patches.
