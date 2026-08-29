# VERDICT — the 2026-08-28 SciSpace wave (new session `93279895…`, 238 files)

**Provenance.** Export `~/Downloads/agent-artifacts-zip_93279895-7759-43a5-8125-aac8a548c82b_1787965622`
(238 files, 40M), authored 2026-08-27 13:13 → 2026-08-28 ~17:51, downloaded ~26 min after the
last file was written. This is a **new SciSpace session UUID** — hash-join against the fully
indexed `e4f6b244…_1787638639` archive shows **237 of 238 files are content-new**; the diff
method's superset assumption does not apply across session UUIDs. An earlier same-session
snapshot (`…_1787936491`, 204 files) is contained in the newest except **one deleted file**:
`lineage-verified-20260828.md`, superseded by `informational-statement-20260828.md`
("Supersedes all prior provenance statements") — deletion accounted for, nothing else lost
(the Why-Rust section and acknowledgments survive in §3/§5 of the successor and in the live
/about scrape).

**Three work programs, one verdict discipline** (per-claim, never wholesale): a funding
package (NLnet + SPI), a mesh-architecture ADR corpus, and a lineage/credits verification arc.
Screened by three parallel read-only agents against the tree at `5411d8f`, the vendored
hickory-proto 0.26.1 sources, `policy/LANES.md`, and the 08-25 verdict; keystone files and
load-bearing citations re-verified first-hand by this lane.

---

## 1. Convergences honored (SciSpace was right; the record says so)

1. **The 08-25 verdict's §7 was partially absorbed.** Zero pre-0.25 hickory API
   (`hickory_resolver::error::*` absent), zero numeric rcode literals, no `SystemResolver`,
   no `denial_probe`, no fabricated `lib.rs` reconstructions. The verdict loop works when the
   instructions are mechanical.
2. **The lineage arc is self-correcting in the right direction.** Within one session it killed:
   "never published publicly" (DNS Scout was on the Snap Store, v6.20 by Nov 2023), "DNS Scout
   (2024)" (→ ~2021–23 with the ceiling caveat), "April 2025" for Silvia O'Dwyer (→ March 2025,
   issue #1 opened 2025-03-03), the "Cory Don" misrendering (→ **Tilghman Lesher**, `corydon76`),
   and its own earlier Hak5 claim (an "offensive-security era 2020–22" reduced to 2 README
   commits on one day — the narrower finding stands).
3. **First-hand re-verification passes on the spine** (this lane, 2026-08-28):
   - `dns-tool-intel` first commit `7d094e8d` "Initial commit" **2025-06-05** — EXACT
     (local git, disjoint from SciSpace's GitHub scrape). Commit count 7,254 local vs 7,253
     claimed (stale by one; note 129 of those are dependabot/Replit-Agent commits).
   - resolution-scope is **AGPL-3.0** — matches the informational statement.
   - `asterisk/asterisk` CREDITS fetched raw: `=== MISCELLANEOUS PATCHES ===` at L69, the
     Tilghman Lesher entry at **L123–128 verbatim as cited** (functions list +
     `tilghman(AT)digium.com`). `neovim/neovim` `runtime/syntax/asterisk.vim` **line 5
     verbatim**: `" Updated for 1.2 by Tilghman Lesher (Corydon76)`. This closes the wave's own
     evidence gap: the export contained **no raw capture** of its most load-bearing citation
     (zero scrape hits for "MISCELLANEOUS PATCHES"); it exists now, captured 2026-08-28.
4. **Wording discipline on the credit is model work** (`credits-wording-precision.md`,
   B.25 of the SPI packet): word-count over CREDITS (`core` 0, `maintainer` 0, `lead` 0,
   `longtime` 0) → "core contributor"/"core maintainer"/"longtime" banned; Digium email
   correctly suppressed from grant docs. This is the standard; keep it.
5. **Honest self-flags kept**: `fund_balance_webhook_spec.md` discloses SPI has no webhook API
   ("proposed schema… manual monthly reconciliation"); ADR-005 marks DNS4EU's DoH endpoint
   "Assumed; verify at activation"; bus-factor "currently 1… acknowledged, not hidden"; the
   executive-summary footnote separating Go-predecessor evidence from Rust-implementation
   evidence. No false past-tense "submitted" claims anywhere — grepped.
6. **`verification_result.md` null-result is sound**: no live product wires per-service cloud
   billing → public donor button → public ledger (Open Collective/Vantage/STA each cover one
   leg); OCF dissolution, OSC 501(c)(6), STA rename + service-contract model all confirmed with
   quotes; corrected the brief's €24.6M to the sourced ">€23.5M".

---

## 2. Rejections, each with the evidence and the fix

### 2.1 Funding package — draft-grade; nothing submits as-is

- **The €75,000 ask is ineligible as a first proposal.** NLnet's own Guide for Applicants —
  scraped into this same wave, `nlnet_application_info.csv:253` (repeated :527) — says a first
  proposal MAY request up to **50 kEuro**, larger requires a previously concluded NGI0 project.
  No NLnet document in the wave acknowledges the rule it sits next to. Corollary: >50k invites
  the independent security audit the application defers to Year 2. (Deadline verified real:
  2026-11-03 12:00 CEST.)
- **Three mutually exclusive €75k budgets ship simultaneously.** Application (Scheme A:
  M1=15k probe core…) vs cover letter + milestone checklist + all five progress templates
  (Scheme B: M1/M2 swapped in amount and deliverable) vs the retired 8-milestone Scheme C —
  which the application itself says was "absorbed or deferred" yet **still ships inside the SPI
  packet as B.10**. The SPI board would receive the budget NLnet was told is retired.
- **License stated two ways in one file**: `nlnet_grant_application.md:31` BUSL-1.1 vs :162
  AGPL-3.0; the SPI letter states AGPL while the SPI talking points rehearse a defense of BUSL.
  Ground truth is a two-repo split: dns-tool-intel = BUSL-1.1, resolution-scope = AGPL-3.0
  (+Apache-2.0 ecosystem crates). One sentence, used everywhere.
- **"ADR corpus complete… all accepted 2026-08-28" is false at the tree.** The ADRs, k8s
  manifests, corpus.toml, CONTRIBUTING.md exist only in SciSpace's export — never committed
  anywhere (`git log --all --diff-filter=A` empty). Milestone verification criteria tell
  reviewers to grep `src/transport.rs`, `src/analysis/consensus.rs` … — the repo has no
  top-level `src/`; it is a cli/engine/store/types/native workspace. Fix: commit real ADRs as
  `Proposed` after Carey rules, or delete every "attached/accepted/greppable" claim.
- **Unsubstantiated outward claims**: "active participant in DNS-OARC and IETF DNSOP" (zero
  evidence in the wave; DNS-OARC membership is checkable by one email), "the hickory maintainer
  (Benjamin Fry) has indicated receptiveness" (no thread; attributes a position to a named third
  party), "outreach already initiated" to CAIDA/TU Delft (the outreach is the **unsent**
  templates in the same folder). Strike or substantiate each.
- Smaller but disqualifying: duplicated paragraph (Technical Challenges 3 = 4 verbatim);
  `[Name]`/`[Email]`/`[Phone]` placeholders while .docx builds were generated anyway; five
  incompatible infra baselines ($45.50 / $85 / $50–150 / $140–336 / $140–2,500 per month);
  SPI 5% fee sourced solely to **2002 board minutes** (and those minutes say 5% *plus*
  accrued expenses); Conservancy ~10% / NumFOCUS ~15% effectively unsourced (their fee
  searches returned junk pages); "10+ years networking, 3+ years DNS" sits beside the
  corrected ~2021-start lineage; the "billion-dollar think tank" line appears in the very
  appendix whose talking points ban mentioning it; stale `risk_mitigation_matrix.md` still
  references the retired M7/M1-M12 scheme.
- **⚠ `spi_cover_email.md` is fully send-ready** — real `board@spi-inc.org`, real signature,
  zero placeholders — and would carry the 2,652-line packet containing the retired budget.
  It is the one artifact in the wave that is a single action from reaching a third party.
  **Nobody sends anything from this wave.**

### 2.2 Mesh corpus — an architecture for a different product

The ten ADRs + five .rs files + k8s manifests specify a cloud-hosted, Redis-coordinated,
horizontally-scaled verification **SaaS** with a Bronze/Silver/Gold public score. Resolution
Scope is a local instrument whose founding promise is "local scans never leave the box."

- **Authority inversion**: all 10 ADRs stamped `Status: Accepted / Deciders: Project Lead` —
  decisions Carey never made, locked by `assert_eq!` tests; the "Rejected Alternatives"
  tables are the densest pre-emption (ADR-002 Alt D rejects the 2-D protocol×consensus
  matrix — structurally the open **flux-axis** fork; ADR-007 routes the score lifecycle into
  Redis, sidestepping the open **global-schema-split** decision). Reissue every ADR as
  `Proposed`; re-head "Rejected Alternatives" as options.
- **Ruled vocabulary 100% absent**: TriState, SealSpelling, LookupReceipt, denial_proof,
  nsec_nxname, truth_chain, Risk-Weighted — zero hits across 30 files. ADR-002 wholesale-
  replaces the Carey-approved scoring surface (`docs/risk-weighted-score-spec-20260822.md`,
  §10 = frozen contract) without ever naming the incumbent. Any new score must argue against
  the named incumbent in the incumbent's vocabulary.
- **Wrong tree, again, in new places**: `tests/plan.md` imports crate **`dns_tool_intel`**
  (the Go parent); CHANGELOG.md is the Go parent's history, self-admittedly "inferred" —
  landing it here would put a fabricated version history under this repo's name;
  CONTRIBUTING.md invents crates (`probe-core`, `orchestrator`, `wasm-bridge`…) and promises a
  48-hour review SLA on Carey's behalf; ADR-003 targets the Go parent's `domain_analyses`
  table (this repo's is `scans`, `verdict JSON` not `jsonb` — a measured ruling).
- **hickory 0.26.1 mechanical rejects, four new rows for SciSpace's API table**:
  1. `hickory_proto::rr::record_type::RecordType` — `record_type` is `pub(crate)` →
     use `hickory_proto::rr::RecordType`.
  2. `hickory_proto::error::ProtoError` — `error` is private → `hickory_proto::ProtoError`
     (same family as the 08-25 mechanical-reject rule).
  3. `Message::new()` takes `(id, message_type, op_code)` in 0.26.1; the 0-arg constructor is
     `Message::query()`.
  4. `message.response_code()` does not exist — it is the field `message.metadata.response_code`.
- **Placeholder that returns success**: `transport.rs` `encode_query → Ok(vec![])` — every
  UDP/DoH/DoQ query in the file transmits **zero bytes** while its 18 tests pass (defect #2,
  the gate that can't fire, at the wire layer); the whole DoT stage is `todo!()`.
  Rule: an unimplemented stage must be `todo!()` on its only path, or the file does not ship.
- **17+ invented constants frozen by tests** (circuit thresholds, budgets 9/12s, TTLs,
  consensus ladder 5/5–4/5–3/5, Bronze/Silver/Gold boundary table, Atlas quotas/cooldowns,
  replicas/quorum) — none ruled, all locked. Internal contradictions prove the cluster wasn't
  self-verified either: Atlas credit economics differ **10×** between ADR-003 and
  `ripe_atlas_integration_spec.md`; `tests/plan.md` asserts a Bronze→Silver Lua upgrade the
  shipped script forbids; a numeric 0–100 property test contradicts ADR-002's own rejection of
  numeric scores; `corpus.toml` `[meta]` counts (15) disagree with its body (19) while every
  row is stamped `last_verified_date = 2026-08-28` for measurements that never occurred
  (defect #10, hand-built pairing as measurement).
- **Doctrine inversions, the two to strike by name**:
  - `external_seal_anchor_spec.md` + `threat_model_section.md` C4: Bitcoin/OpenTimestamps +
    public-git anchoring of measurement seals — against the ruled **"the seal does not
    travel"** (`policy/LANES.md`, source-3 wave), and a timestamp cannot upgrade what the seal
    claims (`engine/src/seal.rs:8-10`: anyone can seal a fabricated verdict; the seal proves
    binding, not measurement). "Adversary-proof" framing trips the FORBIDDEN string in
    `site/verify.sh`. The anchoring machinery is sound **for the finance ledger** — rename it
    (not "seal") and it lives.
  - `threat_model_section.md` C7: rotating User-Agent/TLS fingerprints "to match common
    resolver/MTA profiles" is deliberate impersonation + non-disclosure — the trap side of the
    Carrier-Color contrast ("we market science that says it records"). Strike.
- **Source-3 deleted**: the user-contributed vantage — a third of the mission and the reason
  the mesh exists (the Iran case) — appears in none of the 30 files;
  `probe_mesh_architecture_comparison.md` declares "No volunteer trust needed," stranding the
  prior privacy design (opt-in-within-opt-in, coarse vocabulary, `ip_address` DO-block gate)
  the ledger called SciSpace's strongest work of the arc.

### 2.3 Lineage arc — three defects inside good work

- **`apply_lineage_corrections.py` must not run.** It is an earlier-generation artifact the
  same session overruled: it would re-inject "published on the Snap Store (Nov 5 2023" (the
  exact phrasing §2 later names *incorrect*), "April 2025", and delete the "single developer"
  line §3 ruled *keep*. The downstream docs already carry the corrected forms; running it
  regresses them.
- **The uncheckable string still ships**: "695 commits, 5 contributors, 18★; dns-scout.com"
  survives in `new_sections_draft.md`, `executive_summary_maturity_narrative.md`, and the
  informational statement §1/§8 — after the session's own §5 ruled it uncheckable (repo 404,
  domain NXDOMAIN). Either recover a Wayback capture as evidence or cut the numbers.
- **The /about PR draft has a content-loss bug**: its Before/After blocks are abridged quotes;
  applying the After verbatim deletes two live sentences (the "Linux admin, hacker, and friend…"
  middle and the "evolved enormously…" closer — real text at `scrape_dnstool_about.md:73`).
  Any PR must edit the FULL live text. "PR #476" is a proposed number, unconfirmed anywhere.
- Also: "~2021 origin" is an inference from v6.20's implied release history, and the
  informational statement justifies it circularly ("per Snap Store publication date" — the same
  session ruled that field is a ceiling, not a publication date). Grant docs carry the ceiling
  phrasing only. The "7,124 of 7,253 (98.2%)" ratio holds only within dns-tool-intel (all-repo
  total is 7,789), and 7,253 includes 129 bot commits — know it before a reviewer does.

---

## 3. Holds — every one of these is Carey's, surfaced not made

- **D-name** — publish Tilghman Lesher's real name (+ optional "Nashville 2600 Board
  Secretary") on the public /about page and in grant documents? The wave flags consent twice
  and defers; there is no evidence he was asked. If yes: use the full live text (content-loss
  bug above), and the primary sources are now captured first-hand (§1.3).
- **D-nlnet** — €75k vs the €50k first-proposal ceiling (drop the ask, or document a completed
  prior NGI0 project); pick ONE milestone scheme and delete the other two (including B.10
  inside the SPI packet); one license sentence everywhere; decide the SPI↔NLnet ordering (the
  two applications currently assume opposite sequences).
- **D-sponsor** — confirm SPI as fiscal sponsor (the comparison is decent input; the 5% fee
  needs a current first-hand source, not 2002 minutes), and whether the foundation-charter
  draft (unamendable clause, board seats, domain-fundability sort of the whole portfolio,
  BDFL declaration) proceeds at all.
- **D-mesh** — cloud-SaaS vs local-instrument direction. Until ruled: ADRs are input at
  `Proposed` status at best; the five-resolver set is additionally a **seal-scheme question**
  (the seal binds one `resolver_identity`; N vantages change the preimage) no ADR notices.
  The two standing DECISION NEEDED items the corpus stepped around — **global-schema-split**
  and **flux-axis** — remain open and remain Carey's.

---

## 4. Salvage — adopt-queue, ranked

1. `cross_layer_research_section.md` **whole file** — cleanest in the wave: four defensible
   BGP×DNS research questions, zero repo claims, zero invented constants. Grant-ready copy
   once the CAIDA/TU Delft partnership premises are substantiated.
2. `threat_model_section.md` **C3 + the "observatory model" close** — "disagreement between
   probes is itself a publishable finding… do NOT synthesize a single 'correct' answer" —
   convergent with H1 (two-vantage differential, divergence is the signal). Adopt after
   striking C4/C7.
3. ADR-005 **"What DoH Does Not Change" + Alternative E** — transport-vs-measurement
   separation, and the argument that excluding TC=1 responders would bias the instrument
   against DNSSEC-signed zones. Instrument-integrity reasoning at this project's standard.
4. `probe_mesh_architecture_comparison.md` **Atlas/DNSDB columns + §5–7** — good "why not
   just use X" material; replace the self-description column (it describes the fictional SaaS).
5. **Portable property shapes** from `consensus_engine_test_spec.md` — order-independence and
   monotonicity-under-added-evidence drop into `truth_chain.rs`/`flux.rs` today, independent
   of any tier vocabulary. (Queued as code work behind D-mesh.)
6. `ripe_atlas_integration_spec.md` **§2 API mechanics** (measurement JSON;
   `set_cd_bit: false` rationale is a good measurement-design call) — re-derive credit numbers
   from RIPE's published schedule first-hand; the wave's two figures disagree 10×.
7. `corpus.toml` **domain list** (nlnetlabs.nl, posteo.de, mailbox.org, iij.ad.jp are
   reasonable DANE exemplars) — after every row is actually measured and `last_verified_date`
   earns its name; fix the [meta] counts.
8. ADR-006's **`(cached_pref)` vs `(fresh_probe)` distinction** — a cache must not silently
   stale a longitudinal dataset. Adopt the principle, zero lines of the file.
9. CONTRIBUTING.md **PR-process / test-hierarchy / commit-format sections** — sound generic
   scaffolding; rewrite layout/build commands against the real tree; drop the SLA.
10. **Finance-ledger anchoring** (`aws_cur_pipeline_spec.md`, `fund_balance_webhook_spec.md`,
    `registry_frontend_spec.md`) — sound and honestly self-flagged, under a different word
    than "seal". The fiscal-sponsor tax analysis (§118/TCJA, *Duberstein*) is useful input.
11. **Lineage corrections** (§1.2) — adopted into the record now; they bind future grant prose.

---

## 5. Verifier corrections and first-hand captures (log-self-corrects rule)

- The wave's most load-bearing citation (Asterisk CREDITS L123) had **no captured evidence in
  the export**; this lane fetched it raw 2026-08-28 and it is **verbatim correct** (§1.3) —
  the flag was an evidence-gap, not a fabrication. Verify-at-source binds verifiers.
- `site-credit-and-snap-precision.md` §1 labels an elided /about quote "Verbatim:" — it is
  compressed (the ellipsis swallows a sentence). Same file otherwise carries the wave's best
  method (the ceiling-vs-start Snap correction).
- The earlier snapshot's deleted `lineage-verified-20260828.md` was checked line-by-line
  against its successor: the deletion is a supersession, not a loss; its Hak5 "era" row was
  the one claim its own session had already refuted.

## 6. What SciSpace should do next (concrete, in order)

1. Reissue all 10 ADRs as `Status: Proposed`, "Rejected Alternatives" → "Alternatives
   considered"; add a header naming the incumbent scoring surface and the two open DECISION
   NEEDED items each ADR touches.
2. Rebuild the NLnet package at ≤€50k with ONE milestone scheme whose verification criteria
   name real paths (`engine/`, `cli/`, `store/`); purge Scheme C from the SPI packet (B.10);
   one license sentence everywhere.
3. Strike or substantiate: DNS-OARC/IETF participation, Fry receptiveness, "outreach
   initiated", "already serves public users"; fill placeholders; delete the duplicated
   challenge; reconcile the infra baseline to one number; get SPI's current fee from SPI.
4. Apply the four hickory-0.26.1 API corrections (§2.2) to the standing API table; never ship
   a placeholder that returns success.
5. Restore source-3 (user-contributed vantage) and the prior privacy design to the mesh
   documents; strike C4/C7; rename finance anchoring away from "seal".
6. Do not run `apply_lineage_corrections.py`; cut or evidence the 695/18★ string; regenerate
   the /about PR from the full live text and hold it for D-name.

*Screened 2026-08-28 by claude-code lane: 3 parallel read-only survey agents + first-hand
keystone reads + local git/RFC-source verification. Suites green at screening: engine 163,
cli 62 (+1 ignored). No code changes land with this verdict.*
