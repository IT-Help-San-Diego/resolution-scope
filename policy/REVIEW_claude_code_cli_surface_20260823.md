# Review: the CLI/TUI as proof surface — Claude Code lane, 2026-08-23

**Brief answered:** HERMES → CLAUDE CODE, "foundation strong, UX not final; make
the surface worthy without changing the truth model; split every note into
FOUNDATION / PRODUCT."

**Method (verify, never infer).** Built `cli` at `d8a7c0c`, ran every format
against resolutionscope.com, it-help.tech, cia.gov, example.com, an NXDOMAIN
name, a URL, an empty string, three spellings of one zone; drove the TUI in a
pty (pyte) through every tab and both framings. Re-derived one seal with stock
`openssl dgst -sha3-512` (byte-exact). Then a 34-agent pass: two refuters per
ledger finding (factual lens + lane/doctrine lens) and four fresh-eyes sweeps
(honesty, first-time user, surface congruence, code). Everything below survived
its refuters or was re-filed by them; sweep findings marked PLAUSIBLE are
code-read only (no captured specimen) and I re-checked the three worst at the
source myself.

**Buckets.** FOUNDATION = lies, collapses states, implies hidden intent, gives
guidance the measured state makes unactionable, or moves RFC/consequence logic
into a renderer. PRODUCT = ugly, confusing, unguided. Lane = where the fix
lives. "(engine)" items are **not** touched by this PR — a renderer cannot fix
an engine string without forking the truth model.

---

## A. FOUNDATION — engine lane (Hermes / Science)

| # | Finding | Specimen (captured) | Source |
|---|---|---|---|
| **F1** | **"Domain does not exist" is collapsed into "transient — re-run" for six arms.** DNSSEC and CDS say `no zone (NXDOMAIN)`; SPF/DKIM/DMARC/DANE/CAA say `transient lookup error → Could not measure … Not a finding — re-run`; MTA-STS `transient error — discovery lookup failed … re-run`. Re-running cannot help. The tri-state (Indet) is honest; the WHY is lost and the consequence gives false guidance. Refuters found **`MtaStsDisposition::NoZone` and `CaaDisposition::NoZone` already exist with finished consequence text and are dead in production** — the mappers never route to them. | `resolution-scope this-domain-does-not-exist-zz.com -f summary` | `analysis.rs` `record_absence_verdict` (parent-zone NXDOMAIN → Indet, same as SERVFAIL) → `*_err_to_disposition` (Indet → TransientError). Spf/Dmarc/Dane/Dkim lack a NoZone variant; MtaSts/Caa have one unused. |
| **F2** | **DANE `DnssecRequired` names no zone and its blue consequence directs the wrong party.** Label "dnssec required — zone unsigned"; blue "Sign the zone first" — printed three rows under it-help.tech's own `DNSSEC PASS`. The gate is on the **MX host's** zone (smtp.google.com → google.com, DS=0 DNSKEY=0, measured). `dane_report(d, tlsa_zone)` receives `tlsa_zone` but matches on `d` alone, so ForeignZone and SameZone get one sentence; with ForeignZone "sign the zone" is unactionable and the attribution's own remedy ("that operator publishing TLSA") is insufficient when their zone is unsigned. | it-help.tech, every surface | `truth_chain.rs` DnssecRequired arm; `analysis.rs` host-zone gate (comment names this exact specimen) |
| **F3** | **DKIM "verified — selector resolved, key valid" / "the published key verifies" / "must defeat a working signature" assert a verification that never happens.** The measurement is: a TXT at one of 81 guessed selectors whose `p=` is non-empty. No decode, no key parse, no signature. `p=notakey` reads "verified". A proxy asserting something never measured — the [proxy-defect class]. | cia.gov, it-help.tech `DKIM PASS verified — selector resolved, key valid` | `analysis.rs` `dkim_key_state` (p= non-empty ⇒ Valid); `truth_chain.rs` Verified arm |
| **F4** | **MTA-STS never consults MX and has no `NoMail` variant**, so a null-MX domain gets `HIGH record absent … mail to this domain is exposed to STARTTLS stripping … (or deploy DANE)` three rows above DANE saying `N/A no mail declared … no mail server to pin`. The instrument contradicts itself on **resolutionscope.com, the site's own specimen.** SPF already has `NoMail`. | resolutionscope.com summary/html | `analysis.rs` `score_mta_sts`; `types` MtaStsDisposition |
| **F5** | **SPF classification is a substring match** (`contains("-all")` / `contains("~all")`): ignores `redirect=` (gmail.com `v=spf1 redirect=_spf.google.com` → MEDIUM "receivers get no rejection instruction at all"), record multiplicity (RFC 7208 §4.5 permerror), mechanism order. Verified live by the sweep. | `resolution-scope gmail.com -f summary` | `analysis.rs` `spf_disposition_from_records` |
| **F6** | **CAA precedence hides the named-CA restriction.** it-help.tech publishes `issue "pki.goog"`, `issue "amazon.com"`, `issue "letsencrypt.org"` **and** `issuewild ";"` (dig, live); the report labels only `wildcard-fully-restricted — issuewild ";"` and says "stricter than a named-CA restriction" — comparing against a restriction the same RRset contains and the report omits. Same class as dns-tool-intel #472's sentinel work, one step further. | it-help.tech CAA row + consequence | `analysis.rs` CAA classification; `truth_chain.rs` |
| F7 | **Domain identity is not canonicalised before sealing.** `example.com`, `EXAMPLE.COM`, `example.com.` → identical verdict lines, three different seals, three store lineages; contradicts seal.rs:33 "the same domain … produces the same seal". The cli now canonicalises at its boundary (this PR); the engine should too, so every caller gets one seal. | three `-f text` runs, re-derive line differs only in case/dot | `seal.rs` binds `analysis.domain` verbatim; `analyse_domain_with_selectors` stores it raw |
| F8 (PLAUSIBLE, code-read) | DMARC reads only `p=` of the first record: `pct=` ignored (`p=reject; pct=0` reads "enforced"); multiple records not a permerror. | none captured | `analysis.rs` `dmarc_disposition_from_record` |
| F9 (PLAUSIBLE, code-read) | MTA-STS "enforced … downgrade to plaintext is refused" never compares the policy's `mx:` patterns to the actual MX hosts; a non-matching MX in enforce mode means honoring senders REFUSE delivery (RFC 8461 §5.1) — deployed-but-wrong reported as OK. | none captured | `analysis.rs` policy parse (version + mode + ≥1 mx = valid) |
| F10 (PLAUSIBLE, engine string) | `DaneDisposition::NoMx` = "no MX published — zone exists, **no mail routing**": RFC 5321 §5.1 implicit MX makes a no-MX domain with A/AAAA mail-routable (to the apex host). "No mail routing" asserts an absence not measured. | none captured | `truth_chain.rs` NoMx arm; `analysis.rs` MxShape::NoMx |
| F11 (wording) | `DkimDisposition::Wildcard` discards the wildcard's content. Both captured specimens are `*._domainkey "v=DKIM1; p="` — an empty `p=`, which RFC 6376 §3.6.1 defines as revoked: a positive "every selector revoked" declaration, not "proves nothing". | example.com, resolutionscope.com | `analysis.rs` wildcard probe |

## B. PRODUCT — engine lane (wording only; strings are `&'static str` in the engine)

| # | Finding | Specimen |
|---|---|---|
| P-E1 | CAA WildcardFullyRestricted blue consequence prints the literal placeholder **"*.example"** on a real domain's report. Say "wildcard names under this domain". | it-help.tech CAA consequence |
| P-E2 | `report.rs` (`--format text`, the compartment render): column header **"Score"** over a PASS/FAIL/?/N/A presence column, while the two real scores sit below; no severity/consequence layer at all; canonical order without saying so. Refuters: this is engine-rendered, so its fix is engine-lane — the cli now ships its own `report` format (below) and leaves `text` verbatim as the proof surface the site shows. | `-f text` |
| P-E3 | The re-derive block states the algorithm but not that **the trailing LF after the last `cds=` line is hashed** — measured: with it → the seal; without → `ccf3ddba…`. One clause in `report.rs`/`seal.rs` (beside the producer, so it cannot drift from `SEAL_SCHEME`). | any `-f text` |
| P-E4 | DKIM wildcard/not-found guidance says "provide your actual selector" but never names `--dkim-selector`. The flag name is cli-owned; the sentence is engine-owned — suggest the engine says "a selector supplied to the instrument" and the cli's `--help` (done) names the flag. | example.com DKIM consequence |

## C. NEEDS CAREY / SCIENCE RULING (presentation of a deliberate engine ruling)

| # | Tension |
|---|---|
| R1 | **`DnssecRequired` is Indet + severity LOW.** Science's 2026-08-21 ruling made it "a real finding, Low, Indet, out of the denominator." Consequence on every surface: it ranks as a FINDING while the tally says `unmeasured: 1`, and the new tiers make this visible — `COULD NOT MEASURE (none)` directly above `unmeasured: 1` on it-help.tech. The old TUI footer "(a ? is not a verdict)" sat under a `?` row ranked LOW; this PR replaced that sentence with a tally-relative one that is true either way. The ruling itself is not mine to change: either DnssecRequired becomes a measured Absent-class state with its own precondition label, or the tally learns a "measured, excluded by precondition" bucket. The same question applies to DNSSEC island-of-security. |
| R2 | **PASS/FAIL as the presence glyph.** A first-time reader sees `PASS` beside `MEDIUM — not enforcing`, and `FAIL` beside an RFC line that says the control is Optional/Informational. They are presence words carrying verdict weight. Candidates: `ON/OFF`, `YES/NO`, `present/absent`. Used on the site's specimen too, so a ruling, not a patch. |
| R3 | **JSON additions.** This PR adds `seal`, `seal_scheme`, `engine_version`, `session_hex`, `timestamp_utc`, `coverage{…}`, `risk_weighted`, `scoring_version` as sibling top-level keys; the 16 verdict keys are pinned unchanged (name, type, value). Additive, but the Arm-1 harness owner should confirm no strict-schema consumer exists. `session_id` stays a decimal u64 (> 2^53 — JavaScript consumers lose precision; `session_hex` is the safe join key). |
| R4 | **Default format changed** from the engine's `text` to the cli's `report`. `--format text` is unchanged and still what the site shows. One flag reverts it if the proof surface should stay the default. |

## D. PRODUCT — cli lane: SHIPPED in this PR (`5efd8fd`)

All confirmed by two refuters each unless noted; every item has a test.

1. **Documented invocation works.** `resolution-scope example.com` parsed as "unrecognized subcommand" while main.rs, the DECISION doc, render.rs and the tool's own error message all recommended it. Positional now; `-d` hidden alias.
2. **Parse-time validation.** `-f yaml` scanned the domain and then errored; `--format`/`--audience` are value enums now. Verbs own their flags (`tui --help` no longer advertises `--format`/`--out`/`--audience`-as-no-op; scan has no `--covert`).
3. **Input boundary** (`input.rs`): canonicalise (trim, one trailing dot, lowercase) + validate before any packet. Refused with the fix named: URL/path, empty or `.` (scanned the DNS root and graded it as a customer zone), non-ASCII (→ punycode), bad labels, >253. One zone, one seal from this surface.
4. **Seal on every surface.** Was: text only. Now: report (full seal, scheme, conditions, preimage, the one honest claim), summary (prefix + pointer), HTML (seal, conditions, `<pre>` preimage, `<title>` carries the domain), JSON (seal + scheme + engine + scores), TUI (header line + `7:Seal` tab with the preimage). Seal vocabulary pinned: no "provenance" / "proof of measurement" on any cli surface (history printed "provenance" — removed).
5. **Tiers.** FINDINGS / HOLDING / COULD NOT MEASURE / NOT APPLICABLE on report, summary, HTML, TUI; layout over the engine's Severity; empty tiers say "(none)" rather than vanish.
6. **Attribution before consequence** on every surface (HTML had consequence "Sign the zone first" before the attribution explaining the zone is someone else's; the TUI summary hid the attribution entirely).
7. **One vocabulary.** Score line identical on every surface with a one-line note each (`COVERAGE_NOTE`, `RISK_WEIGHTED_NOTE`, `EXCLUDED_NOTE` — shared constants); "not applicable" spelled one way; audience named the same way everywhere (`blue — defend` / `red — assess`), the TUI header says which framing is live when `m` flips; tab `4:SPF·DKIM·DMARC` names DKIM; no "Surface Flipper"/"Flipper" on user surfaces; tri glyph padded to 4 columns.
8. **TUI measuring state, real.** Paints at ~1s with "measuring <domain> — 8 controls via cloudflare … 1.1s" and eight `still measuring` rows, nothing claimed before it is measured; the engine call runs on the runtime, the loop polls (elapsed and footer stay fresh without a keypress); domain switch aborts the in-flight task so no verdict lands under another name.
9. **TUI safety and keys.** Terminal restored on `?` error and on panic (guard + hook); Ctrl-C quits (was swallowed — and typed a `c` into the domain prompt); Esc/Backspace return to the summary (there was no back); Shift-Tab works (crossterm reports BackTab, the old match could never fire); Tab hint says "domain" (it rescanned a single domain); domain prompt validates through the boundary and shows the reason inline, Esc cancels without a rescan, empty Enter cancels.
10. **Hanging indents** in the TUI — consequence/rfc continuation lines no longer wrap to column 0; tokens wider than the terminal (the seal) split instead of clipping.
11. **History**: readable UTC time column (StoredScan already carried it), percent, legend no longer describes a `measured_at` column that wasn't printed, and the verb no longer runs `migrate()` (a read verb must work under a read-only role).
12. **Real progress on stderr** for the scan verb: what, from where, measured elapsed, seal prefix. Per-control progress is engine work (below).
13. `--help` says what is measured, what the seal is and is not, and the two scores.
14. README gained a "Run it" block.

## E. NOT SHIPPED — engine hooks the live surface needs (Hermes)

Carey's rule today: *show the first material truth as soon as the decisive
evidence exists, then keep measuring toward the sealed report; spinners are
fine when they lead to real data.* The TUI can only honour that with engine
support:

- **Per-control completion events.** `analyse_domain_with_selectors` runs the
  eight scorers strictly sequentially inside one call and emits nothing until
  all eight return. A progress channel/callback (`ControlId` + disposition as
  each lands) lets the TUI light rows as they become **known / still
  measuring / sealed**, without the cli orchestrating scorers (which would
  move `ScoredAnalysis` assembly into a renderer — the wrong fix, per the
  refuters). The seal still lands only when all eight have.
- **Parallelise the scorers** (they are independent): `join!` would cut
  it-help.tech from ~11s to roughly the DKIM sweep alone, and the DKIM sweep
  itself is 81 sequential lookups.
- **Canonicalise the domain in the engine** (F7) so every caller — not only
  this cli — gets one seal per zone.

## F. DOCTRINE HOLDS (checked; no change)

- Seal re-derives with a stock tool: block between the rulers (trailing LF
  included) | `openssl dgst -sha3-512` = printed seal. Byte-identical seals
  before and after this PR for every specimen (`db817349…` it-help.tech,
  `df178f16…` example.com).
- Coverage + Risk-Weighted together on every surface, RWS tagged `scoring v1`,
  never sealed; Indet/NotApplicable out of both denominators; 0/0 reads 0% +
  "unmeasured", never a fake 100.
- No disposition match in `cli/src` (the only `Disposition` imports are
  `#[cfg(test)]`); no RFC literal in `cli/src` (citation boundary PASSED);
  `tlsa_zone` renders as attribution only, never a row or a denominator item;
  eight controls, weights 3/1 via `identity_weight`.
- Measured labels and consequence strings are byte-identical across text,
  summary, HTML, TUI and the JSON disposition names for the same domain and
  audience (sweep, surface-congruence lens).

[proxy-defect class]: a proxy asserting something never measured — the family's organising defect; DKIM "verified" is its cleanest instance in this engine.
