# hickory no_std DNSSEC — upstream status check

**Verified by:** Hermes (first-hand against live sources)
**Date:** 2026-08-22
**Purpose:** Confirm or refute the four load-bearing claims in
`docs/ARCHITECTURE.md §7` (the "no_std DNSSEC decision") that underpin the
Option B trust boundary documented in
`docs/lionsos-compartment-demo-spec.md §5.1`.

**Headline:** Item 1 — the claim that no no_std DNSSEC path exists in hickory
— is **STILL TRUE**. The Option B trust boundary does **not** need to be
re-opened. Two secondary records (PR-status wording and the LionsOS version)
are stale and corrected below.

---

## Item 1 — Is `__dnssec` still `std`-gated? → **STILL TRUE**

The `hickory-proto` `__dnssec` feature declares `std` as a literal member in
its published feature graph — at **both** the latest release and `main` HEAD.

- **Latest release (0.26.1, crates.io `max_version`):**
  `__dnssec = ["dep:bitflags", "dep:rustls-pki-types", "dep:time", "std"]`
- **`main` HEAD**
  (`github.com/hickory-dns/hickory-dns` → `crates/proto/Cargo.toml`, fetched
  live):
  `__dnssec = ["dep:bitflags", "dep:rustls-pki-types", "dep:time", "std"]`

Source: crates.io API `max_version` = 0.26.1 (no newer release exists);
raw.githubusercontent.com main Cargo.toml, line 36.

**Verdict: STILL TRUE.** There is no no_std DNSSEC path at any current hickory
version. Option B stands.

## Item 2 — The three recorded no_std PRs → **CHANGED (merged, not open)**

| PR | title | state | closed/merged |
|---|---|---|---|
| #2104 | `no-std` support for hickory-proto | **MERGED** | 2025-03-18 |
| #2821 | Add initial std feature that keeps MSRV, next step towards no_std | **MERGED** | 2025-03-12 |
| #2806 | Move uses of std to core and alloc in proto crate | **MERGED** | 2025-03-01 |

Source: `gh pr view --repo hickory-dns/hickory-dns` (live).

**Verdict: CHANGED.** The ARCHITECTURE.md §7 wording "the maintainers are
actively merging no_std PRs (#2104, #2821, #2806)" is stale — these three
landed over a year before the 2026-08-17 note was written. The *substantive*
claim survives: the no_std foundation is in `hickory-proto`, but it stops short
of DNSSEC. **Correction is wording-only, not a reversal.**

## Item 3 — Is `__dnssec` still unclaimed / un-ported? → **STILL TRUE**

`__dnssec` remains the last std-gated DNSSEC feature. At `main` HEAD the only
std-gated features are `__dnssec` (and `serde`, a serialization feature, not
DNSSEC). A `denylist` feature exists that can exclude `__dnssec` from a build —
consistent with a no_std-oriented build path that *omits* DNSSEC rather than
porting it.

Source: `main` Cargo.toml lines 34–36 (`dnssec-aws-lc-rs`, `dnssec-ring`,
`__dnssec`) and line 89 (`denylist` includes `__dnssec`).

**Verdict: STILL TRUE.** No upstream no_std DNSSEC port has landed or is
claimed in the issue tracker surface I checked.

## Item 4 — LionsOS maturity → **CHANGED (0.3.0 → 0.4.0)**

| release | date |
|---|---|
| **0.4.0 (Latest)** | **2026-08-21** |
| 0.3.0 | 2025-03-25 |
| 0.2.0 | 2024-08-06 |

Source: `gh release list --repo au-ts/lionsos` (live).

**Verdict: CHANGED.** ARCHITECTURE.md §6 names "LionsOS v0.3 maturity" as an
unmeasured risk. LionsOS shipped **0.4.0 on 2026-08-21** — the day before this
check. The maturity caveat should be re-scoped from "v0.3" to "v0.4, one
release past the point we recorded."

---

## Net effect on the Option B trust boundary

**No change.** The boundary in `lionsos-compartment-demo-spec.md §5.1`
(verdicts cross the compartment, the compartment trusts the IPC channel) rests
on Item 1, which is **still true**. The two CHANGED items are record-corrections:

1. **ARCHITECTURE.md §7** — update the no_std PR sentence from "actively
   merging" to "merged (2025-03); the no_std foundation is in place but DNSSEC
   (`__dnssec`) remains std-gated and unclaimed." The Option A/B/C decision is
   unaffected.
2. **ARCHITECTURE.md §6** — update "LionsOS v0.3 maturity" to "LionsOS v0.4
   (2026-08-21)".

## Sources consulted (all live)

- crates.io API `crates/hickory-proto` → `max_version` = 0.26.1
- `raw.githubusercontent.com/hickory-dns/hickory-dns/main/crates/proto/Cargo.toml`
- `gh pr view --repo hickory-dns/hickory-dns {2104,2821,2806}`
- `gh release list --repo au-ts/lionsos`
- Local `hickory-proto-0.26.1/Cargo.toml` (registry source, cross-check)
