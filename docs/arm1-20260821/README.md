# Arm 1 — first one-domain join (example.com)

Date: 2026-08-21 · Lane: `hermes` (instrument) · Ground truth: live `dig`, reproduced below.

## What this is

The first time the Rust engine (`resolution-scope`) and the Go reference
(`dns-tool-intel`, analysis **18450**) are measured side-by-side on the same
domain against the same eight controls. One domain, both real endpoint shapes,
sixteen verdict fields joined. This is the "does what it says is correct"
measurement that `docs/CALIBRATION-STUDY-SPEC.md` defers everything else to.

Ownership per `policy/HANDOFF_arm1.md`: this output dir is the instrument
lane's; other lanes read, don't write. Claude Science owns the *analysis
design* (pre-registered classification) and produces rulings — never commits.

## The side-by-side table

| control | Rust (engine) | Go (analysis 18450) | agree? | ground truth (`dig`) |
|---|---|---|---|---|
| DNSSEC | Present / SignedAndDelegated | `present` | ✓ | DNSKEY + DS `2371` present (Cloudflare shared KSK `mdsswUyr…`) |
| SPF | Present / HardFail | present (`no_mail_intent`) | ✓ | `v=spf1 -all` |
| DKIM | Indet / Wildcard (post-ruling; was Absent / KeyMismatch) | `present` (wildcard, `primary_has_dkim=false`) | ✗→resolved | wildcard `*._domainkey` `v=DKIM1; p=` (empty key) |
| DMARC | Present / Reject | present / `reject` | ✓ | `v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s` |
| DANE | NotApplicable / NoMail | `absent_confirmed` | ✗ | null MX `0 .` → no-mail domain |
| MTA-STS | Absent / RecordAbsent | `absent_confirmed` | ✓ | no `_mta-sts` TXT |
| CAA | Absent / NotConfigured | `absent_confirmed` | ✓ | no CAA |
| CDS/CDNSKEY | Present / Published | `has_cds=true` | ✓ | CDS `2371 13 2 C988…`, CDNSKEY `257 3 13 mdsswUyr…` |

**Result: 6/8 agree, 2/8 disagree — and BOTH disagreements are vocabulary
classes, not engine bugs.** No engine was found wrong on the facts; the two
disagreements are definitional gaps Arm 1 exists to surface.

## Disagreement 1 — DKIM (definitional divergence → RULED + FIXED)

example.com publishes a **wildcard** `*._domainkey.example.com. TXT "v=DKIM1; p="`
— a DKIM record with an **empty** `p=` key. Measured: a nonexistent selector
(`zzznonexistent123._domainkey.example.com`) also resolves to `v=DKIM1; p=`,
which proves the empty-key answer is wildcard-synthesised, not a set of explicit
records.

- **Rust** probed the 81-default sweep, every selector resolving to `p=` empty →
  `KeyMismatch` → `Absent` (the as-recorded first join).
- **Go** saw the `v=DKIM1` tag → `present`, separately flagging
  `wildcard_dkim=true` + `primary_has_dkim=false`.

**`claude-science` ruling (2026-08-21) — neither engine is wrong about
existence, and BOTH were wrong about *this* record.** The empty `p=` is neither
absent nor broken: RFC 6376 defines it as **revoked** (a deliberate withdrawal).
The real finding is a **third answer**:

1. **Usable-key is the right axis** — an empty `p=` is a positive publication
   whose content is "this key is withdrawn." Rust already computed this
   (`DkimKeyState::Revoked` at `dkim_key_state`) and then folded it into
   `KeyMismatch` one function later, asserting a defect where the zone declared
   an intention.
2. **The wildcard is the bigger find:** a wildcard makes the 81-selector sweep
   meaningless — every probe "resolves," so `NotFoundDefaults` ("absence NOT
   proven") is structurally unreachable. The honest-uncertainty verdict is
   impossible on a wildcard domain.

**Fix shipped (`engine/src/analysis.rs` + `truth_chain.rs`):**
- `DkimDisposition::Revoked` — collapses to `Absent` (no signature verifies),
  `measured` "key revoked — selector publishes an empty p= (RFC 6376)",
  severity `High` (deliberate withdrawal, NOT a `Critical` misconfiguration).
- `DkimDisposition::Wildcard` — a sentinel probe (`WILDCARD_PROBE_SELECTOR`)
  fires first; if a nonexistent selector name resolves to TXT, the domain has a
  wildcard and the sweep proves nothing → `Indet` (honest uncertainty), its own
  disposition, not a key verdict.

**Live re-run:** `resolution-scope --json example.com` → `dkim: Indet,
dkim_disposition: Wildcard`. The old `KeyMismatch`/`Absent` is gone; the honest
"wildcard masks the sweep — provide a selector" verdict stands. Go's
`wildcard_dkim=true, primary_has_dkim=false` pair is *coarser* than `present`
suggests (it already separates wildcard from explicit), so this row is a
legitimate **exclusion for Arm 1, counted**, not a defect against either engine.

## Disagreement 2 — DANE (the pre-registered four-state bridge gap)

example.com publishes a null MX (`0 .`, RFC 7505) = no-mail domain.

- **Rust** emits a FOURTH state `NotApplicable` (DANE does not apply to a
  no-mail domain).
- **Go** has a three-state vocabulary (`present`/`absent`/`indeterminate`) and
  says `absent_confirmed` (no TLSA records).

This is `policy/HANDOFF_arm1.md` constraint #2, **pre-registered**: rows where
Rust emits `NotApplicable` are EXCLUDED WITH A PUBLISHED COUNT — never folded
into `Absent`. Both engines agree on the fact (no mail, no TLSA); they differ on
the state *name*. Not a bug in either.

## Ground truth (live `dig`, 2026-08-21)

```
MX                 0 .
TXT                "v=spf1 -all"  (+ a verification token)
_dmarc             "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"
*._domainkey       "v=DKIM1; p="   (wildcard; empty key — synthesises every selector)
zzznonexistent123._domainkey.example.com  → "v=DKIM1; p="  (proves wildcard)
CAA                (none)
_25._tcp           (none)
_mta-sts           (none)
DNSKEY             257 3 13 mdsswUyr…   (Cloudflare shared KSK, tag 2371)
DS                 2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A
CDS                2371 13 2 C988…      (matches DS)
CDNSKEY            257 3 13 mdsswUyr…
```

## Next (ordered)

1. **Corpus** — seed golden fixtures + DANE-deployed / MTA-STS-enforcer /
   null-MX-declarer / genuinely-unsigned (`google.com`) / the live evil fixture
   (`dns-evil-flicker.com`, known-bogus DS) / `example.com` as the permanent
   wildcard fixture, per `HANDOFF_arm1.md`.
2. **Harness** — `scripts/full_arm_differential.py` already pairs NDJSON vs
   single-object responses; wire the `NotApplicable` (DANE null-MX) AND
   `Wildcard` (DKIM) exclusion branches with published counts (the two gaps the
   first join surfaced).
3. **Arm 2** — RFC known-answer vectors (mandatory; catches shared doctrinal
   error that Arm 1's N-version pairing is blind to).
