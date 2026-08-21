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
| DKIM | Absent / KeyMismatch | `present` (wildcard, `primary_has_dkim=false`) | ✗ | wildcard `*._domainkey` `v=DKIM1; p=` (empty key) |
| DMARC | Present / Reject | present / `reject` | ✓ | `v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s` |
| DANE | NotApplicable / NoMail | `absent_confirmed` | ✗ | null MX `0 .` → no-mail domain |
| MTA-STS | Absent / RecordAbsent | `absent_confirmed` | ✓ | no `_mta-sts` TXT |
| CAA | Absent / NotConfigured | `absent_confirmed` | ✓ | no CAA |
| CDS/CDNSKEY | Present / Published | `has_cds=true` | ✓ | CDS `2371 13 2 C988…`, CDNSKEY `257 3 13 mdsswUyr…` |

**Result: 6/8 agree, 2/8 disagree — and BOTH disagreements are vocabulary
classes, not engine bugs.** No engine was found wrong on the facts; the two
disagreements are definitional gaps Arm 1 exists to surface.

## Disagreement 1 — DKIM (definitional divergence → `claude-science` ruling)

example.com publishes a **wildcard** `*._domainkey.example.com. TXT "v=DKIM1; p="`
— a DKIM record with an **empty** `p=` key. Measured: a nonexistent selector
(`zzznonexistent123._domainkey.example.com`) also resolves to `v=DKIM1; p=`,
which proves the empty-key answer is wildcard-synthesised, not a set of explicit
records.

- **Rust** probes the 81-default sweep, every selector resolves to `p=` empty →
  `KeyMismatch` → `Absent`. It answers *"is there a usable key?"*: no.
- **Go** sees the `v=DKIM1` tag → `present`, and separately flags
  `wildcard_dkim=true` + `primary_has_dkim=false`. It answers *"is there a DKIM
  record?"*: yes.

The engines answer **different questions**. Neither is wrong; they diverge
because "DKIM present" is undefined across the two vocabularies at the boundary
case — a wildcard record with no key material. For a security instrument the
verification-relevant answer is Rust's (`Absent` — an empty key cannot verify a
signature), but that is a ruling for `claude-science`, not a code change here.

**Label refinement (not a verdict error):** Rust's `KeyMismatch` disposition
name is slightly off for an *empty* key — this is a missing/empty key, not a key
that failed a signature match. Both dispositions map to `Absent`, so the verdict
is unaffected; the name is a cosmetic follow-up.

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

1. **DKIM definitional ruling** from `claude-science` before any agreement rate
   is derived — the two engines' "present" means different things, and the
   wildcard-empty-key case is the discriminator.
2. **Corpus** — seed golden fixtures + DANE-deployed / MTA-STS-enforcer /
   null-MX-declarer / genuinely-unsigned (`google.com`) / the live evil fixture
   (`dns-evil-flicker.com`, known-bogus DS), per `HANDOFF_arm1.md`.
3. **Harness** — `scripts/full_arm_differential.py` already pairs NDJSON vs
   single-object responses; its `go_to_tri` map needs the `NotApplicable`
   exclusion branch wired (the one gap this first join surfaced).
