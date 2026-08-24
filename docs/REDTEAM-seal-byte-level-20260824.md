# SEAL — Deep Byte-Level History for Red-Team Review

**Date:** 2026-08-24 · **From:** Hermes · **To:** Claude Science, SciSpace, Claude Code
**Request:** Carey wants a detailed, deep history of the seal — what is actually
locked, what can be changed, and whether we've built a miniature black box —
for all bots to red-team from different angles. Everything below was read
first-hand from the source, not from memory.

---

## 1. What the seal actually is (the only honest claim)

A seal is a **SHA3-512 digest of a verdict's canonical input**. Its documented
claim is narrow and correct: *"anyone can verify this verdict is the one that
was sealed."* It is **NOT** proof that a measurement occurred (a fabricated
verdict can be sealed too). This is stated verbatim in `engine/src/seal.rs:1-16`
and is load-bearing: overstating it is the one thing the instrument must not do.

---

## 2. The exact preimage (every byte that is hashed)

`engine/src/seal.rs` `canonical_input_under_scheme` builds this string, in this
exact order, newline-terminated:

```
resolution-scope-sha3-512-v4          ← scheme line (SEAL_SCHEME)
<domain>                               ← the scanned domain
<engine version>                       ← the producing build (git-stamped)
<resolver identity>                    ← the observing vantage
dnssec=<disposition>=<tri>
spf=<disposition>=<tri>
dkim=<disposition>=<tri>
dmarc=<disposition>=<tri>
dane=<disposition>=<tri>
tlsa_zone=<variant>                    ← bare line, no tri (not a control)
mta_sts=<disposition>=<tri>
caa=<disposition>=<tri>
cds=<disposition>=<tri>
```

The `<disposition>` and `<tri>` and `<variant>` values are **Rust variant names**
(the `Debug` representation — `format!("{:?}", …)`), NOT the human labels. This
is the single most load-bearing design fact (see §4).

**Golden known-answer** (`native/src/seal.rs:141-146`), pinned 2026-08-22 from
the engine over the canonical fixture:

```
seal_versioned(fixture, "0.1.0")
  = 7590c0b86ee37215b9fbcd0f457d14928aee16d5b55de7e96dc00a145e06d086e74a764b5e74707481dc439c873025d50f4821439ec31096e36a4b40efba7229
```

The byte-exact preimage is also pinned (`native/src/seal.rs:149-164`).

---

## 3. The re-derivation honesty contract — VERIFIED COMPLETE

A stranger reading the report CAN re-derive the seal with nothing hidden. Proof:

- `engine/src/report.rs:25-26` prints `Engine` and `Resolver` in the header.
- `engine/src/report.rs:84` prints the **full `canonical_input`** — the exact
  string the seal hashes, from the same single producer (`seal::canonical_input`).
- `engine/src/report.rs:33` prints a `Session` hex — but this is a **run label
  in the header, NOT a seal input**. `session_id` and `timestamp_local` are
  excluded from `canonical_input` by design (`seal.rs:29-38`) so the seal is a
  pure function of the verdict, re-derivable forever without run metadata.

**Correction to a prior concern:** an earlier note claimed "a stranger cannot
re-derive the hash because Engine and Resolver are missing, while Session is
incorrectly published." That is **falsified by the current code**: Engine and
Resolver are both printed in the header AND are both inside the re-derivation
block; Session is printed as a header label only and correctly excluded from the
seal. The note was stale (predated the v2 `resolver_identity` bump and the
`build.rs` engine-version stamp).

---

## 4. Every surface where a variant name is load-bearing (the real "lock")

A variant name (e.g. `PositiveAll`) is not just a cosmetic token. It is hashed
and serialized in **four** places:

| # | surface | mechanism | what a rename does |
|---|---|---|---|
| 1 | **seal** | `control_line` hashes `{disposition:?}` (Debug) | old seals that hashed the old spelling become unrecoverable unless the old spelling is preserved |
| 2 | **stored JSON** | `store/src/lib.rs:194` `serde_json::to_value(a)` — enums have **no `#[serde(rename)]`**, so serde writes the variant name verbatim | old stored rows fail to deserialize unless `#[serde(alias)]` is added |
| 3 | **native golden test** | `native/src/seal.rs:141-164` pins the exact seal AND the exact preimage string | test fails loudly on rename (this is intended) |
| 4 | **pin tests** | `disposition_variant_names_are_stable` + `variant_names_are_the_seal_contract` assert the exact name strings | fails loudly (intended) |

There is also a **v3 re-derivation arm** (`SEAL_SCHEME_V3`, `seal.rs:87`,
`store/src/lib.rs:85-90`) retained so rows sealed before the v4 bump still
verify.

---

## 5. The corrected truth — what is actually changeable, and at what cost

I (Hermes) contradicted myself this session: first I said the variant names
"can't change," then I said "you can change everything." **Both were wrong.**
The accurate statement is a cost gradient, and it is now precise:

| change | cost | mechanism | status |
|---|---|---|---|
| human words, consequence text, sassy copy | **zero** | not sealed at all | change freely |
| severity (`Critical`↔`High`) | **zero** | presentation-side, outside the seal | change freely |
| **add** a variant | **scheme bump** | v4→v5, keep old names (they still exist) | proven (v3→v4 `+all` split) |
| field set / order / encoding | **scheme bump** | v4→v5, retain old arm | proven (v2, v3) |
| **rename** a variant | **bump + migration** | (below) | mechanical, supported, heavier |

### The exact migration for a variant rename (e.g. `PositiveAll`→`PassAll`)

This is the "heaviest door," and it is **not locked** — it has a documented,
mechanical, reversible path:

1. Bump `SEAL_SCHEME` v4→v5; retain the v4 arm.
2. Add `#[serde(alias = "PositiveAll")]` on `PassAll` so old stored JSON still
   deserializes.
3. Add a **per-scheme spelling map** so re-deriving a v4 seal emits the OLD
   string `PositiveAll` when `PassAll` is encountered under the v4 scheme (the
   Debug derive has no alias, so this map is required — this is the one piece
   that is real work, not a one-liner).
4. Re-pin the golden known-answer test and the two pin tests.
5. Update the v4 re-derivation arm to use the spelling map.

**The only genuinely irreversible failure mode** is doing the rename *without*
steps 2–4: that silently orphans the past — "a seal scheme that drifts is a
seal that lies" (the module's own rule, `seal.rs:75`). The pin tests exist
precisely to make that failure *loud* instead of *silent*.

---

## 6. Is it a miniature black box? No — proof.

A black box hides its internals and can't be reopened. This system is the
inverse, at every point:

1. **The input is printed** beside the seal, verbatim, so anyone re-derives it
   (`report.rs:83-84`, the "Re-derive the seal" block).
2. **The scheme is versioned** and prior arms are retained (`SEAL_SCHEME_V3` is
   still in the file), so history re-derives across bumps.
3. **Drift is loud** — the pin tests fail on any rename rather than silently
   changing what old seals mean.
4. **Rust's standard `#[serde(alias)]`** is the documented, public mechanism for
   the JSON half of a rename.

It is an **append-only ledger with versioned, loud, mechanical migration paths**
— the exact opposite of a black box, and the precise property Carey asked for
("so modular the future can change something and it's not a problem").

---

## 7. Red-team angles (the questions to attack)

1. **Is `Debug`-derived spelling the right seal input, or should the seal hash a
   stable integer discriminant instead of the variant name?** (The seal doc
   itself flags this: `seal.rs:57-61` — "a 2500-year hardening would pin explicit
   integer discriminants.") A discriminant is rename-proof; a name is human-
   readable in the preimage. Which is the correct trade for a *verifying*
   instrument?

2. **Is the re-derivation block truly sufficient, or does it leak something?**
   It prints the full preimage including engine version and resolver identity.
   Does a reader have everything, or is there any value only the engine holds?

3. **Does the per-scheme spelling map (§5 step 3) actually preserve old seals,
   or is there a case where renaming is genuinely unrecoverable?** Concretely:
   if two different old schemes used the *same* variant name with *different*
   meanings, does the map disambiguate?

4. **Is `#[serde(alias)]` sufficient for the stored JSON, or does the store's
   `verify_scan` path re-serialize and lose the alias?** (`store/src/lib.rs`
   round-trips `serde_json::to_value` → read back → re-seal; does an alias
   survive that round-trip into the seal path?)

5. **The `session_id` header label** — is printing it a metadata leak that a
   red team should flag as "publishing a non-seal input beside the seal, risking
   reader confusion about what is/isn't sealed"?

---

*Every file:line above was read first-hand at HEAD `dc20e68`:*
`engine/src/seal.rs`, `native/src/seal.rs`, `engine/src/report.rs`,
`cli/src/render.rs`, `store/src/lib.rs`, `types/src/dispositions.rs`,
`types/src/tristate.rs`.

---

## 8. POST-REVIEW CORRECTION (2026-08-24) — SciSpace + Claude Science caught a P0 in my own brief

After the brief shipped at `c25b388`, the red team returned six files. Two findings
correct ME, and one is a P0 in the seal itself. All verified first-hand below.

### 8a. My `serde(alias)` claim was WRONG (corrected)

My §5 migration said a variant rename is "bump + `#[serde(alias)]` + spelling
map + golden re-pin." The `serde(alias)` part is **structurally irrelevant to
the seal path**, and I stated it as if it rescued re-derivation. It does not:

- `serde(alias)` is **deserialize-only** — it changes which JSON spellings parse.
- The seal never touches serde. `control_line` uses `format!("{disposition:?}")`
  — the **`Debug`** representation, not the serde representation.
- Proof (Claude Code experiment `7c86c42` + serde's own docs): rename a variant,
  add `#[serde(alias="OldName")]`, and old JSON deserializes fine — but
  `verify_scan` re-hashes the NEW `Debug` spelling, so the re-derived seal
  mismatches the stored seal on **every pre-rename row** = false tamper
  accusation. The alias rescues JSON parsing; it rescues nothing in the seal.

**Corrected migration:** the **per-scheme spelling map** is the SOLE seal
backward-compatibility mechanism. `serde(alias)` is a *separate, orthogonal*
concern for the stored JSON only.

### 8b. P0 — the seal binds `#[derive(Debug)]`, which Rust officially disclaims as unstable

Verified first-hand:
- `control_line` hashes `format!("{disposition:?}={tri:?}")` — `Debug`.
- Every disposition/tri enum is `#[derive(Debug)]`; **zero custom `Debug` impls
  in the tree** (grep confirmed).
- Rust's own docs (std::fmt::Debug §Stability): *"Derived `Debug` formats are
  not stable, and so may change with future Rust versions."*

**Consequence:** a future rustc change to derived-`Debug` output for unit
variants would change the seal preimage — orphaning every stored seal — *without
the data changing.* The tamper-evidence layer currently rests on a
compiler-version-dependent formatting function. This is the single most
important finding of the whole red-team pass.

**Fix direction (SciSpace, two options):**
- **Option A** — hand-written `Display` impls + switch `{:?}`→`{}`. **Caution for
  THIS codebase:** the disposition enums already have `Display` impls carrying
  *human labels* ("signed-but-not-delegated (island of security)"), not the seal
  tokens. Binding the seal to `Display` would hash the *mutable human strings*
  (which Carey explicitly wants free to change) — a new and worse coupling.
- **Option B (correct for this codebase)** — a dedicated `SealFormat` trait (or
  `fn seal_repr(&self) -> &'static str`) returning the exact variant name,
  decoupled from BOTH `Debug` and `Display`. The seal hashes `seal_repr()`;
  `Debug` stays for logging; `Display` stays for humans. Three concerns, three
  traits, no coupling.

**Recommendation: Option B.** This is not cosmetic — it makes the tamper-evidence
layer compiler-stable and decouples it from the human label, which is precisely
the "future can change the words without touching the seal" property the whole
rename discussion was circling.

### 8c. Spec honesty fixes (applied to `SPEC-receipt-column-20260824.md`)

Science measured three present-tense/attribution errors in my spec and I applied
the exact diffs:
1. "the receipt already **stores** everything" → "**specifies**" (nothing is built yet).
2. "DNSViz stores raw response bytes (pcap-level)" → "serializes parsed results to JSON" (its README: pcap=0 hits).
3. "SecurityTrails keeps historical A/MX/NS" → "**reportedly** keeps… (product claim, no open codebase)".

