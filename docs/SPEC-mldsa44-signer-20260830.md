# SPEC — ML-DSA-44 (algorithm 18) zone signer + `pq.resolutionscope.com` fixture
### 2026-08-30 · claude-code lane · per PQ-FIXTURE-GO @e70d0b0

Provenance: SCOPING-mldsa44-fixture-20260829.md (§1–5 hermes, §6 claude-code
review), BASELINE-algorithm18-20260829.md v5, hermes GO ruling @e70d0b0
(labeled-control conditions adopted), and the fugu-ultra parallel-lane relay
(2026-08-30, via Carey): concurring GO + one accepted criterion — the crypto
head-to-head must weigh substrate/build-surface, not audit status alone (§5).

## 1. What is being built

One Rust binary (`signer/`, new sibling crate) that: generates an ML-DSA-44
CSK from a 32-byte seed, emits the DNSKEY/DS, canonically signs a zone file,
generates the NSEC chain, and verifies its own output. The signed zone is
**data**; it is served by stock NSD on `dnstool-app`. The signer never needs to
run on the box.

## 2. Wire rules (draft-westerbaan-dnssec-mldsa-04; IANA row cites -03, -04
declares the same codepoint)

- **DNSKEY**: flags **257** (single CSK), protocol 3, algorithm **18**, public
  key = raw 1312-octet FIPS 204 §7.2 encoding. RDATA = 1316 B.
- **RRSIG**: **pure ML-DSA** (never HashML-DSA), **empty context string**,
  message = RFC 4034 §3.1.8.1 signing data, signature = raw 2420-octet FIPS 204
  §7.2 encoding. Signer's name uncompressed (RFC 4034 §3.1.7).
- **Presentation format**: algorithm is always decimal `18`, never a mnemonic —
  verified at parser source that NSD (simdzone) and BIND accept numbers and
  reject unknown mnemonics.
- **DS**: computed in-binary — digest type 2 = SHA-256(canonical owner name ‖
  DNSKEY RDATA), RFC 4034 §5.1.4 (algorithm-agnostic by construction). Keytag
  per RFC 4034 App. B.
- **Determinism**: FIPS 204 deterministic variant (rnd = 0³²). RRSIGs become
  re-derivable and diffable; the draft §6 worked example becomes a byte-exact
  KAT. (Draft mandates neither; §7.1 hedging matters for online signing —
  ours is offline.)
- **RFC 4035 §2.2 completeness**: every RRset in the zone carries an alg-18
  RRSIG. Anything less reads as *bogus* (not insecure) to real ML-DSA
  validators, of which PowerDNS master is the first.

## 3. Zone content (minimal, labeled)

```
pq.resolutionscope.com.  SOA   (serial YYYYMMDDNN; refresh/retry/expire/min per parent practice)
pq.resolutionscope.com.  NS    pqns.resolutionscope.com.        ; NS name lives in the PARENT zone (out-of-bailiwick → no glue)
pq.resolutionscope.com.  TXT   "v=pqexperiment1; domain=pq.resolutionscope.com; algorithm=18; algorithm-name=ML-DSA-44; draft=draft-westerbaan-dnssec-mldsa-04; purpose=field-specimen-only; corpus-excluded=YES; dual-sign=NO; label=EXPERIMENT-NOT-PRODUCTION; contact=carey.balboa@it-help.tech"
                               ; schema adopted from SciSpace's pq_fixture_txt_baseline with two corrections:
                               ; draft name fixed (its draft-ietf-dnsop-dnssec-pqc-04 does not exist), and NO
                               ; keytag field until the production key exists (§4 hard rule)
pq.resolutionscope.com.  DNSKEY 257 3 18 <1312-B key>
+ NSEC chain (apex-only zone → one NSEC, self-pointing) + RRSIGs over every RRset
```

Denial: **NSEC**, not NSEC3 (smaller proofs; NSEC3 was the field study's worst
case). Note the measurable contrast pre-registered in SPEC-receipt-column: the
parent is Route 53 compact-denial; the child is plain NSEC — expected, by
design.

## 4. Key custody

**HARD RULE (added 2026-08-30, from the SciSpace-wave review): the draft §6
test-vector key (seed 0x00..0x1f, keytag 59829) is KAT-ONLY. It MUST NEVER
appear in the published zone — its private half is public, so a zone keyed on
it is forgeable by anyone and worthless as a control. The published TXT record
must not pin any keytag until the production key exists. (SciSpace's fixture
template bakes keytag=59829 into the TXT and DNSKEY blocks — do not follow it
for deployment.)**

The 32-byte FIPS 204 seed ξ **is** the private key. It never enters the repo.
Proposed custody (Carey to confirm with the AWS GO): a 0600 file in Carey's
local secrets area on this Mac (pattern of `~/.secrets_env`), e.g.
`~/.secrets/pq-mldsa44.seed`; signing happens locally; deploys ship only the
signed zone file. Loss of the seed = re-key + new DS (10-minute rotation, not
an incident, for a fixture).

## 5. Crypto backend — head-to-head (criteria include substrate, per fugu-ultra)

Criteria: FIPS-204-final conformance evidence; audit/advisory record;
deterministic/seed API; pure-mode + empty-ctx fit to draft §4; `no_std` /
C-free substrate; build surface (cmake/bindgen, cross-compile); license vs
cargo-deny; maintenance. Named tension (fugu-ultra): aws-lc-rs brings a
C/assembly crypto stack; fips204 is pure Rust but lacks aws-lc-rs's FIPS-140-3
lineage. Honest note: the engine already links `ring` (C/asm) via hickory's
`dnssec-ring` feature, so "no C in the tree" is not literally true today — but
the signer is its own crate boundary and its substrate is a fresh choice.

### 5.1 Results (verified at source, 2026-08-30) and the pick

| Criterion | `fips204` 0.4.6 | `aws-lc-rs` 1.18.0 |
|---|---|---|
| FIPS-204-final conformance | README: final (2024-08-13); ships pinned NIST ACVP keyGen/sigGen/sigVer vectors. **Gap: external/ctx-wrapper vectors never picked up** (README frozen 2024-11-08) | FIPS 140-3-validated backing module; ML-DSA APIs stable at 1.18.0 |
| Audit / advisories | No independent audit (README claims none; NCC authorship is provenance, not assurance). Constant-time = source-level claim, self-checked via dudect. **Zero RUSTSEC entries ever** | No crate audit either, but lab-validated module. `aws-lc-sys` carries RUSTSEC-2026-0044…0048 (X.509/libcrypto vintage, not ML-DSA) — the CVE-surface cost of a big C library |
| Deterministic/seed API | **Best in class**: `keygen_from_seed(&[u8;32])` + `try_sign_with_seed(seed, msg, ctx)` — no RNG anywhere in the path | `from_seed` keygen; signing determinism less directly exposed |
| Pure mode + empty ctx | Yes (`&[]`; HashML-DSA is a separate method set — can't land there by accident) | Yes (documented) |
| `no_std` / C-free | **Yes / yes** (no alloc, no unsafe, no build.rs; 4 pure-Rust deps incl. the `sha3` the tree already uses) | No `no_std` (verbatim README); C/asm by design; the FIPS feature drags CMake + Go |
| License / aarch64 / maintenance | MIT OR Apache-2.0 / unrestricted / **stale: core untouched ~20 months** | ISC AND (Apache-2.0 OR ISC) / tier-1 / monthly releases |

Context fact: **no Rust ML-DSA implementation has an independent audit as of
Aug 2026** (RustCrypto ml-dsa: none + 3 RC-era advisories; libcrux: partial
formal verification, pre-0.1). "Pick the audited one" is not an available move;
the real choice is unaudited-pure-Rust vs FIPS-validated-C.

**PICK: `fips204` 0.4.6, pinned, for this fixture.** Decisive: the seed API is
a near-exact fit for §2's determinism requirement (reproducible KSK *and*
reproducible RRSIGs, zero RNG), and substrate coherence — pure Rust, `no_std`,
no build script — keeps C off the `native`-side of the crate boundary (the
tree's C, `ring` via dnssec-ring, sits on the engine side; `native/` already
recorded a ring/C cross-compile blocker). This resolves the fugu-ultra tension
in fips204's favor *for this threat model*. Accepted costs, mitigated in-repo:
no independent audit and a stale core (tolerable for a labeled fixture; pinned
version; feature-trimmed to `ml-dsa-44` alone, `default-rng` off), and no
upstream KAT of the external ctx-wrapper — **mitigated at our layer, where it
matters: the draft-04 §6 worked example IS an external-wrapper KAT** (pure
mode, empty ctx, deterministic), and §7's triple interop check (PowerDNS
master, Go 1.27, self) re-verifies the same wrapper against independent
implementations. **Graduation rule**: if this signer ever signs anything
beyond the labeled fixture, this pick is void — re-run the head-to-head with
aws-lc-rs (std side) and libcrux (if matured) as leading candidates.

**D7 reconciliation (added 2026-08-30, SciSpace-wave review).** SciSpace's
corrected relay brief (authored @e70d0b0, BEFORE this SPEC existed) reversed
its own fips204 recommendation to RustCrypto `ml-dsa` 0.1.1 on activity
grounds and named the three-axis tension (audit=aws-lc-rs / substrate=fips204
/ activity=ml-dsa) as D7, "must be named in the SPEC before picking." §5 +
§5.1 above ARE that treatment, made with facts the brief lacked (fips204's
pinned NIST ACVP vectors; ml-dsa's three RC-era advisories; aws-lc-rs's
no_std wall). Momentary three-lane divergence noted for the record —
hermes=fips204 (nomination, vindicated), SciSpace=ml-dsa (reversal brief +
working pq-keygen code, 19/19 tests, keytag 59829 reproduced), this lane's
verification pass=aws-lc-rs (pre-SPEC recommendation, superseded by §5.1's
substrate ruling). **Residual question settled by measurement, not
re-litigation: the verification harness runs the draft-§6 KAT against BOTH
fips204 and ml-dsa. fips204 stays the signing pick unless it fails its KAT;
SciSpace's pq-keygen (ml-dsa) is adopted as a fourth independent verifier**
(alongside PowerDNS master, Go 1.27, and self) — the crate disagreement
becomes cross-verification redundancy instead of a dispute.

**Substrate refinement (claude-science, 2026-08-30, adopted):** pq-keygen's
own `Cargo.toml` (`ml-dsa` with `default-features = false, features =
["alloc"]`, getrandom excluded) is a no_std-capable configuration — so the
substrate axis does NOT separate fips204 from ml-dsa; it separates both from
aws-lc-rs only. The fips204-vs-ml-dsa separators that remain are: the
deterministic seed-signing API (fips204 `try_sign_with_seed` verified; ml-dsa's
deterministic path an open question in pq-keygen's own notes), advisory history
(zero vs three patched RC-era), and shipped ACVP vectors. Science's rule
adopted verbatim: *a build is an instrument, a category is a self-declaration*
— the harness therefore gains a bare-metal cross-compile check of the chosen
crate rather than trusting crates.io metadata either way.

## 6. Serving

- **NSD** (stock, current 4.x) on `dnstool-app` (i-098e3d8ed90737280,
  us-west-2, EIP 44.226.60.249), bound to the **ENI private IP** on :53
  udp+tcp — measured 2026-08-30: systemd-resolved stubs bind only
  127.0.0.53/54, so the public :53 is free; no resolved changes.
- **SG**: `sg-06fe9448f84977713` needs 53/udp + 53/tcp from 0.0.0.0/0 (today:
  22/80/443 only). **[gate: Carey]**
- TCP posture: every signed response exceeds 1232 → TC=1 → TCP; tune
  `tcp-count`; document the 100%-TCP fact in the fixture TXT/docs — the
  honest-disclosure requirement from the scoping doc stands.

## 7. Verification (all must pass before the DS is published)

**Vantage rule (claude-science Q2 finding, adopted):** public resolvers cannot
validate this fixture — Google Public DNS and Cloudflare are named
downgrade-prone in the measured studies (70% full-paper / 45% poster / 60%
RPKI-context), and per RFC 4035 §5.2 they will report the zone *insecure*,
never *valid*. That insecure reading IS the expected public observable (the
§5.2 story the fixture exists to tell). A **"valid" verdict can only come from
a validator with known algorithm-18 behavior** — the PowerDNS-master container
below is that vantage, not merely an interop check.

1. **KAT**: reproduce draft-westerbaan-04 §6 worked example byte-for-byte
   (deterministic mode) — DNSKEY, RRSIG, DS.
2. **Parse**: `nsd-checkzone` and `named-checkzone` load the signed zone.
3. **Triple interop**: (a) PowerDNS master + OpenSSL ≥ 3.5 (Docker) validates
   the zone; (b) Go 1.27 `crypto/mldsa` mini-verifier checks a RRSIG over the
   RFC 4034 signing data; (c) self-verify.
4. **Negative receipt**: FIPS-204-verify the live testbed's alg-18 RRSIG
   (`dilithium2.pdns.pq-dnssec.dedyn.io`) → expected FAIL — seals 18-labeled ≠
   18-proper with our own instrument.
5. **Engine**: resolution-scope run against the live zone reports
   `ChainUnverified` (D5b live positive control), receipts to ledger.

## 8. Deploy order (reversal-safe)

1. Route 53 **DS-acceptance test** (one ChangeResourceRecordSets with a
   placeholder DS `12345 18 2 <64 hex>`, then delete). **[gate: Carey]**
2. NSD live on :53; external dig receipts (UDP TC=1, TCP full) from ≥2 vantages.
3. Parent records: `pqns.resolutionscope.com A 44.226.60.249`, then
   `pq NS pqns`. Verify end-to-end serving (still insecure-delegation).
4. **The island window (claude-science proposal, 2026-08-30, adopted):** once
   the signed zone (DNSKEY live) serves but BEFORE the DS publishes, hold for
   one deliberate measurement beat — run the engine against the fixture and
   capture `SignedNotDelegated` firing on a zone we own, a branch never before
   observed on owned infrastructure. Event-driven watch armed (DNSKEY
   appearance → wall run + island capture; DS appearance → window closed).
5. **DS last** — publishing it arms validation; the engine's verdict should
   transition `SignedNotDelegated` → `ChainUnverified`, and the :5300
   validator's verdict should flip no-AD → AD. Three sequenced receipts.
5. Engine + baseline: fixture pre-registration lands in BASELINE (v6) the same
   day the DS does; re-run protocol step 3 documented to exclude/label our own
   zone. Rollback = reverse order (DS out first).

## 9. Non-goals

Online signing; NSEC3; multi-algorithm dual-signing (draft §7.2 downgrade
hazard); XMSS/XMSSMT statefuls; serving the signer on the box; any claim that
this zone is a "found in the wild" publisher — it is a labeled control.
