# pq-harness — citation map

The citation boundary (scripts/check-citation-boundary.sh) keeps `RFC <n>`
literals out of non-engine crates so the requirement layer cannot fork. This
crate implements spec-exact wire routines, so its authorities are mapped here
— and canonically in `engine/src/truth_chain.rs` — instead of in source
comments.

| Item in `src/lib.rs` | Authority |
|---|---|
| `name_wire` (lowercased, uncompressed canonical names) | RFC 4034 §6.2 |
| `keytag` | RFC 4034 Appendix B |
| `ds_sha256` (digest type 2 over owner ‖ DNSKEY RDATA) | RFC 4034 §5.1.4 |
| `rrsig_signed_data` (RRSIG RDATA-minus-signature ‖ canonical RRset) | RFC 4034 §3.1.8.1 |
| Pure ML-DSA, empty context, raw byte encodings; §6 worked example | draft-westerbaan-dnssec-mldsa-04 §3, §4, §6 |
| Deterministic variant (rnd = 0³²) | FIPS 204 §5.2 |
| Insecure-not-bogus resolver behavior the fixture exercises | RFC 4035 §5.2 |

Every KAT in this crate is anchored to the draft §6 worked example, whose
base64 blocks are machine-extracted into `fixtures/` (never hand-typed) and
length-validated at extraction. The test-vector seed is KAT-only and must
never key a published zone (SPEC-mldsa44-signer-20260830.md §4 hard rule).
