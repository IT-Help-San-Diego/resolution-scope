# pq-signer — citation map

The citation boundary keeps `RFC <n>` literals out of non-engine crates
(canonical authorities live in engine/src/truth_chain.rs). This crate
implements spec-exact wire routines; authorities are mapped here.

| Item in `src/main.rs` | Authority |
|---|---|
| RRSIG timestamp presentation (YYYYMMDDHHmmSS) | RFC 4034 §3.2 |
| Null MX ("0 ." — zone accepts no mail) | RFC 7505 |
| SPF `v=spf1 -all` | RFC 7208 §4.6.2 (qualifier semantics pinned in engine) |
| Canonical form / signed data / DS / keytag | RFC 4034 (see pq-harness/README.md for the full map) |
| Pure ML-DSA, empty ctx, deterministic rnd=0 | draft-westerbaan-dnssec-mldsa-04 + FIPS 204 §5.2 |
