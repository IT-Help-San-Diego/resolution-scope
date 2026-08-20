-- 002_seal_scheme.sql — each row records WHICH seal scheme sealed it.
--
-- The seal's canonical form can change (v1 → v2 added resolver_identity, the
-- day this migration was written). Verification must re-derive with the
-- scheme that SEALED the row — recomputing an old row under a newer scheme
-- reports it as tampered, which is a false accusation, the one failure a
-- tamper-evidence system must never produce.
--
-- The backfill default is correct by timing: the scheme column arrives
-- within hours of the store's birth, and every row ever written by this
-- store was sealed under v2 (v1 predates the store). The default is then
-- dropped so writers must state the scheme explicitly.

ALTER TABLE scans
    ADD COLUMN seal_scheme TEXT NOT NULL DEFAULT 'resolution-scope-sha3-512-v2';
ALTER TABLE scans
    ALTER COLUMN seal_scheme DROP DEFAULT;
