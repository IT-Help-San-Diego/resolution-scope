-- 005_records.sql — the raw-record evidence table: one row per captured record.
--
-- R-B ruling (2026-08-24), applied to the record layer: the raw DNS records the
-- verdict was computed from are BESIDE the seal, never part of it. The seal
-- attests OUR verdict (judge); the record is the SERVER'S words the verdict
-- read (witness). Nothing in this table is sealed, exactly as lookup_receipts
-- is not sealed. The seal preimage (canonical_input) reads only the eight
-- dispositions/tri-states — it has never touched raw record bytes, and this
-- table rides alongside without changing that.
--
-- Shape A, mirroring lookup_receipts: one row per record string per control
-- per scan. A control with no measured record contributes zero rows (a missing
-- record is informative absence, never a fabricated empty string). `value` is
-- the raw presentation string (e.g. `v=spf1 include:… -all`,
-- `v=DMARC1; p=reject; …`, `0 issue "letsencrypt.org"`), stored verbatim so a
-- reader can re-derive what the scorer actually read — not a summary.
--
-- `control` reuses the SAME TEXT vocabulary and the SAME CHECK constraint as
-- lookup_receipts.control — one vocabulary for "which control", two tables for
-- "what the server said" (receipt) vs "what the server published" (record).
-- The mechanical CHECK (not a documentary comment) is the same principle that
-- governs every other column in this schema.
--
-- Up-only. No BEGIN/COMMIT — the migration ledger wraps each migration in its
-- own transaction (store/src/lib.rs migrate_locked).

CREATE TABLE records (
    scan_id  BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    control  TEXT   NOT NULL
             CHECK (control IN ('dnssec','spf','dkim','dmarc','dane','mta_sts','caa','cds')),
    value    TEXT   NOT NULL
);

-- One scan's records, read scoped by control (precedent: ix_receipts_scan_control).
CREATE INDEX ix_records_scan_control ON records (scan_id, control);
