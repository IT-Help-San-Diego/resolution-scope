-- 006_new_control_keys.sql — widen the control-key CHECKs to the ten-control book.
--
-- FOUND BY CI, NOT BY REVIEW (2026-09-01): the store's postgres tests caught
-- the fourth surface of the write-only asymmetry the foundation audit named
-- (comment 5486396765). Rust-side surfaces were fixed in 4f2facf —
-- control_from_key gained its tls_rpt/csync arms and the ALL-driven
-- round-trip guard now exists — but the SQL schema still enumerated only
-- the founding eight keys, so a tls_rpt or csync receipt/record row
-- violated lookup_receipts_control_check / records_control_check at INSERT.
-- The receipt census test (one receipt per ControlId::ALL) made the gap
-- mechanical: CI red, not a doc note.
--
-- Up-only by doctrine (no Down, no edits to applied history): ALTER the
-- constraints in place. New key order follows ControlId::ALL.
-- No BEGIN/COMMIT — the migration ledger wraps each migration in its own
-- transaction (store/src/lib.rs migrate_locked).

ALTER TABLE lookup_receipts DROP CONSTRAINT lookup_receipts_control_check;
ALTER TABLE lookup_receipts ADD CONSTRAINT lookup_receipts_control_check
    CHECK (control IN ('dnssec','spf','dkim','dmarc','dane','mta_sts','caa','cds','tls_rpt','csync'));

ALTER TABLE records DROP CONSTRAINT records_control_check;
ALTER TABLE records ADD CONSTRAINT records_control_check
    CHECK (control IN ('dnssec','spf','dkim','dmarc','dane','mta_sts','caa','cds','tls_rpt','csync'));
