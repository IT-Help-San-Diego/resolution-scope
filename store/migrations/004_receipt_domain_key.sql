-- 004_receipt_domain_key.sql — receipts become domain-keyed observations.
--
-- RULING (Carey, 2026-08-25, four-mind converged): Approach B at the receipt
-- layer. lookup_receipts.scan_id becomes NULLABLE — a receipt is an
-- observation about a DOMAIN that may or may not ride a local sealed scan.
-- Local scans keep writing scan-linked receipts; the (future) source-3
-- contributed path writes scan-less rows. scans.seal / scans.verdict NOT NULL
-- are UNTOUCHED — the sealed store's founding constraints do not bend.
--
-- Precedent: flux_observations.scan_id has been an "optional link" since the
-- founding schema (001). The read path this migration enables is
-- receipts_by_domain — Science's audit caught that a scan_id-keyed accessor
-- can structurally never reach a NULL-scan_id row (silent data loss).
--
-- The backfill UPDATE below is NOT a rewrite of measured data: it derives
-- each row's domain mechanically from its own scans FK — a denormalization of
-- an existing fact, provably correct by join. (The append-only invariant
-- protects sealed verdict bytes; receipts are beside the seal and carry none.)
-- Up-only. No BEGIN/COMMIT — the migration ledger wraps each migration in
-- its own transaction (store/src/lib.rs migrate_locked).

ALTER TABLE lookup_receipts ALTER COLUMN scan_id DROP NOT NULL;

ALTER TABLE lookup_receipts ADD COLUMN domain TEXT;
ALTER TABLE lookup_receipts ADD COLUMN observed_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE lookup_receipts
   SET domain = s.domain
  FROM scans s
 WHERE lookup_receipts.scan_id = s.id;

ALTER TABLE lookup_receipts ALTER COLUMN domain SET NOT NULL;

-- The domain-keyed read is the accessor's spine (precedent: ix_scans_domain_time,
-- ix_flux_obs_domain_time).
CREATE INDEX ix_receipts_domain_time ON lookup_receipts (domain, observed_at);
