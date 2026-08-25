-- 003_lookup_receipts.sql — the receipt column: one row per control per scan.
--
-- Receipts are BESIDE the seal, never part of it (R-B ruling, 2026-08-24):
-- the seal attests OUR verdict (judge); the receipt records the SERVER'S
-- words (witness). Nothing in this table is sealed, and elapsed_ms — run
-- metadata about the observer, not the target — must never be mixed into the
-- seal, exactly as resolver_identity was already ruled.
--
-- rcode is the TEXT vocabulary, never a raw wire u8. TIMEOUT has no wire
-- rcode at all (the "response" is the absence of a response), so a numeric
-- encoding would silently drop one of the five failure modes the
-- failure-is-a-measurement principle requires decomposing. The CHECK
-- constraints make that mechanical rather than documentary.

CREATE TABLE lookup_receipts (
    scan_id       BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    -- The ControlId as a stable lowercase key — not the display name.
    control       TEXT   NOT NULL
                  CHECK (control IN ('dnssec','spf','dkim','dmarc','dane','mta_sts','caa','cds')),
    rcode         TEXT   NOT NULL
                  CHECK (rcode IN ('NOERROR','NXDOMAIN','SERVFAIL','REFUSED','TIMEOUT')),
    answer_count  INT    NOT NULL CHECK (answer_count >= 0),
    denial_proof  TEXT   NOT NULL
                  CHECK (denial_proof IN ('none','soa_only','nsec','nsec3','nsec_nxname','nsec3_nxname')),
    elapsed_ms    BIGINT NOT NULL CHECK (elapsed_ms >= 0)
);

-- One row per control per scan; the receipt read is always scoped by scan.
CREATE INDEX ix_receipts_scan_control ON lookup_receipts (scan_id, control);
