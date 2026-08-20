-- 001_sealed_history.sql — the store's founding schema.
--
-- Up-only BY DESIGN: no Down sections anywhere in this directory. The Go
-- parent's schema-doc instrument executed Down sections it was never meant
-- to run (dns-tool-intel #467) — this store removes the hazard class instead
-- of guarding it. Rollback of a migration is a new migration.
--
-- verdict is `json`, not `jsonb`, per the 2026-08-17 measured ruling on the
-- parent (GIN 1-2 orders slower than expression indexes, jsonb 27% larger;
-- do not reopen without new query shapes). The verdict column is an archival
-- artifact read back whole for seal verification — not a query surface.

CREATE TABLE scans (
    id             BIGSERIAL PRIMARY KEY,
    domain         TEXT        NOT NULL,
    scanned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The version of the engine that PRODUCED this verdict. Seal verification
    -- hashes this stored value, never the verifier's own version — otherwise
    -- every engine release would orphan all prior sealed history.
    engine_version TEXT        NOT NULL,
    -- SHA3-512 hex, 128 chars, computed BY THE STORE at insert from the
    -- verdict itself (a caller-supplied seal is never accepted).
    seal           TEXT        NOT NULL CHECK (char_length(seal) = 128),
    verdict        JSON        NOT NULL
);

CREATE INDEX ix_scans_domain_time ON scans (domain, scanned_at DESC);

CREATE TABLE flux_observations (
    id                   BIGSERIAL PRIMARY KEY,
    -- Optional link to the scan this observation rode along with.
    scan_id              BIGINT REFERENCES scans(id) ON DELETE CASCADE,
    domain               TEXT        NOT NULL,
    observed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    origin_asns          TEXT[]      NOT NULL DEFAULT '{}',
    excluded_asns        JSON        NOT NULL DEFAULT '[]',
    min_ttl              INT,
    unresolved_addresses INT         NOT NULL DEFAULT 0,
    vantage              TEXT        NOT NULL
);

-- Domain-and-time scoped: the dispersion counter reads a domain's
-- observations in time order.
CREATE INDEX ix_flux_obs_domain_time ON flux_observations (domain, observed_at);
