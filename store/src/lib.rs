// resolution-scope-store — sealed measurement history in PostgreSQL.
//
// The store is the instrument's memory, and it holds itself to the same
// epistemics as the instrument:
//
//   - SEALED ON WRITE, BY THE STORE. `record_scan` computes the seal from
//     the verdict it is handed — a caller-supplied seal is never accepted
//     (derive-from-producer: a seal the store didn't derive is a claim,
//     not a measurement).
//   - VERIFIABLE ON READ, ACROSS VERSIONS. Each row persists the producing
//     engine's version; `verify_scan` re-derives the seal from the stored
//     verdict + stored version and compares byte-for-byte. A tampered
//     verdict, a tampered seal, or a tampered version column all fail.
//   - UP-ONLY MIGRATIONS. No Down sections exist in migrations/ — the
//     hazard class that corrupted the Go parent's schema documentation
//     (dns-tool-intel #467) is removed, not guarded.
//
// Capability shape (ARCHITECTURE.md §3/§4 on ordinary Linux): this crate
// holds a database connection and nothing else — no resolver, no HTTP
// client. The engine never depends on the store.

use anyhow::{bail, Context, Result};
use tokio_postgres::{Client, NoTls};
use tracing::{info, warn};

use resolution_scope_engine::flux::{FluxObservation, FluxVantage};
use resolution_scope_engine::seal::{engine_version, seal_versioned};
use resolution_scope_engine::ScoredAnalysis;

// =============================================================================
// Migrations — embedded, Up-only, ledgered
// =============================================================================

/// Every migration, in application order. Embedded so the binary IS the
/// schema authority (no runtime file dependency), ledgered in
/// `schema_migrations` so re-running is idempotent.
const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("../migrations/001_sealed_history.sql"))];

/// Advisory-lock key for migration serialization — arbitrary but fixed;
/// shared by every resolution-scope-store instance on a database.
const MIGRATION_LOCK_KEY: i64 = 0x0052_5353_544f_5245; // "RSSTORE"

// =============================================================================
// Store
// =============================================================================

pub struct Store {
    client: Client,
}

/// The result of re-deriving a stored scan's seal from its stored verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealCheck {
    /// Recomputed seal matches the stored seal byte-for-byte.
    Verified,
    /// The stored verdict does not hash to the stored seal — the row was
    /// altered after sealing (verdict, seal, or version column).
    Mismatch { stored: String, recomputed: String },
}

/// One stored scan, read back whole.
#[derive(Debug)]
pub struct StoredScan {
    pub id: i64,
    pub domain: String,
    pub engine_version: String,
    pub seal: String,
    pub verdict: ScoredAnalysis,
}

impl Store {
    /// Connect and spawn the connection driver. The URL is the store's ONLY
    /// capability.
    pub async fn connect(database_url: &str) -> Result<Store> {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .context("store: connection failed")?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!(error = %e, "store: connection driver ended");
            }
        });
        Ok(Store { client })
    }

    /// Apply every unapplied migration, in order, each in its own
    /// transaction with its ledger row — a half-applied migration rolls
    /// back WITH its ledger entry, so the ledger can never claim more than
    /// the schema delivers.
    pub async fn migrate(&mut self) -> Result<()> {
        // Serialize concurrent migrators (two app instances starting at once,
        // or parallel tests on a fresh database) with a session advisory
        // lock — without it, simultaneous CREATE TABLE races lose half the
        // starters. Found by exactly that: five concurrent integration tests
        // on an empty database, four failed (2026-08-19).
        self.client
            .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
            .await?;
        let result = self.migrate_locked().await;
        // Unlock even when migration failed; the error still propagates.
        let _ = self
            .client
            .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
            .await;
        result
    }

    async fn migrate_locked(&mut self) -> Result<()> {
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                     version    INT PRIMARY KEY,
                     applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                 )",
                &[],
            )
            .await?;
        for (version, sql) in MIGRATIONS {
            let applied: bool = self
                .client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
                    &[version],
                )
                .await?
                .get(0);
            if applied {
                continue;
            }
            let tx = self.client.transaction().await?;
            tx.batch_execute(sql)
                .await
                .with_context(|| format!("store: migration {version} failed"))?;
            tx.execute(
                "INSERT INTO schema_migrations (version) VALUES ($1)",
                &[version],
            )
            .await?;
            tx.commit().await?;
            info!(version, "store: migration applied");
        }
        Ok(())
    }

    /// Persist a verdict, sealed. The seal is computed HERE, from the
    /// verdict being stored, bound to the engine version compiled into this
    /// build — never accepted from the caller.
    pub async fn record_scan(&self, a: &ScoredAnalysis) -> Result<i64> {
        let version = engine_version();
        let sealed = seal_versioned(a, &version);
        let verdict = serde_json::to_value(a).context("store: verdict serialization failed")?;
        let row = self
            .client
            .query_one(
                "INSERT INTO scans (domain, engine_version, seal, verdict)
                 VALUES ($1, $2, $3, $4) RETURNING id",
                &[&a.domain, &version, &sealed, &verdict],
            )
            .await?;
        Ok(row.get(0))
    }

    /// Re-derive a stored scan's seal from its stored verdict and stored
    /// producing version. Detects any post-write alteration of verdict,
    /// seal, or version.
    pub async fn verify_scan(&self, id: i64) -> Result<SealCheck> {
        let scan = self.read_scan(id).await?;
        let recomputed = seal_versioned(&scan.verdict, &scan.engine_version);
        if recomputed == scan.seal {
            Ok(SealCheck::Verified)
        } else {
            Ok(SealCheck::Mismatch {
                stored: scan.seal,
                recomputed,
            })
        }
    }

    /// Read one stored scan back whole.
    pub async fn read_scan(&self, id: i64) -> Result<StoredScan> {
        let row = self
            .client
            .query_one(
                "SELECT id, domain, engine_version, seal, verdict FROM scans WHERE id = $1",
                &[&id],
            )
            .await?;
        let verdict_json: serde_json::Value = row.get(4);
        let verdict: ScoredAnalysis = serde_json::from_value(verdict_json)
            .context("store: stored verdict no longer deserializes — schema drift")?;
        Ok(StoredScan {
            id: row.get(0),
            domain: row.get(1),
            engine_version: row.get(2),
            seal: row.get(3),
            verdict,
        })
    }

    /// All stored scans for a domain, oldest first.
    pub async fn scan_history(&self, domain: &str) -> Result<Vec<StoredScan>> {
        let rows = self
            .client
            .query(
                "SELECT id FROM scans WHERE domain = $1 ORDER BY scanned_at, id",
                &[&domain],
            )
            .await?;
        let mut scans = Vec::with_capacity(rows.len());
        for row in rows {
            scans.push(self.read_scan(row.get(0)).await?);
        }
        Ok(scans)
    }

    /// Persist one flux observation, optionally linked to a scan row.
    pub async fn record_flux(
        &self,
        domain: &str,
        obs: &FluxObservation,
        scan_id: Option<i64>,
    ) -> Result<i64> {
        let origin_asns: Vec<&str> = obs.origin_asns.iter().map(|s| s.as_str()).collect();
        let excluded = serde_json::to_value(&obs.excluded_asns)?;
        let vantage = vantage_label(&obs.vantage);
        let min_ttl: Option<i32> = obs.min_ttl.map(|t| t as i32);
        let unresolved: i32 = i32::try_from(obs.unresolved_addresses)?;
        let row = self
            .client
            .query_one(
                "INSERT INTO flux_observations
                     (scan_id, domain, origin_asns, excluded_asns, min_ttl,
                      unresolved_addresses, vantage)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                &[
                    &scan_id,
                    &domain,
                    &origin_asns,
                    &excluded,
                    &min_ttl,
                    &unresolved,
                    &vantage,
                ],
            )
            .await?;
        Ok(row.get(0))
    }

    /// A domain's flux observations, oldest first — the exact input shape
    /// of `resolution_scope_engine::flux::dispersion`. This is the loop the
    /// flux signal was waiting for: measurement (engine) → memory (store)
    /// → dispersion (engine, pure) over real history.
    pub async fn flux_history(&self, domain: &str) -> Result<Vec<FluxObservation>> {
        let rows = self
            .client
            .query(
                "SELECT origin_asns, excluded_asns, min_ttl, unresolved_addresses, vantage
                 FROM flux_observations WHERE domain = $1 ORDER BY observed_at, id",
                &[&domain],
            )
            .await?;
        let mut history = Vec::with_capacity(rows.len());
        for row in rows {
            let origin_asns: Vec<String> = row.get(0);
            let excluded_json: serde_json::Value = row.get(1);
            let min_ttl: Option<i32> = row.get(2);
            let unresolved: i32 = row.get(3);
            let vantage_str: String = row.get(4);
            history.push(FluxObservation {
                origin_asns: origin_asns.into_iter().collect(),
                excluded_asns: serde_json::from_value(excluded_json)
                    .context("store: stored exclusions no longer deserialize")?,
                min_ttl: min_ttl.map(|t| t as u32),
                unresolved_addresses: usize::try_from(unresolved)?,
                vantage: vantage_from_label(&vantage_str)?,
            });
        }
        Ok(history)
    }
}

// =============================================================================
// Vantage <-> label — explicit, exhaustive both ways
// =============================================================================
//
// Explicit rather than serde-stringified so the STORED vocabulary is a
// deliberate contract: adding a FluxVantage variant forces a compile error
// here, and an unknown stored label is a loud error, never a silent skip.

fn vantage_label(v: &FluxVantage) -> &'static str {
    match v {
        FluxVantage::Observable => "observable",
        FluxVantage::ProxiedEdge => "proxied-edge",
        FluxVantage::SharedCloudOnly => "shared-cloud-only",
        FluxVantage::NoAddresses => "no-addresses",
        FluxVantage::AsnUnresolved => "asn-unresolved",
    }
}

fn vantage_from_label(s: &str) -> Result<FluxVantage> {
    Ok(match s {
        "observable" => FluxVantage::Observable,
        "proxied-edge" => FluxVantage::ProxiedEdge,
        "shared-cloud-only" => FluxVantage::SharedCloudOnly,
        "no-addresses" => FluxVantage::NoAddresses,
        "asn-unresolved" => FluxVantage::AsnUnresolved,
        other => bail!("store: unknown stored vantage label {other:?}"),
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use resolution_scope_engine::analysis::{
        CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
        DnssecDisposition, MtaStsDisposition, SpfDisposition,
    };
    use resolution_scope_engine::flux::dispersion;
    use resolution_scope_engine::flux::FluxAssessment;
    use std::collections::BTreeSet;

    fn verdict(domain: &str) -> ScoredAnalysis {
        let dnssec = DnssecDisposition::SignedAndDelegated;
        let spf = SpfDisposition::HardFail;
        let dkim = DkimDisposition::NotProbed;
        let dmarc = DmarcDisposition::Reject;
        let dane = DaneDisposition::NoMail;
        let mta = MtaStsDisposition::RecordAbsent;
        let caa = CaaDisposition::Configured;
        let cds = CdsDisposition::Published;
        ScoredAnalysis {
            domain: domain.to_string(),
            session_id: 1,
            timestamp_local: 1_787_000_000,
            resolver_identity: "default".to_string(),
            dnssec_chain: dnssec.chain(),
            dnssec_disposition: dnssec,
            spf: spf.chain(),
            spf_disposition: spf,
            dkim: dkim.chain(),
            dkim_disposition: dkim,
            dmarc: dmarc.chain(),
            dmarc_disposition: dmarc,
            dane: dane.chain(),
            dane_disposition: dane,
            mta_sts: mta.chain(),
            mta_sts_disposition: mta,
            caa: caa.chain(),
            caa_disposition: caa,
            cds_cdnskey: cds.chain(),
            cds_disposition: cds,
        }
    }

    fn obs(asns: &[&str]) -> FluxObservation {
        FluxObservation {
            origin_asns: asns.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>(),
            excluded_asns: vec![],
            min_ttl: Some(120),
            unresolved_addresses: 0,
            vantage: FluxVantage::Observable,
        }
    }

    /// Vantage labels roundtrip exhaustively — a stored label always comes
    /// back as the variant that produced it.
    #[test]
    fn vantage_labels_roundtrip() {
        for v in [
            FluxVantage::Observable,
            FluxVantage::ProxiedEdge,
            FluxVantage::SharedCloudOnly,
            FluxVantage::NoAddresses,
            FluxVantage::AsnUnresolved,
        ] {
            assert_eq!(vantage_from_label(vantage_label(&v)).unwrap(), v);
        }
        assert!(vantage_from_label("garbage").is_err());
    }

    /// The migration set is ordered, dense from 1, and Up-only (no Down
    /// marker text anywhere — the hazard class is removed, not guarded).
    #[test]
    fn migrations_are_ordered_and_up_only() {
        for (expect, (version, sql)) in (1..).zip(MIGRATIONS.iter()) {
            assert_eq!(*version, expect, "migration versions must be dense from 1");
            let lower = sql.to_lowercase();
            assert!(
                !lower.contains("goose down") && !lower.contains("-- down"),
                "migration {version} carries a Down section — Up-only by design"
            );
        }
    }

    // ── Integration (requires a live PostgreSQL; run via RS_STORE_TEST_URL) ──
    //
    // #[ignore] so plain `cargo test` passes without a database; CI's store
    // job provides a postgres service and runs with --include-ignored, so
    // the gate genuinely executes these (an env-gated silent skip would be
    // a check that cannot fail).

    async fn test_store() -> Store {
        let url = std::env::var("RS_STORE_TEST_URL")
            .expect("RS_STORE_TEST_URL must point at a disposable postgres");
        let mut store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        store
    }

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn sealed_roundtrip_and_verification() {
        let store = test_store().await;
        let a = verdict("roundtrip.test");
        let id = store.record_scan(&a).await.expect("record");

        // Read back whole: verdict fields survive the JSON roundtrip.
        let stored = store.read_scan(id).await.expect("read");
        assert_eq!(stored.verdict.domain, a.domain);
        assert_eq!(stored.verdict.dnssec_disposition, a.dnssec_disposition);
        assert_eq!(stored.engine_version, engine_version());

        // The store's own seal verifies.
        assert_eq!(
            store.verify_scan(id).await.expect("verify"),
            SealCheck::Verified
        );
    }

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn tampered_verdict_fails_verification() {
        let store = test_store().await;
        let id = store.record_scan(&verdict("tamper.test")).await.unwrap();

        // Simulate post-write tampering: flip the stored verdict's SPF
        // disposition directly in SQL, behind the seal's back.
        store
            .client
            .execute(
                "UPDATE scans
                 SET verdict = (verdict::jsonb || '{\"spf_disposition\":\"SoftFail\",\"spf\":\"Present\"}'::jsonb)::json
                 WHERE id = $1",
                &[&id],
            )
            .await
            .unwrap();

        match store.verify_scan(id).await.unwrap() {
            SealCheck::Mismatch { .. } => {}
            SealCheck::Verified => panic!("a tampered verdict must not verify"),
        }
    }

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn old_version_rows_still_verify() {
        let store = test_store().await;
        let a = verdict("oldversion.test");

        // Insert a row AS IF an older engine produced it: seal computed with
        // the old version string, version column carrying it.
        let old_version = "0.0.1-ancient";
        let old_seal = seal_versioned(&a, old_version);
        let verdict_json = serde_json::to_value(&a).unwrap();
        let row = store
            .client
            .query_one(
                "INSERT INTO scans (domain, engine_version, seal, verdict)
                 VALUES ($1, $2, $3, $4) RETURNING id",
                &[&a.domain, &old_version, &old_seal, &verdict_json],
            )
            .await
            .unwrap();
        let id: i64 = row.get(0);

        // Verification hashes the STORED version — the current engine
        // version must not orphan old sealed history.
        assert_eq!(store.verify_scan(id).await.unwrap(), SealCheck::Verified);
    }

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn flux_history_feeds_dispersion() {
        let store = test_store().await;
        let domain = "fluxloop.test";
        for asns in [&["14061"][..], &["24940"][..], &["16276"][..]] {
            store
                .record_flux(domain, &obs(asns), None)
                .await
                .expect("record flux");
        }
        let history = store.flux_history(domain).await.expect("history");
        assert_eq!(history.len(), 3);

        // The full loop: engine measures → store remembers → engine's pure
        // dispersion counter reads the memory.
        let signal = dispersion(&history);
        assert_eq!(signal.assessment, FluxAssessment::Dispersing);
        assert_eq!(signal.transitions, 2);
        assert_eq!(signal.distinct_origin_asns, 3);
        assert!(signal.short_ttl_seen);
    }

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn migrate_is_idempotent() {
        let mut store = test_store().await;
        store
            .migrate()
            .await
            .expect("second migrate must be a no-op");
        let count: i64 = store
            .client
            .query_one("SELECT count(*) FROM schema_migrations", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count as usize, MIGRATIONS.len());
    }
}
