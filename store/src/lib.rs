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

use resolution_scope_engine::denial_proof::{
    control_from_key, control_key, DenialProof, LookupReceipt, ReceiptRcode, RecordEntry,
};
use resolution_scope_engine::flux::{FluxObservation, FluxVantage};
use resolution_scope_engine::seal::{
    engine_version, seal_versioned, seal_versioned_under_scheme, SEAL_SCHEME, SEAL_SCHEME_V3,
};
use resolution_scope_engine::ScoredAnalysis;

// =============================================================================
// Migrations — embedded, Up-only, ledgered
// =============================================================================

/// Every migration, in application order. Embedded so the binary IS the
/// schema authority (no runtime file dependency), ledgered in
/// `schema_migrations` so re-running is idempotent.
const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../migrations/001_sealed_history.sql")),
    (2, include_str!("../migrations/002_seal_scheme.sql")),
    (3, include_str!("../migrations/003_lookup_receipts.sql")),
    (4, include_str!("../migrations/004_receipt_domain_key.sql")),
    (5, include_str!("../migrations/005_records.sql")),
];

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
    /// The row was sealed under a scheme this build cannot re-derive.
    /// NOT a tamper verdict: recomputing an old-scheme row under a newer
    /// scheme and calling the difference "Mismatch" would be a false
    /// accusation — the one failure a tamper-evidence system must never
    /// produce. Whoever bumps SEAL_SCHEME adds the previous scheme's
    /// re-derivation arm to verify_scan, keeping old rows verifiable.
    /// Arms present: v4 (current) and v3 (identical canonical form — see
    /// `SEAL_SCHEME_V3`). Rows labeled v1/v2 remain unverifiable here:
    /// v2's form differs (no tlsa_zone line) and whether real v2 rows
    /// still exist and deserialize is an open ledger item.
    UnverifiableScheme { stored_scheme: String },
}

/// The pure seal-check decision, factored from [`Store::verify_scan`] so the
/// scheme dispatch is testable without a database. Dispatch is on the scheme
/// that SEALED the row: the current scheme re-derives directly; v3 re-derives
/// under its own label (identical canonical form — the v4 bump changed the
/// disposition vocabulary, not the byte layout); any other scheme is
/// UnverifiableScheme, never Mismatch.
fn check_stored_seal(scan: StoredScan) -> SealCheck {
    let recomputed = if scan.seal_scheme == SEAL_SCHEME {
        seal_versioned(&scan.verdict, &scan.engine_version)
    } else if scan.seal_scheme == SEAL_SCHEME_V3 {
        seal_versioned_under_scheme(&scan.verdict, &scan.engine_version, SEAL_SCHEME_V3)
    } else {
        return SealCheck::UnverifiableScheme {
            stored_scheme: scan.seal_scheme,
        };
    };
    if recomputed == scan.seal {
        SealCheck::Verified
    } else {
        SealCheck::Mismatch {
            stored: scan.seal,
            recomputed,
        }
    }
}

/// One stored scan, read back whole.
#[derive(Debug)]
pub struct StoredScan {
    pub id: i64,
    pub domain: String,
    pub engine_version: String,
    pub seal: String,
    pub seal_scheme: String,
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
    ///
    /// INVARIANT — stored verdict JSON is append-only. No migration,
    /// backfill, or schema update may deserialize and rewrite a verdict row:
    /// serde normalizes old variant spellings on re-serialization (aliases
    /// are deserialize-only, measured 2026-08-25), so a rewrite pass would
    /// silently change sealed bytes under their unchanged seal and
    /// self-inflict Mismatch on every touched row. Re-derivation happens in
    /// `verify_scan` at read time, never at write time.
    pub async fn record_scan(
        &mut self,
        a: &ScoredAnalysis,
        receipts: &[LookupReceipt],
        records: &[RecordEntry],
    ) -> Result<i64> {
        let version = engine_version();
        let sealed = seal_versioned(a, &version);
        let verdict = serde_json::to_value(a).context("store: verdict serialization failed")?;

        // The scan, its receipts, and its raw records commit atomically: a
        // verdict row with half its evidence would present an evidence set as
        // complete when it is not. Receipts AND records are BESIDE the seal
        // (R-B) — this transaction touches only the receipt and record tables;
        // the seal path and its goldens are byte-untouched.
        let tx = self.client.transaction().await?;
        let row = tx
            .query_one(
                "INSERT INTO scans (domain, engine_version, seal, seal_scheme, verdict)
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[&a.domain, &version, &sealed, &SEAL_SCHEME, &verdict],
            )
            .await?;
        let scan_id: i64 = row.get(0);
        for r in receipts {
            let control = control_key(r.control);
            let rcode = r.rcode.label();
            let answer_count = i32::from(r.answer_count);
            let proof = r.denial_proof.label();
            let elapsed =
                i64::try_from(r.elapsed_ms).context("store: receipt elapsed_ms overflows i64")?;
            tx.execute(
                "INSERT INTO lookup_receipts
                     (scan_id, domain, control, rcode, answer_count, denial_proof, elapsed_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &scan_id,
                    &a.domain,
                    &control,
                    &rcode,
                    &answer_count,
                    &proof,
                    &elapsed,
                ],
            )
            .await?;
        }
        for rec in records {
            let control = control_key(rec.control);
            tx.execute(
                "INSERT INTO records (scan_id, control, value) VALUES ($1, $2, $3)",
                &[&scan_id, &control, &rec.value],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(scan_id)
    }

    /// Read a scan's receipts back whole — one per control, in insert order.
    /// The TEXT vocabulary roundtrips through the store's explicit labels; an
    /// unknown stored label is a loud error, never a silent skip.
    pub async fn receipts_for_scan(&self, scan_id: i64) -> Result<Vec<LookupReceipt>> {
        let rows = self
            .client
            .query(
                "SELECT control, rcode, answer_count, denial_proof, elapsed_ms
                 FROM lookup_receipts WHERE scan_id = $1 ORDER BY ctid",
                &[&scan_id],
            )
            .await?;
        let mut receipts = Vec::with_capacity(rows.len());
        for row in rows {
            let control_key_str: String = row.get(0);
            let rcode_str: String = row.get(1);
            let answer_count: i32 = row.get(2);
            let proof_str: String = row.get(3);
            let elapsed: i64 = row.get(4);

            let control = control_from_key(&control_key_str).with_context(|| {
                format!("store: unknown stored control key {control_key_str:?}")
            })?;
            let rcode = ReceiptRcode::from_label(&rcode_str)
                .with_context(|| format!("store: unknown stored rcode {rcode_str:?}"))?;
            let denial_proof = DenialProof::from_label(&proof_str)
                .with_context(|| format!("store: unknown stored denial_proof {proof_str:?}"))?;
            receipts.push(LookupReceipt {
                control,
                rcode,
                answer_count: u16::try_from(answer_count)
                    .context("store: stored answer_count out of u16 range")?,
                denial_proof,
                elapsed_ms: u64::try_from(elapsed).context("store: stored elapsed_ms negative")?,
            });
        }
        Ok(receipts)
    }

    /// Read a scan's raw records back whole — one row per captured record, in
    /// insert order. The raw bytes are BESIDE the seal (R-B), exactly like the
    /// receipts; an unknown stored control key is a loud error, never a skip.
    pub async fn records_for_scan(&self, scan_id: i64) -> Result<Vec<RecordEntry>> {
        let rows = self
            .client
            .query(
                "SELECT control, value FROM records WHERE scan_id = $1 ORDER BY ctid",
                &[&scan_id],
            )
            .await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let control_key_str: String = row.get(0);
            let value: String = row.get(1);
            let control = control_from_key(&control_key_str).with_context(|| {
                format!("store: unknown stored record control key {control_key_str:?}")
            })?;
            records.push(RecordEntry { control, value });
        }
        Ok(records)
    }

    /// Domain-keyed receipt read (ruling 2026-08-25): reaches BOTH scan-linked
    /// rows and — once source-3 lands — scan-less contributed rows. This is
    /// the accessor the nullable-scan_id design requires: a scan_id-keyed
    /// read path can structurally never reach a NULL-scan_id row (Science's
    /// audit catch). `scan_id` rides along as `Option<i64>`, following the
    /// flux_observations optional-link precedent. Newest first.
    pub async fn receipts_by_domain(
        &self,
        domain: &str,
    ) -> Result<Vec<(Option<i64>, LookupReceipt)>> {
        let rows = self
            .client
            .query(
                "SELECT scan_id, control, rcode, answer_count, denial_proof, elapsed_ms
                 FROM lookup_receipts WHERE domain = $1
                 ORDER BY observed_at DESC, ctid",
                &[&domain],
            )
            .await?;
        let mut receipts = Vec::with_capacity(rows.len());
        for row in rows {
            let scan_id: Option<i64> = row.get(0);
            let control_key_str: String = row.get(1);
            let rcode_str: String = row.get(2);
            let answer_count: i32 = row.get(3);
            let proof_str: String = row.get(4);
            let elapsed: i64 = row.get(5);

            let control = control_from_key(&control_key_str).with_context(|| {
                format!("store: unknown stored control key {control_key_str:?}")
            })?;
            let rcode = ReceiptRcode::from_label(&rcode_str)
                .with_context(|| format!("store: unknown stored rcode {rcode_str:?}"))?;
            let denial_proof = DenialProof::from_label(&proof_str)
                .with_context(|| format!("store: unknown stored denial_proof {proof_str:?}"))?;
            receipts.push((
                scan_id,
                LookupReceipt {
                    control,
                    rcode,
                    answer_count: u16::try_from(answer_count)
                        .context("store: stored answer_count out of u16 range")?,
                    denial_proof,
                    elapsed_ms: u64::try_from(elapsed)
                        .context("store: stored elapsed_ms negative")?,
                },
            ));
        }
        Ok(receipts)
    }

    /// Re-derive a stored scan's seal from its stored verdict and stored
    /// producing version. Detects any post-write alteration of verdict,
    /// seal, or version.
    pub async fn verify_scan(&self, id: i64) -> Result<SealCheck> {
        Ok(check_stored_seal(self.read_scan(id).await?))
    }

    /// Read one stored scan back whole.
    pub async fn read_scan(&self, id: i64) -> Result<StoredScan> {
        let row = self
            .client
            .query_one(
                "SELECT id, domain, engine_version, seal, seal_scheme, verdict
                 FROM scans WHERE id = $1",
                &[&id],
            )
            .await?;
        let verdict_json: serde_json::Value = row.get(5);
        let verdict: ScoredAnalysis = serde_json::from_value(verdict_json)
            .context("store: stored verdict no longer deserializes — schema drift")?;
        Ok(StoredScan {
            id: row.get(0),
            domain: row.get(1),
            engine_version: row.get(2),
            seal: row.get(3),
            seal_scheme: row.get(4),
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
        CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
        DmarcDisposition, DnssecDisposition, MtaStsDisposition, SpfDisposition, TlsRptDisposition,
        TlsaZone,
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
        let tls_rpt = TlsRptDisposition::Published;
        let csync = CsyncDisposition::RecordAbsent;
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
            tlsa_zone: TlsaZone::NoMxHost,
            mta_sts: mta.chain(),
            mta_sts_disposition: mta,
            caa: caa.chain(),
            caa_disposition: caa,
            cds_cdnskey: cds.chain(),
            cds_disposition: cds,
            tls_rpt: tls_rpt.chain(),
            tls_rpt_disposition: tls_rpt,
            csync: csync.chain(),
            csync_disposition: csync,
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
        let mut store = test_store().await;
        let a = verdict("roundtrip.test");
        let id = store.record_scan(&a, &[], &[]).await.expect("record");

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
        let mut store = test_store().await;
        let id = store
            .record_scan(&verdict("tamper.test"), &[], &[])
            .await
            .unwrap();

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
            other => panic!("a tampered verdict must read Mismatch, got {other:?}"),
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
                "INSERT INTO scans (domain, engine_version, seal, seal_scheme, verdict)
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[
                    &a.domain,
                    &old_version,
                    &old_seal,
                    &SEAL_SCHEME,
                    &verdict_json,
                ],
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
    async fn unknown_scheme_is_unverifiable_never_a_tamper_verdict() {
        let store = test_store().await;
        let a = verdict("oldscheme.test");
        let verdict_json = serde_json::to_value(&a).unwrap();
        // A row sealed under a scheme this build does not know. Its seal
        // CANNOT re-derive here — and that must read as "cannot verify",
        // never as "tampered": a false accusation is the one failure a
        // tamper-evidence system must never produce.
        let row = store
            .client
            .query_one(
                "INSERT INTO scans (domain, engine_version, seal, seal_scheme, verdict)
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[
                    &a.domain,
                    &"0.1.0",
                    &"f".repeat(128),
                    &"resolution-scope-sha3-512-v1",
                    &verdict_json,
                ],
            )
            .await
            .unwrap();
        let id: i64 = row.get(0);
        match store.verify_scan(id).await.unwrap() {
            SealCheck::UnverifiableScheme { stored_scheme } => {
                assert_eq!(stored_scheme, "resolution-scope-sha3-512-v1");
            }
            other => panic!("unknown scheme must be UnverifiableScheme, got {other:?}"),
        }
    }

    // ── check_stored_seal: the pure dispatch, no database needed ──────────

    fn planted(scheme: &str, seal: String, a: ScoredAnalysis) -> StoredScan {
        StoredScan {
            id: 0,
            domain: a.domain.clone(),
            engine_version: "0.1.0".into(),
            seal,
            seal_scheme: scheme.into(),
            verdict: a,
        }
    }

    /// The v4 bump's obligation (this enum's own doc): rows sealed under v3
    /// stay VERIFIABLE, because v3's canonical form is byte-identical to
    /// v4's apart from the scheme line.
    ///
    /// DISPATCH test only: expected and actual both ride the shared builder,
    /// so a byte-drift common to both sides passes here. The byte-honesty of
    /// the v3 path rests on the engine's frozen known-answer pin
    /// (`v3_known_answer_seal_is_byte_frozen`, engine/src/seal.rs) — do not
    /// "simplify" that KAT away; this test depends on it.
    #[test]
    fn v3_sealed_row_rederives_to_verified() {
        let a = verdict("v3row.test");
        let s = seal_versioned_under_scheme(&a, "0.1.0", SEAL_SCHEME_V3);
        assert_eq!(
            check_stored_seal(planted(SEAL_SCHEME_V3, s, a)),
            SealCheck::Verified
        );
    }

    /// A re-derivable scheme that does NOT match is tamper evidence — the
    /// arm must produce Mismatch, not hide behind UnverifiableScheme.
    #[test]
    fn v3_sealed_row_tamper_reads_mismatch_not_unverifiable() {
        let a = verdict("v3tamper.test");
        let s = seal_versioned_under_scheme(&a, "0.1.0", SEAL_SCHEME_V3);
        let mut altered = verdict("v3tamper.test");
        altered.resolver_identity = "attacker".into();
        match check_stored_seal(planted(SEAL_SCHEME_V3, s, altered)) {
            SealCheck::Mismatch { .. } => {}
            other => panic!("altered v3 row must read Mismatch, got {other:?}"),
        }
    }

    /// Pure twin of the planted-v1 database test above.
    #[test]
    fn unknown_scheme_is_unverifiable_in_the_pure_path_too() {
        let a = verdict("v1row.test");
        match check_stored_seal(planted("resolution-scope-sha3-512-v1", "f".repeat(128), a)) {
            SealCheck::UnverifiableScheme { stored_scheme } => {
                assert_eq!(stored_scheme, "resolution-scope-sha3-512-v1");
            }
            other => panic!("must be UnverifiableScheme, got {other:?}"),
        }
    }

    /// Refactor guard: a current-scheme roundtrip through the dispatch
    /// verifies. (An earlier first assertion compared
    /// `seal_versioned_under_scheme(.., SEAL_SCHEME)` to `seal_versioned` —
    /// a tautology BY DEFINITION, since the latter is literally defined as
    /// that call; it could not fail under any drift and was removed. The
    /// byte-honesty of this path is pinned by the engine's frozen
    /// known-answer tests, not here. Audit 2026-08-29.)
    #[test]
    fn current_scheme_roundtrip_still_verifies() {
        let a = verdict("current.test");
        let s = seal_versioned(&a, "0.1.0");
        assert_eq!(
            check_stored_seal(planted(SEAL_SCHEME, s, a)),
            SealCheck::Verified
        );
    }

    /// Full-path variant of the pure v3 test: a v3-sealed row planted in a
    /// real database still verifies through verify_scan after the v4 bump.
    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn v3_scheme_row_stays_verifiable_after_the_v4_bump() {
        let store = test_store().await;
        let a = verdict("v3keeps.test");
        let v3_seal = seal_versioned_under_scheme(&a, "0.1.0", SEAL_SCHEME_V3);
        let verdict_json = serde_json::to_value(&a).unwrap();
        let row = store
            .client
            .query_one(
                "INSERT INTO scans (domain, engine_version, seal, seal_scheme, verdict)
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[
                    &a.domain,
                    &"0.1.0",
                    &v3_seal,
                    &SEAL_SCHEME_V3,
                    &verdict_json,
                ],
            )
            .await
            .unwrap();
        let id: i64 = row.get(0);
        assert_eq!(store.verify_scan(id).await.unwrap(), SealCheck::Verified);
    }

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn flux_history_feeds_dispersion() {
        let store = test_store().await;
        let domain = "fluxloop.test";
        // Self-cleaning: this test asserts EXACT dispersion numbers, so prior
        // runs' rows for the specimen domain must not accumulate (a persistent
        // local database is a supported test target, not just fresh CI ones).
        store
            .client
            .execute(
                "DELETE FROM flux_observations WHERE domain = $1",
                &[&domain],
            )
            .await
            .unwrap();
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

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn receipt_roundtrip_and_beside_seal() {
        use resolution_scope_engine::ControlId;

        let mut store = test_store().await;
        let a = verdict("receipt.test");
        let receipts = vec![
            LookupReceipt {
                control: ControlId::Dnssec,
                rcode: ReceiptRcode::NoError,
                answer_count: 1,
                denial_proof: DenialProof::Nsec,
                elapsed_ms: 42,
            },
            LookupReceipt {
                control: ControlId::Spf,
                rcode: ReceiptRcode::NxDomain,
                answer_count: 0,
                denial_proof: DenialProof::SoaOnly,
                elapsed_ms: 7,
            },
            LookupReceipt {
                control: ControlId::Caa,
                rcode: ReceiptRcode::Timeout,
                answer_count: 0,
                denial_proof: DenialProof::None,
                elapsed_ms: 1000,
            },
        ];
        let id = store.record_scan(&a, &receipts, &[]).await.unwrap();

        // Receipts roundtrip through the TEXT vocabulary in a stable order.
        let mut back = store.receipts_for_scan(id).await.unwrap();
        back.sort_by_key(|r| control_key(r.control));
        let mut want = receipts.clone();
        want.sort_by_key(|r| control_key(r.control));
        assert_eq!(back, want);

        // R-B: receipts are BESIDE the seal. The seal is computed from the
        // verdict alone, so the same verdict seals identically with and without
        // receipts — the receipt table never touches the seal preimage.
        let no_receipt_id = store.record_scan(&a, &[], &[]).await.unwrap();
        let with = store.read_scan(id).await.unwrap();
        let without = store.read_scan(no_receipt_id).await.unwrap();
        assert_eq!(
            with.seal, without.seal,
            "receipts must never change the seal (R-B)"
        );

        // The domain-keyed accessor reaches the same rows (and, once source-3
        // lands, would also reach scan-less rows a scan_id-keyed read cannot).
        let by_domain = store.receipts_by_domain("receipt.test").await.unwrap();
        assert!(
            by_domain.len() >= receipts.len(),
            "domain-keyed read must reach at least the scan-linked rows"
        );
        assert!(
            by_domain.iter().filter(|(sid, _)| *sid == Some(id)).count() == receipts.len(),
            "every scan-linked receipt carries its scan_id through the domain read"
        );
    }

    #[tokio::test]
    #[ignore = "requires RS_STORE_TEST_URL (disposable postgres)"]
    async fn record_roundtrip_and_beside_seal() {
        use resolution_scope_engine::ControlId;

        let mut store = test_store().await;
        let a = verdict("record.test");
        let records = vec![
            RecordEntry {
                control: ControlId::Spf,
                value: "v=spf1 include:_spf.example.com -all".to_string(),
            },
            RecordEntry {
                control: ControlId::Dmarc,
                value: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string(),
            },
            RecordEntry {
                control: ControlId::Caa,
                value: "0 issue \"letsencrypt.org\"".to_string(),
            },
            RecordEntry {
                control: ControlId::Dkim,
                value: "google => v=DKIM1; k=rsa; p=MIGfMA0…".to_string(),
            },
        ];
        let id = store.record_scan(&a, &[], &records).await.unwrap();

        // Records roundtrip through the control TEXT vocabulary in insert order.
        let back = store.records_for_scan(id).await.unwrap();
        assert_eq!(back, records, "records must roundtrip byte-for-byte");

        // R-B: records are BESIDE the seal. The seal is computed from the
        // verdict alone, so the same verdict seals identically with and without
        // records — the records table never touches the seal preimage.
        let no_records_id = store.record_scan(&a, &[], &[]).await.unwrap();
        let with = store.read_scan(id).await.unwrap();
        let without = store.read_scan(no_records_id).await.unwrap();
        assert_eq!(
            with.seal, without.seal,
            "records must never change the seal (R-B)"
        );

        // A control with no measured record contributes zero rows — a missing
        // record is informative absence, never a fabricated empty string.
        let empty = store.records_for_scan(no_records_id).await.unwrap();
        assert!(empty.is_empty(), "no records captured => no rows written");
    }
}
