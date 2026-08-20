// =============================================================================
// seal — the "anyone can verify" property (measurement provenance)
// =============================================================================
//
// A seal is a deterministic SHA3-512 digest of a measurement's *verdict
// content*. It exists so a measurement is not merely asserted but verifiable:
// anyone holding the verdict can re-derive the seal and confirm the verdict
// has not been altered in transit, in storage, or by a third party.
//
// This is the "structure-as-label" property from the Carrier Color deep-time
// doctrine — the verification is folded into the shape of the verdict itself,
// not attached as a separate claim. The seal IS the label.
//
// ── WHAT IS SEALED (the verdict) ──────────────────────────────────────────
//   * the domain under analysis
//   * the engine version (which verdict logic produced it)
//   * every control's disposition (the *reason*) and tri-state (the *score*)
//
// ── WHAT IS NOT SEALED (run metadata) ─────────────────────────────────────
//   * session_id   — a per-run random, not part of the verdict
//   * timestamp    — wall-clock provenance, not part of the verdict
//
// The seal deliberately EXCLUDES run metadata so it is a pure function of the
// verdict: the same domain analysed by the same engine produces the same
// seal. A future reader re-derives it from the verdict alone — they do not
// need the original timestamp or session to check authenticity. That is the
// difference between a seal and a signature-of-a-run: a run identity is
// unique and unrecoverable; a verdict seal is reproducible and checkable
// forever.
//
// ── CANONICAL FORM (v1) ────────────────────────────────────────────────────
// The digested byte sequence is, in order, newline-terminated:
//
//   resolution-scope-sha3-512-v1
//   <domain>
//   <engine version>
//   dnssec=<disposition>=<tri>
//   spf=<disposition>=<tri>
//   dkim=<disposition>=<tri>
//   dmarc=<disposition>=<tri>
//   dane=<disposition>=<tri>
//   mta_sts=<disposition>=<tri>
//   caa=<disposition>=<tri>
//   cds=<disposition>=<tri>
//
// Dispositions and tri-states are encoded as their Rust variant names (the
// enum's public, stable identity — renaming a verdict is a breaking change
// and correctly breaks the seal). A "2500-year" hardening would pin explicit
// integer discriminants per variant; v1 uses variant names, which are already
// part of the public API and unambiguous within a fieldless enum.
// =============================================================================

use sha3::{Digest, Sha3_512};

use crate::analysis::ScoredAnalysis;

/// Versioned identifier for the seal scheme. Changing the canonical form
/// (field set, order, encoding) MUST bump this string, or old seals silently
/// become unverifiable — a seal scheme that drifts is a seal that lies.
pub const SEAL_SCHEME: &str = "resolution-scope-sha3-512-v1";

/// Compute the hex-encoded SHA3-512 seal of a measurement's verdict content.
///
/// Deterministic: identical `ScoredAnalysis` verdict fields (domain + the
/// eight dispositions/tri-states) yield the identical seal, regardless of
/// `session_id` or `timestamp_local`. See the module doc for the exact
/// canonical form.
pub fn seal(analysis: &ScoredAnalysis) -> String {
    seal_versioned(analysis, &engine_version())
}

/// Compute the seal for a verdict produced by a SPECIFIC engine version.
///
/// The seal binds the producing engine's version, so verifying a STORED
/// verdict must hash the version that produced it — not whatever version the
/// verifier happens to be running. Without this entry point, every engine
/// release would silently orphan all previously sealed history ("a seal
/// scheme that drifts is a seal that lies" — this module's own rule). The
/// store persists `engine_version` beside each verdict and verifies through
/// here.
pub fn seal_versioned(analysis: &ScoredAnalysis, produced_by_version: &str) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(SEAL_SCHEME.as_bytes());
    hasher.update(b"\n");
    hasher.update(analysis.domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(produced_by_version.as_bytes());
    hasher.update(b"\n");

    // Fixed order — the canonical form's field order is load-bearing. A
    // reordered seal is a different seal, by design.
    hasher.update(control_line(
        "dnssec",
        &analysis.dnssec_disposition,
        &analysis.dnssec_chain,
    ));
    hasher.update(control_line(
        "spf",
        &analysis.spf_disposition,
        &analysis.spf,
    ));
    hasher.update(control_line(
        "dkim",
        &analysis.dkim_disposition,
        &analysis.dkim,
    ));
    hasher.update(control_line(
        "dmarc",
        &analysis.dmarc_disposition,
        &analysis.dmarc,
    ));
    hasher.update(control_line(
        "dane",
        &analysis.dane_disposition,
        &analysis.dane,
    ));
    hasher.update(control_line(
        "mta_sts",
        &analysis.mta_sts_disposition,
        &analysis.mta_sts,
    ));
    hasher.update(control_line(
        "caa",
        &analysis.caa_disposition,
        &analysis.caa,
    ));
    hasher.update(control_line(
        "cds",
        &analysis.cds_disposition,
        &analysis.cds_cdnskey,
    ));

    hex(&hasher.finalize())
}

/// The engine version that produced a verdict. `CARGO_PKG_VERSION` is the
/// crate's own identity; a release pipeline may pin a git-derived version
/// instead (see dns-tool-intel `scripts/version.sh` for the parent pattern).
/// Public so the store can persist the producing version beside each verdict
/// (verification of old rows hashes the stored version, never the current).
pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// One control's canonical line: `name=disposition=tri\n`.
fn control_line(
    name: &str,
    disposition: &dyn std::fmt::Debug,
    tri: &dyn std::fmt::Debug,
) -> String {
    format!("{name}={disposition:?}={tri:?}\n")
}

/// Lowercase hex of a byte slice (SHA3-512 → 128 hex chars).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{
        CaaDisposition, CdsDisposition, DaneDisposition, DkimDisposition, DmarcDisposition,
        MtaStsDisposition, ScoredAnalysis, SpfDisposition,
    };
    use crate::TriState;

    /// A baseline verdict with every control at a distinct, known state, so a
    /// single-field flip is observable in the seal.
    fn baseline() -> ScoredAnalysis {
        ScoredAnalysis {
            domain: "example.com".to_string(),
            session_id: 1,
            timestamp_local: 1_700_000_000,
            dnssec_chain: TriState::Present,
            dnssec_disposition: crate::analysis::DnssecDisposition::SignedAndDelegated,
            spf: TriState::Present,
            spf_disposition: SpfDisposition::HardFail,
            dkim: TriState::Absent,
            dkim_disposition: DkimDisposition::NotFoundDefaults,
            dmarc: TriState::Present,
            dmarc_disposition: DmarcDisposition::Reject,
            dane: TriState::NotApplicable,
            dane_disposition: DaneDisposition::NoMail,
            mta_sts: TriState::Present,
            mta_sts_disposition: MtaStsDisposition::Enforced,
            caa: TriState::Absent,
            caa_disposition: CaaDisposition::NotConfigured,
            cds_cdnskey: TriState::Absent,
            cds_disposition: CdsDisposition::NotPublished,
        }
    }

    #[test]
    fn seal_is_deterministic() {
        assert_eq!(seal(&baseline()), seal(&baseline()));
    }

    #[test]
    fn seal_is_sha3_512_hex() {
        let s = seal(&baseline());
        assert_eq!(s.len(), 128, "SHA3-512 is 64 bytes = 128 hex chars");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn seal_changes_when_a_verdict_flips() {
        let mut tampered = baseline();
        // Flip exactly one tri-state — the seal must break.
        tampered.dnssec_chain = TriState::Absent;
        assert_ne!(seal(&baseline()), seal(&tampered));
    }

    #[test]
    fn seal_changes_when_a_disposition_changes() {
        let mut tampered = baseline();
        // Change the *reason* while leaving the collapsed tri-state alone —
        // the seal must still break, because the disposition is part of the
        // verdict content.
        tampered.spf_disposition = SpfDisposition::SoftFail;
        assert_ne!(seal(&baseline()), seal(&tampered));
    }

    #[test]
    fn seal_ignores_run_metadata() {
        // session_id and timestamp are provenance, not verdict — a future
        // reader must be able to re-derive the seal without knowing them.
        let mut rerun = baseline();
        rerun.session_id = 99_999;
        rerun.timestamp_local = 9_999_999_999;
        assert_eq!(seal(&baseline()), seal(&rerun));
    }

    #[test]
    fn seal_survives_serde_roundtrip() {
        // "Structure-as-label": serialize the verdict to JSON, hand it to a
        // third party, deserialize, re-seal — the seal is identical, proving
        // the verification travels with the verdict and not with a side
        // channel.
        let json = serde_json::to_string(&baseline()).expect("serialize");
        let roundtrip: ScoredAnalysis = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(seal(&baseline()), seal(&roundtrip));
    }
}
