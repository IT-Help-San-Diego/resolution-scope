// seal.rs — verdict seal (no_std MIRROR of engine/src/seal.rs)
//
// The seal is the load-bearing contract of the Option-B compartment: the store
// re-derives SHA3-512 over the verdict's canonical input and compares it to the
// seal that crossed the boundary, which is tamper-evidence that the verdict
// was not altered after measurement.
//
// BYTE-IDENTITY IS LOAD-BEARING. The canonical form (field order, encoding,
// enum variant names via Debug) must match the engine byte-for-byte, or a
// verdict sealed by the engine fails verification in the compartment (and vice
// versa). The golden-seal test below pins this mirror to a value computed from
// the ENGINE (the single source of truth).
//
// The honest claim (unchanged from the engine): "anyone can verify this verdict
// is the one that was sealed." It is NOT proof that the measurement occurred.
//
// The compartment receives the PRODUCING engine version alongside the verdict
// (the store persists engine_version per verdict), so only seal_versioned is
// exposed here — there is no seal()/engine_version() convenience, because the
// compartment must never substitute its OWN version for the engine's.

use sha3::{Digest, Sha3_512};

use alloc::format;
use alloc::string::String;

use resolution_scope_types::ScoredAnalysis;

/// Versioned identifier for the seal scheme. Changing the canonical form MUST
/// bump this string, or old seals silently become unverifiable.
pub const SEAL_SCHEME: &str = "resolution-scope-sha3-512-v2";

/// Compute the hex-encoded SHA3-512 seal for a verdict produced by a SPECIFIC
/// engine version. Deterministic over (domain, the 8 dispositions, the 8
/// tri-states, resolver_identity, produced_by_version).
pub fn seal_versioned(analysis: &ScoredAnalysis, produced_by_version: &str) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(canonical_input(analysis, produced_by_version).as_bytes());
    hex(&hasher.finalize())
}

/// The exact bytes `seal_versioned` hashes. Byte-identical to the engine's
/// canonical_input — this is the single-producer contract made explicit.
pub fn canonical_input(analysis: &ScoredAnalysis, produced_by_version: &str) -> String {
    let mut s = String::with_capacity(384);
    s.push_str(SEAL_SCHEME);
    s.push('\n');
    s.push_str(&analysis.domain);
    s.push('\n');
    s.push_str(produced_by_version);
    s.push('\n');
    s.push_str(&analysis.resolver_identity);
    s.push('\n');

    // Fixed order — the canonical form's field order is load-bearing.
    s.push_str(&control_line(
        "dnssec",
        &analysis.dnssec_disposition,
        &analysis.dnssec_chain,
    ));
    s.push_str(&control_line(
        "spf",
        &analysis.spf_disposition,
        &analysis.spf,
    ));
    s.push_str(&control_line(
        "dkim",
        &analysis.dkim_disposition,
        &analysis.dkim,
    ));
    s.push_str(&control_line(
        "dmarc",
        &analysis.dmarc_disposition,
        &analysis.dmarc,
    ));
    s.push_str(&control_line(
        "dane",
        &analysis.dane_disposition,
        &analysis.dane,
    ));
    s.push_str(&control_line(
        "mta_sts",
        &analysis.mta_sts_disposition,
        &analysis.mta_sts,
    ));
    s.push_str(&control_line(
        "caa",
        &analysis.caa_disposition,
        &analysis.caa,
    ));
    s.push_str(&control_line(
        "cds",
        &analysis.cds_disposition,
        &analysis.cds_cdnskey,
    ));

    s
}

/// One control's canonical line: `name=disposition=tri\n` (Debug variant names).
fn control_line(
    name: &str,
    disposition: &dyn core::fmt::Debug,
    tri: &dyn core::fmt::Debug,
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
    use resolution_scope_types::ScoredAnalysis;
    use resolution_scope_types::TriState;

    /// The canonical fixture — the single producer (`crate::fixtures`), shared
    /// with the bin and the FFI tests. The golden seal pins it.
    fn fixture() -> ScoredAnalysis {
        crate::fixtures::demo_verdict()
    }

    /// The GOLDEN SEAL, computed from the ENGINE (`seal_versioned(&fixture(),
    /// "0.1.0")`) on 2026-08-22. This is the drift-pin: if either the engine
    /// renames a variant or this mirror drifts, this test fails. Version string
    /// is pinned to "0.1.0" (not the live CARGO_PKG_VERSION) so the test is
    /// version-independent — it pins the seal ALGORITHM, not the current version.
    #[test]
    fn seal_matches_engine_golden_value() {
        assert_eq!(
            seal_versioned(&fixture(), "0.1.0"),
            "9a0b7790ff865f24df52ae0449284809cd7f61c5d4ea267f292de8650adcdb2bfdee735e15d4a9bf7ea84052c5b3f6c49cbd0062e30c1f13d4f37ebd70203a35"
        );
    }

    #[test]
    fn canonical_input_is_byte_exact() {
        // The exact preimage the engine hashes. Byte-identity is load-bearing:
        // a seal scheme that drifts is a seal that lies.
        assert_eq!(
            canonical_input(&fixture(), "0.1.0"),
            "resolution-scope-sha3-512-v2\nexample.com\n0.1.0\ndefault\n\
             dnssec=SignedAndDelegated=Present\n\
             spf=SoftFail=Present\n\
             dkim=NotFoundDefaults=Absent\n\
             dmarc=Reject=Present\n\
             dane=NoMail=NotApplicable\n\
             mta_sts=Enforced=Present\n\
             caa=NotConfigured=Absent\n\
             cds=NotPublished=Absent\n"
        );
    }

    #[test]
    fn seal_is_sha3_512_hex() {
        let s = seal_versioned(&fixture(), "0.1.0");
        assert_eq!(s.len(), 128, "SHA3-512 is 64 bytes = 128 hex chars");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn seal_changes_when_a_verdict_flips() {
        let mut tampered = fixture();
        tampered.spf = TriState::Absent;
        assert_ne!(
            seal_versioned(&fixture(), "0.1.0"),
            seal_versioned(&tampered, "0.1.0")
        );
    }

    #[test]
    fn seal_ignores_run_metadata() {
        let mut rerun = fixture();
        rerun.session_id = 99_999;
        rerun.timestamp_local = 9_999_999_999;
        assert_eq!(
            seal_versioned(&fixture(), "0.1.0"),
            seal_versioned(&rerun, "0.1.0")
        );
    }
}
