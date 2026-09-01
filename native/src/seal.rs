// seal.rs — verdict seal (no_std MIRROR of engine/src/seal.rs)
//
// The seal is the load-bearing contract of the Option-B compartment: the store
// re-derives SHA3-512 over the verdict's canonical input and compares it to the
// seal that crossed the boundary, which is tamper-evidence that the verdict
// was not altered after measurement.
//
// BYTE-IDENTITY IS LOAD-BEARING. The canonical form (field order, encoding,
// SealSpelling of every enum value) must match the engine byte-for-byte, or a
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

use resolution_scope_types::{ScoredAnalysis, SealSpelling};

/// Versioned identifier for the seal scheme. Changing the canonical form MUST
/// bump this string, or old seals silently become unverifiable. Bumped to v5
/// in lockstep with the engine (PR #36 punch list, F2): v5 seals the
/// ten-control book (TLS-RPT + CSYNC joined), v3/v4 remain re-derivable
/// through the engine's frozen builders. This mirror must NEVER drift from
/// the engine's current scheme — the cross-impl drift pin (golden below)
/// enforces it bytewise.
pub const SEAL_SCHEME: &str = "resolution-scope-sha3-512-v5";

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
/// One control's canonical line: `name=disposition=tri\n` — the v5 form
/// seals the CONSTRUCTOR-DERIVED tri (`Disposition::chain()` from types/,
/// the same producer every engine constructor sets as `report.tri`), never
/// the raw ScoredAnalysis field. A macro, not a generic fn: `chain()` is an
/// inherent method on each disposition enum, so each call site expands with
/// its concrete type — no trait indirection, no vtable, no_std-friendly.
macro_rules! control_line {
    ($name:literal, $d:expr) => {{
        let name = $name;
        format!(
            "{name}={}={}\n",
            $d.seal_spelling(),
            $d.chain().seal_spelling()
        )
    }};
}

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
    // v5: every control line seals the CONSTRUCTOR-DERIVED tri
    // (Disposition::chain(), the model-boundary collapse in types/) —
    // never the raw ScoredAnalysis field. This is the v5 semantic
    // (single producer through the constructors, same as the engine's
    // canonical_input_v5 which iterates truth_chain()), and it is the
    // cross-impl drift pin's job to hold: any divergence between this
    // mirror and the engine's emission fails the golden below.
    s.push_str(&control_line!("dnssec", &analysis.dnssec_disposition));
    s.push_str(&control_line!("spf", &analysis.spf_disposition));
    s.push_str(&control_line!("dkim", &analysis.dkim_disposition));
    s.push_str(&control_line!("dmarc", &analysis.dmarc_disposition));
    s.push_str(&control_line!("dane", &analysis.dane_disposition));
    // tlsa_zone is a primary measurement (DANE attribution zone), sealed as its
    // own `tlsa_zone=<variant>` line (SealSpelling, same as every disposition).
    // Byte-identical to the engine.
    s.push_str("tlsa_zone=");
    s.push_str(analysis.tlsa_zone.seal_spelling());
    s.push('\n');
    s.push_str(&control_line!("mta_sts", &analysis.mta_sts_disposition));
    s.push_str(&control_line!("caa", &analysis.caa_disposition));
    s.push_str(&control_line!("cds", &analysis.cds_disposition));
    // v5: the ten-control book — TLS-RPT and CSYNC are sealed (PR #36).
    // Order matches the engine's canonical_input_v5 exactly (truth_chain
    // order with the tlsa_zone interleave preserved after dane); the golden
    // tests below pin the whole preimage bytewise against the engine.
    s.push_str(&control_line!("tls_rpt", &analysis.tls_rpt_disposition));
    s.push_str(&control_line!("csync", &analysis.csync_disposition));

    s
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
    /// "0.1.0")`) on 2026-08-31, at the v5 bump (PR #36 punch list, F2 —
    /// the engine's own v5 KAT is `seal::tests::v5_known_answer_seal_is_
    /// byte_frozen`). This is the drift-pin: if either the engine renames a
    /// variant or this mirror drifts, this test fails. Version string is
    /// pinned to "0.1.0" (not the live CARGO_PKG_VERSION) so the test is
    /// version-independent — it pins the seal ALGORITHM, not the current
    /// version. Re-pinned at v5 from engine execution; the preimage golden
    /// below pins the ten-control line order bytewise.
    #[test]
    fn seal_matches_engine_golden_value() {
        assert_eq!(
            seal_versioned(&fixture(), "0.1.0"),
            "7d8bfc5e70552edcca1ab688f6eab7b724461ca303ee36f22f16ca195717d682\
             3d839e7d41de335a1ddb3ab60774fe847758ba3fe729d21ac23a0566b7d8ad90"
        );
    }

    #[test]
    fn canonical_input_is_byte_exact() {
        // The exact preimage the engine hashes. Byte-identity is load-bearing:
        // a seal scheme that drifts is a seal that lies. Re-pinned at v5:
        // tls_rpt and csync are sealed controls now (ten-control book), in
        // truth_chain order with the tlsa_zone interleave preserved.
        assert_eq!(
            canonical_input(&fixture(), "0.1.0"),
            "resolution-scope-sha3-512-v5\nexample.com\n0.1.0\ndefault\n\
             dnssec=SignedAndDelegated=Present\n\
             spf=SoftFail=Present\n\
             dkim=NotFoundDefaults=Indet\n\
             dmarc=Reject=Present\n\
             dane=NoMail=NotApplicable\n\
             tlsa_zone=NoMxHost\n\
             mta_sts=Enforced=Present\n\
             caa=NotConfigured=Absent\n\
             cds=NotPublished=Absent\n\
             tls_rpt=RecordAbsent=Absent\n\
             csync=RecordAbsent=Absent\n"
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
        // v5 semantic (mirror of the engine's canonical_input_v5): the seal
        // covers the dispositions (constructor-derived tri via chain()),
        // not the raw tri fields — flipping the raw field is NOT a verdict
        // change, flipping the DISPOSITION is. Tampering the raw field
        // without the disposition is exactly the drift this v5 form makes
        // inert by construction: the sealed claim is the measured
        // disposition, and the field is a presentation copy.
        let mut tampered = fixture();
        tampered.spf = TriState::Absent; // raw-field flip: NOT sealed (inert)
        assert_eq!(
            seal_versioned(&fixture(), "0.1.0"),
            seal_versioned(&tampered, "0.1.0"),
            "v5 seals the disposition, not the raw tri field"
        );
        let mut flipped = fixture();
        flipped.spf_disposition = resolution_scope_types::SpfDisposition::HardFail;
        assert_ne!(
            seal_versioned(&fixture(), "0.1.0"),
            seal_versioned(&flipped, "0.1.0"),
            "a disposition flip IS a verdict change and must move the seal"
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
