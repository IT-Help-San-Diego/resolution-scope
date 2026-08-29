// =============================================================================
// seal — tamper-evidence for sealed verdicts
// =============================================================================
//
// A seal is a deterministic SHA3-512 digest of a measurement's *verdict
// content*. It is tamper-evidence, not a proof that a measurement occurred:
// anyone can recompute a valid seal over a fabricated verdict, so the seal
// alone cannot establish that a scan happened. What it DOES establish is
// that a verdict matches a published seal — if you hold the seal as a
// trusted value, recomputing it over a verdict confirms that verdict is the
// one that was sealed, and flags any alteration after sealing.
//
// The honest claim (the only one this module makes): "anyone can verify this
// verdict is the one that was sealed." It is NOT "anyone can verify this was
// measured." Overstating the seal as proof-of-measurement is the one thing this
// instrument must not do.
//
// This is the "structure-as-label" property from the Carrier Color deep-time
// doctrine — the verification is folded into the shape of the verdict itself,
// not attached as a separate claim. The seal IS the label.
//
// ── WHAT IS SEALED (the verdict + its observation conditions) ─────────────
//   * the domain under analysis
//   * the engine version (which verdict logic produced it)
//   * the resolver identity (which vantage measured it)
//   * every control's disposition (the *reason*) and tri-state (the *score*)
//
// ── WHAT IS NOT SEALED (run metadata) ─────────────────────────────────────
//   * session_id   — a per-run random, not part of the verdict
//   * timestamp    — wall-clock time, not part of the verdict
//
// The seal deliberately EXCLUDES run metadata so it is a pure function of the
// verdict: the same domain analysed by the same engine produces the same
// seal. A future reader re-derives it from the verdict alone — they do not
// need the original timestamp or session to check authenticity. That is the
// difference between a seal and a signature-of-a-run: a run identity is
// unique and unrecoverable; a verdict seal is reproducible and checkable
// forever.
//
// ── CANONICAL FORM (v2) ────────────────────────────────────────────────────
// The digested byte sequence is, in order, newline-terminated:
//
//   resolution-scope-sha3-512-v2
//   <domain>
//   <engine version>
//   <resolver identity>
//   dnssec=<disposition>=<tri>
//   spf=<disposition>=<tri>
//   dkim=<disposition>=<tri>
//   dmarc=<disposition>=<tri>
//   dane=<disposition>=<tri>
//   tlsa_zone=<variant>
//   mta_sts=<disposition>=<tri>
//   caa=<disposition>=<tri>
//   cds=<disposition>=<tri>
//
// Dispositions and tri-states are encoded as their Rust variant names (the
// enum's public, stable identity — renaming a verdict is a breaking change
// and correctly breaks the seal). A "2500-year" hardening would pin explicit
// integer discriminants per variant; v1 uses variant names, which are already
// part of the public API and unambiguous within a fieldless enum.
//
// `tlsa_zone` (added in v3) is a primary DNS measurement — the MX host's zone
// relationship to the scanned domain — not a disposition and not run metadata.
// It is sealed because two verdicts that differ only in *whose* MX host is
// involved (dhs.gov vs cia.gov, both dane=NotConfigured) mean different things
// and must not seal identically.
// =============================================================================

use sha3::{Digest, Sha3_512};

use crate::analysis::ScoredAnalysis;
use resolution_scope_types::SealSpelling;

/// Versioned identifier for the seal scheme. Changing the canonical form
/// (field set, order, encoding) MUST bump this string, or old seals silently
/// become unverifiable — a seal scheme that drifts is a seal that lies.
/// v2 added `resolver_identity` (the observer's vantage) to the input set.
/// v3 added `tlsa_zone` (the MX-host zone relationship — DANE attribution).
pub const SEAL_SCHEME: &str = "resolution-scope-sha3-512-v4";

/// The immediately prior scheme, retained so the store can RE-DERIVE rows
/// sealed before the v4 bump. v3→v4 changed the disposition token
/// VOCABULARY (the `+all` split added `PositiveAll`), not the byte layout —
/// the canonical form is identical and differs only in the scheme line, so
/// v3 rows re-derive exactly. Verification-only: new seals always bind
/// [`SEAL_SCHEME`].
pub const SEAL_SCHEME_V3: &str = "resolution-scope-sha3-512-v3";

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
    seal_versioned_under_scheme(analysis, produced_by_version, SEAL_SCHEME)
}

/// [`seal_versioned`] under an EXPLICIT scheme label — the re-derivation
/// entry point for rows sealed by a prior scheme whose canonical form this
/// build can still reproduce (today: [`SEAL_SCHEME_V3`]). Never a write
/// path: recording always seals under [`SEAL_SCHEME`].
pub fn seal_versioned_under_scheme(
    analysis: &ScoredAnalysis,
    produced_by_version: &str,
    scheme: &str,
) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(canonical_input_under_scheme(analysis, produced_by_version, scheme).as_bytes());
    hex(&hasher.finalize())
}

/// The exact bytes `seal_versioned` hashes — the seal's canonical input.
///
/// Exposed (rather than private) so the report can print the input beside the
/// seal and turn "anyone can re-check it" into a literal instruction: copy
/// these bytes, hash them with SHA3-512, and the hex digest is the seal. This
/// is single-producer — the report reads the SAME string the seal hashes, so
/// the two can never drift (the mirror defect: a report that re-derives from a
/// different encoding than the seal hashes is a second, hand-kept copy of the
/// canonical form, and it WILL fall out of sync).
///
/// The input carries each value's SEAL SPELLING (not the human labels) —
/// hand-pinned literals owned by resolution-scope-types::seal_spelling, today
/// identical to the Rust variant names: `SignedAndDelegated`, not "signed +
/// delegated — chain validates from the root". Deliberately NOT derived
/// `Debug` output (Rust disclaims its stability across compiler versions), so
/// no toolchain upgrade can orphan sealed history. A report that showed only
/// the human label would name the seal inputs without their values, which is
/// the same as omitting them.
pub fn canonical_input(analysis: &ScoredAnalysis, produced_by_version: &str) -> String {
    canonical_input_under_scheme(analysis, produced_by_version, SEAL_SCHEME)
}

/// [`canonical_input`] under an explicit scheme label. The scheme string is
/// the preimage's FIRST line; every re-derivable prior scheme shares the
/// rest of the builder byte-for-byte (a prior scheme whose field set or
/// encoding differed could NOT reuse this and would need its own builder).
fn canonical_input_under_scheme(
    analysis: &ScoredAnalysis,
    produced_by_version: &str,
    scheme: &str,
) -> String {
    let mut s = String::with_capacity(384);
    s.push_str(scheme);
    s.push('\n');
    s.push_str(&analysis.domain);
    s.push('\n');
    s.push_str(produced_by_version);
    s.push('\n');
    // The observer's vantage: two scans from different resolvers are
    // different measurements even if their verdicts coincide, so the seal
    // must bind the resolver identity too (observation-conditions rule).
    s.push_str(&analysis.resolver_identity);
    s.push('\n');

    // Fixed order — the canonical form's field order is load-bearing. A
    // reordered seal is a different seal, by design.
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
    // tlsa_zone is a primary measurement (the DANE attribution zone), sealed
    // as its own line — its variant NAME is the seal's stable identity, same
    // as every disposition. Not a control (no tri-state), so a bare
    // `tlsa_zone=<variant>` line, not the `name=disposition=tri` shape.
    s.push_str("tlsa_zone=");
    s.push_str(analysis.tlsa_zone.seal_spelling());
    s.push('\n');
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

/// The engine version that produced a verdict. Combines the crate version
/// (`CARGO_PKG_VERSION`, bare semver — `26.x.y`, no leading `v`) with the git
/// describe string from `build.rs`, so a seal names the exact build that
/// produced it. Falls back to a bare crate version when the git stamp is
/// absent/untracked (tarball build) — visibly distinct from a real commit,
/// never a silent default.
/// Public so the store can persist the producing version beside each verdict
/// (verification of old rows hashes the stored version, never the current).
pub fn engine_version() -> String {
    let pkg = env!("CARGO_PKG_VERSION");
    match option_env!("RESOLUTION_SCOPE_GIT_VERSION") {
        Some(git) if !git.is_empty() && git != "untracked" => format!("{pkg}-{git}"),
        _ => pkg.to_string(),
    }
}

/// One control's canonical line: `name=disposition=tri\n`.
///
/// Values are formatted through [`SealSpelling`] — hand-pinned literals in
/// resolution-scope-types — never through derived `Debug`, whose output Rust
/// officially disclaims as unstable across compiler versions (std::fmt::Debug
/// "Stability"). The switch was byte-identical (every golden held).
fn control_line(name: &str, disposition: &dyn SealSpelling, tri: &dyn SealSpelling) -> String {
    format!(
        "{name}={}={}\n",
        disposition.seal_spelling(),
        tri.seal_spelling()
    )
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
            resolver_identity: "default".to_string(),
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
            tlsa_zone: crate::analysis::TlsaZone::NoMxHost,
            mta_sts: TriState::Present,
            mta_sts_disposition: MtaStsDisposition::Enforced,
            caa: TriState::Absent,
            caa_disposition: CaaDisposition::NotConfigured,
            cds_cdnskey: TriState::Absent,
            cds_disposition: CdsDisposition::NotPublished,
        }
    }

    /// v4 known-answer: the ONLY byte-frozen pin in the suite. Every other
    /// seal test compares seal() to seal() and would pass unchanged through a
    /// silent canonical-form drift; this literal is what catches it. Minted
    /// BEFORE any v5 builder change — the ordering is load-bearing, because a
    /// pin minted after a mutation freezes the wrong bytes. When the v5 bump
    /// lands, re-target this at the frozen canonical_input_v4() builder; the
    /// literal itself must NEVER be re-pinned.
    #[test]
    fn v4_known_answer_seal_is_byte_frozen() {
        let s = seal_versioned(&baseline(), "0.0.0-kat");
        assert_eq!(
            s,
            "a5e47988770b3a62bdee9ff50a3068604eeddbc2186784c83129c819f161dd4d\
             bd35fee65b7e92a0625ea3c3f3cc69fd50f49914c30e6e343076e2b0aefc1b29"
        );
    }

    /// v3 companion to the v4 known-answer above, same freeze contract. The
    /// store's v3 re-derive arm (store/src/lib.rs seal dispatch) rides the
    /// SAME shared builder under the v3 label — valid only while v3/v4 are
    /// byte-identical — so at the v5 bump BOTH arms must re-target the frozen
    /// canonical_input_v4() (scheme-line parameterized) or stored v3 rows
    /// false-tamper exactly as v4 rows would. Never re-pin this literal.
    #[test]
    fn v3_known_answer_seal_is_byte_frozen() {
        let s = seal_versioned_under_scheme(&baseline(), "0.0.0-kat", SEAL_SCHEME_V3);
        assert_eq!(
            s,
            "20745a96ae762f15146184233c64149fad3a09415e1b6014990b3168f7ac2e97\
             92fa6b1418ab259908f515f863ee0d7ace22685ab8a957006e1f438621dbd26d"
        );
    }

    #[test]
    fn seal_is_deterministic() {
        assert_eq!(seal(&baseline()), seal(&baseline()));
    }

    #[test]
    fn canonical_input_is_the_seals_exact_preimage() {
        // The re-derivation contract that makes the report's "re-derive the
        // seal" block honest: hashing canonical_input yields EXACTLY the seal.
        // This also pins the refactor — seal_versioned now hashes
        // canonical_input, so if the extraction had reordered or dropped a
        // field, this test (and every existing value-sensitive call site)
        // would catch it. Byte-identity is load-bearing: a seal scheme that
        // drifts is a seal that lies.
        let mut hasher = Sha3_512::new();
        hasher.update(canonical_input(&baseline(), "0.1.0").as_bytes());
        assert_eq!(
            hex(&hasher.finalize()),
            seal_versioned(&baseline(), "0.1.0"),
            "hashing canonical_input must equal the seal — the report re-derivation block and the seal hash the same bytes"
        );
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
        // session_id and timestamp are run metadata, not verdict — a future
        // reader must be able to re-derive the seal without knowing them.
        let mut rerun = baseline();
        rerun.session_id = 99_999;
        rerun.timestamp_local = 9_999_999_999;
        assert_eq!(seal(&baseline()), seal(&rerun));
    }

    #[test]
    fn seal_changes_when_resolver_identity_changes() {
        // The observation-conditions rule: the same verdict measured from a
        // different resolver is a different measurement. The seal must bind
        // the vantage, or two scans from different resolvers would seal
        // identically and be conflated.
        let mut other = baseline();
        other.resolver_identity = "google".to_string();
        assert_ne!(seal(&baseline()), seal(&other));
    }

    #[test]
    fn seal_changes_when_tlsa_zone_changes() {
        // The negative proof from the DANE ruling (§7): two domains can both
        // read dane=NotConfigured while one hosts its own MX (its gap) and the
        // other points at a third-party operator (the operator's gap). The
        // attribution must be sealed, or dhs.gov and cia.gov seal
        // byte-identically while meaning opposite things.
        let mut foreign = baseline();
        foreign.dane_disposition = DaneDisposition::NotConfigured;
        foreign.dane = TriState::Absent;
        foreign.tlsa_zone = crate::analysis::TlsaZone::ForeignZone;
        let mut own = foreign.clone(); // same verdict, different attribution
        own.tlsa_zone = crate::analysis::TlsaZone::SameZone;
        assert_ne!(seal(&foreign), seal(&own));
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
