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
// ── CANONICAL FORM (v5) ────────────────────────────────────────────────────
// The digested byte sequence is, in order, newline-terminated:
//
//   resolution-scope-sha3-512-v5
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
//   tls_rpt=<disposition>=<tri>
//   csync=<disposition>=<tri>
//
// v3/v4 rows remain verifiable through a frozen builder that ends at CDS. The
// current v5 builder derives control lines from truth_chain()/ControlId::ALL,
// so adding a control creates one producer to satisfy instead of two lists to
// remember.
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
use crate::denial_proof::control_key;
use crate::truth_chain::{truth_chain, ControlId, ControlReport};
use resolution_scope_types::SealSpelling;

/// Versioned identifier for the seal scheme. Changing the canonical form
/// (field set, order, encoding) MUST bump this string, or old seals silently
/// become unverifiable — a seal scheme that drifts is a seal that lies.
/// v2 added `resolver_identity` (the observer's vantage) to the input set.
/// v3 added `tlsa_zone` (the MX-host zone relationship — DANE attribution).
/// v4 (retained as SEAL_SCHEME_V4) bound exactly the founding eight controls.
/// v5 binds the current truth_chain()/ControlId::ALL control set by construction.
pub const SEAL_SCHEME: &str = "resolution-scope-sha3-512-v5";

/// The immediately prior scheme, retained so the store can RE-DERIVE rows
/// sealed before the v4 bump. v3→v4 changed the disposition token
/// VOCABULARY (the `+all` split added `PositiveAll`), not the byte layout —
/// the canonical form is identical and differs only in the scheme line, so
/// v3 rows re-derive exactly. Verification-only: new seals always bind
/// [`SEAL_SCHEME`].
pub const SEAL_SCHEME_V4: &str = "resolution-scope-sha3-512-v4";
pub const SEAL_SCHEME_V3: &str = "resolution-scope-sha3-512-v3";

/// Compute the hex-encoded SHA3-512 seal of a measurement's verdict content.
///
/// Deterministic: identical truth-chain verdict fields (domain + the
/// current control dispositions/tri-states) yield the identical seal, regardless of
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
/// v3/v4 dispatch to the frozen eight-control builder. The current v5 builder
/// derives its control lines from truth_chain(), the single control producer.
fn canonical_input_under_scheme(
    analysis: &ScoredAnalysis,
    produced_by_version: &str,
    scheme: &str,
) -> String {
    match scheme {
        SEAL_SCHEME_V3 | SEAL_SCHEME_V4 => {
            canonical_input_v4(analysis, produced_by_version, scheme)
        }
        _ => canonical_input_v5(analysis, produced_by_version, scheme),
    }
}

/// Frozen v3/v4 builder for already-published seals: exactly the founding eight
/// controls plus TLSA-zone attribution, never TLS-RPT/CSYNC.
fn canonical_input_v4(
    analysis: &ScoredAnalysis,
    produced_by_version: &str,
    scheme: &str,
) -> String {
    let mut s = preimage_header(analysis, produced_by_version, scheme);
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

/// Current builder: one producer for control enumeration. Adding a ControlId now
/// forces truth_chain() to compile and the seal follows it by construction.
fn canonical_input_v5(
    analysis: &ScoredAnalysis,
    produced_by_version: &str,
    scheme: &str,
) -> String {
    let mut s = preimage_header(analysis, produced_by_version, scheme);
    for report in truth_chain(analysis) {
        s.push_str(&control_report_line(report));
        if report.control == ControlId::Dane {
            s.push_str("tlsa_zone=");
            s.push_str(analysis.tlsa_zone.seal_spelling());
            s.push('\n');
        }
    }
    s
}

fn preimage_header(analysis: &ScoredAnalysis, produced_by_version: &str, scheme: &str) -> String {
    let mut s = String::with_capacity(512);
    s.push_str(scheme);
    s.push('\n');
    s.push_str(&analysis.domain);
    s.push('\n');
    s.push_str(produced_by_version);
    s.push('\n');
    s.push_str(&analysis.resolver_identity);
    s.push('\n');
    s
}

fn control_report_line(report: ControlReport) -> String {
    format!(
        "{}={}={}\n",
        control_key(report.control),
        report.seal_disposition,
        report.tri.seal_spelling()
    )
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
    compose_engine_version(
        env!("CARGO_PKG_VERSION"),
        option_env!("RESOLUTION_SCOPE_GIT_VERSION"),
    )
}

/// Pure combinator behind [`engine_version`], factored so the fallback rules
/// are testable: `option_env!` is compile-time, so the three git-stamp cases
/// (absent / empty / "untracked") could never be exercised through the public
/// fn — mutation testing found every mutant here surviving (2026-08-29).
///
/// TAG CASE (2026-09-05, alpha.4 release): `git describe --always --dirty
/// --tags` run at an exact tag checkout returns the TAG NAME itself (e.g.
/// "v26.0.0-alpha.4"), not the usual "tag-N-g<hash>" shape. Concatenating
/// that onto the manifest version produced "26.0.0-alpha.4-v26.0.0-alpha.4"
/// on every release build — measured live on the published alpha.4 binary.
/// The stamp is NORMALIZED: leading "v" stripped, and when the result equals
/// the pkg version the stamp ADDS NOTHING (the manifest already carries the
/// tag's semver — Cargo.toml and the tag are bumped in the same release PR),
/// so the version is the bare pkg. Anything else (dirty suffix, hash, older
/// tag) still concatenates — those carry information the manifest lacks.
fn compose_engine_version(pkg: &str, git: Option<&str>) -> String {
    match git {
        Some(git) if !git.is_empty() && git != "untracked" => {
            let stamp = git.strip_prefix('v').unwrap_or(git);
            if stamp == pkg {
                pkg.to_string()
            } else {
                format!("{pkg}-{stamp}")
            }
        }
        // POSITIVELY distinct, not distinct-by-absence. build.rs computes
        // the literal "untracked" precisely so a tarball or vendored build
        // announces itself, and this arm used to throw that away and return
        // the bare version. That was harmless only while every git build
        // carried a suffix; once tag stamps collapse to the bare semver, a
        // tagged RELEASE build and a no-git build stamp the same string and
        // therefore seal identically. Measured on main before this change.
        _ => format!("{pkg}-untracked"),
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
        CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
        DmarcDisposition, MtaStsDisposition, ScoredAnalysis, SpfDisposition, TlsRptDisposition,
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
            tls_rpt: TriState::Absent,
            tls_rpt_disposition: TlsRptDisposition::RecordAbsent,
            csync: TriState::Absent,
            csync_disposition: CsyncDisposition::RecordAbsent,
        }
    }

    /// v4 known-answer for already-published rows: frozen eight-control builder.
    /// This literal is never re-pinned; v5 gets its own current-scheme KAT.
    #[test]
    fn v4_known_answer_seal_is_byte_frozen() {
        let s = seal_versioned_under_scheme(&baseline(), "0.0.0-kat", SEAL_SCHEME_V4);
        assert_eq!(
            s,
            "a5e47988770b3a62bdee9ff50a3068604eeddbc2186784c83129c819f161dd4d\
             bd35fee65b7e92a0625ea3c3f3cc69fd50f49914c30e6e343076e2b0aefc1b29"
        );
    }

    /// Pins the version-string fallback rules mutation testing found
    /// entirely unguarded: a build where the git stamp is empty or
    /// "untracked" must fall back to a POSITIVELY distinct marker,
    /// `<version>-untracked` — "visibly distinct, never a silent default",
    /// the fn's own doc, which the bare version stopped satisfying once tag
    /// stamps began collapsing to that same bare version.
    #[test]
    fn engine_version_fallback_rules_are_pinned() {
        assert_eq!(
            compose_engine_version("26.0.0", Some("g1234abc")),
            "26.0.0-g1234abc"
        );
        // TAG-SHAPE stamps (release builds at an exact tag): the tag name
        // equals the manifest semver, so concatenating duplicated it —
        // "26.0.0-alpha.4-v26.0.0-alpha.4" measured live on the published
        // alpha.4 binary. The tag stamp must collapse to the bare version.
        assert_eq!(
            compose_engine_version("26.0.0-alpha.4", Some("v26.0.0-alpha.4")),
            "26.0.0-alpha.4"
        );
        // ...but stamps that carry MORE than the tag (dirty builds, off-tag
        // hashes) still concatenate — provenance is additive there.
        assert_eq!(
            compose_engine_version("26.0.0-alpha.4", Some("v26.0.0-alpha.4-dirty")),
            "26.0.0-alpha.4-26.0.0-alpha.4-dirty"
        );
        assert_eq!(
            compose_engine_version("26.0.0-alpha.4", Some("v26.0.0-alpha.3-5-gabc1234")),
            "26.0.0-alpha.4-26.0.0-alpha.3-5-gabc1234"
        );
        assert_eq!(
            compose_engine_version("26.0.0", Some("")),
            "26.0.0-untracked"
        );
        assert_eq!(
            compose_engine_version("26.0.0", Some("untracked")),
            "26.0.0-untracked"
        );
        assert_eq!(compose_engine_version("26.0.0", None), "26.0.0-untracked");
        // And the public fn actually routes through the combinator with the
        // real crate version — a body replaced by String::new() fails here.
        assert!(engine_version().starts_with(env!("CARGO_PKG_VERSION")));
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
    fn v5_seal_membership_follows_truth_chain_order() {
        let input = canonical_input(&baseline(), "0.0.0-kat");
        let controls: Vec<&str> = input
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name))
            .filter(|name| *name != "tlsa_zone")
            .collect();
        assert_eq!(
            controls,
            [
                "dnssec", "spf", "dkim", "dmarc", "dane", "mta_sts", "caa", "cds", "tls_rpt",
                "csync",
            ],
            "v5 seal membership must follow truth_chain()/ControlId::ALL order"
        );
    }

    #[test]
    fn v4_seal_membership_is_the_frozen_original_eight_controls() {
        let input = canonical_input_under_scheme(&baseline(), "0.0.0-kat", SEAL_SCHEME_V4);
        let controls: Vec<&str> = input
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name))
            .filter(|name| *name != "tlsa_zone")
            .collect();
        assert_eq!(
            controls,
            ["dnssec", "spf", "dkim", "dmarc", "dane", "mta_sts", "caa", "cds"],
            "v4 remains the frozen already-published eight-control preimage"
        );
        assert!(!input.contains("tls_rpt="));
        assert!(!input.contains("csync="));
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
        // Flip exactly one verdict producer. v5 seals truth_chain() output, so
        // the disposition is the source and the tri-state is derived from it.
        tampered.dnssec_disposition = crate::analysis::DnssecDisposition::Unsigned;
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
    fn seal_changes_when_csync_gate_fires() {
        // RecordAbsent (a signed zone's standing state) and DnssecRequired
        // (structurally inapplicable on an unsigned zone) mean different
        // things and must not seal byte-identically — the same negative
        // proof as tlsa_zone above (policy/RULING_csync_20260901.md).
        let mut absent = baseline();
        absent.csync_disposition = CsyncDisposition::RecordAbsent;
        absent.csync = TriState::Absent;
        let mut inapplicable = absent.clone();
        inapplicable.csync_disposition = CsyncDisposition::DnssecRequired;
        inapplicable.csync = TriState::NotApplicable;
        assert_ne!(seal(&absent), seal(&inapplicable));
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

    /// Current-scheme known-answer (v5 KAT, punch-list F1). Minted by
    /// EXECUTION at c436ba1+ (the seal of `baseline()` under SEAL_SCHEME
    /// with produced_by_version "0.0.0-kat"), never derived by hand. This
    /// literal is the byte-pin: an ALL-reorder, an emission-order change,
    /// a header drift, or a SealSpelling change rewrites v5 preimages
    /// test-green unless this exists — the exact blindness the KAT
    /// doctrine kills, closed on the new scheme's birthday. Re-pin ONLY
    /// on a deliberate scheme change (which bumps SEAL_SCHEME and mints
    /// a new KAT alongside).
    #[test]
    fn v5_known_answer_seal_is_byte_frozen() {
        let s = seal_versioned_under_scheme(&baseline(), "0.0.0-kat", SEAL_SCHEME);
        assert_eq!(
            s,
            "50470d7119da23afc4b794c71ef6f084294a9df1fee03b71078b91f45fcbba7ad\
             ee40b3a4265ae661d5ab1c1af617d0e417d70db7e6f276297ca6891a73608c6"
        );
    }
    // throwaway probe 2: full v5 preimage to /tmp for the native golden.
    #[test]
    fn probe_native_golden_v5_full() {
        let mut f = baseline();
        f.spf_disposition = crate::analysis::SpfDisposition::SoftFail;
        f.mta_sts_disposition = crate::analysis::MtaStsDisposition::Enforced;
        f.dkim_disposition = crate::analysis::DkimDisposition::NotFoundDefaults;
        std::fs::write(
            "/tmp/v5_native_preimage.txt",
            canonical_input_under_scheme(&f, "0.1.0", SEAL_SCHEME),
        )
        .expect("write probe file");
    }

    /// PROVENANCE DISTINCTNESS. build.rs opens by promising the no-git case
    /// falls back to "a VISIBLY-distinct marker (never a silent default)", and
    /// its first line states the property that matters: "two builds emitting
    /// different verdicts must stamp different versions". This string is
    /// hashed into every seal — `seal()` passes `engine_version()` to
    /// `seal_versioned`, which puts it on line 3 of the preimage — so two
    /// build contexts sharing a version string share a seal.
    ///
    /// Before the tag-collapse fix that promise held only by accident: every
    /// git build carried a suffix, so a bare version meant no-git and nothing
    /// else. Collapsing the tag stamp gave the tagged RELEASE build a bare
    /// version too, and an engine built from a modified tarball — where there
    /// is no git to detect dirtiness — became indistinguishable from the
    /// official release.
    #[test]
    fn tag_build_and_no_git_build_stamp_different_versions() {
        let tag = compose_engine_version("26.0.0-alpha.4", Some("v26.0.0-alpha.4"));
        let untracked = compose_engine_version("26.0.0-alpha.4", Some("untracked"));
        let absent = compose_engine_version("26.0.0-alpha.4", None);
        let empty = compose_engine_version("26.0.0-alpha.4", Some(""));
        assert_eq!(tag, "26.0.0-alpha.4", "a tag build stamps the bare semver");
        for (label, got) in [
            ("untracked", &untracked),
            ("absent", &absent),
            ("empty", &empty),
        ] {
            assert_ne!(
                &tag, got,
                "a {label} build stamps the same version as a TAGGED RELEASE build, \
                 so both produce the same seal — build.rs promises a visibly-distinct marker"
            );
        }
    }
}
