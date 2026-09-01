// seal_spelling.rs — the seal's OWN spelling of every sealed enum value.
//
// WHY THIS EXISTS: the seal preimage used to format these values with the
// derived `Debug` impl (`{:?}`). Rust's std documentation disclaims that
// surface explicitly (std::fmt::Debug, "Stability"): "Derived Debug formats
// are not stable, and so may change with future Rust versions." A seal whose
// bytes rest on a compiler non-guarantee is a seal that can be orphaned by a
// toolchain upgrade — not by the data changing, but by the formatter.
//
// So the spellings are HAND-PINNED literals, one per variant, owned here and
// nowhere else. Today every spelling equals its Rust variant name — the
// switch from Debug was byte-identical, proven by every seal golden staying
// green. The literals are deliberately NOT `stringify!(variant)`: a variant
// rename must consciously edit the literal (and the pin test below), making
// the seal impact visible in the diff instead of silently following the
// identifier. Renaming a SPELLING is a seal-scheme event: it changes the
// preimage, so it requires a SEAL_SCHEME bump and a prior-scheme arm carrying
// the old spelling (see engine/src/seal.rs and the 2026-08-25 ledger entry on
// the serde-alias experiment — serde aliases fix JSON parsing only and never
// reach this path).
//
// SEAL-LOAD-BEARING: every string in this file is hashed into seals.

use crate::dispositions::{
    CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
    DmarcDisposition, DnssecDisposition, MtaStsDisposition, SpfDisposition, TlsRptDisposition,
    TlsaZone,
};
use crate::tristate::TriState;

/// The exact bytes the seal preimage carries for this value.
///
/// Object-safe and `no_std`. Implemented only for types that appear in the
/// canonical input; a type without an impl cannot be sealed, by construction.
pub trait SealSpelling {
    /// The pinned preimage spelling — stable across compiler versions and
    /// variant renames, changing only with a deliberate seal-scheme bump.
    fn seal_spelling(&self) -> &'static str;
}

// SEAL-LOAD-BEARING: changing any string below changes every future preimage.
impl SealSpelling for TriState {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::Present => "Present",
            Self::Absent => "Absent",
            Self::Indet => "Indet",
            Self::NotApplicable => "NotApplicable",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for DnssecDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::SignedAndDelegated => "SignedAndDelegated",
            Self::SignedNotDelegated => "SignedNotDelegated",
            Self::BrokenChain => "BrokenChain",
            Self::ChainUnverified => "ChainUnverified",
            Self::Unsigned => "Unsigned",
            Self::NoZone => "NoZone",
            Self::Unreachable => "Unreachable",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for SpfDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::HardFail => "HardFail",
            Self::SoftFail => "SoftFail",
            Self::OtherPolicy => "OtherPolicy",
            Self::PositiveAll => "PositiveAll",
            Self::NotConfigured => "NotConfigured",
            Self::NoMail => "NoMail",
            Self::TransientError => "TransientError",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for DkimDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::Verified => "Verified",
            Self::NotFoundDefaults => "NotFoundDefaults",
            Self::NotProbed => "NotProbed",
            Self::NoMailDomain => "NoMailDomain",
            Self::TransientError => "TransientError",
            Self::KeyMismatch => "KeyMismatch",
            Self::Revoked => "Revoked",
            Self::Wildcard => "Wildcard",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for DmarcDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::Reject => "Reject",
            Self::Quarantine => "Quarantine",
            Self::Monitor => "Monitor",
            Self::InvalidPolicy => "InvalidPolicy",
            Self::NotConfigured => "NotConfigured",
            Self::NoMail => "NoMail",
            Self::TransientError => "TransientError",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for DaneDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::TlsaPublished => "TlsaPublished",
            Self::Verified => "Verified",
            Self::Mismatch => "Mismatch",
            Self::NotConfigured => "NotConfigured",
            Self::NoMx => "NoMx",
            Self::NoMail => "NoMail",
            Self::TransientError => "TransientError",
            Self::DnssecRequired => "DnssecRequired",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for MtaStsDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::Enforced => "Enforced",
            Self::RecordAbsent => "RecordAbsent",
            Self::NoZone => "NoZone",
            Self::TransientError => "TransientError",
            Self::NotEnforced => "NotEnforced",
            Self::PolicyInvalid => "PolicyInvalid",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for CaaDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::FullyRestricted => "FullyRestricted",
            Self::Configured => "Configured",
            Self::WildcardFullyRestricted => "WildcardFullyRestricted",
            Self::NotConfigured => "NotConfigured",
            Self::NoZone => "NoZone",
            Self::TransientError => "TransientError",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for CdsDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::Published => "Published",
            Self::DeletionRequested => "DeletionRequested",
            Self::NotPublished => "NotPublished",
            Self::NoZone => "NoZone",
            Self::TransientError => "TransientError",
        }
    }
}

// SEAL-LOAD-BEARING.
impl SealSpelling for TlsaZone {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::SameZone => "SameZone",
            Self::DescendantZone => "DescendantZone",
            Self::ForeignZone => "ForeignZone",
            Self::ZoneUnmeasured => "ZoneUnmeasured",
            Self::NoMxHost => "NoMxHost",
        }
    }
}

impl SealSpelling for TlsRptDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::Published => "Published",
            Self::RecordAbsent => "RecordAbsent",
            Self::NoZone => "NoZone",
            Self::TransientError => "TransientError",
            Self::PolicyInvalid => "PolicyInvalid",
        }
    }
}

impl SealSpelling for CsyncDisposition {
    fn seal_spelling(&self) -> &'static str {
        match self {
            Self::Published => "Published",
            Self::RecordAbsent => "RecordAbsent",
            Self::NoZone => "NoZone",
            Self::TransientError => "TransientError",
            Self::PolicyInvalid => "PolicyInvalid",
            Self::DnssecRequired => "DnssecRequired",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    /// Every seal spelling is pinned to its literal AND — for the transition
    /// era — shown byte-identical to the derived Debug output the seal used
    /// to hash. The literal assertions are the contract; the Debug half is
    /// the historical byte-identity proof and may be dropped if a future
    /// rustc ever changes derived Debug (the literals, not Debug, are the
    /// seal).
    #[test]
    fn seal_spellings_are_pinned_and_match_the_historical_debug_bytes() {
        fn check<T: SealSpelling + core::fmt::Debug>(v: T, pin: &str) {
            assert_eq!(v.seal_spelling(), pin);
            assert_eq!(format!("{v:?}"), pin, "historical Debug byte-identity");
        }
        check(TriState::Present, "Present");
        check(TriState::Absent, "Absent");
        check(TriState::Indet, "Indet");
        check(TriState::NotApplicable, "NotApplicable");
        check(DnssecDisposition::SignedAndDelegated, "SignedAndDelegated");
        check(DnssecDisposition::SignedNotDelegated, "SignedNotDelegated");
        check(DnssecDisposition::BrokenChain, "BrokenChain");
        check(DnssecDisposition::ChainUnverified, "ChainUnverified");
        check(DnssecDisposition::Unsigned, "Unsigned");
        check(DnssecDisposition::NoZone, "NoZone");
        check(DnssecDisposition::Unreachable, "Unreachable");
        check(SpfDisposition::HardFail, "HardFail");
        check(SpfDisposition::SoftFail, "SoftFail");
        check(SpfDisposition::OtherPolicy, "OtherPolicy");
        check(SpfDisposition::PositiveAll, "PositiveAll");
        check(SpfDisposition::NotConfigured, "NotConfigured");
        check(SpfDisposition::NoMail, "NoMail");
        check(SpfDisposition::TransientError, "TransientError");
        check(DkimDisposition::Verified, "Verified");
        check(DkimDisposition::NotFoundDefaults, "NotFoundDefaults");
        check(DkimDisposition::NotProbed, "NotProbed");
        check(DkimDisposition::NoMailDomain, "NoMailDomain");
        check(DkimDisposition::TransientError, "TransientError");
        check(DkimDisposition::KeyMismatch, "KeyMismatch");
        check(DkimDisposition::Revoked, "Revoked");
        check(DkimDisposition::Wildcard, "Wildcard");
        check(DmarcDisposition::Reject, "Reject");
        check(DmarcDisposition::Quarantine, "Quarantine");
        check(DmarcDisposition::Monitor, "Monitor");
        check(DmarcDisposition::InvalidPolicy, "InvalidPolicy");
        check(DmarcDisposition::NotConfigured, "NotConfigured");
        check(DmarcDisposition::NoMail, "NoMail");
        check(DmarcDisposition::TransientError, "TransientError");
        check(DaneDisposition::TlsaPublished, "TlsaPublished");
        check(DaneDisposition::Verified, "Verified");
        check(DaneDisposition::Mismatch, "Mismatch");
        check(DaneDisposition::NotConfigured, "NotConfigured");
        check(DaneDisposition::NoMx, "NoMx");
        check(DaneDisposition::NoMail, "NoMail");
        check(DaneDisposition::TransientError, "TransientError");
        check(DaneDisposition::DnssecRequired, "DnssecRequired");
        check(MtaStsDisposition::Enforced, "Enforced");
        check(MtaStsDisposition::RecordAbsent, "RecordAbsent");
        check(MtaStsDisposition::NoZone, "NoZone");
        check(MtaStsDisposition::TransientError, "TransientError");
        check(MtaStsDisposition::NotEnforced, "NotEnforced");
        check(MtaStsDisposition::PolicyInvalid, "PolicyInvalid");
        check(CaaDisposition::FullyRestricted, "FullyRestricted");
        check(CaaDisposition::Configured, "Configured");
        check(
            CaaDisposition::WildcardFullyRestricted,
            "WildcardFullyRestricted",
        );
        check(CaaDisposition::NotConfigured, "NotConfigured");
        check(CaaDisposition::NoZone, "NoZone");
        check(CaaDisposition::TransientError, "TransientError");
        check(CdsDisposition::Published, "Published");
        check(CdsDisposition::DeletionRequested, "DeletionRequested");
        check(CdsDisposition::NotPublished, "NotPublished");
        check(CdsDisposition::NoZone, "NoZone");
        check(CdsDisposition::TransientError, "TransientError");
        check(TlsRptDisposition::Published, "Published");
        check(TlsRptDisposition::RecordAbsent, "RecordAbsent");
        check(TlsRptDisposition::NoZone, "NoZone");
        check(TlsRptDisposition::TransientError, "TransientError");
        check(TlsRptDisposition::PolicyInvalid, "PolicyInvalid");
        check(CsyncDisposition::Published, "Published");
        check(CsyncDisposition::RecordAbsent, "RecordAbsent");
        check(CsyncDisposition::NoZone, "NoZone");
        check(CsyncDisposition::TransientError, "TransientError");
        check(CsyncDisposition::PolicyInvalid, "PolicyInvalid");
        check(CsyncDisposition::DnssecRequired, "DnssecRequired");
        check(TlsaZone::SameZone, "SameZone");
        check(TlsaZone::DescendantZone, "DescendantZone");
        check(TlsaZone::ForeignZone, "ForeignZone");
        check(TlsaZone::ZoneUnmeasured, "ZoneUnmeasured");
        check(TlsaZone::NoMxHost, "NoMxHost");
    }

    /// The OTHER half of the spelling contract (Science's directive,
    /// 2026-08-25): `SealSpelling` pins what is EMITTED — this pins what is
    /// ACCEPTED. Serde must accept exactly the seal spelling and nothing
    /// else: a `#[serde(alias)]` or `rename_all` would silently widen the
    /// accepted set, and a deserialize-then-reserialize pass would then
    /// normalize old spellings under an unchanged seal (the recorded
    /// alias-normalization hazard, store/src/lib.rs beside record_scan).
    /// Three checks per variant: serde output == seal_spelling; the spelling
    /// roundtrips; case-mangled forms (lower/UPPER/camel/snake) all reject.
    #[test]
    fn serde_accepts_exactly_the_seal_spellings() {
        use alloc::string::String;

        fn camel(s: &str) -> String {
            let mut c = s.chars();
            match c.next() {
                Some(f) => f.to_lowercase().chain(c).collect(),
                None => String::new(),
            }
        }
        fn snake(s: &str) -> String {
            let mut out = String::new();
            for (i, ch) in s.chars().enumerate() {
                if ch.is_uppercase() {
                    if i != 0 {
                        out.push('_');
                    }
                    out.extend(ch.to_lowercase());
                } else {
                    out.push(ch);
                }
            }
            out
        }

        fn guard<T>(v: T)
        where
            T: SealSpelling
                + serde::Serialize
                + serde::de::DeserializeOwned
                + PartialEq
                + core::fmt::Debug,
        {
            let spelling = v.seal_spelling();
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(
                json,
                format!("\"{spelling}\""),
                "serde surface diverged from the seal surface for {v:?}"
            );
            let back: T = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v, "seal spelling failed serde roundtrip for {v:?}");
            for wrong in [
                spelling.to_lowercase(),
                spelling.to_uppercase(),
                camel(spelling),
                snake(spelling),
            ] {
                if wrong != spelling {
                    assert!(
                        serde_json::from_str::<T>(&format!("\"{wrong}\"")).is_err(),
                        "{wrong:?} must NOT deserialize as {v:?} — an alias/rename has widened the accepted set"
                    );
                }
            }
        }

        guard(TriState::Present);
        guard(TriState::Absent);
        guard(TriState::Indet);
        guard(TriState::NotApplicable);
        guard(DnssecDisposition::SignedAndDelegated);
        guard(DnssecDisposition::SignedNotDelegated);
        guard(DnssecDisposition::BrokenChain);
        guard(DnssecDisposition::ChainUnverified);
        guard(DnssecDisposition::Unsigned);
        guard(DnssecDisposition::NoZone);
        guard(DnssecDisposition::Unreachable);
        guard(SpfDisposition::HardFail);
        guard(SpfDisposition::SoftFail);
        guard(SpfDisposition::OtherPolicy);
        guard(SpfDisposition::PositiveAll);
        guard(SpfDisposition::NotConfigured);
        guard(SpfDisposition::NoMail);
        guard(SpfDisposition::TransientError);
        guard(DkimDisposition::Verified);
        guard(DkimDisposition::NotFoundDefaults);
        guard(DkimDisposition::NotProbed);
        guard(DkimDisposition::NoMailDomain);
        guard(DkimDisposition::TransientError);
        guard(DkimDisposition::KeyMismatch);
        guard(DkimDisposition::Revoked);
        guard(DkimDisposition::Wildcard);
        guard(DmarcDisposition::Reject);
        guard(DmarcDisposition::Quarantine);
        guard(DmarcDisposition::Monitor);
        guard(DmarcDisposition::InvalidPolicy);
        guard(DmarcDisposition::NotConfigured);
        guard(DmarcDisposition::NoMail);
        guard(DmarcDisposition::TransientError);
        guard(DaneDisposition::TlsaPublished);
        guard(DaneDisposition::Verified);
        guard(DaneDisposition::Mismatch);
        guard(DaneDisposition::NotConfigured);
        guard(DaneDisposition::NoMx);
        guard(DaneDisposition::NoMail);
        guard(DaneDisposition::TransientError);
        guard(DaneDisposition::DnssecRequired);
        guard(MtaStsDisposition::Enforced);
        guard(MtaStsDisposition::RecordAbsent);
        guard(MtaStsDisposition::NoZone);
        guard(MtaStsDisposition::TransientError);
        guard(MtaStsDisposition::NotEnforced);
        guard(MtaStsDisposition::PolicyInvalid);
        guard(CaaDisposition::FullyRestricted);
        guard(CaaDisposition::Configured);
        guard(CaaDisposition::WildcardFullyRestricted);
        guard(CaaDisposition::NotConfigured);
        guard(CaaDisposition::NoZone);
        guard(CaaDisposition::TransientError);
        guard(CdsDisposition::Published);
        guard(CdsDisposition::DeletionRequested);
        guard(CdsDisposition::NotPublished);
        guard(CdsDisposition::NoZone);
        guard(CdsDisposition::TransientError);
        guard(TlsRptDisposition::Published);
        guard(TlsRptDisposition::RecordAbsent);
        guard(TlsRptDisposition::NoZone);
        guard(TlsRptDisposition::TransientError);
        guard(TlsRptDisposition::PolicyInvalid);
        guard(CsyncDisposition::Published);
        guard(CsyncDisposition::RecordAbsent);
        guard(CsyncDisposition::NoZone);
        guard(CsyncDisposition::TransientError);
        guard(CsyncDisposition::PolicyInvalid);
        guard(CsyncDisposition::DnssecRequired);
        guard(TlsaZone::SameZone);
        guard(TlsaZone::DescendantZone);
        guard(TlsaZone::ForeignZone);
        guard(TlsaZone::ZoneUnmeasured);
        guard(TlsaZone::NoMxHost);
    }
}
