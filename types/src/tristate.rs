// tristate.rs — Core scoring primitive
//
// Every scored DNS control emits exactly one TriState variant.
// See docs/TEST-PLAN.md Section F (Sensitivity Row Requirement).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TriState {
    /// Control exists and is cryptographically valid.
    Present = 0,
    /// Control is absent or invalid — counted in the score denominator.
    ///
    /// "Absent" = looked for and definitively not found. "Invalid" = a
    /// record exists but fails to constitute the control (syntactically,
    /// cryptographically, or by inverting its own purpose) — treated
    /// identically to absence, because a broken control protects nothing.
    /// This clause settled the 2026-08-24 tri-state fork (see the ledger and
    /// docs/CONSENSUS-REPORT-fork-resolution-20260824.md).
    ///
    /// Examples of the two sub-paths, on the two ends of the weight scale:
    /// - SPF absent: no `v=spf1` record at all (`NotConfigured`). Weight 3
    ///   joins the denominator, nothing joins the numerator.
    /// - SPF invalid: `v=spf1 +all` (`PositiveAll`, severity Critical) — a
    ///   record exists and affirmatively authorizes every sender; it scores
    ///   exactly like no record.
    /// - DNSSEC absent: no DNSKEY anywhere (`Unsigned`).
    /// - DNSSEC invalid: DNSKEY published but no chain can validate —
    ///   `SignedNotDelegated` (no DS at the parent) or `BrokenChain` (bad
    ///   RRSIG): RFC 4033 §5 "Insecure"/bogus — a resolver gets the same
    ///   protection as from an unsigned zone, i.e. none.
    ///
    /// Contrast with [`TriState::Indet`]: Absent is a definitive negative
    /// measurement ("we looked; the answer is no, or broken"); Indet is an
    /// inability to measure. A found-but-broken record is a FINDING, never
    /// an Indet.
    ///
    /// NOTE: "warning" states (e.g. MTA-STS T1-1) MUST map to Absent, not a
    /// fourth value.  See test plan Section F.2d (T1-1 regression test).
    Absent = 1,
    /// Could not measure — excluded from denominator, shown as "?" in the UI.
    Indet = 2,
    /// Measured, and the control does not apply to this domain — e.g. a null MX
    /// (RFC 7505 "MX 0 .") declares "accepts no mail", so SMTP DANE is moot.
    /// Excluded from the denominator like Indet, but it is a POSITIVE
    /// measurement ("we know precisely why it doesn't apply"), not
    /// "couldn't measure". Distinct claim, same arithmetic.
    NotApplicable = 3,
}

impl core::fmt::Display for TriState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TriState::Present => write!(f, "PRESENT"),
            TriState::Absent => write!(f, "ABSENT"),
            TriState::Indet => write!(f, "INDET"),
            TriState::NotApplicable => write!(f, "NOT-APPLICABLE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TriState;
    use alloc::format;

    /// The four variants are the load-bearing contract: the seal binds the
    /// `Debug` representation (the variant NAME). A rename here is a
    /// seal-breaking change and must fail loudly. This pins the exact ordered
    /// set.
    #[test]
    fn variant_names_are_the_seal_contract() {
        let names = [
            format!("{:?}", TriState::Present),
            format!("{:?}", TriState::Absent),
            format!("{:?}", TriState::Indet),
            format!("{:?}", TriState::NotApplicable),
        ];
        assert_eq!(names, ["Present", "Absent", "Indet", "NotApplicable"]);
    }
}
