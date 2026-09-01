// denial_proof.rs — the receipt's denial-grade + rcode vocabulary, and the
// extraction that derives a DenialProof grade from the authority section of a
// negative DNS response.
//
// WHY THIS IS NOT IN `types/`: receipts are BESIDE the seal, never part of it
// (R-B ruling, 2026-08-24). `types/` is the sealed type surface shared with the
// no_std native compartment; a receipt never crosses that boundary and carries
// no SealSpelling. Receipts are the engine's observation and the store's
// record, so their vocabulary lives here, at the engine layer.

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::{RData, Record, RecordType};

use crate::truth_chain::ControlId;

/// The NXNAME meta-TYPE (RFC 9824 §2): the sentinel a compact-denial zone
/// places in an NSEC/NSEC3 Type Bit Maps field to recover "this name does not
/// exist" from a NOERROR response whose rcode erased NXDOMAIN.
const NXNAME: RecordType = RecordType::Unknown(128);

/// The six receipt grades — *who vouched* for an absence. Recorded beside the
/// seal (R-B: the receipt is the witness's words, the seal is the judge's),
/// so these values are NOT sealed and carry no SealSpelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialProof {
    /// No proof at all — an unsigned plain answer, or no authority records.
    None,
    /// SOA present but no NSEC/NSEC3 proof accompanying it — an unsigned
    /// zone's negative answer, or a proof-stripped signed path. (Measured:
    /// unsigned microsoft.com NXDOMAIN arrives as exactly SOA-only. Compact
    /// denials are NOT this grade — their wire responses carry an NSEC.)
    SoaOnly,
    /// An NSEC record present (signed proof of denial, no TYPE128 sentinel).
    Nsec,
    /// An NSEC3 record present (signed proof, no TYPE128 sentinel).
    Nsec3,
    /// NSEC carrying TYPE128 (membership test — RFC 9824 §2 has TYPE128 arrive
    /// "in addition to" the mandated RRSIG + NSEC types). Nonexistence
    /// recoverable.
    NsecNxname,
    /// NSEC3 carrying TYPE128 as its SOLE bitmap entry (sole-entry test).
    /// Nonexistence recoverable; the sole-entry shape also disambiguates
    /// nonexistent-name from Empty Non-Terminal (RFC 9824 §4).
    Nsec3Nxname,
}

impl DenialProof {
    /// The stored TEXT vocabulary. SEAL-adjacent but NOT sealed (receipt).
    pub fn label(self) -> &'static str {
        match self {
            DenialProof::None => "none",
            DenialProof::SoaOnly => "soa_only",
            DenialProof::Nsec => "nsec",
            DenialProof::Nsec3 => "nsec3",
            DenialProof::NsecNxname => "nsec_nxname",
            DenialProof::Nsec3Nxname => "nsec3_nxname",
        }
    }

    /// Parse the stored TEXT vocabulary. Unknown labels are a loud error
    /// (`None`), never a silent skip — an unknown stored grade is a
    /// schema-drift signal, not a value to guess.
    pub fn from_label(s: &str) -> Option<DenialProof> {
        Some(match s {
            "none" => DenialProof::None,
            "soa_only" => DenialProof::SoaOnly,
            "nsec" => DenialProof::Nsec,
            "nsec3" => DenialProof::Nsec3,
            "nsec_nxname" => DenialProof::NsecNxname,
            "nsec3_nxname" => DenialProof::Nsec3Nxname,
            _ => return None,
        })
    }
}

/// The receipt's rcode vocabulary — TEXT, never a numeric wire u8. TIMEOUT has
/// no wire rcode at all (the "response" is the absence of a response), so a
/// numeric encoding would silently drop one of the five failure modes the
/// failure-is-a-measurement principle requires decomposing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptRcode {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    Timeout,
}

impl ReceiptRcode {
    pub fn label(self) -> &'static str {
        match self {
            ReceiptRcode::NoError => "NOERROR",
            ReceiptRcode::NxDomain => "NXDOMAIN",
            ReceiptRcode::ServFail => "SERVFAIL",
            ReceiptRcode::Refused => "REFUSED",
            ReceiptRcode::Timeout => "TIMEOUT",
        }
    }

    pub fn from_label(s: &str) -> Option<ReceiptRcode> {
        Some(match s {
            "NOERROR" => ReceiptRcode::NoError,
            "NXDOMAIN" => ReceiptRcode::NxDomain,
            "SERVFAIL" => ReceiptRcode::ServFail,
            "REFUSED" => ReceiptRcode::Refused,
            "TIMEOUT" => ReceiptRcode::Timeout,
            _ => return None,
        })
    }
}

/// One control's receipt — the witness's record of how the lookup answered.
/// Beside the seal (R-B), never part of it. `elapsed_ms` is run metadata
/// (about the observer, not the target), exactly like `resolver_identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupReceipt {
    pub control: ControlId,
    pub rcode: ReceiptRcode,
    pub answer_count: u16,
    pub denial_proof: DenialProof,
    pub elapsed_ms: u64,
}

/// One raw DNS record captured at classification time — the bytes the verdict
/// was computed from. BESIDE the seal (R-B), exactly like [`LookupReceipt`]:
/// the seal attests OUR verdict (judge); the record is the SERVER'S words the
/// verdict read (witness). Never sealed, never crosses into `types/` (carries
/// no SealSpelling). `control` is the stable [`ControlId`], not a display name
/// — the store maps it through [`control_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    pub control: ControlId,
    /// The raw record presentation string (e.g. `v=spf1 include:… -all`,
    /// `v=DMARC1; p=reject; rua=…`, `0 issue "letsencrypt.org"`).
    pub value: String,
}

/// The stored lowercase key for a control (the `lookup_receipts.control` TEXT
/// vocabulary). Stable across display-string edits — the display `name()` is
/// NOT the stored key.
pub fn control_key(c: ControlId) -> &'static str {
    match c {
        ControlId::Dnssec => "dnssec",
        ControlId::Spf => "spf",
        ControlId::Dkim => "dkim",
        ControlId::Dmarc => "dmarc",
        ControlId::Dane => "dane",
        ControlId::MtaSts => "mta_sts",
        ControlId::Caa => "caa",
        ControlId::Cds => "cds",
        ControlId::TlsRpt => "tls_rpt",
        ControlId::Csync => "csync",
    }
}

/// The inverse of [`control_key`] — the stored TEXT key back to a `ControlId`.
/// Unknown keys are a loud error (`None`), never a silent skip.
pub fn control_from_key(s: &str) -> Option<ControlId> {
    Some(match s {
        "dnssec" => ControlId::Dnssec,
        "spf" => ControlId::Spf,
        "dkim" => ControlId::Dkim,
        "dmarc" => ControlId::Dmarc,
        "dane" => ControlId::Dane,
        "mta_sts" => ControlId::MtaSts,
        "caa" => ControlId::Caa,
        "cds" => ControlId::Cds,
        "tls_rpt" => ControlId::TlsRpt,
        "csync" => ControlId::Csync,
        _ => return None,
    })
}

/// Classify the authority section of a (negative) response into a denial grade.
/// Pure, no I/O — the whole of the receipt's load-bearing logic. Precedence
/// follows the strongest signal first: a TYPE128 sentinel (recoverable
/// nonexistence) outranks a bare NSEC/NSEC3, which outranks a bare SOA.
pub fn extract_denial_proof(authorities: &[Record]) -> DenialProof {
    let mut saw_soa = false;
    let mut saw_nsec = false;
    let mut saw_nsec3 = false;
    for r in authorities {
        match &r.data {
            RData::SOA(_) => saw_soa = true,
            RData::DNSSEC(DNSSECRData::NSEC(nsec)) => {
                saw_nsec = true;
                // NSEC: TYPE128 membership (RFC 9824 §2 — "in addition to" the
                // mandated RRSIG + NSEC types). Use `.type_bit_maps().any()`,
                // NOT `RecordTypeSet::contains()`, which is `__dnssec`-gated.
                if nsec.type_bit_maps().any(|t| t == NXNAME) {
                    return DenialProof::NsecNxname;
                }
            }
            RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => {
                saw_nsec3 = true;
                // NSEC3: TYPE128 sole-entry (RFC 9824 §4). Sole-entry also
                // disambiguates nonexistent-name from Empty Non-Terminal.
                let bits: Vec<RecordType> = nsec3.type_bit_maps().collect();
                if bits.len() == 1 && bits[0] == NXNAME {
                    return DenialProof::Nsec3Nxname;
                }
            }
            _ => {}
        }
    }
    if saw_nsec {
        DenialProof::Nsec
    } else if saw_nsec3 {
        DenialProof::Nsec3
    } else if saw_soa {
        DenialProof::SoaOnly
    } else {
        DenialProof::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::rdata::{NSEC, NSEC3};
    use hickory_proto::dnssec::Nsec3HashAlgorithm;
    use hickory_proto::rr::rdata::SOA;

    fn name(s: &str) -> hickory_proto::rr::Name {
        s.parse().unwrap()
    }

    fn nsec(types: &[RecordType]) -> Record {
        let rdata = RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
            name("example.com."),
            types.iter().copied(),
        )));
        Record::from_rdata(name("example.com."), 300, rdata)
    }

    fn nsec3(types: &[RecordType]) -> Record {
        let rdata = RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            vec![],
            vec![0xAB; 20],
            types.iter().copied(),
        )));
        Record::from_rdata(name("example.com."), 300, rdata)
    }

    fn soa() -> Record {
        let soa = SOA::new(
            name("example.com."),
            name("hostmaster.example.com."),
            2026082501,
            3600,
            600,
            1209600,
            300,
        );
        Record::from_rdata(name("example.com."), 300, RData::SOA(soa))
    }

    // ── the three-class denial model (measured 2026-08-25) ──────────────────

    #[test]
    fn empty_authorities_is_none() {
        assert_eq!(extract_denial_proof(&[]), DenialProof::None);
    }

    #[test]
    fn soa_only_when_soa_but_no_nsec() {
        assert_eq!(extract_denial_proof(&[soa()]), DenialProof::SoaOnly);
    }

    /// Route53 sentinel-less compact denial: NSEC bitmap `RRSIG NSEC`, no
    /// TYPE128 → `nsec` (a real signed proof, existence unresolved).
    #[test]
    fn route53_compact_denial_grades_nsec() {
        let authorities = [nsec(&[RecordType::RRSIG, RecordType::NSEC])];
        assert_eq!(extract_denial_proof(&authorities), DenialProof::Nsec);
    }

    /// Cloudflare compact denial: NSEC bitmap CONTAINING TYPE128 → recoverable.
    #[test]
    fn nsec_membership_recovers_nonexistence() {
        let authorities = [nsec(&[RecordType::RRSIG, RecordType::NSEC, NXNAME])];
        assert_eq!(extract_denial_proof(&authorities), DenialProof::NsecNxname);
    }

    /// NSEC3 with TYPE128 as SOLE entry → Nsec3Nxname (RFC 9824 §4 sole-entry).
    #[test]
    fn nsec3_sole_entry_recovers_nonexistence() {
        let authorities = [nsec3(&[NXNAME])];
        assert_eq!(extract_denial_proof(&authorities), DenialProof::Nsec3Nxname);
    }

    /// NSEC3 with more than TYPE128 is NOT the sentinel (ENT-like shape) —
    /// grades as a plain signed NSEC3, existence unresolved.
    #[test]
    fn nsec3_not_sole_entry_is_plain_nsec3() {
        let authorities = [nsec3(&[RecordType::RRSIG, RecordType::NSEC3])];
        assert_eq!(extract_denial_proof(&authorities), DenialProof::Nsec3);
    }

    /// An NSEC with a multi-entry bitmap that HAPPENS to include TYPE128 still
    /// recovers via membership (NSEC has no sole-entry requirement).
    #[test]
    fn nsec_membership_is_not_sole_entry() {
        let authorities = [nsec(&[RecordType::RRSIG, RecordType::NSEC, NXNAME])];
        assert_eq!(extract_denial_proof(&authorities), DenialProof::NsecNxname);
    }

    /// The sentinel outranks a bare NSEC in the same authority section.
    #[test]
    fn sentinel_outranks_bare_nsec() {
        let authorities = [
            nsec(&[RecordType::RRSIG, RecordType::NSEC]),
            nsec(&[RecordType::RRSIG, RecordType::NSEC, NXNAME]),
        ];
        assert_eq!(extract_denial_proof(&authorities), DenialProof::NsecNxname);
    }

    // ── label roundtrips (the TEXT vocabulary is a deliberate contract) ─────

    #[test]
    fn denial_proof_labels_roundtrip() {
        for p in [
            DenialProof::None,
            DenialProof::SoaOnly,
            DenialProof::Nsec,
            DenialProof::Nsec3,
            DenialProof::NsecNxname,
            DenialProof::Nsec3Nxname,
        ] {
            assert_eq!(DenialProof::from_label(p.label()), Some(p));
        }
        assert_eq!(DenialProof::from_label("garbage"), None);
    }

    #[test]
    fn rcode_labels_roundtrip_and_reject_bad_case() {
        for r in [
            ReceiptRcode::NoError,
            ReceiptRcode::NxDomain,
            ReceiptRcode::ServFail,
            ReceiptRcode::Refused,
            ReceiptRcode::Timeout,
        ] {
            assert_eq!(ReceiptRcode::from_label(r.label()), Some(r));
        }
        // Negative-casing guard (the alias-normalization hazard): the stored
        // vocabulary is exact; a wrong-case or numeric token must NOT parse.
        assert_eq!(ReceiptRcode::from_label("noerror"), None);
        assert_eq!(ReceiptRcode::from_label("3"), None);
        assert_eq!(ReceiptRcode::from_label("255"), None);
    }

    #[test]
    fn control_keys_are_stable_and_lowercase() {
        let keys = [
            (ControlId::Dnssec, "dnssec"),
            (ControlId::Spf, "spf"),
            (ControlId::Dkim, "dkim"),
            (ControlId::Dmarc, "dmarc"),
            (ControlId::Dane, "dane"),
            (ControlId::MtaSts, "mta_sts"),
            (ControlId::Caa, "caa"),
            (ControlId::Cds, "cds"),
            (ControlId::TlsRpt, "tls_rpt"),
            (ControlId::Csync, "csync"),
        ];
        for (c, expect) in keys {
            assert_eq!(
                control_key(c),
                expect,
                "control_key must be a stable lowercase DB key, not the display name"
            );
        }
    }

    /// The ALL-driven round-trip guard (foundation-audit item 6, 2026-08-31):
    /// `control_from_key` had 8 arms against `control_key`'s 10 — receipts
    /// for the new controls were WRITE-ONLY (the store records them, then
    /// hard-errors on read-back). This test iterates `ControlId::ALL`, so
    /// the pair can never silently split again: adding a ControlId variant
    /// forces this test to cover it or fail.
    #[test]
    fn control_key_roundtrip_covers_all_controls() {
        for c in ControlId::ALL {
            let k = control_key(c);
            assert_eq!(
                control_from_key(k),
                Some(c),
                "control_key/control_from_key split: {k} writes but cannot read back"
            );
        }
        assert_eq!(control_from_key("garbage"), None);
        assert_eq!(control_from_key(""), None);
    }
}
