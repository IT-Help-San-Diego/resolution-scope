// corpus.rs — the public-corpus entry type: identity-free BY CONSTRUCTION.
//
// THE RULING (2026-09-03, Carey — nine source-3 decisions, evidence-closed):
// the public corpus collects RESOLVER BEHAVIOR, never people. This type is
// the enforcement: a public-corpus row STRUCTURALLY CANNOT carry a raw IP,
// a per-contributor token, an ASN, a country, or a fine timestamp. The TYPE
// is the guarantee (compiler-enforced); the Lean theorem is its published
// SPECIFICATION; the exporter/checker binds them (Science's correction:
// a theorem cannot prove a Rust type lacks a field — the checker is what
// makes the binding fail loudly if this type ever gains one).
//
// Design constraints, all ruled:
//   - D2 uc-anon pooling: no per-contributor tokens, ever. Every
//     user-contributed measurement pools under the same constant token.
//   - D3 unknown resolvers: measured under Named("unknown"), never dropped,
//     never a raw IP.
//   - D5 k-anonymity applies to AGGREGATION STATISTICS only (Census model),
//     never to individual measurements — so the corpus entry carries no
//     bucketing machinery.
//   - B2-Q4: capability changes create NEW vantage identity — the corpus
//     never silently mixes pre/post-flip strata; `vantage_epoch` carries it.
//   - Corroboration rule (Science §5): agreement across contributors is
//     compared on (domain, per-control disposition, day) — NEVER seal
//     equality (different resolvers legitimately produce different seals).
//     The entry therefore exposes the disposition tuple directly.
//   - Signing-class rule (the on-demand-signing discovery, 2026-09-03):
//     a captured signature is evidence of ONE observation, never a
//     reproducible value, unless the zone is offline-signed. The corpus
//     entry does not store raw DNS bytes at all — it stores the graded
//     vocabulary (rcode, denial grade, disposition), which IS reproducible.

use alloc::string::String;

use crate::dispositions::{
    CaaDisposition, CdsDisposition, CsyncDisposition, DaneDisposition, DkimDisposition,
    DmarcDisposition, DnssecDisposition, MtaStsDisposition, SpfDisposition, TlsRptDisposition,
};

/// The vantage class that produced a corpus entry. Closed vocabulary — the
/// coarse granularity the sidewalk doctrine ruled (the KIND of last mile,
/// never where it terminates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VantageClass {
    /// Our signed release binary run by a person, local (source-3).
    Instrument,
    /// Our scheduled measurement VPSes (the decay-series fleet).
    Fleet,
    /// RIPE Atlas probe measurements (rented breadth, attribution-tagged).
    Atlas,
    /// An observation through a public recursive — the vantage is the
    /// RECURSIVE's position, not the operator's.
    PublicResolver,
}

/// Which stratum a vantage's capabilities belong to. B2-Q4: when a resolver's
/// capability changes (e.g. alg-18 support turns on), the post-change
/// measurements are a NEW vantage identity — mixing strata would misread a
/// resolver change as a domain change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VantageEpoch(pub u32);

/// A resolver identity as it may appear in the PUBLIC corpus: a named alias
/// from the controlled vocabulary, or the catch-all for unknown resolvers.
/// The RawIp variant is DELIBERATELY ABSENT — that is the whole point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolverAlias {
    Cloudflare,
    Google,
    Quad9,
    OpenDNS,
    Dns4Eu,
    /// A resolver that matched no known alias. The measurement is kept
    /// (D3 — the rare-vantage science); the identity is not.
    Unknown,
}

impl ResolverAlias {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolverAlias::Cloudflare => "cloudflare",
            ResolverAlias::Google => "google",
            ResolverAlias::Quad9 => "quad9",
            ResolverAlias::OpenDNS => "opendns",
            ResolverAlias::Dns4Eu => "dns4eu",
            ResolverAlias::Unknown => "unknown",
        }
    }
}

/// The transport a measurement rode on — a vantage axis in its own right
/// (M3, the protocol-transparency differential: the corpus exists to hold
/// how intelligence/receipts/metadata DIFFER by transport from the same
/// vantage, same domain, same moment). Closed vocabulary; carries no
/// identity. Cloudflare-over-DoT and cloudflare-over-plain-53 are
/// DIFFERENT corpus rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp53,
    Tcp53,
    Dot,
    Doh,
    Doq,
    Doh3,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp53 => "udp53",
            Transport::Tcp53 => "tcp53",
            Transport::Dot => "dot",
            Transport::Doh => "doh",
            Transport::Doq => "doq",
            Transport::Doh3 => "doh3",
        }
    }
}

/// The source-3 constant token (D2): every user-contributed measurement
/// pools under this. No per-contributor identifiers exist in this module.
pub const UC_ANON: &str = "uc-anon";

/// Day granularity only (D4: the residual temporal-correlation risk is
/// accepted AND documented; finer timestamps are identity-bearing and
/// structurally excluded).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CorpusDay {
    pub year: i32,
    pub month: u8,
    pub day: u8,
}

/// The per-control disposition tuple — the corroboratable content. This is
/// what agreement is compared on (the corroboration rule), and it is all
/// resolver behavior: no field here can identify a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispositionTuple {
    pub dnssec: DnssecDisposition,
    pub spf: SpfDisposition,
    pub dkim: DkimDisposition,
    pub dmarc: DmarcDisposition,
    pub dane: DaneDisposition,
    pub mta_sts: MtaStsDisposition,
    pub tls_rpt: TlsRptDisposition,
    pub caa: CaaDisposition,
    pub cds: CdsDisposition,
    pub csync: CsyncDisposition,
}

/// The rcode + denial-grade vocabulary — graded, reproducible evidence
/// (NOT raw DNS bytes; the signing-class rule keeps those out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGrades {
    /// The five-value TEXT vocabulary, never a raw wire u8.
    pub rcode: RcodeGrade,
    pub denial: DenialGrade,
    pub answer_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcodeGrade {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialGrade {
    None,
    SoaOnly,
    Nsec,
    Nsec3,
    NsecNxname,
    Nsec3Nxname,
}

/// A PUBLIC corpus entry. The privacy architecture is this type's shape:
///
///   PRESENT: domain, vantage class, epoch, resolver alias, day,
///            the disposition tuple, wire grades.
///   ABSENT (structurally — no field exists to carry them):
///            contributor IP, ASN, country/region, per-contributor token,
///            fine timestamp, raw resolver IP, raw DNS bytes.
///
/// If this type ever gains an identity-bearing field, the corpus checker
/// (the exporter/checker spine) fails loudly — the Lean Tier-4 theorem
/// specifies this shape; the checker binds the code to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusEntry {
    /// The domain measured. Public DNS data (the same fact every DNS
    /// checker publishes).
    pub domain: String,
    /// What kind of vantage produced this (coarse class only).
    pub vantage_class: VantageClass,
    /// Which capability stratum of that vantage (B2-Q4).
    pub vantage_epoch: VantageEpoch,
    /// The resolver's ALIAS, never its address.
    pub resolver: ResolverAlias,
    /// The transport this measurement rode (M3 vantage axis).
    pub transport: Transport,
    /// Day granularity only.
    pub day: CorpusDay,
    /// The corroboratable content: all ten controls' dispositions.
    pub dispositions: DispositionTuple,
    /// Graded wire evidence (reproducible vocabulary).
    pub wire: WireGrades,
}

impl CorpusEntry {
    /// The corroboration key (Science §5): agreement across contributors is
    /// compared on (domain, dispositions, day) — never on seals, which
    /// legitimately differ when resolvers differ.
    pub fn corroboration_key(&self) -> (&str, &DispositionTuple, &CorpusDay) {
        (&self.domain, &self.dispositions, &self.day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> CorpusEntry {
        CorpusEntry {
            domain: "example.com".into(),
            vantage_class: VantageClass::Instrument,
            vantage_epoch: VantageEpoch(1),
            resolver: ResolverAlias::Unknown,
            transport: Transport::Udp53,
            day: CorpusDay {
                year: 2026,
                month: 9,
                day: 3,
            },
            dispositions: DispositionTuple {
                dnssec: DnssecDisposition::Unsigned,
                spf: SpfDisposition::NotConfigured,
                dkim: DkimDisposition::NotProbed,
                dmarc: DmarcDisposition::NotConfigured,
                dane: DaneDisposition::NotConfigured,
                mta_sts: MtaStsDisposition::RecordAbsent,
                tls_rpt: TlsRptDisposition::RecordAbsent,
                caa: CaaDisposition::NotConfigured,
                cds: CdsDisposition::NotPublished,
                csync: CsyncDisposition::RecordAbsent,
            },
            wire: WireGrades {
                rcode: RcodeGrade::NoError,
                denial: DenialGrade::SoaOnly,
                answer_count: 0,
            },
        }
    }

    /// THE STRUCTURAL TEST (the type-level guarantee, tested): a CorpusEntry
    /// can be constructed, serialized, and passed around — and the type
    /// exposes no identity field. This test is the executable form of the
    /// Lean Tier-4 specification: it cannot test for the ABSENCE of a field
    /// directly (no reflection in Rust), but it pins the exact public field
    /// list via the constructor — adding a field breaks this test's
    /// construction, which IS the alarm.
    #[test]
    fn corpus_entry_constructs_with_exactly_the_public_fields() {
        let e = sample_entry();
        assert_eq!(e.domain, "example.com");
        assert_eq!(e.vantage_class, VantageClass::Instrument);
        assert_eq!(e.resolver, ResolverAlias::Unknown);
        assert_eq!(e.resolver.as_str(), "unknown");
        // The uc-anon constant is the only contributor token that exists.
        assert_eq!(UC_ANON, "uc-anon");
    }

    /// Corroboration keys match on identical content and differ on any
    /// disposition change — the agreement axis.
    #[test]
    fn corroboration_key_compares_content_not_identity() {
        let a = sample_entry();
        let mut b = sample_entry();
        assert_eq!(a.corroboration_key(), b.corroboration_key());
        b.dispositions.dnssec = DnssecDisposition::SignedAndDelegated;
        assert_ne!(a.corroboration_key(), b.corroboration_key());
    }

    /// The resolver alias is the ONLY resolver identity — and this guard
    /// CAN FIRE: the match is EXHAUSTIVE with unit-only arms and no
    /// wildcard, so adding a data-carrying variant (e.g. RawIp(Ipv4Addr))
    /// FAILS TO COMPILE this arm — precisely the alarm (CC's finding A,
    /// fixed the ControlId way: the variant list is the match, not an array).
    #[test]
    fn resolver_alias_is_a_closed_alias_vocabulary() {
        for a in [
            ResolverAlias::Cloudflare,
            ResolverAlias::Google,
            ResolverAlias::Quad9,
            ResolverAlias::OpenDNS,
            ResolverAlias::Dns4Eu,
            ResolverAlias::Unknown,
        ] {
            let s = match a {
                ResolverAlias::Cloudflare => "cloudflare",
                ResolverAlias::Google => "google",
                ResolverAlias::Quad9 => "quad9",
                ResolverAlias::OpenDNS => "opendns",
                ResolverAlias::Dns4Eu => "dns4eu",
                ResolverAlias::Unknown => "unknown",
                // no wildcard: a new variant lands HERE and must be named,
                // which is the moment the privacy review happens
            };
            assert!(!s.contains('.'), "aliases are names, not addresses");
        }
    }

    /// The transport axis (CC's finding B): closed vocabulary, the M3
    /// differential's storage. Same exhaustive-match guard shape.
    #[test]
    fn transport_is_a_closed_vocabulary() {
        for t in [
            Transport::Udp53,
            Transport::Tcp53,
            Transport::Dot,
            Transport::Doh,
            Transport::Doq,
            Transport::Doh3,
        ] {
            let s = match t {
                Transport::Udp53 => "udp53",
                Transport::Tcp53 => "tcp53",
                Transport::Dot => "dot",
                Transport::Doh => "doh",
                Transport::Doq => "doq",
                Transport::Doh3 => "doh3",
            };
            assert!(!s.is_empty());
        }
    }

    /// Day granularity only: CorpusDay has exactly year/month/day — no
    /// hour/minute/second fields exist to construct.
    #[test]
    fn corpus_day_is_day_granularity() {
        let d = CorpusDay {
            year: 2026,
            month: 9,
            day: 3,
        };
        assert_eq!((d.year, d.month, d.day), (2026, 9, 3));
    }
}
