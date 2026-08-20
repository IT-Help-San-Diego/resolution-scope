// flux.rs — the FLUX signal: ASN lookup (Team Cymru) + dispersion counting.
//
// Half two of the two-signature threat model (half one: name_similarity).
// Fast-flux is a DNS rotation technique: a domain's A/AAAA records churn
// through many networks (high ASN dispersion) on short TTLs. One observation
// = the set of ORIGIN ASNs the domain's published addresses resolve to right
// now; the signal is those sets CHANGING across consecutive observations.
//
// Epistemics, in the house style:
//   - The ASN set is measured over Origin-classified ASNs only
//     (asn_classification). ProxyEdge members are excluded AND recorded:
//     Cloudflare edge churn is a fact about Cloudflare, and counting it
//     would pollute dispersion in the false-positive direction; asserting
//     stability through it would fabricate a fact about a hidden origin.
//   - Unknown ASNs measure (classify_asn defaults to Origin) — unknown ISP
//     space is where compromised-host flux lives; gating unknowns would
//     blind the detector to its primary signal.
//   - The dispersion counter REPORTS (observations, distinct ASNs,
//     transitions, transition rate, TTL floor). It never claims intent:
//     the assessment is keyed on transition COUNT (0 → Stable, 1 → Transient,
//     ≥2 → Dispersing), so a single failover or an operator added mid-window
//     does not read "dispersing" — "dispersing" is a measured shape, not an
//     accusation.
//
// The Team Cymru origin service is queried over DNS (TXT), same interface the
// Go parent uses (asn_lookup.go): reversed-octet names under
// origin.asn.cymru.com (v4) / nibble-reversed under origin6.asn.cymru.com (v6).

use std::collections::BTreeSet;
use std::net::IpAddr;

use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::asn_classification::{classify_asn, AsnCategory};

// =============================================================================
// Team Cymru query names + response parsing (pure, unit-tested)
// =============================================================================

/// DNS name for a Team Cymru v4 origin lookup: octets reversed.
/// 1.2.3.4 → "4.3.2.1.origin.asn.cymru.com".
pub fn cymru_origin_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            // Nibble format: 32 hex digits, least-significant nibble first.
            let octets = v6.octets();
            let mut labels = Vec::with_capacity(32);
            for byte in octets.iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            format!("{}.origin6.asn.cymru.com", labels.join("."))
        }
    }
}

/// One parsed Team Cymru origin TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CymruOrigin {
    /// The origin ASN(s) for the prefix. Usually one; multi-origin prefixes
    /// return several space-separated in one field ("13335 209242").
    pub asns: Vec<String>,
    pub prefix: String,
    pub country: String,
}

/// Parse a Team Cymru origin TXT string:
///   "13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
/// Mirrors the Go parent's parseTeamCymruResponse (split on '|', first three
/// fields), plus the multi-ASN first field the Go code flattens.
pub fn parse_cymru_origin(record: &str) -> Option<CymruOrigin> {
    let record = record.trim().trim_matches('"');
    let parts: Vec<&str> = record.split('|').collect();
    if parts.len() < 3 {
        return None;
    }
    let asns: Vec<String> = parts[0]
        .split_whitespace()
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
        .map(|t| t.to_string())
        .collect();
    if asns.is_empty() {
        return None; // no numeric ASN = not a usable origin record
    }
    Some(CymruOrigin {
        asns,
        prefix: parts[1].trim().to_string(),
        country: parts[2].trim().to_string(),
    })
}

// =============================================================================
// FluxObservation — one scan's measured vantage
// =============================================================================

/// Why the flux signal is or is not measurable from this observation. An enum,
/// not a bool: ProxiedEdge and SharedCloudOnly both mean "not observable", for
/// different reasons the reader needs to see (the Go defect this replaces
/// collapsed everything to `flux_observable=false` keyed on a display-name map).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FluxVantage {
    /// At least one published address sits in Origin-classified space —
    /// dispersion is measured over exactly those ASNs.
    Observable,
    /// Every resolved ASN is a true reverse-proxy edge: origin rotation is
    /// structurally invisible in DNS. Report "not observable", never "stable".
    ProxiedEdge,
    /// Every resolved ASN is shared-cloud space (proxy edges and VM origins
    /// under one ASN) — cannot tell which the addresses are at ASN granularity.
    SharedCloudOnly,
    /// The domain published no A/AAAA addresses — nothing to observe.
    NoAddresses,
    /// Addresses exist but no ASN could be resolved for any of them
    /// (Team Cymru lookups failed) — could not measure, not "stable".
    AsnUnresolved,
}

/// Why an ASN was excluded from the dispersion basis. Typed, not a string:
/// the two reasons render differently and must never blur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExclusionReason {
    ProxyEdge,
    SharedCloudAmbiguous,
}

/// One observation: the measured ASN vantage of a domain's published
/// addresses at a single point in time. The dispersion counter compares the
/// `origin_asns` sets of consecutive observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FluxObservation {
    /// Origin-classified ASNs — the dispersion measurement basis.
    pub origin_asns: BTreeSet<String>,
    /// ASNs excluded from the basis, with why (ProxyEdge / SharedCloudAmbiguous).
    /// Recorded so an exclusion is never silent.
    pub excluded_asns: Vec<(String, ExclusionReason)>,
    /// Lowest TTL across the A/AAAA answers — the fast-flux co-signal.
    pub min_ttl: Option<u32>,
    /// Addresses whose ASN lookup failed (counted, never silently dropped).
    pub unresolved_addresses: usize,
    pub vantage: FluxVantage,
}

/// Build one observation: resolve A + AAAA, look up each address's origin
/// ASN via Team Cymru, classify, and partition into the measurement basis.
pub async fn observe_flux(resolver: &TokioResolver, domain: &str) -> FluxObservation {
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut min_ttl: Option<u32> = None;

    for rtype in [RecordType::A, RecordType::AAAA] {
        match resolver.lookup(domain, rtype).await {
            Ok(resp) => {
                for rec in resp.answers() {
                    let ip = match &rec.data {
                        RData::A(a) => Some(IpAddr::V4(a.0)),
                        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        addresses.push(ip);
                        min_ttl = Some(min_ttl.map_or(rec.ttl, |t| t.min(rec.ttl)));
                    }
                }
            }
            Err(e) => {
                // NODATA/NXDOMAIN on one family is normal (v4-only zones etc.);
                // the no-addresses case is judged after both families.
                warn!(domain, rtype = %rtype, error = %e, "flux address lookup error");
            }
        }
    }

    if addresses.is_empty() {
        return FluxObservation {
            origin_asns: BTreeSet::new(),
            excluded_asns: Vec::new(),
            min_ttl: None,
            unresolved_addresses: 0,
            vantage: FluxVantage::NoAddresses,
        };
    }

    let mut all_asns: BTreeSet<String> = BTreeSet::new();
    let mut unresolved = 0usize;
    for ip in &addresses {
        let name = cymru_origin_name(*ip);
        match resolver.txt_lookup(name.as_str()).await {
            Ok(rdata) => {
                let mut found = false;
                for rec in rdata.answers() {
                    if let RData::TXT(txt) = &rec.data {
                        for s in &txt.txt_data {
                            if let Some(origin) = parse_cymru_origin(&String::from_utf8_lossy(s)) {
                                all_asns.extend(origin.asns);
                                found = true;
                            }
                        }
                    }
                }
                if !found {
                    unresolved += 1;
                }
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "Team Cymru origin lookup error");
                unresolved += 1;
            }
        }
    }

    observation_from_asns(all_asns, min_ttl, unresolved)
}

/// Pure partition + vantage decision, split from the network path so every
/// branch is unit-testable.
fn observation_from_asns(
    all_asns: BTreeSet<String>,
    min_ttl: Option<u32>,
    unresolved_addresses: usize,
) -> FluxObservation {
    let mut origin_asns = BTreeSet::new();
    let mut excluded_asns = Vec::new();
    for asn in &all_asns {
        match classify_asn(asn) {
            AsnCategory::Origin => {
                origin_asns.insert(asn.clone());
            }
            AsnCategory::ProxyEdge => excluded_asns.push((asn.clone(), ExclusionReason::ProxyEdge)),
            AsnCategory::SharedCloudAmbiguous => {
                excluded_asns.push((asn.clone(), ExclusionReason::SharedCloudAmbiguous))
            }
        }
    }

    let vantage = if !origin_asns.is_empty() {
        FluxVantage::Observable
    } else if all_asns.is_empty() {
        FluxVantage::AsnUnresolved // addresses existed; no ASN resolved
    } else if excluded_asns
        .iter()
        .all(|(_, why)| *why == ExclusionReason::ProxyEdge)
    {
        FluxVantage::ProxiedEdge
    } else {
        FluxVantage::SharedCloudOnly // shared-cloud, or proxy+shared mix
    };

    FluxObservation {
        origin_asns,
        excluded_asns,
        min_ttl,
        unresolved_addresses,
        vantage,
    }
}

// =============================================================================
// Dispersion — the counter over consecutive observations (pure)
// =============================================================================

/// Conventional fast-flux screening bound for the TTL co-signal: rotation
/// only works operationally when caches expire fast. A tunable screening
/// constant, not a standard — no RFC defines fast-flux.
pub const SHORT_TTL_CEILING_SECS: u32 = 300;

/// What the history measured. Descriptive shapes only — none of these is a
/// verdict about intent. The split is keyed on how many times the origin-ASN
/// set CHANGED (transitions), never on how many ASNs were seen: a multi-operator
/// partition that never moves is Stable, while a single switch is Transient
/// (insufficient to characterise as rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FluxAssessment {
    /// Fewer than two observable observations — dispersion is a claim about
    /// CHANGE, and change needs at least two points.
    InsufficientHistory,
    /// Two or more observations, origin-ASN set never changed.
    Stable,
    /// Exactly one transition: the set changed once and then held. This is
    /// indistinguishable from a legitimate failover or an operator added
    /// mid-window — a single change is insufficient to characterise as
    /// rotation, so it gets its own state rather than collapsing into
    /// Dispersing. Honest "I saw one change, and nothing more."
    Transient,
    /// Two or more transitions: the set moved at least twice. Rotation-shaped
    /// (the set does not settle) — still descriptive, not a claim of intent.
    Dispersing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FluxSignal {
    /// Observable observations counted (non-Observable ones are excluded —
    /// a proxied scan says nothing about origin churn).
    pub observations: usize,
    /// Union size of all origin ASNs seen across the history. Reported shape
    /// only — the assessment never reads this count (a stable multi-operator
    /// partition reports 2+ and still reads Stable).
    pub distinct_origin_asns: usize,
    /// Number of consecutive pairs whose origin-ASN sets differ. This is what
    /// the assessment keys on: 0 → Stable, 1 → Transient, ≥2 → Dispersing.
    pub transitions: usize,
    /// `transitions ÷ (observations−1)` — the share of transition BOUNDARIES
    /// that witnessed a set change (Claude Science's "1-in-4 vs 3-in-4"
    /// distinction). Bounded [0,1] regardless of window length. `None` when
    /// fewer than two observations (a rate needs at least one boundary).
    /// Reported for the reader; the assessment is keyed on the transition
    /// COUNT, not this.
    pub transition_rate: Option<f64>,
    /// True when any observation's TTL floor was ≤ SHORT_TTL_CEILING_SECS —
    /// the co-signal, reported alongside, never merged into the assessment.
    pub short_ttl_seen: bool,
    pub assessment: FluxAssessment,
}

/// Count dispersion across a time-ordered history of observations.
/// Non-Observable observations are excluded from the pairwise comparison:
/// a scan that couldn't see origins can neither prove stability nor change.
pub fn dispersion(history: &[FluxObservation]) -> FluxSignal {
    let observable: Vec<&FluxObservation> = history
        .iter()
        .filter(|o| o.vantage == FluxVantage::Observable)
        .collect();

    let mut union: BTreeSet<&String> = BTreeSet::new();
    for o in &observable {
        union.extend(o.origin_asns.iter());
    }
    let transitions = observable
        .windows(2)
        .filter(|w| w[0].origin_asns != w[1].origin_asns)
        .count();
    let short_ttl_seen = observable
        .iter()
        .any(|o| o.min_ttl.is_some_and(|t| t <= SHORT_TTL_CEILING_SECS));

    let assessment = if observable.len() < 2 {
        FluxAssessment::InsufficientHistory
    } else if transitions == 0 {
        FluxAssessment::Stable
    } else if transitions == 1 {
        FluxAssessment::Transient
    } else {
        FluxAssessment::Dispersing
    };
    let transition_rate = if observable.len() >= 2 {
        // Denominators is the number of transition BOUNDARIES (n−1 consecutive
        // pairs), not the number of observations (n). A rate divided by n has a
        // ceiling that drifts with the window (0.5 at n=2, 0.875 at n=8), which
        // is exactly the incomparability a reported rate exists to remove.
        // Divided by n−1 the ceiling is a constant 1.0 regardless of window.
        Some(transitions as f64 / (observable.len() - 1) as f64)
    } else {
        None
    };

    FluxSignal {
        observations: observable.len(),
        distinct_origin_asns: union.len(),
        transitions,
        transition_rate,
        short_ttl_seen,
        assessment,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(asns: &[&str], ttl: Option<u32>) -> FluxObservation {
        observation_from_asns(asns.iter().map(|s| s.to_string()).collect(), ttl, 0)
    }

    // ── Team Cymru name construction ────────────────────────────────────────

    #[test]
    fn cymru_v4_name_reverses_octets() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(cymru_origin_name(ip), "4.3.2.1.origin.asn.cymru.com");
    }

    #[test]
    fn cymru_v6_name_is_reversed_nibbles() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let name = cymru_origin_name(ip);
        assert!(name.ends_with(".origin6.asn.cymru.com"));
        // 32 nibble labels + 4 suffix labels
        assert_eq!(name.split('.').count(), 36);
        // Least-significant nibble first: the ::1 tail leads.
        assert!(name.starts_with("1.0.0.0."));
        // The 2001 head arrives last, least-significant nibble of the pair
        // ordering preserved: ...1.0.0.2.origin6...
        assert!(name.contains("8.b.d.0.1.0.0.2.origin6"));
    }

    // ── Team Cymru response parsing ─────────────────────────────────────────

    #[test]
    fn cymru_parse_standard_line() {
        let o = parse_cymru_origin("\"13335 | 1.1.1.0/24 | US | arin | 2010-07-14\"").unwrap();
        assert_eq!(o.asns, vec!["13335"]);
        assert_eq!(o.prefix, "1.1.1.0/24");
        assert_eq!(o.country, "US");
    }

    #[test]
    fn cymru_parse_multi_origin_prefix() {
        // Multi-origin prefixes return several ASNs in the first field.
        let o = parse_cymru_origin("13335 209242 | 1.1.1.0/24 | US | arin | 2010").unwrap();
        assert_eq!(o.asns, vec!["13335", "209242"]);
    }

    #[test]
    fn cymru_parse_rejects_garbage() {
        assert_eq!(parse_cymru_origin(""), None);
        assert_eq!(parse_cymru_origin("no pipes here"), None);
        assert_eq!(parse_cymru_origin("NA | NA | NA"), None); // no numeric ASN
    }

    // ── Vantage partition (the Go-defect class, pinned) ─────────────────────

    #[test]
    fn vantage_origin_asns_measure() {
        // DigitalOcean + Hetzner (the false-negative population of the Go
        // defect: hosting ASNs must MEASURE, never read "CDN-proxied").
        let o = obs(&["14061", "24940"], Some(60));
        assert_eq!(o.vantage, FluxVantage::Observable);
        assert_eq!(o.origin_asns.len(), 2);
        assert!(o.excluded_asns.is_empty());
    }

    #[test]
    fn vantage_unknown_asn_measures() {
        // Unknown ISP space is the signal's hunting ground — never gated.
        let o = obs(&["394200099"], Some(60));
        assert_eq!(o.vantage, FluxVantage::Observable);
    }

    #[test]
    fn vantage_all_proxy_is_not_observable() {
        // Cloudflare-only: origin rotation structurally invisible.
        let o = obs(&["13335"], Some(300));
        assert_eq!(o.vantage, FluxVantage::ProxiedEdge);
        assert!(o.origin_asns.is_empty());
        assert_eq!(
            o.excluded_asns,
            vec![("13335".to_string(), ExclusionReason::ProxyEdge)]
        );
    }

    #[test]
    fn vantage_shared_cloud_only_is_its_own_reason() {
        // Amazon-only: could be CloudFront edges OR EC2 origins — say so.
        let o = obs(&["16509"], Some(60));
        assert_eq!(o.vantage, FluxVantage::SharedCloudOnly);
    }

    #[test]
    fn vantage_mixed_measures_over_origin_subset_and_records_exclusions() {
        // Cloudflare + a DigitalOcean origin: dispersion measures the DO
        // side; the proxy member is excluded AND visible, never silent.
        let o = obs(&["13335", "14061"], Some(60));
        assert_eq!(o.vantage, FluxVantage::Observable);
        assert_eq!(o.origin_asns.iter().collect::<Vec<_>>(), vec!["14061"]);
        assert_eq!(
            o.excluded_asns,
            vec![("13335".to_string(), ExclusionReason::ProxyEdge)]
        );
    }

    #[test]
    fn vantage_no_asn_resolved_is_unmeasured_not_stable() {
        let o = observation_from_asns(BTreeSet::new(), Some(60), 3);
        assert_eq!(o.vantage, FluxVantage::AsnUnresolved);
        assert_eq!(o.unresolved_addresses, 3);
    }

    // ── Dispersion counting ─────────────────────────────────────────────────

    #[test]
    fn dispersion_needs_two_points() {
        assert_eq!(
            dispersion(&[]).assessment,
            FluxAssessment::InsufficientHistory
        );
        assert_eq!(
            dispersion(&[obs(&["14061"], Some(60))]).assessment,
            FluxAssessment::InsufficientHistory
        );
    }

    #[test]
    fn dispersion_stable_set_is_stable() {
        let h = vec![obs(&["14061"], Some(3600)), obs(&["14061"], Some(3600))];
        let s = dispersion(&h);
        assert_eq!(s.assessment, FluxAssessment::Stable);
        assert_eq!(s.transitions, 0);
        assert_eq!(s.distinct_origin_asns, 1);
        assert!(!s.short_ttl_seen);
    }

    #[test]
    fn dispersion_counts_transitions_and_union() {
        // Rotation through three hosting networks on short TTLs — the
        // fast-flux shape, measured descriptively.
        let h = vec![
            obs(&["14061"], Some(120)),
            obs(&["24940"], Some(120)),
            obs(&["16276"], Some(120)),
        ];
        let s = dispersion(&h);
        assert_eq!(s.assessment, FluxAssessment::Dispersing);
        assert_eq!(s.transitions, 2);
        assert_eq!(s.distinct_origin_asns, 3);
        assert!(s.short_ttl_seen);
    }

    #[test]
    fn dispersion_excludes_non_observable_scans() {
        // A proxied scan in the middle can neither prove stability nor
        // change — it must not create a phantom transition against its
        // empty origin set.
        let h = vec![
            obs(&["14061"], Some(60)),
            obs(&["13335"], Some(60)), // ProxiedEdge — excluded
            obs(&["14061"], Some(60)),
        ];
        let s = dispersion(&h);
        assert_eq!(s.observations, 2);
        assert_eq!(s.transitions, 0);
        assert_eq!(s.assessment, FluxAssessment::Stable);
    }

    #[test]
    fn stable_multi_operator_partition_reads_stable_not_dispersing() {
        // nsa.gov mail infrastructure (Claude Science negative-control,
        // 2026-08-20): two origin ASNs (AS345, AS5374) across the MX set, but
        // a STABLE per-host partition — each named host sits in exactly one
        // ASN and never moves. This is multi-operator ARCHITECTURE, not
        // fast-flux: fast-flux is ONE name whose addresses move between
        // operators over time.
        //
        // Dispersion is a claim about CHANGE, so the assessment keys on
        // transitions (the set changing between consecutive observations),
        // never on the union count. The set {345, 5374} is stable across
        // samples, so it must read Stable.
        let h = vec![
            obs(&["345", "5374"], Some(3600)),
            obs(&["345", "5374"], Some(3600)),
            obs(&["345", "5374"], Some(3600)),
        ];
        let s = dispersion(&h);
        assert_eq!(s.assessment, FluxAssessment::Stable);
        assert_eq!(s.transitions, 0);
        assert!(!s.short_ttl_seen);
        // The union count reports 2 — this is the number a naive
        // ">1 ASN → Dispersing" rule would falsely fire on. It is a REPORTED
        // shape (distinct_origin_asns), never an assessment input; the guard
        // is that the assessment reads transitions, not this count.
        assert_eq!(s.distinct_origin_asns, 2);
    }

    #[test]
    fn single_failover_reads_transient_not_dispersing() {
        // {A},{A},{B},{B}: one real switch (provider-outage failover), then
        // the set holds. One transition is insufficient to characterise as
        // rotation — it must NOT read Dispersing.
        let h = vec![
            obs(&["345"], Some(3600)),
            obs(&["345"], Some(3600)),
            obs(&["5374"], Some(3600)),
            obs(&["5374"], Some(3600)),
        ];
        let s = dispersion(&h);
        assert_eq!(s.assessment, FluxAssessment::Transient);
        assert_eq!(s.transitions, 1);
        assert_eq!(s.distinct_origin_asns, 2);
        assert_eq!(s.transition_rate, Some(1.0 / 3.0)); // 1-in-3 boundaries
    }

    #[test]
    fn operator_added_mid_window_reads_transient_not_dispersing() {
        // {A},{A},{A,B}: a second operator joins once and the set holds. One
        // transition (the union grows) — not rotation.
        let h = vec![
            obs(&["345"], Some(3600)),
            obs(&["345"], Some(3600)),
            obs(&["345", "5374"], Some(3600)),
        ];
        let s = dispersion(&h);
        assert_eq!(s.assessment, FluxAssessment::Transient);
        assert_eq!(s.transitions, 1);
        assert_eq!(s.distinct_origin_asns, 2);
        assert_eq!(s.transition_rate, Some(1.0 / 2.0)); // 1-in-2 boundaries
    }

    #[test]
    fn oscillation_reads_dispersing() {
        // {A},{B},{A},{B}: the set never settles — every consecutive pair
        // differs. Three transitions over four observations is rotation-shaped,
        // not a single event.
        let h = vec![
            obs(&["345"], Some(300)),
            obs(&["5374"], Some(300)),
            obs(&["345"], Some(300)),
            obs(&["5374"], Some(300)),
        ];
        let s = dispersion(&h);
        assert_eq!(s.assessment, FluxAssessment::Dispersing);
        assert_eq!(s.transitions, 3);
        assert_eq!(s.distinct_origin_asns, 2);
        assert_eq!(s.transition_rate, Some(3.0 / 3.0)); // 3-in-3 boundaries
        assert!(s.short_ttl_seen);
    }

    #[test]
    fn transition_rate_is_none_without_a_window() {
        // Fewer than two observations: no rate is meaningful.
        assert_eq!(dispersion(&[]).transition_rate, None);
        assert_eq!(
            dispersion(&[obs(&["345"], Some(3600))]).transition_rate,
            None
        );
    }

    // ── Live (specimen) ─────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires network"]
    async fn live_cloudflare_dns_reads_proxied() {
        use hickory_resolver::config::{ResolverConfig, ResolverOpts};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&hickory_resolver::config::CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build()
        .unwrap();
        // cloudflare.com's own site sits on AS13335 — the canonical
        // ProxiedEdge observation.
        let o = observe_flux(&resolver, "cloudflare.com").await;
        assert_eq!(o.vantage, FluxVantage::ProxiedEdge, "got {o:?}");
    }
}
