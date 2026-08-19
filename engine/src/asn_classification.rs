// asn_classification.rs — the flux signal's ASN classification.
//
// The flux question is: can we observe a domain's real server rotating its IP
// via DNS (fast-flux)? To answer it truthfully we must first know whether the
// IP we resolved is the REAL origin or a reverse-proxy front door. That is a
// fact about the provider's architecture, and it is the ONLY classification in
// the flux signal — everything else is a measurement.
//
// Three states, each backed by a real fact, zero guesses:
//
//   ProxyEdge — the ASN is a true reverse proxy (Cloudflare, Akamai, Fastly,
//     Sucuri, Imperva, KeyCDN). The resolved IP is a proxy edge; the origin is
//     structurally hidden. Flux is NOT observable (a truthful "can't see").
//
//   SharedCloudAmbiguous — one ASN fronts BOTH proxy edges and direct VM
//     origins (Amazon: CloudFront+EC2; Google: GFE+GCE; Microsoft: Azure Front
//     Door+VM). At ASN granularity we cannot tell which the resolved IP is.
//     Flux is not observable, for a DIFFERENT reason than ProxyEdge.
//
//   Origin — the resolved IP is (or is treated as) the real origin. Measure it.
//     This is the DEFAULT for any ASN not in the two lists above.
//
// The default-to-Origin rule is the load-bearing inversion: "not observable"
// is itself a strong positive assertion (it claims the origin is structurally
// hidden). Asserting it about a random ISP is exactly as fabricated as
// asserting stability about Cloudflare — so we fail toward MEASURABLE, not
// toward uncertain. Unknown ASNs are the flux signal's primary hunting ground
// (compromised-host fast-flux lives on consumer/ISP space), and a gate that
// fails closed on unknowns would blind the detector to its own target.
//
// This replaces the Go defect (dns-tool-intel asn_lookup.go:65), where a
// DISPLAY-NAME dictionary (wellKnownASNames) — which contains Comcast, AT&T,
// Verizon, and DigitalOcean alongside Cloudflare — was borrowed as a proxy
// classification. The display map stays cosmetic; classification is its own
// table.

/// The three-way ASN classification for the flux CDN-proxied gate. Stored as an
/// enum (not a `flux_observable` bool) so the WHY survives: ProxyEdge and
/// SharedCloudAmbiguous both mean "not observable", but for different reasons
/// the reader needs to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsnCategory {
    /// True reverse proxy: the resolved IP is an edge node, not the origin.
    ProxyEdge,
    /// One ASN fronts both proxy edges and direct VM origins — at ASN
    /// granularity we cannot tell which the resolved IP is.
    SharedCloudAmbiguous,
    /// The resolved IP is (or is treated as) the real origin — measure it.
    /// Default for any ASN not explicitly classified.
    Origin,
}

/// True reverse proxies: the resolved IP is a front door, not the subject's
/// origin. (Source: dns-tool-intel asn_lookup.go wellKnownASNames — the proxy
/// *property*, not the display name, is what lands an ASN here.)
const PROXY_EDGE_ASNS: &[&str] = &[
    "13335",  // Cloudflare, Inc.
    "209242", // Cloudflare London, LLC
    "20940",  // Akamai International B.V.
    "16625",  // Akamai Technologies, Inc.
    "32787",  // Prolexic Technologies (Akamai DDoS proxy)
    "54113",  // Fastly, Inc.
    "394536", // Sucuri Inc. (website security reverse proxy)
    "30148",  // Sucuri Inc.
    "19551",  // Imperva, Inc. (Incapsula WAF/CDN)
    "394699", // KeyCDN
];

/// Shared clouds: one ASN fronts both proxy edges and direct VM origins. At ASN
/// granularity the resolved IP could be either, so the flux verdict is "not
/// observable" with a specific reason. Prefix-level feeds (AWS ip-ranges.json,
/// Google cloud JSON) shrink but do not eliminate this ambiguity (AWS carries a
/// 4,088-prefix AMAZON catch-all), so this bucket is permanent, not a stopgap.
///
/// Microsoft is included on the same logic as Amazon/Google (Azure Front Door
/// and Azure VMs both publish under AS8075). Alibaba (45102), Tencent (132203),
/// and IBM Cloud (36351) are ALSO shared clouds but are deliberately left as
/// Origin (default) until prefix-level discrimination confirms them — per the
/// fail-toward-measurable rule, an uncertain ASN measures rather than asserts
/// "not observable".
const SHARED_CLOUD_ASNS: &[&str] = &[
    "16509",  // Amazon (CloudFront edges + EC2 origins)
    "14618",  // Amazon
    "38895",  // Amazon
    "16510",  // Amazon
    "36183",  // Amazon
    "15169",  // Google (GFE-proxied + bare GCE)
    "396982", // Google
    "8075",   // Microsoft (Azure Front Door + Azure VM)
];

/// Classify an ASN for the flux CDN-proxied gate.
///
/// Accepts a bare ASN ("13335") or an "AS"-prefixed one ("AS13335"), with
/// optional whitespace. Unknown ASNs return `Origin` — fail toward measurable,
/// never toward "not observable".
pub fn classify_asn(asn: &str) -> AsnCategory {
    let asn = asn.trim().trim_start_matches("AS").trim_start_matches("as");
    if PROXY_EDGE_ASNS.contains(&asn) {
        AsnCategory::ProxyEdge
    } else if SHARED_CLOUD_ASNS.contains(&asn) {
        AsnCategory::SharedCloudAmbiguous
    } else {
        AsnCategory::Origin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxies_are_proxy_edge() {
        for asn in ["13335", "20940", "54113", "19551", "394699", "30148"] {
            assert_eq!(classify_asn(asn), AsnCategory::ProxyEdge, "{asn}");
        }
    }

    #[test]
    fn shared_clouds_are_ambiguous() {
        for asn in ["16509", "15169", "8075", "396982", "36183"] {
            assert_eq!(
                classify_asn(asn),
                AsnCategory::SharedCloudAmbiguous,
                "{asn}"
            );
        }
    }

    #[test]
    fn vps_providers_are_origin() {
        // The false-negative the Go defect produced: a VPS IP IS the origin.
        for asn in ["14061", "24940", "16276", "20473", "63949", "13649"] {
            assert_eq!(classify_asn(asn), AsnCategory::Origin, "{asn}");
        }
    }

    #[test]
    fn carriers_and_isps_are_origin() {
        // Where compromised-host fast-flux actually lives — must be measured.
        for asn in ["7922", "7018", "701", "3356", "174", "4808", "1239"] {
            assert_eq!(classify_asn(asn), AsnCategory::Origin, "{asn}");
        }
    }

    #[test]
    fn unknown_asn_defaults_to_origin() {
        // The load-bearing rule: "not observable" is a positive assertion we
        // only make for a NAMED proxy or shared cloud. A random ASN is measured.
        assert_eq!(classify_asn("999999"), AsnCategory::Origin);
        assert_eq!(classify_asn(""), AsnCategory::Origin);
    }

    #[test]
    fn as_prefix_and_case_are_normalized() {
        assert_eq!(classify_asn("AS13335"), AsnCategory::ProxyEdge);
        assert_eq!(classify_asn("as16509"), AsnCategory::SharedCloudAmbiguous);
        assert_eq!(classify_asn(" 13335 "), AsnCategory::ProxyEdge);
    }
}
