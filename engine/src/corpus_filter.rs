//! Corpus exclusion filter for the Resolution Scope engine.
//!
//! PURPOSE: domains on the exclusion list are experimental fixtures, test
//! vectors, or otherwise ineligible for corpus statistics. They must not be
//! scored, stored, or submitted — a fixture that could count as a discovery
//! is manufactured evidence (the "AI badge cheat" this project rejects).
//!
//! The exclusion is a STATIC LIST BY DESIGN: no environment variables, no
//! runtime config, no database. Changing the list requires a code change and
//! a PR — the intended forcing function, so exclusions are reviewable claims
//! rather than deployment knobs.
//!
//! MATCHING RULES:
//!   1. Case-insensitive ASCII comparison after lowercasing.
//!   2. Exact match: "pq.resolutionscope.com" matches itself.
//!   3. Subdomain match: an entry also matches any of its subdomains
//!      ("sub.pq.resolutionscope.com"), so a fixture's whole subtree is out.
//!   4. Anchoring prevents upward propagation: the production apex
//!      "resolutionscope.com" is NEVER matched by an entry below it.

/// Domains excluded from the corpus.
///
/// Current exclusions:
///   - `pq.resolutionscope.com` — window 1: the ML-DSA-44 (algorithm 18)
///     experiment zone, frozen live as the leave-live baseline (Science
///     condition, 2026-08-31). Its signed TXT self-declares
///     `purpose=field-specimen-only; corpus-excluded=YES`; this module makes
///     that claim mechanical.
///   - `pq2.resolutionscope.com` — window 2: the reset specimen (dual-NS,
///     sidecars, DS TTL 900). Same fixture class, same exclusion.
pub const CORPUS_EXCLUDED_DOMAINS: &[&str] = &["pq.resolutionscope.com", "pq2.resolutionscope.com"];

/// Returns `true` if `domain` is on the corpus exclusion list.
///
/// Matching is case-insensitive; both exact matches and subdomain matches of
/// listed entries return `true`.
pub fn is_corpus_excluded(domain: &str) -> bool {
    let domain_lower = domain.trim_end_matches('.').to_lowercase();
    for &excluded in CORPUS_EXCLUDED_DOMAINS {
        let excluded_lower = excluded.to_lowercase();
        if domain_lower == excluded_lower {
            return true;
        }
        let suffix = format!(".{excluded_lower}");
        if domain_lower.ends_with(&suffix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Positive cases (should be excluded) ─────────────────────────────

    #[test]
    fn exact_match_excluded() {
        assert!(is_corpus_excluded("pq.resolutionscope.com"));
        assert!(is_corpus_excluded("pq2.resolutionscope.com"));
    }

    #[test]
    fn exact_match_uppercase_excluded() {
        assert!(is_corpus_excluded("PQ.RESOLUTIONSCOPE.COM"));
        assert!(is_corpus_excluded("PQ2.RESOLUTIONSCOPE.COM"));
    }

    #[test]
    fn exact_match_mixed_case_excluded() {
        assert!(is_corpus_excluded("Pq.ResolutionScope.Com"));
    }

    #[test]
    fn exact_match_with_trailing_dot_excluded() {
        assert!(is_corpus_excluded("pq.resolutionscope.com."));
    }

    #[test]
    fn subdomain_of_excluded_is_excluded() {
        assert!(is_corpus_excluded("sub.pq.resolutionscope.com"));
        assert!(is_corpus_excluded("deep.a.pq2.resolutionscope.com"));
    }

    // ── Negative cases (should NOT be excluded) ──────────────────────────

    #[test]
    fn production_apex_not_excluded() {
        // The production domain must NOT be filtered.
        assert!(!is_corpus_excluded("resolutionscope.com"));
    }

    #[test]
    fn other_subdomain_of_apex_not_excluded() {
        assert!(!is_corpus_excluded("api.resolutionscope.com"));
        assert!(!is_corpus_excluded("www.resolutionscope.com"));
        assert!(!is_corpus_excluded("mx.dane.resolutionscope.com"));
    }

    #[test]
    fn example_com_not_excluded() {
        assert!(!is_corpus_excluded("example.com"));
    }

    #[test]
    fn empty_string_not_excluded() {
        assert!(!is_corpus_excluded(""));
    }

    #[test]
    fn similar_but_different_domain_not_excluded() {
        // Lookalikes must NOT match.
        assert!(!is_corpus_excluded("pq.resolutionscope.net"));
        assert!(!is_corpus_excluded("pq-resolutionscope.com"));
    }

    #[test]
    fn suffix_without_dot_separator_not_excluded() {
        // No dot boundary → not a subdomain of the entry.
        assert!(!is_corpus_excluded("notpq.resolutionscope.com"));
    }

    #[test]
    fn all_current_exclusions_are_excluded() {
        // The list must satisfy its own invariant: every entry excludes itself.
        for &domain in CORPUS_EXCLUDED_DOMAINS {
            assert!(
                is_corpus_excluded(domain),
                "CORPUS_EXCLUDED_DOMAINS entry '{domain}' failed its own exclusion check"
            );
        }
    }
}
