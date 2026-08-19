// name_similarity.rs — the impersonation name-similarity measurement.
//
// Levenshtein edit distance between two domain names: the minimum number of
// single-character insertions, deletions, or substitutions to turn one into the
// other. This is the MEASUREMENT behind the impersonation signal — a
// typosquatted domain sits a short edit distance from the established domain it
// imitates. It is a pure, database-independent function, so it can run against
// any reference corpus without a query.
//
// It is NOT a brand list. "edit-distance 1 from <older domain>" is a fact the
// reader can re-derive by running the same function over the same two names —
// the same standard as the dig commands in the confessions: a measurement with
// a named instrument, not an opinion with a maintainer. The two-signature
// threat model (impersonation + flux) pairs this with the OTHER impersonation
// facts — registration age, missing SPF/DMARC/DNSSEC, cheap/abused TLD,
// add-period lifecycle — and name-similarity alone proves nothing.
//
// Ported from dns-tool-intel analyzer/name_similarity.go (#441), which shipped
// the same standalone function in Go. Kept standalone here so the port is a
// faithful mirror: the impersonation-signal wiring (which reference corpus,
// what distance threshold) is a SEPARATE decision from the measurement.

/// Levenshtein edit distance, byte-based (matching the Go engine's semantics —
/// domain names are IDNA punycode ASCII, so bytes == characters here). Two-row
/// dynamic programming, bounded by the shorter string.
///
/// Degenerate cases: one empty string costs the other's full length.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    // Bound the DP by the shorter string (the inner row).
    let (a, b) = if a.len() < b.len() { (b, a) } else { (a, b) };
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut curr = vec![0usize; b.len() + 1];
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] != b[j - 1] { 1 } else { 0 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = curr;
    }
    prev[b.len()]
}

/// Edit distance after ASCII-lowercasing. DNS names are case-insensitive, so
/// "Google.com" and "google.com" are distance 0 — the normalization keeps the
/// comparison about the labels rather than the case.
pub fn domain_edit_distance(a: &str, b: &str) -> usize {
    edit_distance(&a.to_ascii_lowercase(), &b.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_cases() {
        let cases: &[(&str, &str, usize)] = &[
            ("", "", 0),              // both empty
            ("", "abc", 3),           // a empty
            ("abc", "", 3),           // b empty
            ("google", "google", 0),  // identical
            ("google", "go0gle", 1),  // substitution
            ("gogle", "google", 1),   // insertion
            ("google", "gogle", 1),   // deletion
            ("google", "goolge", 2),  // transposition = 2 swaps
            ("kitten", "sitting", 3), // classic
        ];
        for (a, b, want) in cases {
            assert_eq!(edit_distance(a, b), *want, "edit_distance({a:?}, {b:?})");
        }
    }

    #[test]
    fn domain_edit_distance_cases() {
        let cases: &[(&str, &str, usize)] = &[
            ("Google.com", "google.com", 0),             // case-insensitive
            ("google.com", "go0gle.com", 1),             // homoglyph substitution
            ("gogle.com", "google.com", 1),              // missing letter
            ("hermes-agent.com", "hermes-agnet.com", 2), // transposition
        ];
        for (a, b, want) in cases {
            assert_eq!(
                domain_edit_distance(a, b),
                *want,
                "domain_edit_distance({a:?}, {b:?})"
            );
        }
    }
}
