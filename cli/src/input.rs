//! input.rs — the instrument's input boundary.
//!
//! Everything a user types reaches the engine through `canonical_domain`.
//! Two reasons this is a boundary and not a convenience:
//!
//! 1. The engine seals the domain string VERBATIM (seal.rs binds
//!    `analysis.domain`), and the store keys history on it. `example.com`,
//!    `EXAMPLE.COM` and `example.com.` are one zone (DNS names are
//!    case-insensitive; the trailing dot is the same FQDN) but would produce
//!    three seals and three history lineages. Canonicalising here keeps one
//!    zone → one seal from this surface. (The engine-side canonicalisation is
//!    an engine-lane item; this boundary is the cli's own defence.)
//!
//! 2. A string that can never resolve — a pasted URL, an empty `$VAR`, a
//!    label with spaces — must be refused HERE with a message that names the
//!    fix. Sent onward, hickory's parse error surfaces through every control
//!    as "transient lookup error — re-run", which is false guidance: re-running
//!    cannot help. Refusing before any network is the honest answer.
//!
//! This module holds no verdict logic. It never touches a disposition.

use std::fmt;

/// Why an input was refused — each variant carries the fix in its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    Empty,
    Root,
    Whitespace(String),
    IpAddress(String),
    LooksLikeUrl(String),
    NotAscii(String),
    BadLabel { domain: String, label: String },
    TooLong(String),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Empty => write!(
                f,
                "empty domain — pass a name like `example.com` (an unset shell variable is the usual cause)"
            ),
            InputError::Root => write!(
                f,
                "`.` is the DNS root, not a zone to measure — pass a name like `example.com`"
            ),
            InputError::Whitespace(s) => write!(
                f,
                "{s:?} contains whitespace — one domain per argument (e.g. `resolution-scope a.com b.com`)"
            ),
            InputError::IpAddress(s) => write!(
                f,
                "{s:?} is an IP address — pass the zone name, not an address"
            ),
            InputError::LooksLikeUrl(s) => write!(
                f,
                "{s:?} looks like a URL or path — pass the bare domain name (e.g. `example.com`, not `https://example.com/`)"
            ),
            InputError::NotAscii(s) => write!(
                f,
                "{s:?} contains non-ASCII characters — pass the punycode form (`xn--…`) of an internationalised name"
            ),
            InputError::BadLabel { domain, label } => write!(
                f,
                "{domain:?} is not a valid DNS name: label {label:?} must be 1–63 characters of letters, digits, `-` or `_`, and must not start or end with `-`"
            ),
            InputError::TooLong(s) => write!(
                f,
                "{s:?} is longer than 253 characters — not a valid DNS name"
            ),
        }
    }
}

impl std::error::Error for InputError {}

/// Canonicalise one user-typed domain: trim whitespace, drop one trailing
/// dot, lowercase ASCII, and validate the label syntax. Returns the form the
/// engine will measure and seal.
pub fn canonical_domain(raw: &str) -> Result<String, InputError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(InputError::Empty);
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(InputError::Whitespace(trimmed.to_string()));
    }
    if trimmed.contains("://") || trimmed.contains('/') {
        return Err(InputError::LooksLikeUrl(trimmed.to_string()));
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        return Err(InputError::IpAddress(trimmed.to_string()));
    }
    if !trimmed.is_ascii() {
        return Err(InputError::NotAscii(trimmed.to_string()));
    }
    // One trailing dot is the FQDN marker; strip exactly one so "example.com."
    // and "example.com" canonicalise together, while "example.com.." still
    // fails the empty-label check below.
    let no_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    let lower = no_dot.to_ascii_lowercase();
    if lower.is_empty() {
        // The input was "." — the root. Scanning the root as a customer zone
        // grades mail posture on "." (a real failure mode, caught 2026-08-23).
        return Err(InputError::Root);
    }
    if lower.len() > 253 {
        return Err(InputError::TooLong(trimmed.to_string()));
    }
    for label in lower.split('.') {
        let ok_len = !label.is_empty() && label.len() <= 63;
        let ok_chars = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let ok_edges = !label.starts_with('-') && !label.ends_with('-');
        if !(ok_len && ok_chars && ok_edges) {
            return Err(InputError::BadLabel {
                domain: trimmed.to_string(),
                label: label.to_string(),
            });
        }
    }
    Ok(lower)
}

/// Canonicalise a whole list, refusing the first bad one with its reason.
pub fn canonical_domains(raw: &[String]) -> Result<Vec<String>, InputError> {
    raw.iter().map(|d| canonical_domain(d)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_zone_one_spelling() {
        // The three spellings that sealed differently on 2026-08-23.
        assert_eq!(canonical_domain("example.com").unwrap(), "example.com");
        assert_eq!(canonical_domain("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(canonical_domain("example.com.").unwrap(), "example.com");
        assert_eq!(canonical_domain("  Example.Com.  ").unwrap(), "example.com");
    }

    #[test]
    fn empty_and_root_are_refused() {
        // `-d ""` scanned the DNS root and graded it as a customer zone.
        assert_eq!(canonical_domain(""), Err(InputError::Empty));
        assert_eq!(canonical_domain("   "), Err(InputError::Empty));
        assert_eq!(canonical_domain("."), Err(InputError::Root));
    }

    #[test]
    fn urls_and_paths_are_refused_with_the_fix_named() {
        for s in ["https://example.com/", "example.com/path", "http://x"] {
            let e = canonical_domain(s).unwrap_err();
            assert!(matches!(e, InputError::LooksLikeUrl(_)), "{s}: {e:?}");
            assert!(e.to_string().contains("bare domain name"));
        }
        let e = canonical_domain("not a domain").unwrap_err();
        assert!(matches!(e, InputError::Whitespace(_)));
        assert!(e.to_string().contains("one domain per argument"));
        let e = canonical_domain("a.com\tb.com").unwrap_err();
        assert!(matches!(e, InputError::Whitespace(_)));
    }

    #[test]
    fn ip_addresses_are_refused() {
        for s in ["1.1.1.1", "::1", "2606:4700::1111"] {
            let e = canonical_domain(s).unwrap_err();
            assert!(matches!(e, InputError::IpAddress(_)), "{s}: {e:?}");
        }
    }

    #[test]
    fn bad_labels_are_refused() {
        assert!(matches!(
            canonical_domain("-bad.com"),
            Err(InputError::BadLabel { .. })
        ));
        assert!(matches!(
            canonical_domain("bad-.com"),
            Err(InputError::BadLabel { .. })
        ));
        assert!(matches!(
            canonical_domain("a..b"),
            Err(InputError::BadLabel { .. })
        ));
        assert!(matches!(
            canonical_domain("example.com.."),
            Err(InputError::BadLabel { .. })
        ));
        assert!(matches!(
            canonical_domain("-"),
            Err(InputError::BadLabel { .. })
        ));
        assert!(matches!(
            canonical_domain("..."),
            Err(InputError::BadLabel { .. })
        ));
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(matches!(
            canonical_domain(&long_label),
            Err(InputError::BadLabel { .. })
        ));
    }

    #[test]
    fn non_ascii_points_at_punycode() {
        let e = canonical_domain("bücher.de").unwrap_err();
        assert!(matches!(e, InputError::NotAscii(_)));
        assert!(e.to_string().contains("xn--"));
        assert_eq!(
            canonical_domain("xn--bcher-kva.de").unwrap(),
            "xn--bcher-kva.de"
        );
    }

    #[test]
    fn underscores_and_single_labels_are_allowed() {
        // Underscore-prefixed names exist in DNS; a TLD is a real zone.
        assert_eq!(
            canonical_domain("_dmarc.example.com").unwrap(),
            "_dmarc.example.com"
        );
        assert_eq!(canonical_domain("com").unwrap(), "com");
    }

    #[test]
    fn too_long_is_refused() {
        let s = format!("{}.com", vec!["abcdefghij"; 26].join("."));
        assert!(s.len() > 253);
        assert!(matches!(canonical_domain(&s), Err(InputError::TooLong(_))));
    }

    #[test]
    fn list_fails_on_first_bad_entry() {
        let raw = vec!["ok.com".to_string(), "".to_string(), "x.com".to_string()];
        assert_eq!(canonical_domains(&raw), Err(InputError::Empty));
        let raw = vec!["A.com".to_string(), "b.com.".to_string()];
        assert_eq!(canonical_domains(&raw).unwrap(), vec!["a.com", "b.com"]);
    }
}
