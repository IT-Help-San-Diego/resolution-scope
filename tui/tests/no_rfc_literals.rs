// no_rfc_literals.rs — build-enforced single-producer guard (ARCHITECTURE.md §8).
//
// The truth-chain contract names one producer of verdict meaning:
// engine/src/truth_chain.rs. The RFC-requirement layer ("Optional (RFC 9989)…")
// is part of that meaning — a citation is a CLAIM, and a claim belongs where it
// is authored once, audited once, and fixed once. Before this guard, the RFC
// strings lived in the TUI as shipped literals; relocating them into the engine
// (commit a6c1e0c) is only durable if a SECOND renderer cannot silently
// reintroduce the same class by copying them back (meta-pattern item 2).
//
// This test fails if any RFC citation — `RFC` followed by a number — appears in
// a string literal in this renderer crate's source. It is the same shape as the
// negative `required-features` assertion: the single-producer rule stops being
// enforced by intention and becomes enforced by the build. Every future
// surface (website, flipper) gets a copy of this file.
//
// Scope note: this matches an RFC *citation* (RFC + digits), not the bare word
// "rfc" — the detail view carries a lowercase "rfc" field LABEL (main.rs), which
// is layout chrome, not a citation. The renderer READS engine.rfc_requirement;
// it must never author its own.

use std::fs;
use std::path::Path;

/// `RFC` (any case) optionally followed by whitespace, then a digit — the shape
/// of a citation like "RFC 9989" or "rfc7489". Deliberately does NOT match the
/// bare word "rfc" used as a UI field label.
fn contains_rfc_citation(line: &str) -> bool {
    let bytes = line.as_bytes();
    let lower = line.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let mut i = 0;
    while i + 3 <= lb.len() {
        if &lb[i..i + 3] == b"rfc" {
            // Skip optional whitespace after "rfc".
            let mut j = i + 3;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j].is_ascii_digit() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Recursively collect every `.rs` file under a directory.
fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// No RFC citation may appear in this renderer crate's source. The engine is the
/// single producer of the RFC-requirement layer; a renderer that authors its own
/// citation is out of contract (and would silently drift from the engine's
/// audited, current-status text).
#[test]
fn renderer_holds_no_rfc_citations() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(src.is_dir(), "expected renderer src/ at {}", src.display());

    let mut files = Vec::new();
    rs_files(&src, &mut files);
    assert!(
        !files.is_empty(),
        "found no .rs files under {} — the scanner measured nothing",
        src.display()
    );

    let mut offenders = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read source file");
        for (n, line) in text.lines().enumerate() {
            if contains_rfc_citation(line) {
                offenders.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "RFC citations found in the renderer — the truth-chain contract keeps ALL \
         RFC-requirement text in engine/src/truth_chain.rs (the single producer). \
         Read the RFC from the engine's ControlReport.rfc_requirement instead of \
         authoring a citation here:\n{}",
        offenders.join("\n")
    );
}

/// Positive control: the matcher must actually fire on real citations, or the
/// guard above could pass by measuring nothing. A guard never watched failing
/// is a guard that cannot fail.
#[test]
fn matcher_detects_real_citations() {
    // Real citation shapes that MUST be caught.
    assert!(contains_rfc_citation("Optional (RFC 9989). TXT at _dmarc"));
    assert!(contains_rfc_citation("obsoletes rfc7489"));
    assert!(contains_rfc_citation("see RFC\t8659 for CAA"));
    // The bare field label and prose "RFC" (no number) must NOT be caught —
    // those are layout chrome, not citations.
    assert!(!contains_rfc_citation("  rfc        "));
    assert!(!contains_rfc_citation("the full truth chain — RFC"));
    assert!(!contains_rfc_citation("no citation here"));
}
