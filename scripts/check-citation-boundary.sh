#!/usr/bin/env bash
# check-citation-boundary.sh — the truth-chain citation boundary, repo-wide.
#
# RFC citations are layer-1 facts of the truth-chain contract (ARCHITECTURE.md
# §8) and live in ONE place: engine/src/truth_chain.rs. A renderer crate that
# holds its own "RFC <n>" string has forked the requirement layer, and forks
# go stale silently (the DMARC 7489→9989 obsolescence was caught by audit, not
# by a failure — this script is what makes the next one a failure).
#
# Per-crate copies of a guard test are the hand-maintained-mirror pattern the
# guard exists to prevent, and with sibling crates and no workspace a
# workspace-level test is unavailable. So this script ENUMERATES crates:
# every directory holding a Cargo.toml except engine/ and types/ is scanned.
# A new renderer crate (web, flipper) is covered the day its Cargo.toml exists
# — by default, not by memory.
#
# Written for bash 3.2 (macOS ships it): no mapfile, no assoc arrays.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# An RFC citation is "RFC" followed (optionally after whitespace) by digits.
# Case-sensitive: the lowercase "rfc" render label in the TUI is a field name,
# not a citation.
#
# GAP FIX 1 (depth): find -maxdepth 2 misses nested manifests like
# web/server/Cargo.toml. Dropping the cap discovers every crate at any depth.
#
# GAP FIX 2 (split-line): grep is line-bound, so "RFC\n9989" passes. We read
# each file whole, strip newlines, then match against the collapsed string.
# This catches citations split across source lines without false-positive on
# the bare word "RFC" (no digit follows in the collapsed text).
PATTERN='RFC[[:space:]]*[0-9]'

# Positive control: the matcher must fire on a known citation, or the gate
# could pass by matching nothing. A guard never watched failing is a guard
# that cannot fail — this is the bash equivalent of the Rust test's
# matcher_detects_real_citations, kept here so the single authority is
# self-verifying after the per-crate test was removed.
if ! printf 'Optional (RFC 9989)' | grep -qE "$PATTERN"; then
    echo "✗ matcher self-test failed: PATTERN '$PATTERN' does not match a real citation"
    exit 1
fi
if printf '  rfc        ' | grep -qE "$PATTERN"; then
    echo "✗ matcher self-test failed: PATTERN matched the bare field label 'rfc' (false positive)"
    exit 1
fi

fail=0
scanned=0
files_scanned=0

# Every crate root = a directory containing a Cargo.toml at ANY depth from the
# repo root (engine/Cargo.toml, tui/Cargo.toml, native/Cargo.toml, future
# web/Cargo.toml, web/server/Cargo.toml, flipper/Cargo.toml, ...). The only
# exclusion is target/ (build artifacts).
while IFS= read -r manifest; do
    crate_dir="$(dirname "$manifest")"
    crate_name="$(basename "$crate_dir")"
    # The carve-out is by EXACT PATH, not basename. Matching on basename
    # exempted any crate named engine/ or types/ at ANY depth — a future
    # web/types/ or render/engine/ would have been skipped silently, with no
    # line printed and no contribution to the count, which is the quietest way
    # a boundary check can be defeated. Measured 2026-09-05.
    crate_rel="${crate_dir#./}"
    if [ "$crate_rel" = "engine" ] || [ "$crate_rel" = "types" ]; then
        # Licensed citation producers. engine/ holds the requirement layer
        # (truth_chain.rs) and the scoring logic; types/ holds the disposition
        # semantics, whose RFC citations live in the enum doc comments and move
        # WITH the type so the semantics and their authority stay colocated.
        continue
    fi
    scanned=$((scanned + 1))
    src_dir="$crate_dir/src"
    if [ ! -d "$src_dir" ]; then
        echo "✗ $crate_name: has Cargo.toml but no src/ — cannot scan; failing closed"
        fail=1
        continue
    fi
    # EVERY compiled path, not just src/. tests/, examples/, benches/ and a
    # crate-root build.rs are all Rust that cargo compiles, and none of them
    # was ever read. That was live, not hypothetical: pq-harness/tests/ is
    # tracked and exercised by the crates matrix, and an RFC literal placed
    # there left this gate green while the job's own name says "RFC literals
    # stay in the engine". Measured 2026-09-05, and measured again before
    # widening: zero existing literals live in these paths, so the extension
    # names no pre-existing violation.
    scan_dirs="$src_dir"
    for extra in tests examples benches; do
        [ -d "$crate_dir/$extra" ] && scan_dirs="$scan_dirs $crate_dir/$extra"
    done
    # Scan each .rs file whole: read it, strip newlines, then match. This
    # catches citations split across source lines (arm 6 of the six-arm test).
    hits=""
    crate_files=0
    while IFS= read -r src_file; do
        files_scanned=$((files_scanned + 1))
        crate_files=$((crate_files + 1))
        # Read the file, collapse newlines to nothing, then test the pattern.
        collapsed=$(tr -d '\n\r' < "$src_file")
        if printf '%s' "$collapsed" | grep -qE "$PATTERN" 2>/dev/null; then
            # Also run line-bound grep for the human-readable file:line output.
            line_hits=$(grep -nE "$PATTERN" "$src_file" 2>/dev/null) || true
            if [ -n "$line_hits" ]; then
                hits="$hits$line_hits"$'\n'
            else
                # The match was split across lines — name the file.
                hits="$hits${src_file}: (citation split across lines)$'\n'"
            fi
        fi
    done < <( { find $scan_dirs -name '*.rs'; [ -f "$crate_dir/build.rs" ] && echo "$crate_dir/build.rs"; } | sort )

    if [ -n "$hits" ]; then
        echo "✗ $crate_name: RFC citation literal(s) outside the engine:"
        echo "$hits" | sed 's/^/    /' | sed '/^$/d'
        echo "    Citations live in engine/src/truth_chain.rs (layer 1 of the"
        echo "    truth chain); render from the model instead."
        fail=1
    elif [ "$crate_files" -eq 0 ]; then
        # A crate whose compiled paths hold no .rs files at all reported ✓ and
        # incremented the crate count. The check counted CRATES, never FILES,
        # so "8 crates scanned" could mean eight directories and zero reads —
        # a pass by finding nothing, which is the defect this gate exists to
        # prevent, in the gate.
        echo "✗ $crate_name: zero .rs files found across src/, tests/, examples/, benches/, build.rs — cannot scan; failing closed"
        fail=1
    else
        echo "✓ $crate_name: no RFC citation literals ($crate_files file(s): src/, tests/, examples/, benches/, build.rs)"
    fi
done < <(find . -name Cargo.toml -not -path '*/target/*' | sort)

# Apparatus check: a gate that enumerated nothing must fail, not pass —
# "could this command have succeeded while measuring nothing?"
if [ "$scanned" -eq 0 ]; then
    echo "✗ no non-engine/types crates found — the enumeration is broken; failing closed"
    exit 1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "CITATION BOUNDARY: PASSED ($scanned non-engine/types crate(s), $files_scanned file(s) read)"
