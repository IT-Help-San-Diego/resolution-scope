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
# guard exists to prevent, and with three sibling crates and no workspace a
# workspace-level test is unavailable. So this script ENUMERATES crates:
# every directory holding a Cargo.toml except engine/ is scanned. A new
# renderer crate (web, flipper) is covered the day its Cargo.toml exists —
# by default, not by memory.
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

fail=0
scanned=0

# Every crate root = a directory containing a Cargo.toml at ANY depth from the
# repo root (engine/Cargo.toml, tui/Cargo.toml, native/Cargo.toml, future
# web/Cargo.toml, web/server/Cargo.toml, flipper/Cargo.toml, ...). The only
# exclusion is target/ (build artifacts).
while IFS= read -r manifest; do
    crate_dir="$(dirname "$manifest")"
    crate_name="$(basename "$crate_dir")"
    if [ "$crate_name" = "engine" ]; then
        continue # the single licensed producer of citations
    fi
    scanned=$((scanned + 1))
    src_dir="$crate_dir/src"
    if [ ! -d "$src_dir" ]; then
        echo "✗ $crate_name: has Cargo.toml but no src/ — cannot scan; failing closed"
        fail=1
        continue
    fi
    # Scan each .rs file whole: read it, strip newlines, then match. This
    # catches citations split across source lines (arm 6 of the six-arm test).
    hits=""
    while IFS= read -r src_file; do
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
    done < <(find "$src_dir" -name '*.rs' | sort)

    if [ -n "$hits" ]; then
        echo "✗ $crate_name: RFC citation literal(s) outside the engine:"
        echo "$hits" | sed 's/^/    /' | sed '/^$/d'
        echo "    Citations live in engine/src/truth_chain.rs (layer 1 of the"
        echo "    truth chain); render from the model instead."
        fail=1
    else
        echo "✓ $crate_name: no RFC citation literals in src/"
    fi
done < <(find . -name Cargo.toml -not -path '*/target/*' | sort)

# Apparatus check: a gate that enumerated nothing must fail, not pass —
# "could this command have succeeded while measuring nothing?"
if [ "$scanned" -eq 0 ]; then
    echo "✗ no non-engine crates found — the enumeration is broken; failing closed"
    exit 1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "CITATION BOUNDARY: PASSED ($scanned non-engine crate(s) scanned)"
