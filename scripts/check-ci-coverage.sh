#!/usr/bin/env bash
# check-ci-coverage.sh — every CI job must be GATED, not merely run.
#
# WHY. `ci-ok` is the single required context branch protection asks for. A job
# that is DEFINED but missing from ci-ok's `needs` still runs, still shows a
# green tick on the PR, and gates NOTHING — it can go red while ci-ok goes
# green and the PR merges. This repository has recorded that exact defect
# before, on the seal-scheme-consistency job, and caught it by hand.
#
# Now that branch protection requires ci-ok and nothing else, the cost of that
# mistake is no longer "a check nobody noticed" — it is a merge that protection
# believes it verified.
#
# The check is a set comparison and needs no network: every job except ci-ok
# must appear in ci-ok's needs, and every entry in needs must name a real job.
# It fails closed if it cannot parse the file or finds no jobs at all.

set -uo pipefail
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "FAIL: not inside a git work tree — refusing to run against an unknown source" >&2; exit 2; }
CI="${1:-$ROOT/.github/workflows/ci.yml}"
[ -f "$CI" ] || { echo "FAIL: no such workflow: $CI" >&2; exit 2; }

command -v ruby >/dev/null || { echo "FAIL: ruby is required to parse the workflow YAML" >&2; exit 2; }

# -EUTF-8: ruby -e defaults to US-ASCII and these messages carry em dashes;
# without it the script dies on its own diagnostics rather than on a finding.
ruby -EUTF-8 -ryaml -e '
  ci = ARGV[0]
  begin
    d = YAML.load_file(ci)
  rescue => e
    warn "FAIL: could not parse #{ci}: #{e.message}"; exit 2
  end
  jobs = (d["jobs"] || {}).keys
  if jobs.empty?
    warn "FAIL: found ZERO jobs -- the parser and the file disagree"; exit 1
  end
  unless jobs.include?("ci-ok")
    warn "FAIL: no ci-ok job -- the single required context is missing"; exit 1
  end
  needs = d["jobs"]["ci-ok"]["needs"]
  needs = [needs] if needs.is_a?(String)
  if needs.nil? || needs.empty?
    warn "FAIL: ci-ok requires nothing -- it would go green on its own"; exit 1
  end
  others  = jobs - ["ci-ok"]
  ungated = others - needs
  ghosts  = needs - others
  fails = 0
  ungated.each do |j|
    warn "FAIL: job \"#{j}\" is defined but NOT in ci-ok needs -- it runs, shows green, and gates nothing"
    fails += 1
  end
  ghosts.each do |j|
    warn "FAIL: ci-ok needs \"#{j}\" but no such job is defined -- a required gate that cannot report"
    fails += 1
  end
  exit 1 if fails > 0
  puts "check-ci-coverage: OK -- #{others.size} jobs, all listed in ci-ok needs, no ghosts"
' "$CI"
