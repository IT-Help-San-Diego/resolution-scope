#!/usr/bin/env python3
"""Arm 1 — eight-control N-version differential (Rust engine vs Go reference).

Corpus: the frozen golden fixtures (Go reference, content-addressed via
`manifest.json` + per-analysis X-SHA3-512) against the live Rust engine.

The 2026-08-21 rulings are wired as MECHANICAL exclusion branches, not prose:
  1. DANE `NotApplicable` (null-MX / no-mail) — Rust emits a fourth state the
     Go three-state vocabulary cannot express. EXCLUDED WITH A COUNT, never
     folded into `Absent` (HANDOFF_arm1.md constraint #2).
  2. DKIM `Wildcard` — a wildcard `*._domainkey` makes the 81-selector sweep
     non-probative on both engines (Rust `Wildcard` disposition; Go
     `wildcard_dkim=true`). EXCLUDED WITH A COUNT (claude-science ruling:
     vocabulary-width difference, not a defect against either engine).

Per-control agreement rates ONLY, never an aggregate (CALIBRATION-STUDY-SPEC
constraint #3). Disagreements are reported raw and marked "needs live arbiter",
never auto-scored against either side (constraint #6). The raw table is
published; the rate is derived, never stored as prose (constraint #5).

Usage:
    python3 scripts/arm1_differential.py            # run over all 8 fixtures
    python3 scripts/arm1_differential.py --domain example.com   # one domain
    python3 scripts/arm1_differential.py --out /path/arm1-sealed.json

Output: a human table to stdout + a sealed JSON (per-domain, per-control,
exclusion-classified) to `docs/arm1-20260821/arm1-join-<date>.json`.
"""
import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

FIXTURES = '/Users/careybalboa/Documents/GitHub/dns-tool-intel/tests/golden_fixtures'
BIN = os.path.expanduser(
    '~/Documents/GitHub/resolution-scope/cli/target/debug/resolution-scope')

# The eight-control join contract. `go_key` is the full_results member; `go_field`
# is the verdict field within it; `rust_key` is the ScoredAnalysis tri-state key.
# `rust_disp` is the disposition key consulted for exclusion decisions.
ARMS = [
    # (name, rust_key, rust_disp, go_key, go_field)
    ('dnssec', 'dnssec_chain', 'dnssec_disposition', 'dnssec_analysis', 'dnssec_state'),
    ('spf', 'spf', 'spf_disposition', 'spf_analysis', 'spf_state'),
    ('dkim', 'dkim', 'dkim_disposition', 'dkim_analysis', 'dkim_state'),
    ('dmarc', 'dmarc', 'dmarc_disposition', 'dmarc_analysis', 'dmarc_state'),
    ('dane', 'dane', 'dane_disposition', 'dane_analysis', 'dane_state'),
    ('mta_sts', 'mta_sts', 'mta_sts_disposition', 'mta_sts_analysis', 'mta_sts_state'),
    ('caa', 'caa', 'caa_disposition', 'caa_analysis', 'caa_state'),
    # CDS/CDNSKEY has no *_state field in Go: it publishes has_cds / has_cdnskey.
    ('cds_cdnskey', 'cds_cdnskey', 'cds_disposition', 'cds_cdnskey', None),
]


def go_tri_state(analysis, field):
    """Map a Go *_state value (or the CDS has_cds bool) to the Rust TriState."""
    if analysis is None:
        return 'Indet'
    if field is None:
        # CDS/CDNSKEY: has_cds is the publication signal.
        has_cds = analysis.get('has_cds')
        if has_cds is True:
            return 'Present'
        if has_cds is False:
            return 'Absent'
        return 'Indet'
    state = analysis.get(field)
    if state == 'present':
        return 'Present'
    if state == 'absent_confirmed':
        return 'Absent'
    return 'Indet'


def rust_run(domain):
    """Run the Rust engine on one domain, return the ScoredAnalysis dict."""
    try:
        r = subprocess.run(
            [BIN, '-d', domain, '--format', 'json'],
            capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f'ERR {e}'
    # NDJSON: one compact object per domain. Take the first line that parses.
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if 'domain' in doc:
            return doc, None
    return None, 'NO_JSON'


def exclusion_reason(arm, rust, go_analysis):
    """Return a non-empty reason if this (arm, domain) row is an exclusion."""
    if arm == 'dane':
        if rust.get('dane') == 'NotApplicable':
            return 'dane_not_applicable_null_mx'
    if arm == 'dkim':
        if rust.get('dkim_disposition') == 'Wildcard':
            return 'dkim_wildcard_rust'
        if go_analysis is not None and go_analysis.get('wildcard_dkim') is True:
            return 'dkim_wildcard_go'
    return None


def fixture_domains():
    """Read the golden fixtures into {domain: full_results} (filename is
    authoritative: cia_gov.json -> cia.gov)."""
    domains = {}
    for path in sorted(glob.glob(os.path.join(FIXTURES, '*.json'))):
        if path.endswith('manifest.json'):
            continue
        fx = json.load(open(path))
        stem = os.path.basename(path)[:-5]
        head, _, tld = stem.rpartition('_')
        domain = head.replace('_', '.') + '.' + tld
        domains[domain] = fx.get('full_results', fx)
    return domains


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--domain', default=None)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()

    fixtures = fixture_domains()
    if args.domain:
        fixtures = {args.domain: fixtures.get(args.domain, {})}

    rows = []          # per (domain, arm) verdict rows
    exclusions = {}    # reason -> count
    agreement = {arm: {'agree': 0, 'total': 0, 'disagree': 0} for arm, *_ in ARMS}

    for domain, fr in sorted(fixtures.items()):
        rust, err = rust_run(domain)
        if rust is None:
            print(f'{domain:28} NO_RUST ({err})')
            continue
        for arm, rust_key, rust_disp, go_key, go_field in ARMS:
            go_analysis = fr.get(go_key)
            go_tri = go_tri_state(go_analysis, go_field)
            rust_tri = rust.get(rust_key, '?')
            exc = exclusion_reason(arm, rust, go_analysis)
            if exc:
                exclusions[exc] = exclusions.get(exc, 0) + 1
                rows.append({'domain': domain, 'arm': arm,
                             'go': go_tri, 'rust': rust_tri,
                             'verdict': 'EXCLUDED', 'reason': exc,
                             'rust_disposition': rust.get(rust_disp)})
                continue
            if rust_tri == go_tri:
                verdict = 'PARITY'
                agreement[arm]['agree'] += 1
            else:
                verdict = 'DISAGREE — needs live arbiter'
                agreement[arm]['disagree'] += 1
            agreement[arm]['total'] += 1
            rows.append({'domain': domain, 'arm': arm,
                         'go': go_tri, 'rust': rust_tri,
                         'verdict': verdict, 'reason': None,
                         'rust_disposition': rust.get(rust_disp)})

    # ── human table ──────────────────────────────────────────────────────────
    print(f"{'domain':28} {'arm':10} {'Go':10} {'Rust':12} {'verdict'}")
    print('-' * 92)
    for r in rows:
        print(f"{r['domain']:28} {r['arm']:10} {r['go']:10} {r['rust']:12} {r['verdict']}")

    print('-' * 92)
    print('PER-CONTROL AGREEMENT (exclusions removed from the denominator):')
    for arm, *_ in ARMS:
        a = agreement[arm]
        rate = (a['agree'] / a['total'] * 100) if a['total'] else float('nan')
        print(f"  {arm:10} {a['agree']}/{a['total']} = {rate:5.1f}%   "
              f"({a['disagree']} disagreement(s))")

    print()
    print('EXCLUSIONS (counted, never folded into a verdict):')
    for reason, n in sorted(exclusions.items()):
        print(f"  {reason}: {n}")

    # ── sealed JSON output ───────────────────────────────────────────────────
    payload = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'tool': 'scripts/arm1_differential.py',
        'rust_binary': BIN,
        'fixtures_dir': FIXTURES,
        'arms': [a[0] for a in ARMS],
        'exclusion_rules': {
            'dane_not_applicable_null_mx': 'Rust dane==NotApplicable (null-MX no-mail)',
            'dkim_wildcard_rust': 'Rust dkim_disposition==Wildcard',
            'dkim_wildcard_go': 'Go wildcard_dkim==true',
        },
        'agreement': agreement,
        'exclusions': exclusions,
        'rows': rows,
    }
    payload_bytes = json.dumps(payload, indent=1, sort_keys=True).encode()
    seal = hashlib.sha3_512(payload_bytes).hexdigest()
    payload['sha3_512'] = seal

    out = args.out or os.path.expanduser(
        f'~/Documents/GitHub/resolution-scope/docs/arm1-20260821/'
        f'arm1-join-{datetime.now(timezone.utc).strftime("%Y%m%d")}.json')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(payload, open(out, 'w'), indent=1, sort_keys=True)
    print(f'\nsealed -> {out}')
    print(f'sha3-512 = {seal}')


if __name__ == '__main__':
    main()
