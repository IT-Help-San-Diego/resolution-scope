#!/usr/bin/env python3
"""Full-arm differential: Rust engine vs Go fixture vs live protocol.

Extends fixture_differential.py past DNSSEC to SPF/DMARC/DANE/CAA/MTA-STS.
The Go fixture's `*_state` fields are the comparand (frozen Go measurement);
the Rust engine's TriState output is the port under test; live protocol (dig)
is the arbiter on disagreement.

Mapping (Go `*_state` -> Rust TriState):
  present          -> Present
  absent_confirmed -> Absent
  anything else    -> Indet   (indeterminate/unmeasured/unconfirmed/None)

NOTE on scope:
- DANE now probes SMTP DANE (MX -> _25._tcp.<mx-host> TLSA, RFC 7672) — the
  same surface as Go. A remaining DANE disagreement is the "no-mail" edge
  (RFC 7505 null MX, or no MX record): Rust returns Indet (DANE not
  applicable, excluded from the score denominator), while Go records
  absent_confirmed. Deliberate: a non-mail domain should not be penalized
  for lacking mail DANE.
- MTA-STS uses the DNS TXT proxy (HTTP policy fetch deferred to Tier 2).
  The Go engine fetches https://mta-sts.<domain>/.well-known/mta-sts.txt, so
  a TXT-present-but-policy-unverified domain reads Indet here vs Go's
  present/absent. Genuine deferral, not a port defect.
"""
import json, glob, os, subprocess

FIX = '/Users/careybalboa/Documents/GitHub/dns-tool-intel/tests/golden_fixtures'
BIN = os.path.expanduser('~/Documents/GitHub/resolution-scope/engine/target/debug/resolution-scope-engine')

ARMS = {
    'spf': ('spf_analysis', 'spf_state'),
    'dmarc': ('dmarc_analysis', 'dmarc_state'),
    'caa': ('caa_analysis', 'caa_state'),
    'dane': ('dane_analysis', 'dane_state'),
    'mta_sts': ('mta_sts_analysis', 'mta_sts_state'),
}

def go_to_tri(state):
    if state == 'present':
        return 'Present'
    if state == 'absent_confirmed':
        return 'Absent'
    return 'Indet'

def rust_run(domain):
    r = subprocess.run([BIN, '--json', domain], capture_output=True, text=True, timeout=90)
    # tracing (INFO/WARN) goes to stderr now; stdout carries one compact JSON
    # object per domain. Find the line that parses and carries our fields.
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith('{') and 'dnssec_chain' in line:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None

def main():
    domains = {}
    for path in sorted(glob.glob(os.path.join(FIX, '*.json'))):
        if path.endswith('manifest.json'):
            continue
        fx = json.load(open(path))
        stem = os.path.basename(path)[:-5]
        head, _, tld = stem.rpartition('_')
        domain = head.replace('_', '.') + '.' + tld
        domains[domain] = fx.get('full_results', fx)

    print(f"{'domain':26} {'arm':8} {'Go':9} {'Rust':8} verdict")
    print('-' * 70)
    n_match = n_scope = n_real_diff = 0
    for domain, fr in sorted(domains.items()):
        rust = rust_run(domain)
        if rust is None:
            print(f"{domain:26} {'(all)':8} {'?':9} {'NO_RUST':8} engine failed to emit JSON")
            continue
        for arm, (key, state_key) in ARMS.items():
            go_state = (fr.get(key) or {}).get(state_key)
            go_tri = go_to_tri(go_state)
            rust_tri = rust.get(arm, '?')
            if rust_tri == go_tri:
                verdict = 'PARITY'
                n_match += 1
            elif arm in ('dane', 'mta_sts'):
                verdict = 'SCOPE-DIFF (different surface)'
                n_scope += 1
            else:
                verdict = 'REAL-DIFF — check live'
                n_real_diff += 1
            print(f"{domain:26} {arm:8} {str(go_tri):9} {str(rust_tri):8} {verdict}")

    print('-' * 70)
    print(f"parity={n_match} scope-diff={n_scope} real-diff={n_real_diff}")

if __name__ == '__main__':
    main()
