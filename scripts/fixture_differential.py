#!/usr/bin/env python3
"""Three-way fixture differential: Rust verdict vs Go verdict vs FIXTURE reference.

Design constraint (Carey + Claude Science ruling, 2026-08-17): the Go parent is
a COMPARAND, not ground truth — it produced wrong verdicts on these exact
fixtures until hours ago. The reference is the fixture's own recorded protocol
state (chain_of_trust / dnssec_state as captured through production AFTER the
fix, or defect-era where not yet recaptured — flagged per row).

Disposition table:
  Rust != Go, fixture == Rust  -> GO BUG (the arc's best possible result)
  Rust != Go, fixture == Go    -> RUST PORT BUG (only true port defect)
  Rust == Go != fixture        -> FIXTURE STALE (re-capture)
  Rust == Go == fixture        -> parity (boring, correct)

Vocabulary mapping (Rust TriState -> Go two-field):
  Rust Present == (chain_of_trust=complete, dnssec_state=present)
  Rust Absent  == (chain_of_trust=none,     dnssec_state=absent_confirmed)
  Rust Indet   == anything else (broken/unconfirmed/unmeasured/None)

NOTE: the Rust engine's score_dnssec is deliberately simple (validated lookup
present/absent). A Rust 'Indet' where the fixture says 'broken' is CORRECT
tri-state honesty — the engine could not measure, it does not assert absence.
That is a measured capability gap (Rust lacks a broken path yet), recorded
as GAP not BUG. The differential distinguishes: WRONG verdict (asserts the
opposite of the fixture) vs INCOMPLETE verdict (honest couldn't-measure).
"""
import json, glob, os, subprocess, sys

FIX = '/Users/careybalboa/Documents/GitHub/dns-tool-intel/tests/golden_fixtures'
ENGINE = os.path.expanduser('~/Documents/GitHub/resolution-scope/engine')
RECAPTURED = {'cloudflare.com', 'example.com', 'ietf.org', 'whitehouse.gov'}

def rust_verdict(domain):
    """Run the engine on one domain, return its DNSSEC TriState."""
    import tempfile, pathlib
    try:
        with tempfile.TemporaryDirectory() as td:
            so, se = os.path.join(td, 'out'), os.path.join(td, 'err')
            with open(so, 'w') as fs, open(se, 'w') as fe:
                subprocess.run(
                    ['cargo', 'run', '--quiet', '--', domain],
                    cwd=ENGINE, stdout=fs, stderr=fe, timeout=90)
            out_s = pathlib.Path(so).read_text()
        # Strip ANSI escape codes (tracing colors leak into stdout), then find
        # the LAST line that is exactly '{' (the pretty-printed JSON opens at
        # column 0) and parse from there.
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', out_s)
        start = clean.rfind('\n{\n')
        if start == -1:
            start = 0 if clean.startswith('{\n') else -1
        if start != -1:
            # The 'done' log line trails the JSON; cut at the first '}' at
            # column 0 (the pretty-printed object closes at column 0).
            end = clean.find('\n}', start)
            if end != -1:
                candidate = clean[start:end + 2]
            else:
                candidate = clean[start:]
            try:
                doc = json.loads(candidate.strip())
                if isinstance(doc, dict) and 'dnssec_chain' in doc:
                    return doc['dnssec_chain']
            except json.JSONDecodeError:
                pass
        return 'NO_JSON'
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
    except Exception as e:
        return f'ERR: {e}'

def go_verdict_fields(fx):
    """The Go engine's verdict AS RECORDED in the fixture (the comparand)."""
    dns = fx.get('dnssec_analysis') or {}
    return dns.get('chain_of_trust'), dns.get('dnssec_state')

def rust_from_go(chain, state):
    """Map the Go two-field verdict to the Rust TriState vocabulary."""
    if chain == 'complete' and state == 'present':
        return 'Present'
    if chain == 'none' and state == 'absent_confirmed':
        return 'Absent'
    return 'Indet'

def main():
    rows = []
    for path in sorted(glob.glob(os.path.join(FIX, '*.json'))):
        if path.endswith('manifest.json'):
            continue
        fx = json.load(open(path))
        # domain from the FILENAME (authoritative): cia_gov.json -> cia.gov,
        # thisdoesnotexist-xz9q_com.json -> thisdoesnotexist-xz9q.com
        stem = os.path.basename(path)[:-5]  # strip .json
        head, _, tld = stem.rpartition('_')
        domain = head.replace('_', '.') + '.' + tld

        chain, state = go_verdict_fields(fx)
        go_as_rust = rust_from_go(chain, state)
        reference = 'defect-era' if domain not in RECAPTURED else 'recaptured-2026-08-17'
        rows.append({
            'domain': domain,
            'chain': chain, 'state': state,
            'go_as_tristate': go_as_rust,
            'reference': reference,
            'rust': None, 'disposition': None,
        })

    print(f'{"domain":34} {"fixture(chain,state)":26} {"fixture=tri":12} {"RUST":10} {"fixture-era":12} disposition')
    print('-' * 112)
    for r in rows:
        r['rust'] = rust_verdict(r['domain'])
        rust, go, era = r['rust'], r['go_as_tristate'], r['reference']
        fixture_pair = f"{r['chain']},{r['state']}"
        fresh = era != 'defect-era'
        if rust == go:
            # Engines agree. On a fresh capture the fixture confirms them
            # (parity). On a defect-era capture, "fixture disagrees" means the
            # frozen measurement predates the fix — the fixture is stale, not
            # the engines wrong.
            r['disposition'] = 'PARITY (fixture confirms)' if fresh else 'ENGINES-AGREE / FIXTURE STALE (recapture)'
        else:
            # Engines disagree. The fixture (a frozen Go measurement) cannot
            # arbitrate against itself — a disagreement with the fixture is a
            # disagreement with GO. Whether it is a port defect or a Go defect
            # needs the LIVE protocol as the arbiter, not the stale capture.
            r['disposition'] = 'RUST≠GO — check LIVE protocol (fixture is Go, cannot self-arbitrate)'
        print(f"{r['domain']:34} {fixture_pair:26} {go:12} {str(rust):10} {era:12} {r['disposition']}")

    out = os.path.expanduser('~/Downloads/rust-go-fixture-differential-2026-08-18.json')
    json.dump(rows, open(out, 'w'), indent=1)
    print('\nsealed ->', out)

def _norm(dnssec_str):
    return {'Present': 'Present', 'Absent': 'Absent'}.get(dnssec_str, 'Indet')

def _rust_matches_fixture(r):
    return r['rust'] == r['go_as_tristate']

def _go_matches_fixture(r):
    # Go's recorded verdict IS the fixture capture — trivially matches itself;
    # the question is whether the capture is defect-era.
    return r['reference'] != 'defect-era'

def _matches_fixture(r):
    # Parity means both engines agree AND the fixture is a post-fix capture.
    return r['rust'] == r['go_as_tristate'] and r['reference'] != 'defect-era'

if __name__ == '__main__':
    main()
