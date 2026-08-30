#!/usr/bin/env python3
import importlib.util
import sys
from pathlib import Path

MODULE = Path(__file__).with_name('pq_fixture_monitor.py')
spec = importlib.util.spec_from_file_location('pq_fixture_monitor', MODULE)
mon = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mon
spec.loader.exec_module(mon)


def obs(vantage, rrtype, answer_count, algorithms=None, ad=False, qname=None):
    return mon.DigObservation(
        timestamp='2026-08-30T00:00:00Z',
        vantage=vantage,
        resolver='test',
        rrtype=rrtype,
        qname=qname or mon.DOMAIN,
        rcode='NOERROR',
        ad=ad,
        aa=False,
        tc=False,
        answer_count=answer_count,
        algorithms=algorithms or [],
        keytags=[],
        soa_minimum=None,
        soa_ttl=None,
        raw_answer=[],
        raw_authority=[],
    )


def test_classifies_unsigned_child_with_authenticated_parent_denial():
    observations = [
        obs('route53-parent', 'DS', 0, ad=True),
        obs('route53-parent', 'DS', 0, ad=True),
        obs('authoritative', 'DNSKEY', 0, []),
    ]
    assert mon.classify_phase(observations) == 'pre_dnskey_unsigned_child_parent_authenticated_no_ds'


def test_classifies_island_window_before_ds_publish():
    observations = [
        obs('route53-parent', 'DS', 0, ad=True),
        obs('public-recursive', 'DS', 0, ad=True),
        obs('authoritative', 'DNSKEY', 1, [18]),
    ]
    assert mon.classify_phase(observations) == 'island_window_signed_not_delegated'


def test_classifies_ds_decay_window_after_ds_publish():
    observations = [
        obs('route53-parent', 'DS', 1, [18], ad=False),
        obs('public-recursive', 'DS', 0, [], ad=True),
        obs('authoritative', 'DNSKEY', 1, [18]),
    ]
    assert mon.classify_phase(observations) == 'ds_published_decay_window_public_cache'


def test_parses_ad_flag_and_rcode():
    header = ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1'
    assert mon.parse_flags(header) == ('NOERROR', True, False, False)


def test_extracts_ds_algorithm_and_keytag():
    lines = ['pq.resolutionscope.com. 300 IN DS 12345 18 2 ABCD']
    assert mon.extract_algorithms(lines, 'DS') == [18]
    assert mon.extract_keytags(lines, 'DS') == [12345]


def test_extracts_soa_minimum_and_ttl():
    lines = ['pq.resolutionscope.com. 300 IN SOA pqns.resolutionscope.com. hostmaster.resolutionscope.com. 1 3600 900 604800 86400']
    assert mon.extract_soa(lines) == (86400, 300)


def test_classifies_all_public_ds_visible():
    observations = [
        obs('route53-parent', 'DS', 1, [18]),
        obs('public-recursive', 'DS', 1, [18], ad=True),
        obs('authoritative', 'DNSKEY', 1, [18]),
    ]
    assert mon.classify_phase(observations) == 'chainunverified_window_all_public_ds_visible'


def test_pre_dnskey_ignores_public_timeout_when_parent_authoritative_is_clear():
    observations = [
        obs('route53-parent', 'DS', 0, ad=True),
        obs('public-recursive', 'DS', 0, ad=False),  # timeout/UNKNOWN-like: not proof, but not parent truth
        obs('authoritative', 'DNSKEY', 0, []),
    ]
    assert mon.classify_phase(observations) == 'pre_dnskey_unsigned_child_parent_authenticated_no_ds'
