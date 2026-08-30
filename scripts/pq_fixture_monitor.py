#!/usr/bin/env python3
"""Monitor pq.resolutionscope.com across three DNS vantages.

Vantages:
  1. route53-parent: parent-side DS as seen from configured recursives.
  2. authoritative: direct queries to the fixture authoritative server.
  3. public-recursive: public recursive resolver observations.

The JSONL output is intentionally append-only friendly: each line is one
observation with timestamp, vantage, resolver, rrtype, rcode, AD/AA/TC flags,
answer count, observed algorithms/keytags, SOA minimum/TTL where visible, and a
phase classifier. This records the island-window and parent-cache decay curve
instead of collapsing it to a single pass/fail.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

DOMAIN = "pq.resolutionscope.com"
PARENT = "resolutionscope.com"
AUTH = "44.232.227.144"
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
PARENT_MINIMUM_FALLBACK = 86400


def discover_parent_authorities() -> list[str]:
    proc = subprocess.run(
        ["dig", "+short", "NS", PARENT, "@1.1.1.1"],
        text=True,
        capture_output=True,
        timeout=6,
    )
    servers = [line.strip().rstrip(".") for line in proc.stdout.splitlines() if line.strip()]
    return servers


@dataclass(frozen=True)
class DigObservation:
    timestamp: str
    vantage: str
    resolver: str
    rrtype: str
    qname: str
    rcode: str
    ad: bool
    aa: bool
    tc: bool
    answer_count: int
    algorithms: list[int]
    keytags: list[int]
    soa_minimum: int | None
    soa_ttl: int | None
    raw_answer: list[str]
    raw_authority: list[str]

    def to_json(self) -> dict:
        return self.__dict__.copy()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_dig(server: str, qname: str, rrtype: str, timeout: int = 4, tcp: bool = False) -> str:
    cmd = ["dig", "+dnssec", "+time=" + str(timeout), "+tries=1", "+nocmd", "+comments", "+noquestion", "+answer", "+authority"]
    if tcp:
        cmd.insert(1, "+tcp")
    cmd += [qname, rrtype, "@" + server]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout + 3)
    return proc.stdout + proc.stderr


def parse_flags(header: str) -> tuple[str, bool, bool, bool]:
    rcode_match = re.search(r"status:\s*([A-Z]+)", header)
    rcode = rcode_match.group(1) if rcode_match else "UNKNOWN"
    flags_match = re.search(r"flags:\s*([^;]+);", header)
    flags = set(flags_match.group(1).split()) if flags_match else set()
    return rcode, "ad" in flags, "aa" in flags, "tc" in flags


def section_lines(output: str) -> tuple[list[str], list[str]]:
    answer: list[str] = []
    authority: list[str] = []
    current: list[str] | None = None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(";; ANSWER SECTION:"):
            current = answer
            continue
        if line.startswith(";; AUTHORITY SECTION:"):
            current = authority
            continue
        if line.startswith(";;"):
            current = None if not (line.startswith(";; ANSWER") or line.startswith(";; AUTHORITY")) else current
            continue
        if current is not None and not line.startswith(";"):
            current.append(line)
    return answer, authority


def extract_algorithms(lines: list[str], rrtype: str) -> list[int]:
    algs: list[int] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 5 or fields[3].upper() != rrtype.upper():
            continue
        try:
            if rrtype.upper() == "DNSKEY":
                algs.append(int(fields[6]))
            elif rrtype.upper() == "DS":
                algs.append(int(fields[5]))
            elif rrtype.upper() == "RRSIG":
                algs.append(int(fields[5]))
        except (IndexError, ValueError):
            continue
    return sorted(set(algs))


def extract_keytags(lines: list[str], rrtype: str) -> list[int]:
    tags: list[int] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 5 or fields[3].upper() != rrtype.upper():
            continue
        try:
            if rrtype.upper() == "DNSKEY":
                # DNSKEY line has no keytag; computed elsewhere by signers.
                continue
            if rrtype.upper() == "DS":
                tags.append(int(fields[4]))
            elif rrtype.upper() == "RRSIG":
                tags.append(int(fields[10]))
        except (IndexError, ValueError):
            continue
    return sorted(set(tags))


def extract_soa(lines: list[str]) -> tuple[int | None, int | None]:
    for line in lines:
        fields = line.split()
        if len(fields) >= 11 and fields[3].upper() == "SOA":
            try:
                ttl = int(fields[1])
                minimum = int(fields[10])
                return minimum, ttl
            except ValueError:
                return None, None
    return None, None


def observe(vantage: str, resolver: str, qname: str, rrtype: str, tcp: bool = False) -> DigObservation:
    out = run_dig(resolver, qname, rrtype, tcp=tcp)
    rcode, ad, aa, tc = parse_flags(out)
    ans, auth = section_lines(out)
    minimum, ttl = extract_soa(auth + ans)
    return DigObservation(
        timestamp=utc_now(),
        vantage=vantage,
        resolver=resolver,
        rrtype=rrtype.upper(),
        qname=qname,
        rcode=rcode,
        ad=ad,
        aa=aa,
        tc=tc,
        answer_count=sum(1 for line in ans if len(line.split()) > 3 and line.split()[3].upper() == rrtype.upper()),
        algorithms=extract_algorithms(ans, rrtype),
        keytags=extract_keytags(ans, rrtype),
        soa_minimum=minimum,
        soa_ttl=ttl,
        raw_answer=ans,
        raw_authority=auth,
    )


def classify_phase(observations: list[DigObservation]) -> str:
    child_dnskey = [o for o in observations if o.qname == DOMAIN and o.rrtype == "DNSKEY"]
    parent_ds = [o for o in observations if o.qname == DOMAIN and o.rrtype == "DS"]
    auth_dnskey_live = any(o.vantage == "authoritative" and o.answer_count > 0 and 18 in o.algorithms for o in child_dnskey)
    route53_ds_live = any(o.vantage == "route53-parent" and o.answer_count > 0 and 18 in o.algorithms for o in parent_ds)
    public_ds = [o for o in parent_ds if o.vantage == "public-recursive"]
    public_ds_live = [o for o in public_ds if o.answer_count > 0 and 18 in o.algorithms]
    if not auth_dnskey_live and not route53_ds_live:
        return "pre_dnskey_unsigned_child_parent_authenticated_no_ds"
    if auth_dnskey_live and not route53_ds_live:
        return "island_window_signed_not_delegated"
    if auth_dnskey_live and route53_ds_live and len(public_ds_live) < len(public_ds):
        return "ds_published_decay_window_public_cache"
    if auth_dnskey_live and route53_ds_live:
        return "chainunverified_window_all_public_ds_visible"
    return "mixed_or_unclassified"


def collect_once() -> dict:
    observations: list[DigObservation] = []
    parent_authorities = discover_parent_authorities()
    # Route 53 parent authoritative vantage: immediate parent-side DS truth, no recursive cache.
    for server in parent_authorities:
        observations.append(observe("route53-parent", server, DOMAIN, "DS"))
    # Public recursive parent DS vantage: records recursive negative-cache / DS-propagation decay.
    for resolver in PUBLIC_RESOLVERS:
        observations.append(observe("public-recursive", resolver, DOMAIN, "DS"))
    # Direct authoritative fixture vantage: no cache, source of child DNSKEY/TXT/SOA truth.
    for rrtype in ["SOA", "TXT", "DNSKEY"]:
        observations.append(observe("authoritative", AUTH, DOMAIN, rrtype, tcp=rrtype == "DNSKEY"))
    # Public recursive child DNSKEY vantage: records recursive child-side cache/validation behavior.
    for resolver in PUBLIC_RESOLVERS:
        observations.append(observe("public-recursive", resolver, DOMAIN, "DNSKEY"))
    phase = classify_phase(observations)
    parent_min = next((o.soa_minimum for o in observations if o.rrtype == "DS" and o.soa_minimum), PARENT_MINIMUM_FALLBACK)
    return {
        "timestamp": utc_now(),
        "domain": DOMAIN,
        "phase": phase,
        "parent_authorities": parent_authorities,
        "public_resolvers": PUBLIC_RESOLVERS,
        "parent_negative_cache_floor_seconds": parent_min,
        "observations": [o.to_json() for o in observations],
    }


def write_jsonl(path: Path, entry: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Monitor pq.resolutionscope.com DNSSEC transition across three vantages")
    parser.add_argument("--out", default="evidence/pq-fixture/monitor.jsonl", help="append-only JSONL output path")
    parser.add_argument("--interval", type=int, default=0, help="seconds between samples; 0 = one shot")
    parser.add_argument("--count", type=int, default=1, help="number of samples when interval > 0")
    args = parser.parse_args(argv)
    out = Path(args.out)
    samples = args.count if args.interval > 0 else 1
    for idx in range(samples):
        entry = collect_once()
        write_jsonl(out, entry)
        print(json.dumps({"timestamp": entry["timestamp"], "phase": entry["phase"], "out": str(out)}))
        if idx + 1 < samples:
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
