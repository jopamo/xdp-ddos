#!/usr/bin/env python3
"""
blocked_report.py — parse WAN_INPUT_DROP messages from journald and
produce a per-network summary with WHOIS (RDAP) metadata.

▪  install:  python -m pip install ipwhois
▪  run:      python blocked_report.py
"""

import re
import sys
import json
import subprocess
from collections import defaultdict
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, WhoisLookupError

# ---------- fetch kernel logs (current boot) ------------------------
try:
    journal_raw = subprocess.check_output(
        ['journalctl', '-k', '-b'], text=True, timeout=10
    )
except subprocess.CalledProcessError as e:
    sys.exit(f"journalctl failed: {e}")
except subprocess.TimeoutExpired:
    sys.exit("journalctl timed out")

DROP_RE = re.compile(
    r'^(\w{3} +\d{1,2} \d{2}:\d{2}:\d{2}) .*?WAN_INPUT_DROP:\s*(.*)'
)
KV_RE = re.compile(r'(\w+)=([^ ]+)')

def parse_line(line: str):
    m = DROP_RE.search(line)
    if not m:
        return None
    ts, rest = m.groups()
    kv = {k.lower(): v for k, v in KV_RE.findall(rest)}
    kv['timestamp'] = ts
    return kv

records = [r for r in map(parse_line, journal_raw.splitlines()) if r]

# ---------- count hits per IP --------------------------------------
hits = defaultdict(int)
for r in records:
    if 'src' in r:
        hits[r['src']] += 1

if not hits:
    sys.exit("No WAN_INPUT_DROP messages found in this boot session.")

# ---------- RDAP / WHOIS helper ------------------------------------
whois_cache = {}  # ip -> {range, org, country}

def rdap(ip: str):
    if ip in whois_cache:
        return whois_cache[ip]

    info = {'range': '-', 'org': '-', 'country': '-'}
    try:
        data = IPWhois(ip).lookup_rdap()
        net  = data.get('network', {}) or {}
        # range
        cidr = net.get('cidr')
        if cidr:
            info['range'] = cidr
        else:
            s, e = net.get('start_address'), net.get('end_address')
            info['range'] = f"{s} - {e}" if s and e else '-'
        # org / country
        info['org']     = net.get('name')    or '-'
        info['country'] = net.get('country') or '-'
    except (IPDefinedError, WhoisLookupError):
        info['range'] = 'private/reserved'
    except Exception as e:
        info['range'] = f'error: {e}'
    whois_cache[ip] = info
    return info

# enrich all IPs
for ip in hits:
    rdap(ip)

# ---------- aggregate by range -------------------------------------
range_to_ips = defaultdict(list)
for ip, meta in whois_cache.items():
    range_to_ips[meta['range']].append(ip)

ordered = sorted(
    range_to_ips.items(),
    key=lambda kv: sum(hits[i] for i in kv[1]),
    reverse=True,
)

# ---------- report --------------------------------------------------
print("\nBlocked-IP Range Report (current boot)\n" + "=" * 80)
for rng, ips in ordered:
    total = sum(hits[i] for i in ips)
    first = ips[0]
    org   = whois_cache[first]['org']
    ctry  = whois_cache[first]['country']
    print(f"\nRange        : {rng}")
    print(f"Organisation : {org}")
    print(f"Country      : {ctry}")
    print(f"Total hits   : {total}")
    print("IPs:")
    for ip in sorted(ips, key=lambda x: hits[x], reverse=True):
        print(f"  {ip:<15} {hits[ip]} hits")
print("\nDone.")
