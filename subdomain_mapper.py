#!/usr/bin/env python3
"""
subdomain_mapper.py — discover a domain's subdomains passively, then
(optionally, with confirmation) check which ones are actually alive.

IMPORTANT: only run the active phase (DNS resolution + HTTP probing)
against domains you own or are explicitly authorized to test. The passive
phase (certificate transparency + HackerTarget lookups) only queries
third-party public data sources and never contacts the target directly,
so it's safe to run against any domain out of curiosity. The active phase
sends real DNS queries and HTTP requests to the target's own
infrastructure and requires you to confirm authorization first.

Usage:
  python3 subdomain_mapper.py example.com
  python3 subdomain_mapper.py example.com --passive-only
  python3 subdomain_mapper.py example.com --yes --output results.json
"""

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import time

import requests

CRTSH_URL = "https://crt.sh/"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"


# ----------------------------------------------------------------------
# 1. Passive source A: Certificate Transparency logs via crt.sh
# ----------------------------------------------------------------------
def fetch_crtsh(domain, timeout=30):
    """Every subdomain that has ever had a TLS certificate issued for it,
    as recorded in public Certificate Transparency logs."""
    print(f"[crt.sh] querying certificate transparency logs for {domain} ...", file=sys.stderr)
    try:
        r = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "subdomain-mapper-portfolio-tool"},
        )
        r.raise_for_status()
        rows = r.json()
    except (requests.RequestException, ValueError) as e:
        # crt.sh is a free, best-effort community service — it does go down
        # or time out sometimes. Don't let that crash the whole run.
        print(f"[crt.sh] request failed or returned bad data: {e}", file=sys.stderr)
        return set()

    names = set()
    for row in rows:
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain.lower()):
                names.add(name)
    print(f"[crt.sh] found {len(names)} unique names", file=sys.stderr)
    return names


# ----------------------------------------------------------------------
# 2. Passive source B: HackerTarget's free host-search API
# ----------------------------------------------------------------------
def fetch_hackertarget(domain, timeout=15):
    """A second, independent passive source — combining two sources catches
    what either one misses on its own (same idea as the GitHub PoC dual
    search in the CVE triage tool)."""
    print(f"[hackertarget] querying {domain} ...", file=sys.stderr)
    try:
        r = requests.get(HACKERTARGET_URL, params={"q": domain}, timeout=timeout)
        r.raise_for_status()
        text = r.text
    except requests.RequestException as e:
        print(f"[hackertarget] request failed: {e}", file=sys.stderr)
        return set()

    if "API count exceeded" in text or "error" in text.lower():
        print(f"[hackertarget] rate-limited or errored: {text.strip()[:100]}", file=sys.stderr)
        return set()

    names = set()
    for line in text.splitlines():
        parts = line.split(",")
        if parts and parts[0].strip():
            names.add(parts[0].strip().lower())
    print(f"[hackertarget] found {len(names)} unique names", file=sys.stderr)
    return names


# ----------------------------------------------------------------------
# 3. Active phase A: DNS resolution
# ----------------------------------------------------------------------
def resolve_dns(hostname, timeout=5):
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout):
        return None


# ----------------------------------------------------------------------
# 4. Active phase B: HTTP probing
# ----------------------------------------------------------------------
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def probe_http(hostname, timeout=6):
    """Try HTTPS first, fall back to HTTP. Return status/server/title or None."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            title_match = TITLE_RE.search(r.text[:5000])  # only look at the head of the page
            return {
                "scheme": scheme,
                "status_code": r.status_code,
                "final_url": r.url,
                "server": r.headers.get("Server"),
                "title": title_match.group(1).strip()[:80] if title_match else None,
            }
        except requests.RequestException:
            continue
    return None


# ----------------------------------------------------------------------
# 5. Orchestration
# ----------------------------------------------------------------------
def discover_passive(domain):
    names = set()
    names |= fetch_crtsh(domain)
    names |= fetch_hackertarget(domain)
    # crt.sh sometimes returns the bare domain itself and oddities like
    # emails pasted into cert fields — keep this simple and just filter
    # to things that look like real hostnames
    names = {n for n in names if n and " " not in n and "@" not in n}
    return sorted(names)


def check_alive(hostname):
    ip = resolve_dns(hostname)
    if not ip:
        return {"hostname": hostname, "ip": None, "alive": False, "http": None}
    http_result = probe_http(hostname)
    return {
        "hostname": hostname,
        "ip": ip,
        "alive": http_result is not None,
        "http": http_result,
    }


def run_active_phase(hostnames, max_workers=10):
    results = []
    print(f"\nResolving + probing {len(hostnames)} hosts ({max_workers} at a time) ...", file=sys.stderr)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_alive, h): h for h in hostnames}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            results.append(result)
            if i % 10 == 0 or i == len(hostnames):
                print(f"  ... {i}/{len(hostnames)} checked", file=sys.stderr)
    return results


# ----------------------------------------------------------------------
# 6. CLI
# ----------------------------------------------------------------------
def confirm_authorization(domain):
    print(f"\nThe next step will send real DNS queries and HTTP requests to subdomains of '{domain}'.")
    print("Only proceed if you own this domain or have explicit written authorization to test it.")
    answer = input("Type 'yes' to confirm you are authorized, anything else to stop: ").strip().lower()
    return answer == "yes"


def print_results(results):
    alive = [r for r in results if r["alive"]]
    dead = [r for r in results if not r["alive"]]

    print(f"\n{'='*90}")
    print(f"ALIVE ({len(alive)}):")
    print(f"{'='*90}")
    for r in sorted(alive, key=lambda x: x["hostname"]):
        h = r["http"]
        print(f"  {r['hostname']:40} {r['ip']:16} [{h['status_code']}] {h.get('title') or ''}")

    print(f"\n{len(dead)} resolved-but-not-responding or unresolved hostnames (see output file for full list)")


def main():
    ap = argparse.ArgumentParser(description="Passive (and optionally active) subdomain discovery")
    ap.add_argument("domain", help="Target domain, e.g. example.com")
    ap.add_argument("--passive-only", action="store_true",
                     help="Only discover subdomains — skip DNS resolution and HTTP probing entirely")
    ap.add_argument("--yes", action="store_true",
                     help="Skip the interactive authorization prompt (use in scripts/CI you already control)")
    ap.add_argument("--max-workers", type=int, default=10, help="Concurrent DNS/HTTP checks")
    ap.add_argument("--output", help="Write full results to this file (.json)")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()  # we deliberately use verify=False for broad probing coverage

    subdomains = discover_passive(args.domain)
    print(f"\nDiscovered {len(subdomains)} unique subdomain names (passive sources only).")

    if not subdomains:
        print("Nothing found — try a different domain, or the passive sources may be temporarily down.")
        return

    if args.passive_only:
        for s in subdomains:
            print(f"  {s}")
        if args.output:
            with open(args.output, "w") as f:
                json.dump(subdomains, f, indent=2)
            print(f"\nWrote {len(subdomains)} subdomains to {args.output}")
        return

    if not args.yes and not confirm_authorization(args.domain):
        print("Stopping before the active phase. (Passive results above are still yours to use.)")
        return

    results = run_active_phase(subdomains, max_workers=args.max_workers)
    print_results(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nWrote {len(results)} full result(s) to {args.output}")


if __name__ == "__main__":
    main()