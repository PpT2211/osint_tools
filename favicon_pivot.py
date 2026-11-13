#!/usr/bin/env python3
"""
favicon_pivot.py — fetch a target's favicon, hash it, and search Shodan and
Censys for other hosts serving the byte-identical file. Useful for finding
other deployments of the same software/panel, estimating exposure of a
specific product, or clustering infrastructure that shares custom tooling.

IMPORTANT ON ALGORITHMS: Shodan and Censys hash favicons differently.
  - Shodan: MurmurHash3 (32-bit x86) of the BASE64-ENCODED favicon bytes
  - Censys: plain MD5 of the RAW favicon bytes
These are not interchangeable — this script computes both separately.

Setup:
  pip install -r requirements.txt
  export SHODAN_API_KEY=...          # account.shodan.io
  export CENSYS_API_TOKEN=...        # Platform API Personal Access Token:
                                      # accounts.censys.io/settings/personal-access-tokens
  export CENSYS_ORG_ID=...           # your Censys Platform organization ID (required by the
                                      # Platform API on every request, visible in the Platform
                                      # web console URL)

NOTE on Censys auth: Censys retired the old v2 Search API (Basic Auth with
an API ID + Secret) in favor of the Platform API, which uses Bearer-token
auth (a Personal Access Token) plus a required organization_id on every
request, and POSTs the query as JSON instead of a GET query parameter.

Usage:
  python3 favicon_pivot.py https://target.example
  python3 favicon_pivot.py https://target.example --favicon-url https://target.example/assets/icon.ico
  python3 favicon_pivot.py https://target.example --output results.json
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from urllib.parse import urljoin
import dotenv
import mmh3
import requests

dotenv.load_dotenv()
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
CENSYS_API_TOKEN = os.environ.get("CENSYS_API_TOKEN")
CENSYS_ORG_ID = os.environ.get("CENSYS_ORG_ID")

SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
CENSYS_SEARCH_URL = "https://api.platform.censys.io/v3/global/search/query"


# ----------------------------------------------------------------------
# 1. Find and fetch the favicon
# ----------------------------------------------------------------------
ICON_LINK_RE = re.compile(
    r'<link[^>]+rel=["\'](?:shortcut icon|icon)["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def discover_favicon_url(site_url, timeout=10):
    """Prefer the favicon actually declared in the page's <head> — many sites
    don't use the default /favicon.ico path at all. Fall back to /favicon.ico
    if nothing is declared or the page can't be fetched."""
    try:
        r = requests.get(site_url, timeout=timeout)
        match = ICON_LINK_RE.search(r.text)
        if match:
            return urljoin(site_url, match.group(1))
    except requests.RequestException as e:
        print(f"[discover] couldn't fetch {site_url} to look for a declared favicon: {e}", file=sys.stderr)
    return urljoin(site_url, "/favicon.ico")


def fetch_favicon_bytes(favicon_url, timeout=10):
    try:
        r = requests.get(favicon_url, timeout=timeout)
        r.raise_for_status()
        if len(r.content) == 0:
            print(f"[fetch] {favicon_url} returned an empty body", file=sys.stderr)
            return None
        return r.content
    except requests.RequestException as e:
        print(f"[fetch] failed to get {favicon_url}: {e}", file=sys.stderr)
        return None


# ----------------------------------------------------------------------
# 2. The two different hashes
# ----------------------------------------------------------------------
def shodan_hash(favicon_bytes):
    """MurmurHash3 x86 32-bit of the base64-encoded bytes — matches Shodan's
    http.favicon.hash exactly."""
    b64 = base64.encodebytes(favicon_bytes)
    return mmh3.hash(b64)


def censys_md5(favicon_bytes):
    """Plain MD5 of the raw bytes — matches Censys's
    services.http.response.favicons.md5_hash field."""
    return hashlib.md5(favicon_bytes).hexdigest()


# ----------------------------------------------------------------------
# 3. Query each platform
# ----------------------------------------------------------------------
def search_shodan(hash_value, limit=20):
    if not SHODAN_API_KEY:
        print("[shodan] SHODAN_API_KEY not set — skipping", file=sys.stderr)
        return None
    try:
        r = requests.get(
            SHODAN_SEARCH_URL,
            params={"key": SHODAN_API_KEY, "query": f"http.favicon.hash:{hash_value}"},
            timeout=20,
        )
        if r.status_code == 401:
            print("[shodan] 401 — invalid API key", file=sys.stderr)
            return None
        if r.status_code == 403:
            print("[shodan] 403 — your plan may not include search API access "
                  "(the free membership tier has very limited query credits)", file=sys.stderr)
            return None
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        print(f"[shodan] request failed: {e}", file=sys.stderr)
        return None

    matches = []
    for m in data.get("matches", [])[:limit]:
        matches.append({
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "org": m.get("org"),
            "hostnames": m.get("hostnames", []),
            "country": (m.get("location") or {}).get("country_name"),
        })
    return {"total": data.get("total", 0), "matches": matches}


def search_censys(md5_value, limit=20):
    # if not (CENSYS_API_TOKEN and CENSYS_ORG_ID):
    #     print("[censys] CENSYS_API_TOKEN/CENSYS_ORG_ID not set — skipping", file=sys.stderr)
    #     return None

    headers = {
        "Authorization": f"Bearer {CENSYS_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    # "host." prefix matches the field naming pattern used throughout Censys's
    # own Platform API examples (host.ip, host.services, etc.)
    body = {"query": f"host.services.http.response.favicons.md5_hash:{md5_value}", "page_size": limit}

    try:
        r = requests.post(
            CENSYS_SEARCH_URL,
            params={"organization_id": CENSYS_ORG_ID},
            headers=headers,
            json=body,
            timeout=20,
        )
        if r.status_code == 401:
            print("[censys] 401 — invalid or expired Personal Access Token", file=sys.stderr)
            return None
        if r.status_code == 403:
            print("[censys] 403 — your account/role may not have API access "
                  "(check the API Access role in your Platform account settings)", file=sys.stderr)
            return None
        if r.status_code == 429:
            print("[censys] 429 — rate limited or out of query credits for this billing period", file=sys.stderr)
            return None
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        print(f"[censys] request failed: {e}", file=sys.stderr)
        return None

    result = data.get("result", {})
    hits = result.get("hits", [])

    matches = []
    for hit in hits:
        # Each hit is keyed by asset type (host_v1 / certificate_v1 / webproperty_v1);
        # we only queried host-shaped data, so host_v1 is what we expect here.
        host = hit.get("host_v1") or hit.get("host") or {}
        location = host.get("location") or {}
        asn = host.get("autonomous_system") or {}
        matches.append({
            "ip": host.get("ip"),
            "autonomous_system": asn.get("name"),
            "country": location.get("country"),
        })

    return {"total": result.get("total_hits", 0), "matches": matches}


# ----------------------------------------------------------------------
# 4. CLI
# ----------------------------------------------------------------------
def run(site_url, favicon_url=None):
    favicon_url = favicon_url or discover_favicon_url(site_url)
    print(f"[favicon] using {favicon_url}", file=sys.stderr)

    favicon_bytes = fetch_favicon_bytes(favicon_url)
    if favicon_bytes is None:
        print("No favicon found or fetched — nothing to hash.", file=sys.stderr)
        return None

    s_hash = shodan_hash(favicon_bytes)
    c_hash = censys_md5(favicon_bytes)

    print(f"\nFavicon: {len(favicon_bytes)} bytes")
    print(f"Shodan hash (http.favicon.hash):              {s_hash}")
    print(f"Censys hash (favicons.md5_hash):               {c_hash}")
    print(f"\nShodan query (paste into shodan.io search bar):")
    print(f"  http.favicon.hash:{s_hash}")
    print(f"Censys query (paste into the 'query' field in platform.censys.io search, "
          f"or the JSON body of a /v3/global/search/query call):")
    print(f"  host.services.http.response.favicons.md5_hash:{c_hash}")

    shodan_results = search_shodan(s_hash)
    censys_results = search_censys(c_hash)

    if shodan_results:
        print(f"\n[shodan] {shodan_results['total']} total hosts reported, showing up to {len(shodan_results['matches'])}:")
        for m in shodan_results["matches"]:
            print(f"  {m['ip']:16} :{m['port']:<6} {m.get('org') or '':30} {', '.join(m['hostnames'])}")

    if censys_results:
        print(f"\n[censys] {censys_results['total']} total hosts reported, showing up to {len(censys_results['matches'])}:")
        for m in censys_results["matches"]:
            print(f"  {m['ip']:16} {m.get('autonomous_system') or '':35} {m.get('country') or ''}")

    return {
        "site_url": site_url,
        "favicon_url": favicon_url,
        "favicon_size_bytes": len(favicon_bytes),
        "shodan_hash": s_hash,
        "censys_md5_hash": c_hash,
        "shodan_results": shodan_results,
        "censys_results": censys_results,
    }


def main():
    ap = argparse.ArgumentParser(description="Hash a site's favicon and pivot across Shodan/Censys")
    ap.add_argument("site_url", help="e.g. https://target.example")
    ap.add_argument("--favicon-url", help="Exact favicon URL, if you already know it (skips auto-discovery)")
    ap.add_argument("--output", help="Write full results to this file (.json)")
    args = ap.parse_args()

    result = run(args.site_url, favicon_url=args.favicon_url)
    if result and args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nWrote results to {args.output}")


if __name__ == "__main__":
    main()