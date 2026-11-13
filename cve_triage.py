#!/usr/bin/env python3
"""
cve_triage.py — a CVE prioritization tool.

Pulls recently published CVEs matching a keyword, then enriches each one
with:
  - CISA KEV status     (is this confirmed being exploited in the wild?)
  - EPSS score          (modeled probability of exploitation in 30 days)
  - CVSS base score      (from NVD, if available)
  - public PoC count    (GitHub repos mentioning the CVE ID)

...and combines them into one priority score, so you can answer:
"of everything published this week, what should I actually look at first?"

Setup:
  pip install -r requirements.txt
  export NVD_API_KEY=your_key_here        # optional, raises rate limit
  export GITHUB_TOKEN=your_token_here      # optional, raises rate limit

Usage:
  python3 cve_triage.py --days 7 --keyword "web application"
  python3 cve_triage.py --days 14 --keyword wordpress --output results.json
  python3 cve_triage.py --days 7 --keyword apache --output results.csv --min-score 5

Output: a ranked table printed to the console, and optionally a JSON/CSV file.
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
import dotenv
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"


dotenv.load_dotenv()
NVD_API_KEY = os.environ.get("NVD_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


# ----------------------------------------------------------------------
# 1. Fetch recently published CVEs from NVD, filtered by keyword
# ----------------------------------------------------------------------
def fetch_recent_cves(days, keyword, results_per_page=50):
    """Return a list of dicts: {id, description, cvss_score, published}."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }

    print(f"[nvd] fetching CVEs published {start.date()} to {end.date()} "
          f"matching '{keyword}' ...", file=sys.stderr)

    if not NVD_API_KEY:
        print("[nvd] no NVD_API_KEY set — using the public rate limit "
              "(5 requests/30s). Fine for occasional runs; retrying on "
              "rate-limit errors below if needed.", file=sys.stderr)

    r = None
    max_retries = 4
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(NVD_API, params=params, headers=headers, timeout=30)
            if r.status_code == 403:
                # NVD returns 403 for rate-limit/key issues, not 429 — back off and retry
                wait = 2 ** attempt  # 2s, 4s, 8s, 16s
                print(f"[nvd] rate-limited (403) — waiting {wait}s and retrying "
                      f"({attempt}/{max_retries}) ...", file=sys.stderr)
                time.sleep(wait)
                continue
            r.raise_for_status()
            break
        except requests.RequestException as e:
            print(f"[nvd] request failed (attempt {attempt}/{max_retries}): {e}", file=sys.stderr)
            if attempt == max_retries:
                return []
            time.sleep(2 ** attempt)
    else:
        print("[nvd] gave up after repeated rate-limit errors — try again in a minute, "
              "or set NVD_API_KEY once the activation email arrives.", file=sys.stderr)
        return []

    if r is None or not r.ok:
        return []

    data = r.json()
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]

        # Description: NVD stores multiple language entries, we want English
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS score: NVD has multiple possible versions (v3.1, v3.0, v2) —
        # prefer the newest available
        cvss_score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_score = metrics[key][0]["cvssData"]["baseScore"]
                break

        out.append({
            "id": cve_id,
            "description": desc[:200],
            "cvss_score": cvss_score,
            "published": cve.get("published", ""),
        })

    print(f"[nvd] found {len(out)} CVEs", file=sys.stderr)
    return out


# ----------------------------------------------------------------------
# 2. CISA Known Exploited Vulnerabilities list
# ----------------------------------------------------------------------
def fetch_kev_ids():
    """Return a set of CVE IDs that CISA confirms are being exploited."""
    print("[kev] fetching CISA KEV catalog ...", file=sys.stderr)
    try:
        r = requests.get(KEV_URL, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[kev] request failed: {e} — continuing without KEV data", file=sys.stderr)
        return set()

    data = r.json()
    ids = {v["cveID"] for v in data.get("vulnerabilities", [])}
    print(f"[kev] loaded {len(ids)} known-exploited CVE IDs", file=sys.stderr)
    return ids


# ----------------------------------------------------------------------
# 3. EPSS scores (batched — EPSS supports comma-separated CVE lists)
# ----------------------------------------------------------------------
def fetch_epss_scores(cve_ids, batch_size=100):
    """Return {cve_id: epss_score} for as many as EPSS has data for."""
    scores = {}
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        try:
            r = requests.get(EPSS_API, params={"cve": ",".join(batch)}, timeout=30)
            r.raise_for_status()
        except requests.RequestException as e:
            print(f"[epss] request failed for batch: {e}", file=sys.stderr)
            continue
        for row in r.json().get("data", []):
            scores[row["cve"]] = float(row["epss"])
    print(f"[epss] got scores for {len(scores)}/{len(cve_ids)} CVEs", file=sys.stderr)
    return scores


# ----------------------------------------------------------------------
# 4. Public PoC search via GitHub — two strategies, merged and deduplicated
#
#    Strategy A: topic search. Many PoC authors deliberately tag their repo
#    with the CVE ID as a GitHub "topic" (e.g. topic:cve-2021-44228) so it's
#    discoverable — this is a stronger, more deliberate signal than free text.
#
#    Strategy B: text search with in:name,description,readme. GitHub's
#    DEFAULT repo search only matches name/description/topics — it does NOT
#    search the README unless you explicitly add "in:readme". Most PoC repos
#    mention the CVE only in the README, so without this qualifier you miss
#    most of them.
#
#    We run both, then dedupe by full_name (owner/repo) so a repo matching
#    both strategies is only counted once.
# ----------------------------------------------------------------------
def search_github_pocs(cve_id, per_query_results=5, sleep_between=1.0):
    """Return (count, [example repo URLs]) for this CVE, deduped across strategies."""
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    queries = [
        f"topic:{cve_id.lower()}",                      # Strategy A: explicit tag
        f'"{cve_id}" in:name,description,readme',       # Strategy B: README-inclusive text match
    ]

    found = {}  # full_name -> html_url, naturally dedupes across both queries
    for q in queries:
        try:
            r = requests.get(
                GITHUB_SEARCH_API,
                params={"q": q, "per_page": per_query_results, "sort": "stars", "order": "desc"},
                headers=headers,
                timeout=15,
            )
            if r.status_code == 403:
                print(f"[github] rate limited on query '{q}' for {cve_id} — "
                      f"partial results for this run", file=sys.stderr)
                continue
            r.raise_for_status()
            for item in r.json().get("items", []):
                found[item["full_name"]] = item["html_url"]
        except requests.RequestException as e:
            print(f"[github] request failed for {cve_id} ({q}): {e}", file=sys.stderr)
        finally:
            time.sleep(sleep_between if not GITHUB_TOKEN else sleep_between / 3)

    return len(found), list(found.values())[:3]  # count, a few example links as evidence


# ----------------------------------------------------------------------
# 5. Scoring — combine everything into one priority number
# ----------------------------------------------------------------------
def priority_score(cve):
    """
    Higher = look at this first.
    This weighting is a starting point, not gospel — tune it and be ready
    to explain WHY you weighted it this way (that's the interesting part).
    """
    score = 0.0

    if cve["in_kev"]:
        score += 50          # confirmed real-world exploitation dominates everything else

    score += (cve.get("epss_score") or 0) * 30          # 0..1 -> up to 30 points

    cvss = cve.get("cvss_score") or 0
    score += (cvss / 10) * 15                            # 0..10 -> up to 15 points

    poc_count = cve.get("poc_count") or 0
    score += min(poc_count, 10) * 0.5                     # diminishing returns after 10 PoCs

    return round(score, 2)


# ----------------------------------------------------------------------
# 6. Pipeline + CLI
# ----------------------------------------------------------------------
def run(days, keyword, check_pocs=True, min_score=0.0):
    cves = fetch_recent_cves(days, keyword)
    if not cves:
        return []

    kev_ids = fetch_kev_ids()
    epss_scores = fetch_epss_scores([c["id"] for c in cves])

    for c in cves:
        c["in_kev"] = c["id"] in kev_ids
        c["epss_score"] = epss_scores.get(c["id"])

        if check_pocs:
            print(f"[github] checking PoCs for {c['id']} ...", file=sys.stderr)
            c["poc_count"], c["poc_examples"] = search_github_pocs(c["id"])
        else:
            c["poc_count"] = None
            c["poc_examples"] = []

        c["priority_score"] = priority_score(c)

    cves = [c for c in cves if c["priority_score"] >= min_score]
    cves.sort(key=lambda c: c["priority_score"], reverse=True)
    return cves


def print_table(cves, limit=25):
    print(f"\n{'SCORE':>6}  {'CVE ID':16}  {'KEV':4}  {'EPSS':6}  {'CVSS':5}  {'POCS':5}  DESCRIPTION")
    print("-" * 110)
    for c in cves[:limit]:
        epss = f"{c['epss_score']:.3f}" if c.get("epss_score") is not None else "  -  "
        cvss = f"{c['cvss_score']:.1f}" if c.get("cvss_score") is not None else " - "
        kev = "YES" if c["in_kev"] else "no"
        poc = c["poc_count"] if c["poc_count"] is not None else "-"
        print(f"{c['priority_score']:6.1f}  {c['id']:16}  {kev:4}  {epss:6}  {cvss:5}  {poc:5}  {c['description'][:50]}")
        for link in c.get("poc_examples", []):
            print(f"{'':6}  {'':16}  {'':4}  {'':6}  {'':5}  {'':5}  -> {link}")
    if len(cves) > limit:
        print(f"... and {len(cves) - limit} more (see the output file for the full list)")


def write_output(cves, path):
    if path.endswith(".csv"):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(cves[0].keys()))
            writer.writeheader()
            writer.writerows(cves)
    else:
        with open(path, "w") as f:
            json.dump(cves, f, indent=2)
    print(f"\nWrote {len(cves)} results to {path}")


def main():
    ap = argparse.ArgumentParser(description="CVE triage: rank recent CVEs by real-world priority")
    ap.add_argument("--days", type=int, default=7, help="How many days back to search NVD")
    ap.add_argument("--keyword", required=True, help="Keyword to filter CVEs, e.g. 'web application', 'wordpress'")
    ap.add_argument("--output", help="Write full results to this file (.json or .csv)")
    ap.add_argument("--min-score", type=float, default=0.0, help="Only show results at or above this priority score")
    ap.add_argument("--no-poc-check", action="store_true", help="Skip GitHub PoC search (faster, less rate-limit risk)")
    ap.add_argument("--limit", type=int, default=25, help="Max rows to print to console")
    args = ap.parse_args()

    cves = run(
        days=args.days,
        keyword=args.keyword,
        check_pocs=not args.no_poc_check,
        min_score=args.min_score,
    )

    if not cves:
        print("No results.")
        return

    print_table(cves, limit=args.limit)

    if args.output:
        write_output(cves, args.output)


if __name__ == "__main__":
    main()