#!/usr/bin/env python3
"""
ioc_enrich.py — enrich an indicator of compromise (IP, domain, hash, or URL)
against multiple free threat-intel sources and combine them into one verdict.

For IPs specifically, this also does a WHOIS/RDAP lookup (via the `ipwhois`
library) to show who actually owns the IP — no API key needed for this part,
it's public registry data.

Setup:
  pip install -r requirements.txt
  export VT_API_KEY=...          # virustotal.com/gui/join-us
  export ABUSEIPDB_API_KEY=...   # abuseipdb.com/register
  export GREYNOISE_API_KEY=...   # viz.greynoise.io/signup
  export ABUSECH_AUTH_KEY=...    # auth.abuse.ch (covers URLhaus + MalwareBazaar)

Usage:
  python3 ioc_enrich.py 1.2.3.4
  python3 ioc_enrich.py evil-domain.example
  python3 ioc_enrich.py 44d88612fea8a8f36de82e1278abb02f
  python3 ioc_enrich.py http://bad.example/payload.exe
  python3 ioc_enrich.py --file iocs.txt --output results.json

Any key that isn't set is simply skipped for that indicator — the tool still
runs with whatever sources you've configured.
"""

import argparse
import json
import os
import re
import sys
import time
import dotenv
import requests
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError, HTTPLookupError

dotenv.load_dotenv()
VT_API_KEY = os.environ.get("VT_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY")
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY")

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
GREYNOISE_URL = "https://api.greynoise.io/v3/community"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_URL_URL = "https://urlhaus-api.abuse.ch/v1/url/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"


# ----------------------------------------------------------------------
# 1. Figure out what kind of indicator this is
# ----------------------------------------------------------------------
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def classify(indicator):
    if indicator.startswith(("http://", "https://")):
        return "url"
    if IPV4_RE.match(indicator):
        return "ip"
    if SHA256_RE.match(indicator):
        return "hash"
    if SHA1_RE.match(indicator):
        return "hash"
    if MD5_RE.match(indicator):
        return "hash"
    if "." in indicator and " " not in indicator:
        return "domain"
    return "unknown"


# ----------------------------------------------------------------------
# 2. Each source as its own function — returns None if no key / no data,
#    otherwise a small dict of what it found
# ----------------------------------------------------------------------
def check_virustotal(indicator, ioc_type):
    if not VT_API_KEY:
        return None
    headers = {"x-apikey": VT_API_KEY}
    endpoint = {
        "ip": f"{VT_BASE}/ip_addresses/{indicator}",
        "domain": f"{VT_BASE}/domains/{indicator}",
        "hash": f"{VT_BASE}/files/{indicator}",
    }.get(ioc_type)
    if not endpoint:
        return None  # VT URL lookups need a base64 url-id; skipped for simplicity here

    try:
        r = requests.get(endpoint, headers=headers, timeout=15)
        if r.status_code == 404:
            return {"source": "virustotal", "found": False}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        return {
            "source": "virustotal",
            "found": True,
            "malicious_vendors": malicious,
            "suspicious_vendors": suspicious,
            "total_vendors": total,
            "link": f"https://www.virustotal.com/gui/search/{indicator}",
        }
    except requests.RequestException as e:
        print(f"[virustotal] request failed: {e}", file=sys.stderr)
        return None


def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return None
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        r = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "source": "abuseipdb",
            "found": True,
            "abuse_confidence_score": d["abuseConfidenceScore"],  # 0-100
            "total_reports": d["totalReports"],
            "country": d.get("countryCode"),
            "is_tor": d.get("isTor", False),
        }
    except requests.RequestException as e:
        print(f"[abuseipdb] request failed: {e}", file=sys.stderr)
        return None


def check_greynoise(ip):
    if not GREYNOISE_API_KEY:
        return None
    headers = {"key": GREYNOISE_API_KEY}
    try:
        r = requests.get(f"{GREYNOISE_URL}/{ip}", headers=headers, timeout=15)
        if r.status_code == 404:
            return {"source": "greynoise", "found": False}
        r.raise_for_status()
        d = r.json()
        return {
            "source": "greynoise",
            "found": True,
            # GreyNoise classification: "benign" (known good scanner/crawler),
            # "malicious" (known bad actor), or "unknown"
            "classification": d.get("classification", "unknown"),
            "name": d.get("name"),
            "noise": d.get("noise", False),  # True = internet background scanning, not targeted
        }
    except requests.RequestException as e:
        print(f"[greynoise] request failed: {e}", file=sys.stderr)
        return None


def check_ip_whois(ip):
    """
    Who actually owns/operates this IP — no API key needed, this is public
    RDAP/WHOIS data. Useful as CONTEXT (which org, which country, what kind
    of network — residential ISP vs. hosting/VPS provider), not as a
    malicious/benign signal on its own, so it's deliberately kept out of
    combine_verdict()'s scoring.
    """
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1, rate_limit_timeout=10)
        network = res.get("network") or {}
        return {
            "source": "whois",
            "found": True,
            "asn": res.get("asn"),
            "asn_org": res.get("asn_description"),
            "asn_country": res.get("asn_country_code"),
            "network_name": network.get("name"),
            "network_cidr": network.get("cidr"),
        }
    except IPDefinedError:
        # Private/reserved ranges (10.x, 192.168.x, etc.) have no public WHOIS record
        return {"source": "whois", "found": False, "reason": "private/reserved IP range"}
    except (ASNRegistryError, HTTPLookupError) as e:
        print(f"[whois] lookup failed for {ip}: {e}", file=sys.stderr)
        return None
    except Exception as e:  # ipwhois can raise a few other edge-case exceptions
        print(f"[whois] unexpected error for {ip}: {e}", file=sys.stderr)
        return None


def check_urlhaus(indicator, ioc_type):
    if not ABUSECH_AUTH_KEY:
        return None
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    url = URLHAUS_URL_URL if ioc_type == "url" else URLHAUS_HOST_URL
    key = "url" if ioc_type == "url" else "host"
    try:
        r = requests.post(url, headers=headers, data={key: indicator}, timeout=15)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return {"source": "urlhaus", "found": False}
        urls = d.get("urls", [])
        return {
            "source": "urlhaus",
            "found": True,
            "malware_url_count": len(urls) if ioc_type != "url" else 1,
            "threat": d.get("threat") or (urls[0].get("threat") if urls else None),
            "link": d.get("urlhaus_reference"),
        }
    except requests.RequestException as e:
        print(f"[urlhaus] request failed: {e}", file=sys.stderr)
        return None


def check_malwarebazaar(file_hash):
    if not ABUSECH_AUTH_KEY:
        return None
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    try:
        r = requests.post(
            MALWAREBAZAAR_URL,
            headers=headers,
            data={"query": "get_info", "hash": file_hash},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return {"source": "malwarebazaar", "found": False}
        info = d["data"][0]
        return {
            "source": "malwarebazaar",
            "found": True,
            "file_type": info.get("file_type"),
            "signature": info.get("signature"),  # often the malware family name
            "first_seen": info.get("first_seen"),
            "tags": info.get("tags", []),
        }
    except requests.RequestException as e:
        print(f"[malwarebazaar] request failed: {e}", file=sys.stderr)
        return None


# ----------------------------------------------------------------------
# 3. Run the right sources for this indicator type, combine into a verdict
# ----------------------------------------------------------------------
def enrich(indicator):
    ioc_type = classify(indicator)
    results = {"indicator": indicator, "type": ioc_type, "sources": {}}

    if ioc_type == "unknown":
        results["verdict"] = "unrecognized indicator format"
        return results

    if ioc_type in ("ip", "domain", "hash"):
        vt = check_virustotal(indicator, ioc_type)
        if vt:
            results["sources"]["virustotal"] = vt

    if ioc_type == "ip":
        whois = check_ip_whois(indicator)  # no key needed, always attempted for IPs
        if whois:
            results["sources"]["whois"] = whois
        abuseipdb = check_abuseipdb(indicator)
        if abuseipdb:
            results["sources"]["abuseipdb"] = abuseipdb
        greynoise = check_greynoise(indicator)
        if greynoise:
            results["sources"]["greynoise"] = greynoise

    if ioc_type in ("ip", "domain", "url"):
        urlhaus = check_urlhaus(indicator, ioc_type)
        if urlhaus:
            results["sources"]["urlhaus"] = urlhaus

    if ioc_type == "hash":
        mb = check_malwarebazaar(indicator)
        if mb:
            results["sources"]["malwarebazaar"] = mb

    results["verdict"] = combine_verdict(results["sources"])
    return results


def combine_verdict(sources):
    """
    Simple, explainable rule-based combination — not a trained model, but
    documents exactly WHY a verdict was reached, which matters more than
    a single opaque score for this kind of tool.
    """
    reasons = []

    vt = sources.get("virustotal")
    if vt and vt.get("found") and vt.get("malicious_vendors", 0) >= 3:
        reasons.append(f"VirusTotal: {vt['malicious_vendors']}/{vt['total_vendors']} vendors flag it malicious")

    abuseipdb = sources.get("abuseipdb")
    if abuseipdb and abuseipdb.get("abuse_confidence_score", 0) >= 50:
        reasons.append(f"AbuseIPDB: {abuseipdb['abuse_confidence_score']}/100 abuse confidence "
                        f"({abuseipdb['total_reports']} reports)")

    greynoise = sources.get("greynoise")
    if greynoise and greynoise.get("classification") == "malicious":
        reasons.append(f"GreyNoise: classified malicious ({greynoise.get('name')})")
    elif greynoise and greynoise.get("classification") == "benign":
        reasons.append(f"GreyNoise: classified BENIGN — likely a known good scanner/crawler ({greynoise.get('name')})")

    urlhaus = sources.get("urlhaus")
    if urlhaus and urlhaus.get("found"):
        reasons.append(f"URLhaus: hosting/linked to malware (threat: {urlhaus.get('threat')})")

    mb = sources.get("malwarebazaar")
    if mb and mb.get("found"):
        reasons.append(f"MalwareBazaar: known malware sample ({mb.get('signature') or 'unclassified'})")

    # A GreyNoise "benign" tag is a meaningful signal pulling AWAY from malicious,
    # even if something else flagged it — surface that tension rather than hiding it
    benign_signal = greynoise and greynoise.get("classification") == "benign"

    if any(r for r in reasons if "GreyNoise: classified BENIGN" not in r):
        verdict = "SUSPICIOUS/MALICIOUS" if not benign_signal else "MIXED SIGNALS — review manually"
    elif reasons:
        verdict = "likely benign (known scanner)"
    else:
        verdict = "no negative signals from configured sources"

    return {"verdict": verdict, "reasons": reasons}


# ----------------------------------------------------------------------
# 4. CLI
# ----------------------------------------------------------------------
def print_result(result):
    print(f"\n{'='*70}")
    print(f"Indicator: {result['indicator']}  (type: {result['type']})")
    print(f"{'='*70}")

    if not result["sources"]:
        print("No sources returned data (check your API keys, or nothing on record).")
    for name, data in result["sources"].items():
        print(f"\n[{name}]")
        for k, v in data.items():
            if k != "source":
                print(f"  {k}: {v}")

    v = result["verdict"]
    print(f"\nVERDICT: {v['verdict'] if isinstance(v, dict) else v}")
    if isinstance(v, dict):
        for reason in v["reasons"]:
            print(f"  - {reason}")


def main():
    ap = argparse.ArgumentParser(description="Enrich IOCs against free threat-intel sources")
    ap.add_argument("indicator", nargs="?", help="A single IP, domain, hash, or URL")
    ap.add_argument("--file", help="A text file with one indicator per line")
    ap.add_argument("--output", help="Write full results to this file (.json)")
    args = ap.parse_args()

    if not args.indicator and not args.file:
        ap.error("provide an indicator or --file")

    indicators = [args.indicator] if args.indicator else []
    if args.file:
        with open(args.file) as f:
            indicators += [line.strip() for line in f if line.strip()]

    all_results = []
    for ind in indicators:
        result = enrich(ind)
        print_result(result)
        all_results.append(result)
        time.sleep(1)  # be polite across multiple lookups, several free tiers are tight

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nWrote {len(all_results)} result(s) to {args.output}")


if __name__ == "__main__":
    main()