# ============================================================
# fetcher.py — API Integration
# Threat Intelligence Dashboard
# ============================================================
# This file fetches threat intelligence data from:
#   1. AbuseIPDB   → Malicious IP reports
#   2. AlienVault OTX → IOC pulse feeds (IPs, Domains, Hashes)
#   3. URLhaus     → Malicious URLs (no API key needed)
#   4. NVD (NIST)  → CVE vulnerability data
#
# Each function:
#   - Makes an HTTP request to the API
#   - Parses the JSON response
#   - Saves data to the SQLite database
#   - Returns a summary count of new records added
# ============================================================

import requests
import os
import streamlit as st
from dotenv import load_dotenv
from database import insert_ioc, insert_cve

# Load environment variables from .env file
load_dotenv()

# ─────────────────────────────────────────────
# API KEYS
# Fetched securely from environment variables
# ─────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY       = os.getenv("OTX_API_KEY", "")
NVD_API_KEY        =os.getenv("NVD_APPI_KEY","")

# ──────────────────────────────────────────────────────────
# 1. FETCH FROM ABUSEIPDB
# ──────────────────────────────────────────────────────────
def fetch_abuseipdb(limit=100):
    """
    Fetches recently reported malicious IP addresses from AbuseIPDB.

    API Endpoint:
        GET https://api.abuseipdb.com/api/v2/blacklist

    How it works:
        - Sends a GET request with your API key in the headers
        - API returns a list of IPs with abuse confidence scores
        - We store each IP in our database

    Parameters:
        limit (int): Max number of IPs to fetch (default 100)

    Returns:
        int: Number of new IPs inserted into the database
    
    Example API Response (single item):
        {
            "ipAddress":        "185.220.101.45",
            "abuseConfidenceScore": 100,
            "countryCode":      "DE",
            "usageType":        "Data Center/Web Hosting/Transit"
        }
    """
    if not ABUSEIPDB_API_KEY:
        print("[!] AbuseIPDB API key not set. Skipping.")
        return 0

    url = "https://api.abuseipdb.com/api/v2/blacklist"

    # Headers — this is how we authenticate with AbuseIPDB
    headers = {
        "Key":    ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    # Query parameters — limit how many results we get
    params = {
        "confidenceMinimum": 90,    # Only highly-reported IPs (90%+ confidence)
        "limit":             limit
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()  # Raises error if status code is 4xx or 5xx

        data      = response.json()
        ip_list   = data.get("data", [])
        new_count = 0

        for item in ip_list:
            ip_address       = item.get("ipAddress", "")
            confidence_score = item.get("abuseConfidenceScore", 0)
            country          = item.get("countryCode", "")

            if ip_address:
                insert_ioc(
                    indicator_value  = ip_address,
                    indicator_type   = "IP",
                    threat_category  = "malicious-ip",
                    source           = "AbuseIPDB",
                    country          = country,
                    confidence_score = confidence_score
                )
                new_count += 1

        print(f"[✓] AbuseIPDB: Fetched {new_count} malicious IPs.")
        return new_count

    except requests.exceptions.RequestException as e:
        print(f"[✗] AbuseIPDB fetch failed: {e}")
        return 0


# ──────────────────────────────────────────────────────────
# 2. FETCH FROM ALIENVALUT OTX
# ──────────────────────────────────────────────────────────
def fetch_otx(max_pulses=5):
    """
    Fetches threat intelligence pulses from AlienVault OTX.
    
    What is a "Pulse"?
        A pulse is a collection of IOCs grouped around a threat campaign.
        E.g., a pulse titled "Emotet Malware Campaign" may contain:
          - 20 malicious IPs
          - 15 malicious domains
          - 10 file hashes

    API Endpoint:
        GET https://otx.alienvault.com/api/v1/pulses/subscribed

    How it works:
        - Fetches your subscribed threat pulses
        - For each pulse, extracts IOCs (IPs, domains, hashes)
        - Stores each IOC in our database

    Parameters:
        max_pulses (int): Number of pulses to process (default 5)

    Returns:
        int: Number of new IOCs inserted

    Example IOC from OTX pulse:
        {
            "type":      "IPv4",
            "indicator": "45.33.32.156",
            "description": "Known C2 server"
        }
    """
    if not OTX_API_KEY:
        print("[!] OTX API key not set. Skipping.")
        return 0

    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    # OTX uses a custom header "X-OTX-API-KEY" for authentication
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    params = {
        "limit": max_pulses
    }

    # Maps OTX indicator types → our standard types
    type_map = {
        "IPv4":           "IP",
        "IPv6":           "IP",
        "domain":         "Domain",
        "hostname":       "Domain",
        "URL":            "Domain",
        "FileHash-MD5":   "Hash",
        "FileHash-SHA1":  "Hash",
        "FileHash-SHA256":"Hash",
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()

        data      = response.json()
        pulses    = data.get("results", [])
        new_count = 0

        for pulse in pulses:
            pulse_name     = pulse.get("name", "Unknown")
            threat_category = pulse.get("tags", ["unknown"])[0] if pulse.get("tags") else "unknown"
            indicators     = pulse.get("indicators", [])

            for ioc in indicators:
                raw_type  = ioc.get("type", "")
                indicator = ioc.get("indicator", "")

                # Map OTX type → our type
                our_type = type_map.get(raw_type, None)

                if indicator and our_type:
                    insert_ioc(
                        indicator_value  = indicator,
                        indicator_type   = our_type,
                        threat_category  = threat_category.lower(),
                        source           = "AlienVault OTX",
                        country          = None,
                        confidence_score = 75  # OTX doesn't provide per-IOC scores
                    )
                    new_count += 1

        print(f"[✓] AlienVault OTX: Fetched {new_count} IOCs from {len(pulses)} pulses.")
        return new_count

    except requests.exceptions.RequestException as e:
        print(f"[✗] AlienVault OTX fetch failed: {e}")
        return 0


# ──────────────────────────────────────────────────────────
# 3. FETCH FROM URLHAUS
# ──────────────────────────────────────────────────────────
def fetch_urlhaus(limit=100):
    """
    Fetches recent malicious URLs from URLhaus by abuse.ch.
    
    KEY ADVANTAGE: NO API KEY REQUIRED.
    URLhaus provides a free public feed of active malware URLs.

    API Endpoint:
        POST https://urlhaus-api.abuse.ch/v1/urls/recent/

    How it works:
        - Sends a POST request (no auth needed)
        - API returns recently submitted malicious URLs
        - We extract the domain from each URL and store it

    Parameters:
        limit (int): Max URLs to process (default 100)

    Returns:
        int: Number of new domains inserted

    Example API Response (single URL entry):
        {
            "url":          "http://malicious-site.ru/payload.exe",
            "url_status":   "online",
            "threat":       "malware_download",
            "tags":         ["emotet", "loader"]
        }
    """
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    try:
        # URLhaus uses POST even for fetching (unusual but that's their API design)
        response = requests.post(url, timeout=15)
        response.raise_for_status()

        data      = response.json()
        urls_list = data.get("urls", [])[:limit]
        new_count = 0

        for item in urls_list:
            raw_url    = item.get("url", "")
            threat     = item.get("threat", "malware")
            url_status = item.get("url_status", "")

            # Extract just the domain from the full URL
            # e.g., "http://evil.com/path" → "evil.com"
            try:
                from urllib.parse import urlparse
                parsed = urlparse(raw_url)
                domain = parsed.netloc or parsed.path
            except Exception:
                domain = raw_url

            if domain and url_status in ["online", "unknown"]:
                insert_ioc(
                    indicator_value  = domain,
                    indicator_type   = "Domain",
                    threat_category  = threat.lower(),
                    source           = "URLhaus",
                    country          = None,
                    confidence_score = 85
                )
                new_count += 1

        print(f"[✓] URLhaus: Fetched {new_count} malicious domains.")
        return new_count

    except requests.exceptions.RequestException as e:
        print(f"[✗] URLhaus fetch failed: {e}")
        return 0


# ──────────────────────────────────────────────────────────
# 4. FETCH CVE DATA FROM NVD (NIST)
# ──────────────────────────────────────────────────────────
def fetch_cve_feed(results_per_page=20):
    

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": 0
    }

    # ── Get NVD API Key (Local or Streamlit Cloud) ──
    nvd_key = os.getenv("NVD_API_KEY") or st.secrets.get("NVD_API_KEY", None)

    headers = {}
    if nvd_key:
        headers["apiKey"] = nvd_key
        print("[✓] Using NVD API Key")
    else:
        print("[!] NVD API key not found — using anonymous access (may be rate limited)")

    # ── Severity Mapping ──
    def score_to_severity(score):
        if score is None:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    try:
        response = requests.get(url, params=params, headers=headers, timeout=20)

        print("NVD Status Code:", response.status_code)

        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        print("Vulnerabilities received:", len(vulnerabilities))

        new_count = 0

        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "")

            descriptions = cve_item.get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available."
            )

            cvss_score = None
            metrics = cve_item.get("metrics", {})

            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    try:
                        cvss_score = metrics[version][0]["cvssData"]["baseScore"]
                    except (KeyError, IndexError):
                        pass
                    break

            severity = score_to_severity(cvss_score)
            published_date = cve_item.get("published", "")[:10]

            if cve_id:
                insert_cve(
                    cve_id=cve_id,
                    description=description[:500],
                    severity=severity,
                    cvss_score=cvss_score,
                    published_date=published_date
                )
                new_count += 1

        print(f"[✓] NVD CVE Feed: Fetched {new_count} CVEs.")
        return new_count

    except Exception as e:
        print("[✗] NVD fetch failed:", str(e))
        try:
            print("Response text:", response.text)
        except:
            pass
        return 0


# ──────────────────────────────────────────────────────────
# 5. IP REPUTATION CHECK (Single IP Lookup)
# ──────────────────────────────────────────────────────────
def check_ip_reputation(ip_address):
    """
    Checks a single IP address against AbuseIPDB and OTX.
    Used in the "IP Reputation Checker" feature of the dashboard.

    Parameters:
        ip_address (str): The IP to investigate

    Returns:
        dict: Combined reputation data from both sources
    
    Example return:
        {
            "ip": "1.2.3.4",
            "abuseipdb": {
                "abuse_score":    95,
                "country":        "CN",
                "isp":            "China Telecom",
                "total_reports":  342,
                "last_reported":  "2024-12-01"
            },
            "otx": {
                "pulse_count":    12,
                "malware_families": ["Emotet", "TrickBot"],
                "is_known_threat": True
            }
        }
    """
    result = {
        "ip":         ip_address,
        "abuseipdb":  None,
        "otx":        None,
        "errors":     []
    }

    # ── AbuseIPDB Check ───────────────────────
    if ABUSEIPDB_API_KEY:
        try:
            url     = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params  = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}

            resp = requests.get(url, headers=headers, params=params, timeout=15)
            resp.raise_for_status()

            data = resp.json().get("data", {})
            result["abuseipdb"] = {
                "abuse_score":    data.get("abuseConfidenceScore", 0),
                "country":        data.get("countryCode", "N/A"),
                "isp":            data.get("isp", "N/A"),
                "domain":         data.get("domain", "N/A"),
                "total_reports":  data.get("totalReports", 0),
                "last_reported":  data.get("lastReportedAt", "Never"),
                "is_public":      data.get("isPublic", False),
                "usage_type":     data.get("usageType", "N/A")
            }
        except Exception as e:
            result["errors"].append(f"AbuseIPDB: {str(e)}")
    else:
        result["errors"].append("AbuseIPDB API key not configured.")

    # ── AlienVault OTX Check ─────────────────
    if OTX_API_KEY:
        try:
            url     = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            headers = {"X-OTX-API-KEY": OTX_API_KEY}

            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()

            data          = resp.json()
            pulse_info    = data.get("pulse_info", {})
            pulse_count   = pulse_info.get("count", 0)
            malware_list  = list(set([
                tag
                for pulse in pulse_info.get("pulses", [])
                for tag in pulse.get("tags", [])
            ]))[:10]  # Keep top 10 tags

            result["otx"] = {
                "pulse_count":      pulse_count,
                "tags":             malware_list,
                "is_known_threat":  pulse_count > 0,
                "country":          data.get("country_name", "N/A"),
                "asn":              data.get("asn", "N/A")
            }
        except Exception as e:
            result["errors"].append(f"OTX: {str(e)}")
    else:
        result["errors"].append("OTX API key not configured.")

    return result


# ──────────────────────────────────────────────────────────
# FETCH ALL (convenience wrapper)
# ──────────────────────────────────────────────────────────
def fetch_all_feeds():
    """
    Fetches data from all sources at once.
    Returns a summary dictionary with counts.
    
    Called when user clicks "Refresh All Data" in the dashboard.
    """
    print("\n[→] Starting full threat intelligence fetch...\n")

    counts = {
        "abuseipdb": fetch_abuseipdb(limit=100),
        "otx":       fetch_otx(max_pulses=5),
        "urlhaus":   fetch_urlhaus(limit=100),
        "cve":       fetch_cve_feed(results_per_page=20)
    }

    total = sum(counts.values())
    print(f"\n[✓] Total new records fetched: {total}")
    print(f"    AbuseIPDB: {counts['abuseipdb']} IPs")
    print(f"    OTX:       {counts['otx']} IOCs")
    print(f"    URLhaus:   {counts['urlhaus']} Domains")
    print(f"    CVE Feed:  {counts['cve']} Vulnerabilities\n")

    return counts
