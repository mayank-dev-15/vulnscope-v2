"""
VulnScope v2 - CVE Fetcher
Pulls CVEs from NVD API 2.0 with rate-limit handling
"""
import asyncio
import httpx
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from database import get_db, upsert_cve, log_fetch, get_stats
from websocket_mgr import manager

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_DELAY = 6.0  # NVD allows ~10 req/min without key, 50 with key
REQUEST_TIMEOUT = 30.0
FETCH_INTERVAL = 300  # 5 minutes between fetches

# Known vulnerable vendor-product combos to watch
WATCHLIST = [
    ("microsoft", "windows"),
    ("microsoft", "exchange"),
    ("apache", "log4j"),
    ("vmware", "vcenter"),
    ("cisco", "ios"),
    ("fortinet", "fortios"),
    ("atlassian", "confluence"),
    ("google", "chrome"),
    ("mozilla", "firefox"),
    ("apple", "ios"),
]


def parse_severity(cve_item: dict) -> tuple:
    """Extract CVSS score and severity from CVE data"""
    metrics = cve_item.get("metrics", {})
    
    # Try CVSS v3.1 first, then v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss = metric_list[0].get("cvssData", {})
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString", "")
            severity = cvss.get("baseSeverity", "").upper()
            if severity:
                return score, severity, vector

    return None, "UNKNOWN", ""


def extract_cpe_info(configurations: list) -> tuple:
    """Extract vendor and product from CPE configurations"""
    vendor = ""
    product = ""
    for config in (configurations or []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria.startswith("cpe:2.3:"):
                    parts = criteria.split(":")
                    if len(parts) > 4:
                        vendor = parts[3] if not vendor else vendor
                        product = parts[4] if not product else product
                        if vendor and product:
                            return vendor, product
    return vendor, product


def extract_references(cve_item: dict) -> list:
    refs = []
    for ref in cve_item.get("references", []):
        refs.append({
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tags": ref.get("tags", []),
        })
    return refs


async def fetch_cve_page(client: httpx.AsyncClient, start_index: int,
                         results_per_page: int = 100,
                         api_key: str = "") -> Optional[dict]:
    """Fetch a single page of CVEs from NVD API 2.0"""
    # Get CVEs modified in last 24h
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(hours=24)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = await client.get(NVD_BASE, params=params, headers=headers,
                                timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 403:
            print(f"[NVD] Rate limited, waiting...")
            await asyncio.sleep(30)
            return None
        else:
            print(f"[NVD] HTTP {resp.status_code}: {resp.text[:200]}")
            return None
    except Exception as e:
        print(f"[NVD] Request error: {e}")
        return None


async def process_cve(cve_item: dict) -> Optional[dict]:
    """Convert NVD CVE item to internal format"""
    cve_info = cve_item.get("cve", {})
    cve_id = cve_info.get("id", "")
    if not cve_id:
        return None

    descriptions = cve_info.get("descriptions", [])
    desc_en = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_en = d.get("value", "")
            break

    cvss_score, severity, cvss_vector = parse_severity(cve_item)

    # Weakness info
    weaknesses = cve_info.get("weaknesses", [])
    cwe_id = None
    if weaknesses:
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    break
            if cwe_id:
                break

    vendor, product = extract_cpe_info(cve_item.get("configurations", []))

    return {
        "cve_id": cve_id,
        "description": desc_en[:2000] if desc_en else "",
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published_date": cve_info.get("published", ""),
        "last_modified": cve_info.get("lastModified", ""),
        "vendor": vendor,
        "product": product,
        "references": extract_references(cve_item),
        "cwe_id": cwe_id,
    }


async def fetch_cves_continuous(api_key: str = ""):
    """Main loop: continuously fetch and process new CVEs"""
    print("[CVE Fetcher] Starting continuous CVE ingestion...")

    while True:
        try:
            async with httpx.AsyncClient() as client:
                total_fetched = 0
                total_new = 0

                # Fetch first page
                data = await fetch_cve_page(client, 0, api_key=api_key)
                if not data:
                    await asyncio.sleep(FETCH_INTERVAL)
                    continue

                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                print(f"[NVD] Fetched page 1: {len(vulnerabilities)} items (total: {total_results})")

                db = await get_db()

                for vuln in vulnerabilities:
                    cve_data = await process_cve(vuln.get("cve", {}))
                    if cve_data:
                        is_new = await upsert_cve(db, cve_data)
                        total_fetched += 1
                        if is_new:
                            total_new += 1
                            # Broadcast new CVE via WebSocket
                            await manager.broadcast_cve(cve_data)

                # Fetch remaining pages
                if total_results > 100:
                    pages = (total_results // 100)
                    for page in range(1, min(pages + 1, 5)):  # Max 5 pages per cycle
                        await asyncio.sleep(RATE_LIMIT_DELAY)
                        data = await fetch_cve_page(client, page * 100, api_key=api_key)
                        if data:
                            vulnerabilities = data.get("vulnerabilities", [])
                            for vuln in vulnerabilities:
                                cve_data = await process_cve(vuln.get("cve", {}))
                                if cve_data:
                                    is_new = await upsert_cve(db, cve_data)
                                    total_fetched += 1
                                    if is_new:
                                        total_new += 1
                                        await manager.broadcast_cve(cve_data)

                await log_fetch(db, "nvd", "success", total_fetched, total_new)

                # Broadcast updated stats
                stats = await get_stats(db)
                await manager.broadcast_stats(stats)

                await db.close()
                print(f"[NVD] Cycle complete: {total_fetched} fetched, {total_new} new")

        except Exception as e:
            print(f"[CVE Fetcher] Error: {e}")
            try:
                db = await get_db()
                await log_fetch(db, "nvd", "error", error=str(e))
                await db.close()
            except:
                pass

        await asyncio.sleep(FETCH_INTERVAL)
