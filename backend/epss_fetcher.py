"""
VulnScope v2 - EPSS Fetcher
FIRST.org Exploit Prediction Scoring System — probability of exploitation in next 30 days
"""
import csv
import io
import httpx
import asyncio
from datetime import datetime, timezone
from database import get_db, upsert_cve

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv"
FETCH_INTERVAL = 86400  # Daily (EPSS updates daily)


async def fetch_epss_scores() -> dict:
    """Download and parse the latest EPSS scores CSV"""
    print("[EPSS] Fetching latest scores...")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(EPSS_URL, timeout=60, follow_redirects=True)
            if resp.status_code != 200:
                print(f"[EPSS] HTTP {resp.status_code}")
                return {}

            # Parse CSV
            reader = csv.DictReader(io.StringIO(resp.text))
            scores = {}
            for row in reader:
                cve_id = row.get("cve", "").strip()
                epss = row.get("epss", "0").strip()
                percentile = row.get("percentile", "0").strip()
                if cve_id and epss:
                    scores[cve_id] = {
                        "epss_score": float(epss),
                        "epss_percentile": float(percentile),
                    }
            print(f"[EPSS] Loaded {len(scores)} scores")
            return scores
    except Exception as e:
        print(f"[EPSS] Error: {e}")
        return {}


async def update_epss_scores():
    """Update EPSS scores in the database"""
    print("[EPSS] Starting EPSS score update...")

    scores = await fetch_epss_scores()
    if not scores:
        return

    db = await get_db()

    # Ensure EPSS columns exist
    try:
        await db.execute("ALTER TABLE cves ADD COLUMN epss_score REAL DEFAULT 0")
        await db.execute("ALTER TABLE cves ADD COLUMN epss_percentile REAL DEFAULT 0")
    except:
        pass  # Columns already exist

    updated = 0
    for cve_id, data in scores.items():
        await db.execute("""
            UPDATE cves SET epss_score = ?, epss_percentile = ?
            WHERE cve_id = ?
        """, (data["epss_score"], data["epss_percentile"], cve_id))
        updated += 1

    await db.commit()
    await db.close()
    print(f"[EPSS] Updated {updated} CVE EPSS scores")


async def epss_loop():
    """Continuous EPSS update loop"""
    while True:
        await update_epss_scores()
        await asyncio.sleep(FETCH_INTERVAL)
