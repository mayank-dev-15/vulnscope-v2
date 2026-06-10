"""
VulnScope v2 - Trend Analytics Engine
Time-series vulnerability trends, vendor breakdowns, exploit timelines
"""
import json
import asyncio
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from database import get_db


async def get_daily_trends(db, days: int = 30) -> list:
    """Get daily CVE publication trend"""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = await db.execute("""
        SELECT DATE(published_date) as day,
               COUNT(*) as total,
               SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
               SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
               SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium
        FROM cves
        WHERE published_date >= ?
        GROUP BY day
        ORDER BY day ASC
    """, (since,))
    return [dict(r) for r in await rows.fetchall()]


async def get_severity_distribution(db) -> dict:
    """Get breakdown by severity"""
    rows = await db.execute("""
        SELECT severity, COUNT(*) as count
        FROM cves
        GROUP BY severity
        ORDER BY count DESC
    """)
    return {r["severity"]: r["count"] for r in await rows.fetchall()}


async def get_top_vendors(db, limit: int = 20) -> list:
    """Get most affected vendors"""
    rows = await db.execute("""
        SELECT vendor, COUNT(*) as cve_count,
               SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
               ROUND(AVG(cvss_score), 1) as avg_cvss
        FROM cves
        WHERE vendor != ''
        GROUP BY vendor
        ORDER BY cve_count DESC
        LIMIT ?
    """, (limit,))
    return [dict(r) for r in await rows.fetchall()]


async def get_top_products(db, limit: int = 20) -> list:
    """Get most affected products"""
    rows = await db.execute("""
        SELECT vendor, product, COUNT(*) as cve_count,
               SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as critical_high
        FROM cves
        WHERE product != '' AND vendor != ''
        GROUP BY vendor, product
        ORDER BY cve_count DESC
        LIMIT ?
    """, (limit,))
    return [dict(r) for r in await rows.fetchall()]


async def get_top_cwes(db, limit: int = 15) -> list:
    """Get most common CWE weakness types"""
    rows = await db.execute("""
        SELECT cwe_id, COUNT(*) as count,
               ROUND(AVG(cvss_score), 1) as avg_cvss,
               SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
        FROM cves
        WHERE cwe_id IS NOT NULL AND cwe_id != ''
        GROUP BY cwe_id
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))
    return [dict(r) for r in await rows.fetchall()]


async def get_exploit_timeline(db) -> dict:
    """Get exploit discovery timeline stats"""
    rows = await db.execute("""
        SELECT c.published_date, COUNT(e.id) as exploit_count
        FROM cves c
        JOIN exploits e ON c.cve_id = e.cve_id
        WHERE c.published_date IS NOT NULL
        GROUP BY DATE(c.published_date)
        ORDER BY c.published_date DESC
        LIMIT 90
    """)
    return [dict(r) for r in await rows.fetchall()]


async def get_ransomware_trends(db) -> list:
    """Get ransomware-associated CVE trends"""
    rows = await db.execute("""
        SELECT rm.ransomware_family, COUNT(*) as cve_count,
               SUM(CASE WHEN c.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical
        FROM ransomware_mapping rm
        JOIN cves c ON rm.cve_id = c.cve_id
        GROUP BY rm.ransomware_family
        ORDER BY cve_count DESC
    """)
    return [dict(r) for r in await rows.fetchall()]


async def get_epss_stats(db) -> dict:
    """Get EPSS score distribution statistics"""
    rows = await db.execute("""
        SELECT
            COUNT(*) as total_with_epss,
            COUNT(CASE WHEN epss_score > 0.9 THEN 1 END) as critical_epss,
            COUNT(CASE WHEN epss_score > 0.5 THEN 1 END) as high_epss,
            COUNT(CASE WHEN epss_score > 0.1 THEN 1 END) as medium_epss,
            ROUND(AVG(epss_score), 4) as avg_epss,
            ROUND(MAX(epss_score), 4) as max_epss
        FROM cves
        WHERE epss_score > 0
    """)
    row = await rows.fetchone()
    return dict(row) if row else {}


async def get_weekly_summary(db) -> dict:
    """Get weekly vulnerability summary"""
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    month_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    async def count(sql, *params):
        r = await db.execute(sql, params)
        row = await r.fetchone()
        return row[0] if row else 0

    return {
        "new_cves_week": await count("SELECT COUNT(*) FROM cves WHERE fetched_at >= ?", week_ago),
        "new_cves_month": await count("SELECT COUNT(*) FROM cves WHERE fetched_at >= ?", month_ago),
        "new_exploits_week": await count(
            "SELECT COUNT(*) FROM exploits WHERE id IN (SELECT MAX(id) FROM exploits GROUP BY cve_id)"),
        "critical_week": await count(
            "SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL' AND fetched_at >= ?", week_ago),
        "ransomware_week": await count(
            "SELECT COUNT(*) FROM ransomware_mapping WHERE added_date >= ?", week_ago),
    }


async def get_risk_distribution(db) -> dict:
    """Get ML risk score distribution"""
    rows = await db.execute("""
        SELECT risk_level, COUNT(*) as count, ROUND(AVG(exploit_risk_score), 1) as avg_score
        FROM cves
        WHERE risk_level IS NOT NULL AND risk_level != 'UNKNOWN'
        GROUP BY risk_level
        ORDER BY avg_score DESC
    """)
    return [dict(r) for r in await rows.fetchall()]


async def get_attack_surface(db) -> dict:
    """Get attack surface overview - CVEs by attack tactic"""
    rows = await db.execute("""
        SELECT tactic, technique, COUNT(*) as cve_count
        FROM attack_mappings
        GROUP BY tactic, technique
        ORDER BY cve_count DESC
    """)
    techniques = [dict(r) for r in await rows.fetchall()]

    # Group by tactic
    tactic_map = defaultdict(list)
    for t in techniques:
        tactic_map[t["tactic"]].append({
            "technique": t["technique"],
            "cve_count": t["cve_count"],
        })

    return {
        "total_mappings": sum(t["cve_count"] for t in techniques),
        "unique_techniques": len(set(t["technique"] for t in techniques)),
        "by_tactic": {k: v for k, v in tactic_map.items()},
    }
