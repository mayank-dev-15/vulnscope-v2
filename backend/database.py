"""
VulnScope v2 - Database Layer
Async SQLite with connection pooling
"""
import aiosqlite
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional

DB_PATH = Path(__file__).parent.parent / "data" / "vulnscope.db"


async def get_db() -> aiosqlite.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(str(DB_PATH))
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=NORMAL")
    return db


async def init_db():
    db = await get_db()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT DEFAULT 'UNKNOWN',
            cvss_score REAL,
            cvss_vector TEXT,
            published_date TEXT,
            last_modified TEXT,
            vendor TEXT DEFAULT '',
            product TEXT DEFAULT '',
            references_json TEXT DEFAULT '[]',
            cwe_id TEXT,
            fetched_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
        CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date);
        CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(vendor);

        CREATE TABLE IF NOT EXISTS exploits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            source TEXT NOT NULL,
            title TEXT,
            url TEXT DEFAULT '',
            exploit_type TEXT DEFAULT '',
            date_published TEXT,
            confidence TEXT DEFAULT 'medium',
            description TEXT DEFAULT '',
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve_id);
        CREATE INDEX IF NOT EXISTS idx_exploits_source ON exploits(source);

        CREATE TABLE IF NOT EXISTS ransomware_mapping (
            cve_id TEXT PRIMARY KEY,
            ransomware_family TEXT,
            known_campaigns TEXT DEFAULT '[]',
            added_date TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE TABLE IF NOT EXISTS cisa_kev (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware_campaign_use TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE TABLE IF NOT EXISTS fetch_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            status TEXT,
            items_fetched INTEGER DEFAULT 0,
            items_new INTEGER DEFAULT 0,
            error_message TEXT,
            timestamp TEXT DEFAULT (datetime('now'))
        );
    """)
    await db.commit()
    await db.close()


async def upsert_cve(db: aiosqlite.Connection, cve: dict) -> bool:
    """Returns True if new, False if updated"""
    existing = await db.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve["cve_id"],))
    is_new = await existing.fetchone() is None

    await db.execute("""
        INSERT INTO cves (cve_id, description, severity, cvss_score, cvss_vector,
                          published_date, last_modified, vendor, product,
                          references_json, cwe_id, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(cve_id) DO UPDATE SET
            description=excluded.description,
            severity=excluded.severity,
            cvss_score=excluded.cvss_score,
            last_modified=excluded.last_modified,
            references_json=excluded.references_json,
            fetched_at=datetime('now')
    """, (
        cve["cve_id"], cve.get("description", ""), cve.get("severity", "UNKNOWN"),
        cve.get("cvss_score"), cve.get("cvss_vector"),
        cve.get("published_date"), cve.get("last_modified"),
        cve.get("vendor", ""), cve.get("product", ""),
        json.dumps(cve.get("references", [])), cve.get("cwe_id")
    ))
    await db.commit()
    return is_new


async def add_exploit(db: aiosqlite.Connection, exploit: dict):
    await db.execute("""
        INSERT OR REPLACE INTO exploits (cve_id, source, title, url, exploit_type,
                                          date_published, confidence, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        exploit["cve_id"], exploit["source"], exploit.get("title", ""),
        exploit.get("url", ""), exploit.get("exploit_type", ""),
        exploit.get("date_published"), exploit.get("confidence", "medium"),
        exploit.get("description", "")
    ))
    await db.commit()


async def get_cve(db: aiosqlite.Connection, cve_id: str) -> Optional[dict]:
    row = await db.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    result = await row.fetchone()
    if result is None:
        return None
    return dict(result)


async def search_cves(
    db: aiosqlite.Connection,
    query: str = "",
    severity: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    limit: int = 50,
    offset: int = 0
) -> List[dict]:
    conditions = []
    params = []

    if query:
        conditions.append("(cve_id LIKE ? OR description LIKE ? OR vendor LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like, like])

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())

    if has_exploit:
        conditions.append("cve_id IN (SELECT DISTINCT cve_id FROM exploits)")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    sql = f"""
        SELECT * FROM cves
        {where}
        ORDER BY published_date DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    rows = await db.execute(sql, params)
    results = await rows.fetchall()
    return [dict(r) for r in results]


async def get_exploits_for_cve(db: aiosqlite.Connection, cve_id: str) -> List[dict]:
    rows = await db.execute(
        "SELECT * FROM exploits WHERE cve_id = ? ORDER BY date_published DESC",
        (cve_id,)
    )
    return [dict(r) for r in await rows.fetchall()]


async def get_stats(db: aiosqlite.Connection) -> dict:
    async def count(sql, params=()):
        r = await db.execute(sql, params)
        row = await r.fetchone()
        return row[0] if row else 0

    total = await count("SELECT COUNT(*) FROM cves")
    critical = await count("SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'")
    high = await count("SELECT COUNT(*) FROM cves WHERE severity = 'HIGH'")
    with_exploits = await count("SELECT COUNT(DISTINCT cve_id) FROM exploits")
    ransomware = await count("SELECT COUNT(*) FROM ransomware_mapping")
    kev = await count("SELECT COUNT(*) FROM cisa_kev")

    last_fetch = await db.execute("SELECT timestamp FROM fetch_log ORDER BY id DESC LIMIT 1")
    lf = await last_fetch.fetchone()
    last_fetched = lf[0] if lf else None

    day_ago = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent_24h = await count("SELECT COUNT(*) FROM cves WHERE fetched_at >= ?", (day_ago,))

    return {
        "total_cves": total,
        "critical_count": critical,
        "high_count": high,
        "with_exploits": with_exploits,
        "ransomware_related": ransomware,
        "cisa_kev_count": kev,
        "last_fetched": last_fetched,
        "recent_cves_24h": recent_24h,
    }


async def log_fetch(db: aiosqlite.Connection, source: str, status: str,
                    items_fetched: int = 0, items_new: int = 0, error: str = ""):
    await db.execute("""
        INSERT INTO fetch_log (source, status, items_fetched, items_new, error_message)
        VALUES (?, ?, ?, ?, ?)
    """, (source, status, items_fetched, items_new, error))
    await db.commit()
