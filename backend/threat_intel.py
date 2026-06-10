"""
VulnScope v2 - Threat Intelligence
APT group, threat actor, and malware family correlation
"""
import asyncio
from database import get_db

# Known APT/Vendor → CWE/CVE pattern mapping
THREAT_ACTORS = {
    "APT28 (Fancy Bear)": {
        "aliases": ["Sofacy", "Sednit", "Pawn Storm", "STRONTIUM"],
        "country": "Russia",
        "targets": ["Government", "Military", "NATO", "Media"],
        "known_cwes": ["CWE-79", "CWE-78", "CWE-287", "CWE-20"],
        "keywords": ["outlook", "office 365", "vpn", "credential theft", "phishing"],
        "ransomware": False,
    },
    "APT29 (Cozy Bear)": {
        "aliases": ["The Dukes", "YTTRIUM", "Nobelium"],
        "country": "Russia",
        "targets": ["Government", "Think Tanks", "Healthcare", "Technology"],
        "known_cwes": ["CWE-287", "CWE-502", "CWE-306"],
        "keywords": ["solarwinds", "m365", "azure", "supply chain", "oauth"],
        "ransomware": False,
    },
    "APT41 (Winnti)": {
        "aliases": ["Winnti", "BARIUM", "Axiom", "Wicked Panda"],
        "country": "China",
        "targets": ["Healthcare", "Technology", "Telecom", "Gaming"],
        "known_cwes": ["CWE-502", "CWE-89", "CWE-78"],
        "keywords": ["supply chain", "video game", "telecom", "healthcare"],
        "ransomware": False,
    },
    "Lazarus Group": {
        "aliases": ["HIDDEN COBRA", "ZINC", "Diamond Sleet"],
        "country": "North Korea",
        "targets": ["Financial", "Cryptocurrency", "Government", "Defense"],
        "known_cwes": ["CWE-502", "CWE-434", "CWE-78"],
        "keywords": ["crypto", "blockchain", "financial", "bank", "swift"],
        "ransomware": True,
    },
    "LockBit": {
        "aliases": ["LOCKBIT", "Bitwise Spider"],
        "country": "Russia",
        "targets": ["Healthcare", "Education", "Government", "Manufacturing"],
        "known_cwes": ["CWE-269", "CWE-287", "CWE-434", "CWE-502"],
        "keywords": ["ransomware", "ransomware-as-a-service", "raas", "double extortion"],
        "ransomware": True,
    },
    "ALPHV (BlackCat)": {
        "aliases": ["BlackCat", "ALPHV", "Noberus"],
        "country": "Russia",
        "targets": ["Energy", "Healthcare", "Education", "Legal"],
        "known_cwes": ["CWE-269", "CWE-287", "CWE-732"],
        "keywords": ["ransomware", "rust", "exfiltration", "double extortion"],
        "ransomware": True,
    },
    "Clop": {
        "aliases": ["CLOP", "TA505", "FIN11"],
        "country": "Russia",
        "targets": ["Retail", "Finance", "Aviation"],
        "known_cwes": ["CWE-502", "CWE-434", "CWE-20"],
        "keywords": ["managed file transfer", "accellion", "goanywhere", "moveit"],
        "ransomware": True,
    },
    "Conti": {
        "aliases": ["Wizard Spider", "GOLD ULRICK"],
        "country": "Russia",
        "targets": ["Healthcare", "Emergency Services", "Law Enforcement"],
        "known_cwes": ["CWE-269", "CWE-502"],
        "keywords": ["ransomware", "trickbot", "cobalt strike", "emotet"],
        "ransomware": True,
    },
    "APT10 (Stone Panda)": {
        "aliases": ["Stone Panda", "menuPass", "CICADA"],
        "country": "China",
        "targets": ["Telecom", "Aerospace", "Defense", "Managed IT Providers"],
        "known_cwes": ["CWE-502", "CWE-89", "CWE-79"],
        "keywords": ["managed service provider", "telecom", "aerospace", "satellite"],
        "ransomware": False,
    },
    "APT39 (Chafer)": {
        "aliases": ["Chafer", "Remix Kitten"],
        "country": "Iran",
        "targets": ["Telecom", "Travel", "IT Services"],
        "known_cwes": ["CWE-89", "CWE-79", "CWE-434"],
        "keywords": ["telecom", "travel", "middle east", "iran"],
        "ransomware": False,
    },
    "APT32 (OceanLotus)": {
        "aliases": ["OceanLotus", "APT-C-00", "SeaLotus"],
        "country": "Vietnam",
        "targets": ["Manufacturing", "Technology", "Media"],
        "known_cwes": ["CWE-502", "CWE-79", "CWE-78"],
        "keywords": ["manufacturing", "automotive", "southeast asia"],
        "ransomware": False,
    },
    "Kimsuky": {
        "aliases": ["Velvet Chollima", "Black Banshee", "THALLIUM"],
        "country": "North Korea",
        "targets": ["Government", "Think Tanks", "Nuclear", "Academia"],
        "known_cwes": ["CWE-79", "CWE-78", "CWE-20"],
        "keywords": ["nuclear", "diplomat", "think tank", "korea"],
        "ransomware": False,
    },
    "REvil": {
        "aliases": ["Sodinokibi", "GOLD SOUTHFIELD"],
        "country": "Russia",
        "targets": ["Technology", "Manufacturing", "Legal"],
        "known_cwes": ["CWE-269", "CWE-502", "CWE-89"],
        "keywords": ["ransomware-as-a-service", "kaseya", "jbs", "double extortion"],
        "ransomware": True,
    },
    "Hive": {
        "aliases": ["Hive"],
        "country": "Russia",
        "targets": ["Healthcare", "Education"],
        "known_cwes": ["CWE-269", "CWE-287"],
        "keywords": ["ransomware", "healthcare", "education"],
        "ransomware": True,
    },
    "Akira": {
        "aliases": ["Akira"],
        "country": "Unknown",
        "targets": ["Education", "Finance", "Manufacturing"],
        "known_cwes": ["CWE-287", "CWE-269"],
        "keywords": ["ransomware", "ransom", "linux", "vmware"],
        "ransomware": True,
    },
}

# Product-specific threat actor mapping
PRODUCT_THREATS = {
    "microsoft_exchange": ["APT28", "APT29", "Hafnium", "Lazarus Group"],
    "vmware": ["LockBit", "ALPHV", "Conti"],
    "cisco": ["APT28", "APT41"],
    "fortinet": ["APT29", "LockBit"],
    "apache": ["APT28", "APT10", "Lazarus Group"],
    "atlassian": ["APT41", "LockBit"],
    "palo alto": ["APT29", "APT41"],
    "citrix": ["APT28", "Conti"],
    "pulse secure": ["APT29", "APT28"],
    "f5": ["APT29", "APT41"],
    "solarwinds": ["APT29"],
    "log4j": ["APT41", "Lazarus Group", "LockBit"],
    "accellion": ["Clop"],
    "goanywhere": ["Clop"],
    "moveit": ["Clop"],
    "kaseya": ["REvil"],
    "microsoft_windows": ["Conti", "LockBit", "APT28", "APT29"],
}


def correlate_threat_actors(cve_data: dict) -> list:
    """Correlate CVE with known threat actors"""
    matches = []
    desc = (cve_data.get("description") or "").lower()
    vendor = (cve_data.get("vendor") or "").lower()
    product = (cve_data.get("product") or "").lower()
    cwe = (cve_data.get("cwe_id") or "")
    base_cwe = cwe.split(":")[0].strip() if ":" in cwe else cwe.strip()

    for actor_name, actor in THREAT_ACTORS.items():
        score = 0
        reasons = []

        # CWE match
        if base_cwe in actor["known_cwes"]:
            score += 3
            reasons.append(f"CWE {base_cwe} used by {actor_name}")

        # Keyword match in description
        desc_matches = [kw for kw in actor["keywords"] if kw in desc]
        if desc_matches:
            score += len(desc_matches) * 2
            reasons.append(f"Keywords: {', '.join(desc_matches)}")

        # Vendor/Product match
        vendor_product = f"{vendor}_{product}"
        for prod_key, actors in PRODUCT_THREATS.items():
            if prod_key.replace("_", " ") in vendor_product or \
               prod_key.replace("_", " ") in desc:
                for a in actors:
                    if actor_name.split("(")[0].strip() in a or \
                       any(alias.lower() in a.lower() for alias in actor["aliases"]):
                        score += 4
                        reasons.append(f"Targets {prod_key}")

        if score >= 3:
            matches.append({
                "actor": actor_name,
                "country": actor["country"],
                "targets": actor["targets"],
                "ransomware_affiliated": actor["ransomware"],
                "confidence_score": min(score, 10),
                "confidence": "high" if score >= 6 else "medium" if score >= 4 else "low",
                "reasons": reasons,
            })

    return sorted(matches, key=lambda x: -x["confidence_score"])[:5]


async def init_threat_tables(db):
    """Create threat intelligence tables"""
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS threat_actors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            actor_name TEXT NOT NULL,
            country TEXT,
            targets_json TEXT DEFAULT '[]',
            ransomware_affiliated INTEGER DEFAULT 0,
            confidence_score REAL DEFAULT 0,
            confidence TEXT DEFAULT 'low',
            reasons_json TEXT DEFAULT '[]',
            correlated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
            UNIQUE(cve_id, actor_name)
        );
        CREATE INDEX IF NOT EXISTS idx_threat_cve ON threat_actors(cve_id);
        CREATE INDEX IF NOT EXISTS idx_threat_actor ON threat_actors(actor_name);
    """)


async def store_threat_actors(db, cve_id: str, actors: list):
    """Store threat actor correlations"""
    for actor in actors:
        await db.execute("""
            INSERT OR IGNORE INTO threat_actors
            (cve_id, actor_name, country, targets_json, ransomware_affiliated,
             confidence_score, confidence, reasons_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id, actor["actor"], actor["country"],
            json.dumps(actor["targets"]), 1 if actor["ransomware_affiliated"] else 0,
            actor["confidence_score"], actor["confidence"],
            json.dumps(actor["reasons"]),
        ))


import json


async def batch_threat_correlation():
    """Correlate all CVEs with threat actors"""
    print("[Threat Intel] Running threat actor correlation...")
    db = await get_db()
    await init_threat_tables(db)

    rows = await db.execute("""
        SELECT cve_id, description, vendor, product, cwe_id FROM cves
        WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM threat_actors)
        AND severity IN ('CRITICAL', 'HIGH')
        LIMIT 300
    """)
    cves = [dict(r) for r in await rows.fetchall()]

    for cve in cves:
        actors = correlate_threat_actors(cve)
        if actors:
            await store_threat_actors(db, cve["cve_id"], actors)

    await db.commit()
    await db.close()
    print(f"[Threat Intel] Correlated {len(cves)} CVEs with threat actors")


async def get_actor_stats(db) -> dict:
    """Get threat actor activity stats"""
    rows = await db.execute("""
        SELECT actor_name, country, COUNT(*) as cve_count,
               SUM(confidence_score) as total_confidence
        FROM threat_actors
        GROUP BY actor_name
        ORDER BY cve_count DESC
        LIMIT 20
    """)
    return [dict(r) for r in await rows.fetchall()]


async def threat_intel_loop():
    await asyncio.sleep(90)
    while True:
        await batch_threat_correlation()
        await asyncio.sleep(14400)  # Every 4 hours
