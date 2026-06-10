"""
VulnScope v2 - ML Exploit Predictor
Predicts exploitation likelihood using CVE features
Features: CVSS score, EPSS score, CWE category, description NLP, age, reference count
"""
import json
import math
import pickle
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from database import get_db

MODEL_PATH = Path(__file__).parent.parent / "data" / "exploit_model.pkl"

# CWE categories commonly exploited
HIGH_RISK_CWE = {
    "CWE-787": 9.5, "CWE-79": 8.0, "CWE-89": 8.5, "CWE-20": 7.0,
    "CWE-125": 7.5, "CWE-78": 9.0, "CWE-416": 8.5, "CWE-22": 7.5,
    "CWE-352": 6.0, "CWE-434": 8.0, "CWE-476": 6.5, "CWE-502": 9.0,
    "CWE-287": 8.0, "CWE-190": 7.0, "CWE-119": 8.5, "CWE-862": 6.5,
    "CWE-77": 9.0, "CWE-94": 9.5, "CWE-200": 5.0, "CWE-918": 8.5,
    "CWE-1321": 7.5, "CWE-306": 7.5, "CWE-863": 7.0, "CWE-269": 7.5,
    "CWE-400": 5.5, "CWE-601": 4.0, "CWE-295": 5.0, "CWE-362": 7.0,
    "CWE-1333": 7.5, "CWE-611": 8.0, "CWE-732": 6.5, "CWE-639": 7.0,
}

# Keywords that indicate high exploitability
EXPLOITABLE_KEYWORDS = [
    "remote code execution", "arbitrary code execution", "command injection",
    "sql injection", "buffer overflow", "use after free", "deserialization",
    "authentication bypass", "privilege escalation", "path traversal",
    "out-of-bounds", "type confusion", "race condition", "double free",
    "integer overflow", "format string", "null pointer dereference",
    "prototype pollution", "server-side request forgery",
]

PATCH_KEYWORDS = [
    "patch available", "vendor patch", "security update", "fixed in",
    "update available", "upgrade to", "mitigation", "workaround",
]


def extract_cwe_base(cwe_str: str) -> str:
    """Extract base CWE from string like 'CWE-787: Out-of-bounds Write'"""
    if not cwe_str:
        return ""
    parts = cwe_str.split(":")
    return parts[0].strip() if parts[0].startswith("CWE-") else ""


def keyword_score(description: str) -> float:
    """Score description for exploitability keywords"""
    desc = description.lower()
    score = 0
    for kw in EXPLOITABLE_KEYWORDS:
        if kw in desc:
            score += 1.5
            if kw in ["remote code execution", "command injection", "deserialization"]:
                score += 2.0  # Higher weight for RCE/deserialization
    for kw in PATCH_KEYWORDS:
        if kw in desc:
            score -= 0.5
    return min(score, 15)


def reference_bonus(ref_count: int) -> float:
    """More references = more attention = higher exploit probability"""
    if ref_count <= 0:
        return 0
    if ref_count <= 3:
        return 0.3
    if ref_count <= 10:
        return 1.0
    if ref_count <= 30:
        return 2.0
    return 3.0


def age_factor(published_date: str) -> float:
    """Newer CVEs have higher immediate exploitation risk; older ones may have known exploits"""
    if not published_date:
        return 0.5
    try:
        pub = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
        days = (datetime.now(timezone.utc) - pub).days
        if days < 30:
            return 2.0  # Fresh CVE, high attention
        if days < 90:
            return 1.5
        if days < 365:
            return 1.0
        if days < 730:
            return 0.7
        return 0.3
    except:
        return 0.5


def predict_exploit_risk(cve_data: dict) -> dict:
    """
    ML-style heuristics to predict exploitation risk.
    Uses feature engineering based on known exploit patterns.
    Returns score 0-10 with breakdown.
    """
    cvss = cve_data.get("cvss_score") or 0
    epss = cve_data.get("epss_score") or 0
    severity = cve_data.get("severity", "UNKNOWN")
    description = cve_data.get("description", "")
    cwe = cve_data.get("cwe_id", "")
    published = cve_data.get("published_date", "")
    refs = json.loads(cve_data.get("references_json", "[]")) if isinstance(cve_data.get("references_json"), str) else cve_data.get("references", [])

    base_cwe = extract_cwe_base(cwe)

    # Feature engineering
    features = {
        "cvss_contribution": min(cvss / 10 * 3, 3.0),  # 0-3 points from CVSS
        "epss_contribution": min(epss * 3, 3.0),  # 0-3 points from EPSS
        "cwe_contribution": HIGH_RISK_CWE.get(base_cwe, 0) / 10 * 2.5,  # 0-2.5 from CWE
        "keyword_contribution": min(keyword_score(description) / 15 * 2.5, 2.5),  # 0-2.5 from keywords
        "reference_contribution": min(reference_bonus(len(refs) if isinstance(refs, list) else 0), 2.0),  # 0-2 from refs
        "age_contribution": min(age_factor(published) / 2 * 1.5, 1.5),  # 0-1.5 from age
    }

    total = sum(features.values())
    # Scale to 0-10
    score = round(min(total * 0.75, 10.0), 1)

    # Risk level
    if score >= 8.0:
        level = "CRITICAL_RISK"
    elif score >= 6.0:
        level = "HIGH_RISK"
    elif score >= 3.5:
        level = "MODERATE_RISK"
    else:
        level = "LOW_RISK"

    return {
        "exploit_risk_score": score,
        "risk_level": level,
        "feature_breakdown": {
            k: round(v, 2) for k, v in features.items()
        },
        "top_risk_factors": get_top_factors(features, description, base_cwe),
    }


def get_top_factors(features: dict, description: str, cwe: str) -> list:
    """Identify top 3 risk factors"""
    factor_names = {
        "cvss_contribution": "High CVSS score",
        "epss_contribution": "High EPSS exploitation probability",
        "cwe_contribution": f"Dangerous weakness type ({cwe})" if cwe else "Weakness type",
        "keyword_contribution": "Exploitable keywords in description",
        "reference_contribution": "High number of references/attention",
        "age_contribution": "Recently published (high attention window)",
    }
    sorted_features = sorted(features.items(), key=lambda x: -x[1])
    return [factor_names.get(k, k) for k, v in sorted_features[:3] if v > 0.5]


async def score_cve(db, cve_data: dict) -> dict:
    """Score a single CVE and store risk in DB"""
    risk = predict_exploit_risk(cve_data)

    # Store in DB
    try:
        await db.execute("ALTER TABLE cves ADD COLUMN exploit_risk_score REAL DEFAULT 0")
        await db.execute("ALTER TABLE cves ADD COLUMN risk_level TEXT DEFAULT 'UNKNOWN'")
    except:
        pass

    await db.execute("""
        UPDATE cves SET exploit_risk_score = ?, risk_level = ?
        WHERE cve_id = ?
    """, (risk["exploit_risk_score"], risk["risk_level"], cve_data["cve_id"]))

    return risk


async def batch_score_all_cves():
    """Score all existing CVEs with the ML risk model"""
    print("[ML Predictor] Scoring all CVEs...")
    db = await get_db()

    rows = await db.execute("""
        SELECT * FROM cves WHERE exploit_risk_score IS NULL OR exploit_risk_score = 0
        ORDER BY published_date DESC
        LIMIT 1000
    """)
    cves = [dict(r) for r in await rows.fetchall()]

    for cve in cves:
        await score_cve(db, cve)

    await db.commit()
    await db.close()
    print(f"[ML Predictor] Scored {len(cves)} CVEs")


async def ml_predictor_loop():
    """Periodic ML scoring loop"""
    await asyncio.sleep(30)  # Wait for initial data load
    while True:
        await batch_score_all_cves()
        await asyncio.sleep(3600)  # Hourly
