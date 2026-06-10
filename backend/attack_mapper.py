"""
VulnScope v2 - MITRE ATT&CK Mapper
Maps CVEs to ATT&CK techniques based on CWE and description patterns
"""
import re
import json
import asyncio
from database import get_db

# CWE → ATT&CK Technique mapping (curated)
CWE_TO_ATTACK = {
    # Execution
    "CWE-78":  {"id": "T1203", "tactic": "Execution", "technique": "Exploitation for Client Execution"},
    "CWE-94":  {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    "CWE-77":  {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    "CWE-502": {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    # Privilege Escalation
    "CWE-269": {"id": "T1068", "tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation"},
    "CWE-250": {"id": "T1068", "tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation"},
    "CWE-732": {"id": "T1068", "tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation"},
    # Defense Evasion
    "CWE-287": {"id": "T1548", "tactic": "Defense Evasion", "technique": "Abuse Elevation Control Mechanism"},
    "CWE-863": {"id": "T1548", "tactic": "Defense Evasion", "technique": "Abuse Elevation Control Mechanism"},
    "CWE-306": {"id": "T1548", "tactic": "Defense Evasion", "technique": "Abuse Elevation Control Mechanism"},
    # Credential Access
    "CWE-522": {"id": "T1552", "tactic": "Credential Access", "technique": "Unsecured Credentials"},
    "CWE-798": {"id": "T1552", "tactic": "Credential Access", "technique": "Unsecured Credentials"},
    "CWE-287": {"id": "T1078", "tactic": "Defense Evasion", "technique": "Valid Accounts"},
    # Persistence
    "CWE-434": {"id": "T1547", "tactic": "Persistence", "technique": "Boot or Logon Autostart Execution"},
    # Lateral Movement
    "CWE-918": {"id": "T1210", "tactic": "Lateral Movement", "technique": "Exploitation of Remote Services"},
    "CWE-88":  {"id": "T1210", "tactic": "Lateral Movement", "technique": "Exploitation of Remote Services"},
    # Collection
    "CWE-200": {"id": "T1005", "tactic": "Collection", "technique": "Data from Local System"},
    # Command & Control
    "CWE-20":  {"id": "T1071", "tactic": "Command and Control", "technique": "Application Layer Protocol"},
    "CWE-79":  {"id": "T1189", "tactic": "Initial Access", "technique": "Drive-by Compromise"},
    # Exfiltration
    "CWE-22":  {"id": "T1048", "tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol"},
    "CWE-23":  {"id": "T1048", "tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol"},
    # Impact
    "CWE-787": {"id": "T1055", "tactic": "Privilege Escalation", "technique": "Process Injection"},
    "CWE-125": {"id": "T1005", "tactic": "Collection", "technique": "Data from Local System"},
    "CWE-416": {"id": "T1055", "tactic": "Privilege Escalation", "technique": "Process Injection"},
    "CWE-119": {"id": "T1203", "tactic": "Execution", "technique": "Exploitation for Client Execution"},
    "CWE-190": {"id": "T1055", "tactic": "Privilege Escalation", "technique": "Process Injection"},
    "CWE-476": {"id": "T1499", "tactic": "Impact", "technique": "Endpoint Denial of Service"},
    "CWE-400": {"id": "T1499", "tactic": "Impact", "technique": "Endpoint Denial of Service"},
    "CWE-362": {"id": "T1068", "tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation"},
    # Initial Access
    "CWE-601": {"id": "T1566", "tactic": "Initial Access", "technique": "Phishing"},
    "CWE-352": {"id": "T1566", "tactic": "Initial Access", "technique": "Phishing"},
    "CWE-89":  {"id": "T1190", "tactic": "Initial Access", "technique": "Exploit Public-Facing Application"},
    "CWE-1333":{"id": "T1499", "tactic": "Impact", "technique": "Endpoint Denial of Service"},
    "CWE-611": {"id": "T1190", "tactic": "Initial Access", "technique": "Exploit Public-Facing Application"},
    "CWE-639": {"id": "T1078", "tactic": "Credential Access", "technique": "Valid Accounts"},
    "CWE-1321":{"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    "CWE-295": {"id": "T1557", "tactic": "Credential Access", "technique": "Man-in-the-Middle"},
    "CWE-732": {"id": "T1548", "tactic": "Defense Evasion", "technique": "Abuse Elevation Control Mechanism"},
}

# Description keyword → ATT&CK mapping
DESC_TO_ATTACK = [
    (r"remote code execution|rce|arbitrary code", "T1203", "Execution", "Exploitation for Client Execution"),
    (r"sql injection|sqli", "T1190", "Initial Access", "Exploit Public-Facing Application"),
    (r"cross.site scripting|xss", "T1189", "Initial Access", "Drive-by Compromise"),
    (r"privilege escalation|elevation of privilege", "T1068", "Privilege Escalation", "Exploitation for Privilege Escalation"),
    (r"denial of service|dos|ddos", "T1499", "Impact", "Endpoint Denial of Service"),
    (r"authentication bypass|auth bypass", "T1548", "Defense Evasion", "Abuse Elevation Control Mechanism"),
    (r"path traversal|directory traversal", "T1005", "Collection", "Data from Local System"),
    (r"deserialization|unserialize", "T1059", "Execution", "Command and Scripting Interpreter"),
    (r"ssrf|server.side request forgery", "T1190", "Initial Access", "Exploit Public-Facing Application"),
    (r"xxe|xml external entity", "T1190", "Initial Access", "Exploit Public-Facing Application"),
    (r"buffer overflow|stack overflow|heap overflow", "T1203", "Execution", "Exploitation for Client Execution"),
    (r"use.after.free|uaf", "T1055", "Privilege Escalation", "Process Injection"),
    (r"command injection|os command", "T1059", "Execution", "Command and Scripting Interpreter"),
    (r"information disclosure|sensitive information", "T1005", "Collection", "Data from Local System"),
    (r"phishing|social engineering", "T1566", "Initial Access", "Phishing"),
    (r"credential|password|token leak", "T1552", "Credential Access", "Unsecured Credentials"),
    (r"csrf|cross.site request forgery", "T1566", "Initial Access", "Phishing"),
    (r"race condition|toctou", "T1068", "Privilege Escalation", "Exploitation for Privilege Escalation"),
    (r"prototype pollution", "T1059", "Execution", "Command and Scripting Interpreter"),
    (r"code injection|template injection|ssti", "T1059", "Execution", "Command and Scripting Interpreter"),
]


def map_cve_to_attack(cve_data: dict) -> list:
    """Map a CVE to MITRE ATT&CK techniques"""
    techniques = []
    seen = set()

    # Check CWE mapping
    cwe = cve_data.get("cwe_id", "")
    if cwe:
        base_cwe = cwe.split(":")[0].strip() if ":" in cwe else cwe.strip()
        if base_cwe in CWE_TO_ATTACK:
            t = CWE_TO_ATTACK[base_cwe]
            key = f"{t['id']}_{t['technique']}"
            if key not in seen:
                techniques.append({
                    "technique_id": t["id"],
                    "tactic": t["tactic"],
                    "technique": t["technique"],
                    "confidence": "medium",
                    "source": f"CWE mapping ({base_cwe})",
                })
                seen.add(key)

    # Check description keywords
    desc = (cve_data.get("description") or "").lower()
    for pattern, tech_id, tactic, technique in DESC_TO_ATTACK:
        if re.search(pattern, desc):
            key = f"{tech_id}_{technique}"
            if key not in seen:
                techniques.append({
                    "technique_id": tech_id,
                    "tactic": tactic,
                    "technique": technique,
                    "confidence": "low",
                    "source": "Description keyword match",
                })
                seen.add(key)

    return techniques[:5]  # Max 5 techniques


async def init_attack_tables(db):
    """Create ATT&CK mapping tables"""
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS attack_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            tactic TEXT,
            technique TEXT,
            confidence TEXT DEFAULT 'medium',
            source TEXT,
            mapped_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
            UNIQUE(cve_id, technique_id)
        );
        CREATE INDEX IF NOT EXISTS idx_attack_cve ON attack_mappings(cve_id);
        CREATE INDEX IF NOT EXISTS idx_attack_technique ON attack_mappings(technique_id);
    """)


async def map_and_store(db, cve_data: dict):
    """Map CVE to ATT&CK and store results"""
    cve_id = cve_data["cve_id"]
    techniques = map_cve_to_attack(cve_data)

    for t in techniques:
        await db.execute("""
            INSERT OR IGNORE INTO attack_mappings
            (cve_id, technique_id, tactic, technique, confidence, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cve_id, t["technique_id"], t["tactic"], t["technique"],
              t["confidence"], t["source"]))


async def batch_map_all():
    """Map all CVEs to ATT&CK techniques"""
    print("[ATT&CK Mapper] Starting full mapping...")
    db = await get_db()
    await init_attack_tables(db)

    rows = await db.execute("""
        SELECT cve_id, description, cwe_id FROM cves
        WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM attack_mappings)
        LIMIT 500
    """)
    cves = [dict(r) for r in await rows.fetchall()]

    for cve in cves:
        await map_and_store(db, cve)

    await db.commit()
    await db.close()
    print(f"[ATT&CK Mapper] Mapped {len(cves)} CVEs")


async def get_attack_techniques(db, cve_id: str) -> list:
    rows = await db.execute(
        "SELECT * FROM attack_mappings WHERE cve_id = ?", (cve_id,)
    )
    return [dict(r) for r in await rows.fetchall()]


async def get_tactic_stats(db) -> dict:
    """Get breakdown of CVEs by ATT&CK tactic"""
    rows = await db.execute("""
        SELECT tactic, COUNT(*) as count
        FROM attack_mappings
        GROUP BY tactic
        ORDER BY count DESC
    """)
    return {r["tactic"]: r["count"] for r in await rows.fetchall()}


async def attack_mapper_loop():
    """Periodic ATT&CK mapping loop"""
    await asyncio.sleep(60)
    while True:
        await batch_map_all()
        await asyncio.sleep(7200)  # Every 2 hours
