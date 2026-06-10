"""
VulnScope v2 - Risk Engine
Custom vulnerability risk scoring beyond CVSS — combines CVSS, EPSS, exploit availability,
threat actor interest, and asset context
"""
import json
import asyncio
from database import get_db


class RiskEngine:
    """
    Custom risk scoring engine that goes beyond CVSS.
    Risk = CVSS(30%) + EPSS(25%) + ExploitAvailable(20%) + ThreatActor(15%) + Age(10%)
    """

    @staticmethod
    def cvss_component(cvss_score: float) -> float:
        """CVSS contribution: 0-10 scaled to 0-3"""
        if not cvss_score:
            return 0
        return (cvss_score / 10.0) * 3.0

    @staticmethod
    def epss_component(epss_score: float, epss_percentile: float) -> float:
        """EPSS contribution: probability * percentile factor, max 2.5"""
        if not epss_score or not epss_percentile:
            return 0
        return min(epss_score * 2.5 + (epss_percentile / 100) * 1.0, 2.5)

    @staticmethod
    def exploit_component(exploit_count: int, has_active_exploit: bool,
                          is_cisa_kev: bool) -> float:
        """Exploit availability contribution: max 2.0"""
        score = 0
        if is_cisa_kev:
            score += 1.5  # Actively exploited in the wild
        if has_active_exploit:
            score += 1.0
        score += min(exploit_count * 0.3, 1.0)
        return min(score, 2.0)

    @staticmethod
    def threat_actor_component(threat_actors: list) -> float:
        """Threat actor interest contribution: max 1.5"""
        if not threat_actors:
            return 0
        high_conf = sum(1 for a in threat_actors if a.get("confidence") == "high")
        return min(high_conf * 1.0 + len(threat_actors) * 0.3, 1.5)

    @staticmethod
    def age_component(published_date: str) -> float:
        """Age-based urgency: newer = higher, max 1.0"""
        if not published_date:
            return 0.5
        try:
            from datetime import datetime, timezone
            pub = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - pub).days
            if days < 7:
                return 1.0
            if days < 30:
                return 0.8
            if days < 90:
                return 0.5
            if days < 365:
                return 0.3
            return 0.1
        except:
            return 0.5

    def calculate(self, cve_data: dict, exploits: list = None,
                  threat_actors: list = None) -> dict:
        """Calculate comprehensive risk score"""

        components = {
            "cvss": round(self.cvss_component(cve_data.get("cvss_score") or 0), 2),
            "epss": round(self.epss_component(
                cve_data.get("epss_score") or 0,
                cve_data.get("epss_percentile") or 0,
            ), 2),
            "exploit": round(self.exploit_component(
                len(exploits or []),
                bool(exploits),
                bool(cve_data.get("is_cisa_kev")),
            ), 2),
            "threat_actor": round(self.threat_actor_component(threat_actors or []), 2),
            "age_urgency": round(self.age_component(cve_data.get("published_date")), 2),
        }

        total = sum(components.values())
        # Scale to 0-10
        score = round(min(total, 10.0), 1)

        if score >= 8.0:
            level = "EXTREME"
        elif score >= 6.0:
            level = "SEVERE"
        elif score >= 4.0:
            level = "ELEVATED"
        elif score >= 2.0:
            level = "MODERATE"
        else:
            level = "LOW"

        return {
            "vulnscope_risk_score": score,
            "vulnscope_risk_level": level,
            "components": components,
            "recommendation": self.get_recommendation(score, components),
        }

    @staticmethod
    def get_recommendation(score: float, components: dict) -> dict:
        """Generate remediation recommendation based on risk profile"""
        if score >= 8.0:
            priority = "IMMEDIATE"
            timeline = "Within 24 hours"
            actions = [
                "Apply vendor patch immediately",
                "Implement emergency mitigations",
                "Isolate affected systems if patch unavailable",
                "Enable enhanced monitoring and logging",
                "Escalate to incident response team",
            ]
        elif score >= 6.0:
            priority = "HIGH"
            timeline = "Within 72 hours"
            actions = [
                "Apply patch on priority schedule",
                "Verify exploit detection signatures",
                "Review access controls on affected systems",
                "Monitor for exploitation attempts",
            ]
        elif score >= 4.0:
            priority = "STANDARD"
            timeline = "Within 2 weeks"
            actions = [
                "Schedule patch deployment",
                "Review vulnerability in asset inventory",
                "Check for compensating controls",
            ]
        else:
            priority = "ROUTINE"
            timeline = "Within 30 days"
            actions = [
                "Include in regular patch cycle",
                "Monitor for new exploit developments",
            ]

        return {"priority": priority, "timeline": timeline, "actions": actions}


risk_engine = RiskEngine()


async def calculate_risk_for_cve(db, cve_id: str) -> dict:
    """Calculate comprehensive risk for a single CVE"""
    # Get CVE data
    row = await db.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    cve = await row.fetchone()
    if not cve:
        return {}
    cve_data = dict(cve)

    # Get exploits
    exp_rows = await db.execute(
        "SELECT * FROM exploits WHERE cve_id = ?", (cve_id,)
    )
    exploits = [dict(r) for r in await exp_rows.fetchall()]

    # Get threat actors
    ta_rows = await db.execute(
        "SELECT * FROM threat_actors WHERE cve_id = ?", (cve_id,)
    )
    threat_actors = [dict(r) for r in await ta_rows.fetchall()]

    # Check CISA KEV
    kev_row = await db.execute(
        "SELECT cve_id FROM cisa_kev WHERE cve_id = ?", (cve_id,)
    )
    cve_data["is_cisa_kev"] = await kev_row.fetchone() is not None

    return risk_engine.calculate(cve_data, exploits, threat_actors)
