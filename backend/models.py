"""
VulnScope v2 - Data Models
Real-time CVE feed with exploit correlation
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class CVEReference(BaseModel):
    url: str
    source: str = ""
    tags: List[str] = []


class CVEData(BaseModel):
    cve_id: str
    description: str
    severity: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    vendor: str = ""
    product: str = ""
    references: List[CVEReference] = []
    cwe_id: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "cve_id": "CVE-2024-12345",
                "description": "Remote code execution in ExampleApp",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "vendor": "examplecorp",
                "product": "exampleapp"
            }
        }


class ExploitMatch(BaseModel):
    source: str  # exploitdb, github, metasploit, cisa_kev, nuclei
    title: str
    url: str = ""
    exploit_type: str = ""  # PoC, weaponized, ransomware, etc
    date_published: Optional[str] = None
    confidence: str = "medium"  # high, medium, low
    description: str = ""


class CVEWithExploits(BaseModel):
    cve: CVEData
    exploits: List[ExploitMatch] = []
    has_exploit: bool = False
    is_ransomware_related: bool = False
    is_cisa_kev: bool = False


class WebSocketMessage(BaseModel):
    type: str  # new_cve, exploit_match, stats_update, alert, heartbeat
    data: dict
    timestamp: str


class StatsResponse(BaseModel):
    total_cves: int
    critical_count: int
    high_count: int
    with_exploits: int
    ransomware_related: int
    cisa_kev_count: int
    last_fetched: Optional[str] = None
    recent_cves_24h: int


class SearchQuery(BaseModel):
    query: str
    severity: Optional[str] = None
    has_exploit: Optional[bool] = None
    limit: int = 50
    offset: int = 0
