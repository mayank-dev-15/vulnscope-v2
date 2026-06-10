# VulnScope v2 🔴

> *"If you don't know the vulnerabilities, you're already exploited."*

**Real-time CVE feed with exploit correlation engine and live WebSocket dashboard.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-teal?logo=fastapi)](https://fastapi.tiangolo.com)
[![WebSocket](https://img.shields.io/badge/WebSocket-Real--time-orange)](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://docker.com)

---

## ⚡ Features

- **📡 Real-time CVE Feed** — WebSocket streaming from NVD API 2.0, updated every 5 minutes
- **💥 Exploit Correlation** — Automatic matching against ExploitDB, GitHub Advisories, and CISA KEV
- **☠️ Ransomware Tracking** — Identifies CVEs associated with ransomware campaigns (LockBit, Clop, Conti, Akira, etc.)
- **🛡️ CISA KEV Integration** — Tracks Known Exploited Vulnerabilities with remediation deadlines
- **🔥 Live Dashboard** — Dark-themed SPA with real-time updates, search, filtering, and severity stats
- **📊 CVSS Scoring** — v2/v3.0/v3.1 score parsing with severity classification
- **🔍 Full-Text Search** — Search across CVE IDs, descriptions, vendors, and products
- **🚨 Alert System** — Toast notifications for critical exploits, ransomware, and CISA KEV matches
- **🐳 Docker Support** — One-command deployment with persistent data volume

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     VulnScope v2                             │
├───────────────┬─────────────────┬───────────────────────────┤
│  NVD API 2.0  │  ExploitDB      │  GitHub Advisories        │
│  (CVEs)       │  (Exploits)     │  (PoCs)                   │
├───────────────┴─────────────────┴───────────────────────────┤
│              CVE Fetcher (5 min cycle)                       │
│              Exploit Correlator (10 min cycle)               │
├─────────────────────────────────────────────────────────────┤
│              SQLite Database                                 │
│  ┌──────────┬──────────┬──────────────────┬──────────────┐  │
│  │  cves    │ exploits │ ransomware_map   │  cisa_kev    │  │
│  └──────────┴──────────┴──────────────────┴──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│              FastAPI + WebSocket                             │
│  /api/cves  /api/stats  /api/exploits  /ws                  │
├─────────────────────────────────────────────────────────────┤
│              Live Dashboard (HTML/CSS/JS)                    │
│  Real-time feed • Search • Filters • Detail view • Alerts   │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- pip

### Install & Run

```bash
# Clone
git clone https://github.com/mayank-dev-15/vulnscope-v2.git
cd vulnscope-v2

# Install dependencies
pip install -r backend/requirements.txt

# Optional: Set NVD API key for higher rate limits
# Get one free at: https://nvd.nist.gov/developers/request-an-api-key
# Windows: set NVD_API_KEY=your-key
# Linux/macOS: export NVD_API_KEY=your-key

# Run
python backend/main.py
```

Visit **http://localhost:8000** — the dashboard loads and begins fetching CVEs automatically.

### Docker

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

## 📡 WebSocket API

Connect to `ws://localhost:8000/ws`

### Incoming Messages

| Type | Description |
|------|-------------|
| `new_cve` | New CVE published with exploit info |
| `stats_update` | Live statistics update |
| `alert` | Critical alert (exploit available, ransomware) |
| `heartbeat` | Connection health (every 30s) |

### Client Actions

```javascript
// Subscribe to severity channel
ws.send(JSON.stringify({ action: "subscribe", channel: "critical" }));

// Request current stats
ws.send(JSON.stringify({ action: "stats" }));
```

## 🔌 REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Service health & status |
| `GET /api/stats` | Dashboard statistics |
| `GET /api/cves?query=&severity=&has_exploit=` | Search/filter CVEs |
| `GET /api/cves/{cve_id}` | CVE detail with exploits |
| `GET /api/exploits?source=` | Browse known exploits |
| `GET /api/cisa-kev` | CISA KEV catalog |
| `GET /api/ransomware` | Ransomware-associated CVEs |
| `GET /api/recent-alerts` | Critical CVEs with active exploits |

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, uvicorn |
| Real-time | WebSocket (native) |
| Database | SQLite (WAL mode, async via aiosqlite) |
| HTTP Client | httpx, aiohttp |
| Frontend | Vanilla HTML/CSS/JS, zero dependencies |
| Container | Docker, docker-compose |
| Data Sources | NVD API 2.0, ExploitDB, CISA KEV, GitHub Advisories |

## 📊 Data Sources

- **NVD API 2.0** — Primary CVE feed, CVSS scores, CWE mappings
- **ExploitDB** — Public exploit database matching
- **GitHub Security Advisories** — Community PoCs and patches
- **CISA KEV** — Actively exploited vulnerabilities catalog
- **Ransomware Intelligence** — Hardcoded mapping of CVEs to known ransomware campaigns

## 🔐 Security Notes

- NVD API key is optional but recommended (raises rate limit from ~10 to ~50 req/min)
- Dashboard is intended for local/internal use — add authentication for public deployment
- No exploit code is executed — only metadata is correlated and displayed

---

**VulnScope v2** — Know your attack surface before attackers do.
