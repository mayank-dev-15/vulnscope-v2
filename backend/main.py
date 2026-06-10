"""
VulnScope v2 - Main FastAPI Application
Real-time CVE feed | ML Predictor | EPSS | ATT&CK | Threat Intel | Similarity | Trends | Risk Engine | Notifications
"""
import asyncio
import os
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from database import init_db, get_db, search_cves, get_cve, get_exploits_for_cve, get_stats
from cve_fetcher import fetch_cves_continuous
from exploit_corr import correlate_recent_cves
from websocket_mgr import manager
from epss_fetcher import epss_loop
from ml_predictor import ml_predictor_loop, score_cve, predict_exploit_risk
from attack_mapper import attack_mapper_loop, get_attack_techniques, get_tactic_stats, init_attack_tables
from threat_intel import threat_intel_loop, correlate_threat_actors, get_actor_stats, init_threat_tables
from similarity import cve_index, build_index, similarity_loop
from trends import (
    get_daily_trends, get_severity_distribution, get_top_vendors,
    get_top_products, get_top_cwes, get_exploit_timeline,
    get_ransomware_trends, get_epss_stats, get_weekly_summary,
    get_risk_distribution, get_attack_surface,
)
from risk_engine import calculate_risk_for_cve
from notifier import notification_loop


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[VulnScope v2] ⚡ Starting enhanced engine...")
    await init_db()

    # Initialize new tables
    db = await get_db()
    await init_attack_tables(db)
    await init_threat_tables(db)
    try:
        await db.execute("CREATE TABLE IF NOT EXISTS notification_sent (cve_id TEXT, channel TEXT, sent_at TEXT)")
    except:
        pass
    await db.close()

    # Start all background services
    nvd_api_key = os.environ.get("NVD_API_KEY", "")
    tasks = [
        asyncio.create_task(fetch_cves_continuous(nvd_api_key)),
        asyncio.create_task(correlate_recent_cves()),
        asyncio.create_task(epss_loop()),
        asyncio.create_task(ml_predictor_loop()),
        asyncio.create_task(attack_mapper_loop()),
        asyncio.create_task(threat_intel_loop()),
        asyncio.create_task(similarity_loop()),
        asyncio.create_task(notification_loop()),
        asyncio.create_task(manager.heartbeat()),
    ]

    print(f"[VulnScope v2] ✅ 9 services running on port 8000")

    yield

    for t in tasks:
        t.cancel()
    print("[VulnScope v2] Shutdown complete")


app = FastAPI(
    title="VulnScope v2",
    description="Real-time CVE feed with ML exploit prediction, EPSS, ATT&CK mapping, threat intel, and risk scoring",
    version="2.5.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


# ─── WebSocket ──────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, channel: str = "all"):
    await manager.connect(websocket, channel)
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            action = msg.get("action", "")

            if action == "subscribe":
                new_channel = msg.get("channel", "all")
                await manager.subscribe(websocket, new_channel)
                await websocket.send_text(json.dumps({
                    "type": "subscribed", "data": {"channel": new_channel},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            elif action == "stats":
                db = await get_db()
                stats = await get_stats(db)
                await db.close()
                await websocket.send_text(json.dumps({
                    "type": "stats_update", "data": stats,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            elif action == "search":
                db = await get_db()
                cves = await search_cves(db, msg.get("query", ""), msg.get("severity"),
                                         msg.get("has_exploit"), msg.get("limit", 20))
                await db.close()
                await websocket.send_text(json.dumps({
                    "type": "search_results", "data": [dict(c) for c in cves],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS] Error: {e}")
        await manager.disconnect(websocket)


# ─── Core API ───────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "online", "version": "2.5.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ws_clients": manager.online_count,
        "services": {
            "cve_fetcher": "running", "exploit_correlator": "running",
            "epss": "running", "ml_predictor": "running",
            "attack_mapper": "running", "threat_intel": "running",
            "similarity": "running", "notifier": "running",
            "websocket": "running",
        },
        "index_status": cve_index.status(),
    }


@app.get("/api/stats")
async def get_statistics():
    db = await get_db()
    stats = await get_stats(db)
    epss = await get_epss_stats(db)
    weekly = await get_weekly_summary(db)
    total = stats.get("total_cves", 0)
    await db.close()
    return {**stats, "epss": epss, "weekly": weekly, "total_cves": total}


@app.get("/api/cves")
async def list_cves(
    query: str = "",
    severity: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    risk_level: Optional[str] = None,
    vendor: Optional[str] = None,
    sort_by: str = "published_date",
    limit: int = Query(default=50, le=200),
    offset: int = 0,
):
    db = await get_db()
    conditions = []
    params = []

    if query:
        conditions.append("(c.cve_id LIKE ? OR c.description LIKE ? OR c.vendor LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like, like])
    if severity:
        conditions.append("c.severity = ?")
        params.append(severity.upper())
    if has_exploit is not None:
        if has_exploit:
            conditions.append("c.cve_id IN (SELECT DISTINCT cve_id FROM exploits)")
        else:
            conditions.append("c.cve_id NOT IN (SELECT DISTINCT cve_id FROM exploits)")
    if risk_level:
        conditions.append("c.risk_level = ?")
        params.append(risk_level)
    if vendor:
        conditions.append("c.vendor LIKE ?")
        params.append(f"%{vendor}%")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    sort_col = "c.published_date" if sort_by == "published_date" else \
               "c.cvss_score" if sort_by == "cvss" else \
               "c.epss_score" if sort_by == "epss" else \
               "c.exploit_risk_score" if sort_by == "risk" else "c.published_date"

    sql = f"SELECT c.* FROM cves c {where} ORDER BY {sort_col} DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = await db.execute(sql, params)
    results = []
    for r in await rows.fetchall():
        d = dict(r)
        try:
            d["references"] = json.loads(d.get("references_json", "[]"))
        except:
            d["references"] = []
        d.pop("references_json", None)
        results.append(d)
    await db.close()
    return {"total": len(results), "limit": limit, "offset": offset, "cves": results}


@app.get("/api/cves/{cve_id}")
async def get_cve_detail(cve_id: str):
    db = await get_db()
    cve = await get_cve(db, cve_id)
    if not cve:
        await db.close()
        raise HTTPException(status_code=404, detail="CVE not found")

    exploits = await get_exploits_for_cve(db, cve_id)
    attack = await get_attack_techniques(db, cve_id)
    threat_rows = await db.execute("SELECT * FROM threat_actors WHERE cve_id = ?", (cve_id,))
    threat_actors = [dict(r) for r in await threat_rows.fetchall()]

    # Risk analysis
    risk = await calculate_risk_for_cve(db, cve_id)

    # Similar CVEs
    similar = cve_index.find_similar_cves(cve_id, limit=10) if cve_index.built else []

    await db.close()

    cve_dict = dict(cve)
    try:
        cve_dict["references"] = json.loads(cve_dict.get("references_json", "[]"))
    except:
        cve_dict["references"] = []
    cve_dict.pop("references_json", None)

    return {
        "cve": cve_dict,
        "exploits": [dict(e) for e in exploits],
        "attack_techniques": attack,
        "threat_actors": threat_actors,
        "risk_analysis": risk,
        "similar_cves": similar,
        "has_exploit": len(exploits) > 0,
    }


# ─── New Enhanced Endpoints ─────────────────────────────

@app.get("/api/trends/daily")
async def daily_trends(days: int = 30):
    db = await get_db()
    trends = await get_daily_trends(db, days)
    await db.close()
    return {"days": days, "trends": trends}


@app.get("/api/trends/severity")
async def severity_distribution():
    db = await get_db()
    dist = await get_severity_distribution(db)
    await db.close()
    return dist


@app.get("/api/trends/vendors")
async def top_vendors(limit: int = 20):
    db = await get_db()
    vendors = await get_top_vendors(db, limit)
    await db.close()
    return {"vendors": vendors}


@app.get("/api/trends/products")
async def top_products(limit: int = 20):
    db = await get_db()
    products = await get_top_products(db, limit)
    await db.close()
    return {"products": products}


@app.get("/api/trends/cwes")
async def top_cwes(limit: int = 15):
    db = await get_db()
    cwes = await get_top_cwes(db, limit)
    await db.close()
    return {"cwes": cwes}


@app.get("/api/trends/ransomware")
async def ransomware_trends():
    db = await get_db()
    trends = await get_ransomware_trends(db)
    await db.close()
    return {"ransomware_trends": trends}


@app.get("/api/trends/summary")
async def weekly_summary():
    db = await get_db()
    summary = await get_weekly_summary(db)
    epss = await get_epss_stats(db)
    risk = await get_risk_distribution(db)
    attack = await get_attack_surface(db)
    await db.close()
    return {"weekly": summary, "epss": epss, "risk_distribution": risk, "attack_surface": attack}


@app.get("/api/ml/predict/{cve_id}")
async def predict_cve(cve_id: str):
    db = await get_db()
    row = await db.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    cve = await row.fetchone()
    if not cve:
        await db.close()
        raise HTTPException(status_code=404)
    risk = predict_exploit_risk(dict(cve))
    await db.close()
    return {"cve_id": cve_id, **risk}


@app.get("/api/ml/top-risks")
async def top_risks(limit: int = 20):
    db = await get_db()
    rows = await db.execute("""
        SELECT cve_id, description, severity, cvss_score, epss_score,
               exploit_risk_score, risk_level
        FROM cves
        WHERE exploit_risk_score > 0
        ORDER BY exploit_risk_score DESC LIMIT ?
    """, (limit,))
    results = [dict(r) for r in await rows.fetchall()]
    await db.close()
    return {"top_risks": results}


@app.get("/api/attack/tactics")
async def attack_tactics():
    db = await get_db()
    stats = await get_tactic_stats(db)
    await db.close()
    return {"tactic_stats": stats}


@app.get("/api/threat/actors")
async def threat_actors_list():
    db = await get_db()
    stats = await get_actor_stats(db)
    await db.close()
    return {"actors": stats}


@app.get("/api/similarity/search")
async def similarity_search(q: str, limit: int = 20):
    if not cve_index.built:
        await build_index()
    results = cve_index.search(q, limit)
    return {"query": q, "results": results}


@app.get("/api/similarity/{cve_id}")
async def similar_cves(cve_id: str, limit: int = 10):
    if not cve_index.built:
        await build_index()
    results = cve_index.find_similar_cves(cve_id, limit)
    return {"cve_id": cve_id, "similar": results}


@app.get("/api/risk/{cve_id}")
async def risk_analysis(cve_id: str):
    db = await get_db()
    risk = await calculate_risk_for_cve(db, cve_id)
    await db.close()
    if not risk:
        raise HTTPException(status_code=404)
    return {"cve_id": cve_id, **risk}


@app.get("/api/exploits")
async def list_exploits(source: Optional[str] = None, limit: int = 50, offset: int = 0):
    db = await get_db()
    if source:
        rows = await db.execute(
            "SELECT * FROM exploits WHERE source = ? ORDER BY date_published DESC LIMIT ? OFFSET ?",
            (source, limit, offset))
    else:
        rows = await db.execute(
            "SELECT * FROM exploits ORDER BY date_published DESC LIMIT ? OFFSET ?",
            (limit, offset))
    exploits = [dict(r) for r in await rows.fetchall()]
    await db.close()
    return {"total": len(exploits), "exploits": exploits}


@app.get("/api/cisa-kev")
async def get_cisa_kev(limit: int = 100):
    db = await get_db()
    rows = await db.execute("SELECT * FROM cisa_kev ORDER BY date_added DESC LIMIT ?", (limit,))
    kev = [dict(r) for r in await rows.fetchall()]
    await db.close()
    return {"total": len(kev), "cisa_kev": kev}


@app.get("/api/ransomware")
async def get_ransomware_cves():
    db = await get_db()
    rows = await db.execute("""
        SELECT rm.*, c.severity, c.cvss_score, c.description
        FROM ransomware_mapping rm JOIN cves c ON rm.cve_id = c.cve_id
        ORDER BY rm.added_date DESC
    """)
    results = [dict(r) for r in await rows.fetchall()]
    await db.close()
    return {"total": len(results), "ransomware_cves": results}


@app.get("/api/recent-alerts")
async def get_recent_alerts(limit: int = 20):
    db = await get_db()
    rows = await db.execute("""
        SELECT c.*, e.source as exploit_source, e.title as exploit_title, e.url as exploit_url, e.exploit_type
        FROM cves c JOIN exploits e ON c.cve_id = e.cve_id
        WHERE c.severity IN ('CRITICAL', 'HIGH')
        ORDER BY c.published_date DESC LIMIT ?
    """, (limit,))
    results = []
    for r in await rows.fetchall():
        d = dict(r)
        try:
            d["references"] = json.loads(d.get("references_json", "[]"))
        except:
            d["references"] = []
        d.pop("references_json", None)
        results.append(d)
    await db.close()
    return {"total": len(results), "alerts": results}


# ─── Frontend ───────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    fp = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    return FileResponse(fp) if os.path.exists(fp) else HTMLResponse("<h1>Frontend not found</h1>", status_code=404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
