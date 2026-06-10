"""
VulnScope v2 - Main FastAPI Application
Real-time WebSocket CVE feed with exploit correlation
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    print("[VulnScope v2] Initializing...")
    await init_db()
    print("[VulnScope v2] Database initialized")

    # Start background tasks
    nvd_api_key = os.environ.get("NVD_API_KEY", "")
    cve_task = asyncio.create_task(fetch_cves_continuous(nvd_api_key))
    corr_task = asyncio.create_task(correlate_recent_cves())
    heartbeat_task = asyncio.create_task(manager.heartbeat())

    print("[VulnScope v2] All services running")

    yield

    # Shutdown
    cve_task.cancel()
    corr_task.cancel()
    heartbeat_task.cancel()
    print("[VulnScope v2] Shutdown complete")


app = FastAPI(
    title="VulnScope v2",
    description="Real-time CVE feed with exploit correlation engine",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for frontend
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


# ─── WebSocket ───────────────────────────────────────────
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
                    "type": "subscribed",
                    "data": {"channel": new_channel},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))

            elif action == "stats":
                db = await get_db()
                stats = await get_stats(db)
                await db.close()
                await websocket.send_text(json.dumps({
                    "type": "stats_update",
                    "data": stats,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))

    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS] Error: {e}")
        await manager.disconnect(websocket)


# ─── REST API ────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ws_clients": manager.online_count,
        "services": {
            "cve_fetcher": "running",
            "exploit_correlator": "running",
            "websocket": "running",
        },
    }


@app.get("/api/stats")
async def get_statistics():
    db = await get_db()
    stats = await get_stats(db)
    await db.close()
    return stats


@app.get("/api/cves")
async def list_cves(
    query: str = "",
    severity: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
):
    db = await get_db()
    cves = await search_cves(db, query, severity, has_exploit, limit, offset)
    await db.close()

    # Enrich with exploit info
    results = []
    for cve in cves:
        cve_dict = dict(cve)
        if "references_json" in cve_dict:
            try:
                cve_dict["references"] = json.loads(cve_dict["references_json"])
            except:
                cve_dict["references"] = []
            del cve_dict["references_json"]
        results.append(cve_dict)

    return {
        "total": len(results),
        "limit": limit,
        "offset": offset,
        "cves": results,
    }


@app.get("/api/cves/{cve_id}")
async def get_cve_detail(cve_id: str):
    db = await get_db()
    cve = await get_cve(db, cve_id)
    if not cve:
        await db.close()
        raise HTTPException(status_code=404, detail="CVE not found")

    exploits = await get_exploits_for_cve(db, cve_id)
    await db.close()

    cve_dict = dict(cve)
    if "references_json" in cve_dict:
        try:
            cve_dict["references"] = json.loads(cve_dict["references_json"])
        except:
            cve_dict["references"] = []
        del cve_dict["references_json"]

    return {
        "cve": cve_dict,
        "exploits": [dict(e) for e in exploits],
        "has_exploit": len(exploits) > 0,
    }


@app.get("/api/exploits")
async def list_exploits(
    source: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
):
    db = await get_db()
    if source:
        rows = await db.execute(
            "SELECT * FROM exploits WHERE source = ? ORDER BY date_published DESC LIMIT ? OFFSET ?",
            (source, limit, offset)
        )
    else:
        rows = await db.execute(
            "SELECT * FROM exploits ORDER BY date_published DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
    exploits = [dict(r) for r in await rows.fetchall()]
    await db.close()
    return {"total": len(exploits), "exploits": exploits}


@app.get("/api/cisa-kev")
async def get_cisa_kev(limit: int = Query(default=100, le=500)):
    db = await get_db()
    rows = await db.execute(
        "SELECT * FROM cisa_kev ORDER BY date_added DESC LIMIT ?",
        (limit,)
    )
    kev_items = [dict(r) for r in await rows.fetchall()]
    await db.close()
    return {"total": len(kev_items), "cisa_kev": kev_items}


@app.get("/api/ransomware")
async def get_ransomware_cves():
    db = await get_db()
    rows = await db.execute("""
        SELECT rm.*, c.severity, c.cvss_score, c.description
        FROM ransomware_mapping rm
        JOIN cves c ON rm.cve_id = c.cve_id
        ORDER BY rm.added_date DESC
    """)
    results = [dict(r) for r in await rows.fetchall()]
    await db.close()
    return {"total": len(results), "ransomware_cves": results}


@app.get("/api/recent-alerts")
async def get_recent_alerts(limit: int = 20):
    """Get recent critical/high CVEs with exploits"""
    db = await get_db()
    rows = await db.execute("""
        SELECT c.*, e.source as exploit_source, e.title as exploit_title,
               e.url as exploit_url, e.exploit_type
        FROM cves c
        JOIN exploits e ON c.cve_id = e.cve_id
        WHERE c.severity IN ('CRITICAL', 'HIGH')
        ORDER BY c.published_date DESC
        LIMIT ?
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


# ─── Serve Frontend ──────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path)
    return HTMLResponse("<h1>Frontend not found</h1>", status_code=404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
