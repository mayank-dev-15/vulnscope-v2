"""
VulnScope v2 - WebSocket Connection Manager
Manages real-time client connections and broadcasting
"""
import json
import asyncio
from typing import Dict, Set
from datetime import datetime, timezone
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "all": set(),
            "critical": set(),
            "high": set(),
        }
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, channel: str = "all"):
        await websocket.accept()
        async with self._lock:
            if channel not in self.active_connections:
                self.active_connections[channel] = set()
            self.active_connections[channel].add(websocket)
            self.active_connections["all"].add(websocket)
        print(f"[WS] Client connected to {channel} | total: {len(self.active_connections['all'])}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            for channel in self.active_connections.values():
                channel.discard(websocket)
        print(f"[WS] Client disconnected | total: {len(self.active_connections['all'])}")

    async def subscribe(self, websocket: WebSocket, channel: str):
        async with self._lock:
            if channel not in self.active_connections:
                self.active_connections[channel] = set()
            self.active_connections[channel].add(websocket)

    async def broadcast(self, message: dict, channel: str = "all"):
        """Send message to all clients on a channel"""
        async with self._lock:
            targets = self.active_connections.get(channel, set()).copy()

        if not targets:
            return

        payload = json.dumps(message)
        disconnected = set()

        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                disconnected.add(ws)

        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    for ch in self.active_connections.values():
                        ch.discard(ws)

    async def broadcast_cve(self, cve_data: dict, exploits: list = None):
        """Broadcast a new CVE to relevant channels"""
        severity = cve_data.get("severity", "UNKNOWN")
        timestamp = datetime.now(timezone.utc).isoformat()

        msg = {
            "type": "new_cve",
            "data": {
                "cve": cve_data,
                "exploits": exploits or [],
                "has_exploit": bool(exploits),
            },
            "timestamp": timestamp,
        }

        # Broadcast to all
        await self.broadcast(msg, "all")

        # Also broadcast to severity-specific channel
        severity_lower = severity.lower()
        if severity_lower in self.active_connections:
            await self.broadcast(msg, severity_lower)

        # Critical/High → critical channel
        if severity in ("CRITICAL", "HIGH"):
            await self.broadcast(msg, "critical")

    async def broadcast_alert(self, alert_type: str, title: str, message: str,
                              cve_id: str = "", severity: str = "HIGH"):
        """Send an alert to all connected clients"""
        await self.broadcast({
            "type": "alert",
            "data": {
                "alert_type": alert_type,
                "title": title,
                "message": message,
                "cve_id": cve_id,
                "severity": severity,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def broadcast_stats(self, stats: dict):
        await self.broadcast({
            "type": "stats_update",
            "data": stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def heartbeat(self):
        """Send heartbeat every 30 seconds"""
        while True:
            await asyncio.sleep(30)
            await self.broadcast({
                "type": "heartbeat",
                "data": {"online": len(self.active_connections["all"])},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    @property
    def online_count(self) -> int:
        return len(self.active_connections["all"])


manager = ConnectionManager()
