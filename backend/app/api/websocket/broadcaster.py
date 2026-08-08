"""WebSocket broadcaster — pushes every normalized event the instant it's
written, plus periodic stats heartbeat (every 5s) per section 1.6.

Endpoint: /ws/live
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from app.core.logging import get_logger

log = get_logger(__name__)

# ─── Connection registry ─────────────────────────────────────────────────────

_connections: set[WebSocket] = set()
_stats_task: asyncio.Task | None = None


async def register(ws: WebSocket) -> None:
    """Register a new WebSocket connection."""
    await ws.accept()
    _connections.add(ws)
    log.info("ws_client_connected", total=len(_connections))


async def unregister(ws: WebSocket) -> None:
    """Remove a WebSocket connection."""
    _connections.discard(ws)
    log.info("ws_client_disconnected", total=len(_connections))


async def broadcast_event(event: dict[str, Any]) -> None:
    """Push a normalized event to all connected WebSocket clients."""
    if not _connections:
        return

    message = json.dumps({"type": "event", "data": event}, default=str)
    dead: list[WebSocket] = []

    for ws in _connections.copy():
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)

    for ws in dead:
        _connections.discard(ws)


async def broadcast_stats(stats: dict[str, Any]) -> None:
    """Push a stats heartbeat to all connected WebSocket clients."""
    if not _connections:
        return

    message = json.dumps({"type": "stats_heartbeat", "data": stats}, default=str)
    dead: list[WebSocket] = []

    for ws in _connections.copy():
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)

    for ws in dead:
        _connections.discard(ws)


async def _stats_heartbeat_loop() -> None:
    """Send stats heartbeat every 5 seconds to connected clients."""
    from app.services.enrichment.stats import compute_dashboard_stats

    while True:
        try:
            await asyncio.sleep(5)
            if _connections:
                stats = await compute_dashboard_stats()
                await broadcast_stats({
                    "active_honeypots": int(stats["active_honeypots"]),
                    "total_events_24h": int(stats["total_events_24h"]),
                    "active_blocks": int(stats["active_blocks"]),
                })
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("stats_heartbeat_error", error=str(exc))
            await asyncio.sleep(5)


async def start_heartbeat() -> None:
    """Start the periodic stats heartbeat background task."""
    global _stats_task
    _stats_task = asyncio.create_task(_stats_heartbeat_loop())
    log.info("ws_stats_heartbeat_started")


async def stop_heartbeat() -> None:
    """Stop the stats heartbeat."""
    global _stats_task
    if _stats_task:
        _stats_task.cancel()
        try:
            await _stats_task
        except asyncio.CancelledError:
            pass
        _stats_task = None


async def websocket_handler(ws: WebSocket) -> None:
    """Handle a WebSocket connection lifecycle."""
    await register(ws)
    try:
        while True:
            # Keep connection alive — client may send pings or subscription updates
            data = await ws.receive_text()
            # Could handle client-side filter subscriptions here
            log.debug("ws_client_message", data=data[:100])
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.debug("ws_connection_error", error=str(exc))
    finally:
        await unregister(ws)
