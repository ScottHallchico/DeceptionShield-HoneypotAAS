"""Main FastAPI application — assembles all routes, middleware, and lifecycle hooks."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — startup and shutdown hooks."""
    settings = get_settings()
    setup_logging(settings.log_level)

    from app.core.logging import get_logger
    log = get_logger("app")
    log.info("app_starting", env=settings.app_env)

    # Start WebSocket stats heartbeat
    from app.api.websocket.broadcaster import start_heartbeat, stop_heartbeat
    await start_heartbeat()

    # Start Kafka consumer (non-blocking — runs in background)
    from app.services.log_shipping.consumer import start_consumer
    consumer_task = asyncio.create_task(start_consumer())

    # Start block expiry checker (periodic task)
    async def _expire_loop():
        from app.services.response_engine.engine import expire_blocks
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await expire_blocks()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("expire_loop_error", error=str(exc))
                await asyncio.sleep(60)

    expiry_task = asyncio.create_task(_expire_loop())

    log.info("app_started")

    yield

    # Shutdown
    log.info("app_shutting_down")
    consumer_task.cancel()
    expiry_task.cancel()
    await stop_heartbeat()

    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    try:
        await expiry_task
    except asyncio.CancelledError:
        pass

    log.info("app_stopped")


def create_app() -> FastAPI:
    """Factory function to create and configure the FastAPI app."""
    settings = get_settings()

    app = FastAPI(
        title="HoneypotAAS Backend",
        description="Cybersecurity Deception Network for SMBs — Backend API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.app_debug else None,
        redoc_url="/redoc" if settings.app_debug else None,
    )

    # ── CORS ──────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── REST routes ───────────────────────────────────────────
    from app.api.routes.assistant import router as assistant_router
    from app.api.routes.attackers import router as attackers_router
    from app.api.routes.auth import router as auth_router
    from app.api.routes.blocklist import router as blocklist_router
    from app.api.routes.events import router as events_router
    from app.api.routes.honeypots import router as honeypots_router
    from app.api.routes.ingest import router as ingest_router
    from app.api.routes.rules import router as rules_router
    from app.api.routes.stats import router as stats_router

    app.include_router(auth_router)
    app.include_router(events_router)
    app.include_router(attackers_router)
    app.include_router(stats_router)
    app.include_router(honeypots_router)
    app.include_router(blocklist_router)
    app.include_router(rules_router)
    app.include_router(assistant_router)
    app.include_router(ingest_router)

    # ── WebSocket ─────────────────────────────────────────────
    from app.api.websocket.broadcaster import websocket_handler

    @app.websocket("/ws/live")
    async def ws_live(ws):
        await websocket_handler(ws)

    # ── Health check ──────────────────────────────────────────
    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "honeypot-aas-backend"}

    return app


# Module-level app instance for uvicorn
app = create_app()
