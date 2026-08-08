"""Direct event ingestion route — for development use without Kafka.

In production, events flow through Filebeat → Kafka → consumer.
This endpoint allows direct HTTP POST for local development and testing.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.security import get_current_user
from app.schemas.schemas import EventCreate, EventResponse
from app.services.enrichment.normalizer import normalize_event

router = APIRouter(prefix="/api/ingest", tags=["ingestion"])


@router.post("/event", response_model=EventResponse)
async def ingest_event(
    body: EventCreate,
    user=Depends(get_current_user),
) -> dict[str, Any]:
    """Directly ingest a single event (development/testing bypass for Kafka).

    Runs the full normalization + enrichment pipeline, writes to DB,
    and pushes to WebSocket.
    """
    # Convert to raw dict for the normalizer
    raw = body.model_dump(mode="json")
    raw["honeypot_type"] = body.honeypot_type

    normalized = await normalize_event(raw)
    if normalized is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail="Event was filtered (duplicate or invalid)")

    # Write to DB
    from app.services.log_shipping.consumer import _write_to_db
    await _write_to_db(normalized)

    # Push to WebSocket
    from app.api.websocket.broadcaster import broadcast_event
    await broadcast_event(normalized)

    # Evaluate response rules
    from app.services.response_engine.engine import evaluate_rules
    await evaluate_rules(normalized)

    return normalized


@router.post("/batch")
async def ingest_batch(
    events: list[EventCreate],
    user=Depends(get_current_user),
) -> dict:
    """Ingest a batch of events (development/testing)."""
    processed = 0
    errors = 0

    for event in events:
        try:
            raw = event.model_dump(mode="json")
            raw["honeypot_type"] = event.honeypot_type

            normalized = await normalize_event(raw)
            if normalized:
                from app.services.log_shipping.consumer import _write_to_db
                await _write_to_db(normalized)

                from app.api.websocket.broadcaster import broadcast_event
                await broadcast_event(normalized)

                from app.services.response_engine.engine import evaluate_rules
                await evaluate_rules(normalized)

                processed += 1
        except Exception:
            errors += 1

    return {"processed": processed, "errors": errors, "total": len(events)}
