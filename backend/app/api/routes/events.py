"""Event routes — GET /api/events, GET /api/events/{session_id}."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.models import Event, Session
from app.schemas.schemas import (
    EventListResponse,
    EventResponse,
    SessionResponse,
)

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=EventListResponse)
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    honeypot_type: str | None = None,
    severity: str | None = None,
    technique: str | None = None,
    attacker_ip: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> EventListResponse:
    """Paginated, filterable event list."""
    query = select(Event)
    count_query = select(func.count(Event.id))

    # Apply filters
    if honeypot_type:
        query = query.where(Event.honeypot_type == honeypot_type)
        count_query = count_query.where(Event.honeypot_type == honeypot_type)
    if severity:
        query = query.where(Event.severity == severity)
        count_query = count_query.where(Event.severity == severity)
    if technique:
        query = query.where(Event.technique == technique)
        count_query = count_query.where(Event.technique == technique)
    if attacker_ip:
        query = query.where(Event.attacker_ip == attacker_ip)
        count_query = count_query.where(Event.attacker_ip == attacker_ip)
    if start_date:
        query = query.where(Event.timestamp >= start_date)
        count_query = count_query.where(Event.timestamp >= start_date)
    if end_date:
        query = query.where(Event.timestamp <= end_date)
        count_query = count_query.where(Event.timestamp <= end_date)

    # Total count
    total = (await db.execute(count_query)).scalar() or 0

    # Paginated results
    offset = (page - 1) * page_size
    query = query.order_by(Event.timestamp.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    events = result.scalars().all()

    return EventListResponse(
        items=[EventResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
        has_more=(offset + page_size) < total,
    )


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session_detail(
    session_id: uuid.UUID,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> SessionResponse:
    """Full session detail with all events — for replay view."""
    result = await db.execute(
        select(Session).where(Session.id == session_id)
    )
    session_obj = result.scalar_one_or_none()

    if not session_obj:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Session not found")

    # Load related events
    events_result = await db.execute(
        select(Event)
        .where(Event.session_id == session_id)
        .order_by(Event.timestamp)
    )
    events = events_result.scalars().all()

    return SessionResponse(
        id=session_obj.id,
        attacker_ip=session_obj.attacker_ip,
        honeypot_id=session_obj.honeypot_id,
        honeypot_type=session_obj.honeypot_type,
        started_at=session_obj.started_at,
        ended_at=session_obj.ended_at,
        duration_seconds=session_obj.duration_seconds,
        event_count=session_obj.event_count,
        commands=session_obj.commands,
        tty_log=session_obj.tty_log,
        events=[EventResponse.model_validate(e) for e in events],
    )
