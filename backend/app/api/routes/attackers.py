"""Attacker routes — GET /api/attackers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.models import Attacker, Session
from app.schemas.schemas import AttackerListResponse, AttackerResponse

router = APIRouter(prefix="/api/attackers", tags=["attackers"])


@router.get("", response_model=AttackerListResponse)
async def list_attackers(
    sort_by: str = Query("threat_score", regex="^(threat_score|total_events|last_seen|first_seen)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    is_blocked: bool | None = None,
    min_threat_score: float | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> AttackerListResponse:
    """Aggregated attacker list, sortable by threat score."""
    query = select(Attacker)
    count_query = select(func.count(Attacker.id))

    if is_blocked is not None:
        query = query.where(Attacker.is_blocked == is_blocked)
        count_query = count_query.where(Attacker.is_blocked == is_blocked)

    if min_threat_score is not None:
        query = query.where(Attacker.threat_score >= min_threat_score)
        count_query = count_query.where(Attacker.threat_score >= min_threat_score)

    # Dynamic sort
    sort_col = getattr(Attacker, sort_by, Attacker.threat_score)
    if sort_order == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    total = (await db.execute(count_query)).scalar() or 0
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    attackers = result.scalars().all()

    session_query = select(Session.id, Session.attacker_ip).where(Session.attacker_ip.in_([a.ip for a in attackers]))
    session_result = await db.execute(session_query)
    sessions_by_ip = {}
    for session_id, ip in session_result.all():
        sessions_by_ip.setdefault(ip, []).append(str(session_id))

    items = []
    for a in attackers:
        a_dict = {
            "id": a.id,
            "ip": a.ip,
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
            "total_events": a.total_events,
            "honeypots_hit": a.honeypots_hit,
            "techniques_used": a.techniques_used,
            "geo": a.geo,
            "reputation": a.reputation,
            "threat_score": a.threat_score,
            "is_blocked": a.is_blocked,
            "sessions": sessions_by_ip.get(a.ip, []),
        }
        items.append(AttackerResponse.model_validate(a_dict))

    return AttackerListResponse(
        items=items,
        total=total,
    )
