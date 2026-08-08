"""Attacker routes — GET /api/attackers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.models import Attacker
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

    return AttackerListResponse(
        items=[AttackerResponse.model_validate(a) for a in attackers],
        total=total,
    )
