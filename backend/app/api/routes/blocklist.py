"""Blocklist routes — GET /api/blocklist, POST /api/blocklist/{ip}/unblock."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.models import BlocklistEntry
from app.schemas.schemas import BlocklistEntryResponse, BlocklistResponse, UnblockRequest
from app.services.response_engine.engine import unblock_ip

router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])


@router.get("", response_model=BlocklistResponse)
async def list_blocklist(
    active_only: bool = Query(True),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> BlocklistResponse:
    """List blocked IPs with audit trail."""
    query = select(BlocklistEntry)
    count_query = select(func.count(BlocklistEntry.id))

    if active_only:
        query = query.where(BlocklistEntry.is_active)
        count_query = count_query.where(BlocklistEntry.is_active)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(BlocklistEntry.blocked_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    entries = result.scalars().all()

    return BlocklistResponse(
        items=[BlocklistEntryResponse.model_validate(e) for e in entries],
        total=total,
    )


@router.post("/{ip}/unblock")
async def unblock(
    ip: str,
    body: UnblockRequest | None = None,
    user=Depends(get_current_user),
) -> dict:
    """Manually unblock an IP — removes AWS SG + pfSense rules and updates audit trail."""
    success = await unblock_ip(
        ip=ip,
        unblocked_by=user.get("email", "unknown"),
    )

    if not success:
        raise HTTPException(status_code=404, detail="No active block found for this IP")

    return {
        "status": "unblocked",
        "ip": ip,
        "unblocked_by": user.get("email", "unknown"),
        "reason": body.reason if body else "Manual unblock",
    }
