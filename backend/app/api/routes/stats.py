"""Stats routes — GET /api/stats."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.security import get_current_user
from app.schemas.schemas import DashboardStats
from app.services.enrichment.stats import compute_dashboard_stats

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("", response_model=DashboardStats)
async def get_stats(
    user=Depends(get_current_user),
) -> DashboardStats:
    """Dashboard summary metrics."""
    stats = await compute_dashboard_stats()
    return DashboardStats(**stats)
