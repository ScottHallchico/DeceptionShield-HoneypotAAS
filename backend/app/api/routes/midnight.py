"""Midnight blockchain integration routes.

Proxies requests to the midnight-bridge sidecar, providing the REST API for
the frontend's Collective Threat Intelligence panel.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.core.security import get_current_user
from app.services.midnight.client import MidnightBridgeClient
from app.services.midnight.threat_ledger import compute_indicator_hash, query_indicator

router = APIRouter(prefix="/api/midnight", tags=["midnight"])


@router.get("/stats")
async def midnight_stats(user=Depends(get_current_user)) -> dict:
    """Get global attestation stats from the Midnight Collective Defense Ledger."""
    settings = get_settings()
    if not settings.midnight_enabled:
        return {
            "totalAttestations": 0,
            "uniqueIndicators": 0,
            "networkMode": "disabled",
            "enabled": False,
        }

    client = MidnightBridgeClient()
    stats = await client.stats()
    stats["enabled"] = True
    return stats


@router.get("/query/{ip}")
async def midnight_query_ip(ip: str, user=Depends(get_current_user)) -> dict:
    """Query corroboration count for an attacker IP.

    The IP is hashed server-side before being sent to the bridge — the raw
    IP never leaves this service.
    """
    result = await query_indicator(ip)
    return {
        "ip": ip,
        "corroborationCount": result.get("corroborationCount", 0),
        "highConfidenceCount": result.get("highConfidenceCount", 0),
    }


@router.get("/health")
async def midnight_health(user=Depends(get_current_user)) -> dict:
    """Check the health of the midnight-bridge sidecar."""
    client = MidnightBridgeClient()
    return await client.health()
