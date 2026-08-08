"""AbuseIPDB reputation lookup with TTL caching.

Per the implementation plan (section 1.4): cached with TTL to respect rate limits.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Simple in-memory TTL cache: {ip: (result_dict, timestamp)}
_cache: dict[str, tuple[dict[str, Any], float]] = {}
_CACHE_TTL_SECONDS = 3600  # 1 hour


async def lookup_reputation(ip: str) -> dict[str, Any]:
    """Query AbuseIPDB for an IP's abuse confidence score.

    Returns a dict matching the ReputationInfo schema:
        {abuseipdb_score: int, known_malicious: bool}
    """
    default = {"abuseipdb_score": 0, "known_malicious": False}

    # Check cache first
    if ip in _cache:
        cached_result, cached_at = _cache[ip]
        if time.time() - cached_at < _CACHE_TTL_SECONDS:
            return cached_result

    settings = get_settings()
    if not settings.abuseipdb_api_key:
        return default

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            result = {
                "abuseipdb_score": data.get("abuseConfidenceScore", 0),
                "known_malicious": data.get("abuseConfidenceScore", 0) >= 50,
            }

            # Cache the result
            _cache[ip] = (result, time.time())
            return result

    except Exception as exc:
        log.warning("abuseipdb_lookup_failed", ip=ip, error=str(exc))
        return default


def clear_reputation_cache() -> None:
    """Flush the reputation cache (useful for tests)."""
    _cache.clear()
