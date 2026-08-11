"""HTTP client for the midnight-bridge Node.js sidecar service.

This is the only module that communicates with the bridge. It mirrors the
same internal-HTTP-call pattern used for pfSense integration in the response
engine — nothing new architecturally, just one more internal service call.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


class MidnightBridgeClient:
    """Async HTTP client wrapping the midnight-bridge REST API."""

    def __init__(self, base_url: str | None = None):
        settings = get_settings()
        self._base_url = (base_url or settings.midnight_bridge_url).rstrip("/")

    async def attest(
        self,
        indicator_hash: str,
        severity_score: int,
    ) -> dict[str, Any]:
        """Submit an attestation to the Midnight ledger.

        Returns:
            {"txHash": "0x...", "status": "confirmed" | "pending" | "failed"}

        On failure, returns {"txHash": None, "status": "failed", "error": "..."}
        rather than raising — the caller decides how to handle.
        """
        import httpx

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self._base_url}/attest",
                    json={
                        "indicatorHash": indicator_hash,
                        "severityScore": severity_score,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                log.info(
                    "midnight_attest_success",
                    indicator_hash=indicator_hash[:16] + "…",
                    tx_hash=data.get("txHash", "")[:18] + "…",
                    status=data.get("status"),
                )
                return data

        except Exception as exc:
            # Log the failure WITH the indicator hash (but not the salt or raw IP)
            log.error(
                "midnight_attest_failed",
                indicator_hash=indicator_hash[:16] + "…",
                error=str(exc),
            )
            return {"txHash": None, "status": "failed", "error": str(exc)}

    async def query(self, indicator_hash: str) -> dict[str, Any]:
        """Query corroboration count for an indicator.

        Returns:
            {"corroborationCount": int, "highConfidenceCount": int}
        """
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self._base_url}/query/{indicator_hash}",
                )
                resp.raise_for_status()
                return resp.json()

        except Exception as exc:
            log.warning(
                "midnight_query_failed",
                indicator_hash=indicator_hash[:16] + "…",
                error=str(exc),
            )
            return {"corroborationCount": 0, "highConfidenceCount": 0}

    async def stats(self) -> dict[str, Any]:
        """Get global attestation stats from the ledger.

        Returns:
            {"totalAttestations": int, "uniqueIndicators": int, "networkMode": str}
        """
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self._base_url}/stats")
                resp.raise_for_status()
                return resp.json()

        except Exception as exc:
            log.warning("midnight_stats_failed", error=str(exc))
            return {"totalAttestations": 0, "uniqueIndicators": 0, "networkMode": "unknown"}

    async def health(self) -> dict[str, Any]:
        """Check bridge service health."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base_url}/health")
                resp.raise_for_status()
                return resp.json()

        except Exception as exc:
            return {"status": "unreachable", "error": str(exc)}
