"""Threat ledger service — computes indicator hashes and manages attestations.

This module sits in the enrichment pipeline, called after a block action is
confirmed in the response engine. It:
  1. Computes a one-way hash of the attacker IP + per-deployment salt so the
     raw IP never touches the chain in any form
  2. Converts the severity string to a numeric score for the ZK circuit
  3. Submits the attestation via the midnight-bridge sidecar
  4. Queries corroboration counts for indicators being evaluated

Security: The salt (midnight_indicator_salt) must NEVER appear in logs, error
responses, or committed files. If the salt leaks, the IP-hash privacy claim
is reversible by brute force over the ~4.3 billion IPv4 address space.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.midnight.client import MidnightBridgeClient

log = get_logger(__name__)

# ─── Severity mapping ───────────────────────────────────────────────────────

_SEVERITY_SCORES: dict[str, int] = {
    "low": 20,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


def compute_severity_score(severity: str) -> int:
    """Map a severity string to a numeric score (0-100) for the ZK circuit.

    The score determines whether the attestation clears the high-confidence
    threshold (≥ 70) in the Compact contract, without the score itself ever
    being disclosed on-chain.
    """
    return _SEVERITY_SCORES.get(severity.lower(), 20)


def compute_indicator_hash(ip: str, salt: str | None = None) -> str:
    """Compute a one-way SHA-256 hash of an attacker IP + deployment salt.

    The hash is computed off-chain so the raw IP never touches the Midnight
    network in any form — public or private witness.

    Args:
        ip: The attacker's IP address.
        salt: Per-deployment salt. If not provided, reads from settings.
              The salt value is NEVER logged or included in error responses.

    Returns:
        64-character lowercase hex string (SHA-256 digest).
    """
    if salt is None:
        settings = get_settings()
        salt = settings.midnight_indicator_salt

    # Concatenate IP + salt and hash
    payload = f"{ip}{salt}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


async def attest_indicator(
    ip: str,
    severity: str,
    mitre_technique: str | None = None,
) -> dict[str, Any]:
    """Submit an attestation to the Midnight Collective Defense Ledger.

    Called by the response engine after a block action is confirmed. This is
    the natural last step in the block pipeline — not a separate subsystem.

    Args:
        ip: The blocked attacker's IP address (hashed before transmission).
        severity: Severity string (low/medium/high/critical).
        mitre_technique: Optional MITRE ATT&CK technique ID for metadata.

    Returns:
        Dict with txHash, status (pending/confirmed/failed), and any error.
    """
    settings = get_settings()
    if not settings.midnight_enabled:
        log.debug("midnight_disabled_skipping_attestation")
        return {"txHash": None, "status": "disabled"}

    indicator_hash = compute_indicator_hash(ip)
    severity_score = compute_severity_score(severity)

    log.info(
        "midnight_attesting",
        indicator_hash=indicator_hash[:16] + "…",
        severity_score=severity_score,
        mitre_technique=mitre_technique,
    )

    client = MidnightBridgeClient()
    result = await client.attest(indicator_hash, severity_score)

    # Track attestation status for the caller to persist
    if result.get("status") == "failed":
        log.error(
            "midnight_attestation_failed",
            indicator_hash=indicator_hash[:16] + "…",
            error=result.get("error", "unknown"),
        )

    return result


async def query_indicator(ip: str) -> dict[str, Any]:
    """Query the Midnight ledger for independent corroboration of an indicator.

    Called by the response engine before finalizing a block decision. If other
    deployments have independently attested this indicator, the corroboration
    count is factored into the block decision (lowering the threshold for
    independently-corroborated threats).

    Args:
        ip: The attacker's IP address (hashed before querying).

    Returns:
        Dict with corroborationCount and highConfidenceCount.
    """
    settings = get_settings()
    if not settings.midnight_enabled:
        return {"corroborationCount": 0, "highConfidenceCount": 0}

    indicator_hash = compute_indicator_hash(ip)
    client = MidnightBridgeClient()
    result = await client.query(indicator_hash)

    if result.get("corroborationCount", 0) > 0:
        log.info(
            "midnight_corroboration_found",
            indicator_hash=indicator_hash[:16] + "…",
            corroboration_count=result["corroborationCount"],
            high_confidence_count=result.get("highConfidenceCount", 0),
        )

    return result
