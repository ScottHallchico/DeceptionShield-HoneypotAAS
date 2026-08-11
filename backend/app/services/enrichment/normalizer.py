"""Normalization & enrichment service — section 1.4 of the implementation plan.

Kafka consumer that:
- Validates raw honeypot log lines against a JSON schema per honeypot type
- Normalizes into the unified event schema
- Enriches with GeoIP + IP reputation
- Deduplicates repeated identical events within a short window
- Writes normalized events to Postgres and publishes to the normalized-events topic
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger
from app.services.enrichment.geoip import enrich_geoip
from app.services.enrichment.mitre import classify_event
from app.services.enrichment.reputation import lookup_reputation

log = get_logger(__name__)

# ─── Deduplication window ────────────────────────────────────────────────────

_DEDUP_WINDOW_SECONDS = 5
_DEDUP_MAX_SIZE = 10000

# OrderedDict for LRU-style eviction: {event_hash: last_seen_timestamp}
_recent_events: OrderedDict[str, float] = OrderedDict()


def _event_fingerprint(raw: dict[str, Any]) -> str:
    """Create a hash fingerprint for dedup — same attacker, same payload, same
    honeypot within a short window should not produce duplicate events."""
    key_parts = [
        raw.get("attacker_ip", ""),
        raw.get("honeypot_id", ""),
        raw.get("event_type", ""),
        str(raw.get("payload", ""))[:256],  # Cap payload length for hashing
    ]
    return hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]


def _is_duplicate(fingerprint: str) -> bool:
    """Check if an event with this fingerprint was seen recently."""
    now = time.time()

    # Evict expired entries
    while _recent_events:
        oldest_key, oldest_time = next(iter(_recent_events.items()))
        if now - oldest_time > _DEDUP_WINDOW_SECONDS:
            _recent_events.pop(oldest_key)
        else:
            break

    # Size-based eviction if cache is too large
    while len(_recent_events) > _DEDUP_MAX_SIZE:
        _recent_events.popitem(last=False)

    if fingerprint in _recent_events:
        _recent_events.move_to_end(fingerprint)
        _recent_events[fingerprint] = now
        return True

    _recent_events[fingerprint] = now
    return False


# ─── Honeypot-specific raw log parsers ───────────────────────────────────────


def _parse_cowrie_log(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a Cowrie SSH/Telnet JSON log line into the unified schema."""
    event_id = raw.get("eventid", "")

    # Map Cowrie event IDs to our event types
    if "login" in event_id:
        event_type = "login_attempt"
        technique = "brute_force"
        payload = f"username={raw.get('username', '')}, password={raw.get('password', '')}"
    elif "command" in event_id:
        event_type = "command_exec"
        technique = "credential_reuse"
        payload_val = raw.get("input")
        if isinstance(payload_val, dict):
            payload = raw.get("message", "")
        else:
            payload = str(payload_val) if payload_val else raw.get("message", "")
    elif "download" in event_id or "transfer" in event_id:
        event_type = "file_download"
        technique = "payload_drop"
        payload = raw.get("url", raw.get("destfile", ""))
    elif "session" in event_id:
        # Session open/close — skip as standalone events, tracked in sessions table
        return None
    else:
        event_type = "exploit_probe"
        technique = None
        payload = raw.get("message", "")

    return {
        "honeypot_id": raw.get("sensor", raw.get("honeypot_id", "cowrie-01")),
        "honeypot_type": "cowrie",
        "attacker_ip": raw.get("src_ip", raw.get("attacker_ip", "")),
        "event_type": event_type,
        "technique": technique,
        "payload": payload,
        "session_id": None,  # Cowrie sessions are short strings, DB expects UUID
        "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
    }


def _parse_dionaea_log(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a Dionaea JSON log line into the unified schema."""
    connection = raw.get("connection", {})
    event_type_raw = raw.get("type", raw.get("event_type", ""))

    if "download" in event_type_raw or "offer" in event_type_raw:
        event_type = "file_download"
        technique = "payload_drop"
    elif "login" in event_type_raw or "credentials" in event_type_raw:
        event_type = "login_attempt"
        technique = "brute_force"
    elif "exploit" in event_type_raw or "shellcode" in event_type_raw:
        event_type = "exploit_probe"
        technique = "cve_exploit_attempt"
    else:
        event_type = "exploit_probe"
        technique = None

    return {
        "honeypot_id": raw.get("sensor", raw.get("honeypot_id", "dionaea-01")),
        "honeypot_type": "dionaea",
        "attacker_ip": connection.get("remote_host", raw.get("src_ip", raw.get("attacker_ip", ""))),
        "event_type": event_type,
        "technique": technique,
        "payload": raw.get("payload", raw.get("message", "")),
        "session_id": None,
        "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
    }


def _parse_wp_decoy_log(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a WordPress decoy JSON log line."""
    return {
        "honeypot_id": raw.get("honeypot_id", "wp-decoy-01"),
        "honeypot_type": "wp-decoy",
        "attacker_ip": raw.get("attacker_ip", raw.get("remote_addr", "")),
        "event_type": raw.get("event_type", "login_attempt"),
        "technique": raw.get("technique", "brute_force"),
        "payload": raw.get("payload", ""),
        "session_id": None,
        "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
    }


def _parse_rdp_decoy_log(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse an RDP decoy JSON log line."""
    return {
        "honeypot_id": raw.get("honeypot_id", "rdp-decoy-01"),
        "honeypot_type": "rdp-decoy",
        "attacker_ip": raw.get("attacker_ip", raw.get("remote_addr", "")),
        "event_type": raw.get("event_type", "login_attempt"),
        "technique": "brute_force",
        "payload": raw.get("payload", ""),
        "session_id": None,
        "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
    }


def _parse_smb_decoy_log(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse an SMB decoy / Samba honeypot JSON log line."""
    return {
        "honeypot_id": raw.get("honeypot_id", "smb-decoy-01"),
        "honeypot_type": "smb-decoy",
        "attacker_ip": raw.get("attacker_ip", raw.get("remote_addr", "")),
        "event_type": raw.get("event_type", "exploit_probe"),
        "technique": raw.get("technique", None),
        "payload": raw.get("payload", ""),
        "session_id": None,
        "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
    }


_PARSERS = {
    "cowrie": _parse_cowrie_log,
    "dionaea": _parse_dionaea_log,
    "wp-decoy": _parse_wp_decoy_log,
    "rdp-decoy": _parse_rdp_decoy_log,
    "smb-decoy": _parse_smb_decoy_log,
}


# ─── Severity classification ────────────────────────────────────────────────


def _classify_severity(
    event_type: str,
    technique: str | None,
    reputation_score: int,
) -> str:
    """Assign severity based on event type, technique, and reputation."""
    if reputation_score >= 80:
        return "critical"
    if event_type == "file_download":
        return "high"
    if technique == "cve_exploit_attempt":
        return "critical"
    if event_type == "exploit_probe":
        return "high"
    if event_type == "command_exec":
        return "medium"
    if reputation_score >= 50:
        return "medium"
    return "low"


# ─── Summary generation for embeddings ───────────────────────────────────────


def generate_event_summary(event: dict[str, Any]) -> str:
    """Generate a natural-language summary of an event for embedding.

    Per section 1.11: a template-generated sentence, not the raw payload,
    since raw payloads are often binary/obfuscated and embed poorly.
    """
    parts = [
        f"{event.get('attacker_ip', 'unknown IP')}",
        f"attempted {event.get('event_type', 'unknown action').replace('_', ' ')}",
        f"against {event.get('honeypot_id', 'unknown honeypot')}",
        f"({event.get('honeypot_type', 'unknown type')})",
    ]

    if event.get("technique"):
        parts.append(f"using {event['technique'].replace('_', ' ')} technique")

    if event.get("mitre_attck_id"):
        parts.append(f"(MITRE {event['mitre_attck_id']})")

    geo = event.get("geo", {})
    if geo and geo.get("country"):
        parts.append(f"from {geo.get('country', '')}")
        if geo.get("city"):
            parts[-1] = f"from {geo['city']}, {geo['country']}"

    if event.get("severity"):
        parts.append(f"— severity: {event['severity']}")

    return " ".join(parts)


# ─── Main normalization pipeline ─────────────────────────────────────────────


async def normalize_event(raw_json: str | bytes | dict) -> dict[str, Any] | None:
    """Full normalization pipeline for a single raw event.

    1. Parse raw JSON
    2. Determine honeypot type and apply type-specific parser
    3. Enrich with GeoIP + reputation
    4. Classify MITRE ATT&CK technique
    5. Assign severity
    6. Deduplicate
    7. Generate summary for embedding

    Returns the normalized event dict or None if the event is a duplicate or invalid.
    """
    # Parse raw input
    if isinstance(raw_json, (str, bytes)):
        try:
            raw = json.loads(raw_json)
        except json.JSONDecodeError:
            log.warning("invalid_json_event", raw=str(raw_json)[:200])
            return None
    else:
        raw = raw_json

    # Determine honeypot type
    honeypot_type = raw.get("honeypot_type", "").lower()
    if not honeypot_type:
        # Try to infer from event ID or sensor name
        sensor = raw.get("sensor", raw.get("honeypot_id", ""))
        for hp_type in _PARSERS:
            if hp_type.replace("-", "") in sensor.lower().replace("-", ""):
                honeypot_type = hp_type
                break

    if honeypot_type not in _PARSERS:
        log.warning("unknown_honeypot_type", honeypot_type=honeypot_type)
        return None

    # Apply type-specific parser
    parsed = _PARSERS[honeypot_type](raw)
    if parsed is None:
        return None

    # Validate required fields
    if not parsed.get("attacker_ip"):
        log.warning("missing_attacker_ip", parsed_event=parsed)
        return None

    # Deduplication check
    fingerprint = _event_fingerprint(parsed)
    if _is_duplicate(fingerprint):
        log.debug("duplicate_event_skipped", fingerprint=fingerprint)
        return None

    # Enrich with GeoIP
    geo = enrich_geoip(parsed["attacker_ip"])
    parsed["geo"] = geo

    # Enrich with reputation
    reputation = await lookup_reputation(parsed["attacker_ip"])
    parsed["reputation"] = reputation

    # Classify MITRE ATT&CK
    mitre_id, technique_label = classify_event(
        parsed["event_type"],
        parsed["honeypot_type"],
        parsed.get("payload"),
    )
    parsed["mitre_attck_id"] = mitre_id

    # Assign severity
    parsed["severity"] = _classify_severity(
        parsed["event_type"],
        parsed.get("technique"),
        reputation.get("abuseipdb_score", 0),
    )

    # Generate UUID
    parsed["id"] = str(uuid.uuid4())

    # Normalize timestamp
    if isinstance(parsed.get("timestamp"), str):
        try:
            parsed["timestamp"] = datetime.fromisoformat(
                parsed["timestamp"].replace("Z", "+00:00")
            ).isoformat()
        except ValueError:
            parsed["timestamp"] = datetime.now(UTC).isoformat()

    # Generate summary for RAG embedding
    parsed["summary_text"] = generate_event_summary(parsed)

    return parsed
