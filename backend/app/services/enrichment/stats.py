"""Dashboard stats computation — used by GET /api/stats and the WebSocket heartbeat."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text

from app.core.logging import get_logger
from app.db.session import async_session_factory
from app.models.models import Attacker, BlocklistEntry, Event, HoneypotInstance

log = get_logger(__name__)


async def compute_dashboard_stats() -> dict[str, Any]:
    """Compute real-time dashboard summary metrics."""
    now = datetime.now(UTC)
    one_hour_ago = now - timedelta(hours=1)
    twenty_four_hours_ago = now - timedelta(hours=24)

    async with async_session_factory() as session:
        # Total events
        total_events = (await session.execute(select(func.count(Event.id)))).scalar() or 0

        # Total unique attackers
        total_attackers = (await session.execute(select(func.count(Attacker.id)))).scalar() or 0

        # Active honeypots
        active_honeypots = (
            await session.execute(
                select(func.count(HoneypotInstance.id)).where(HoneypotInstance.status == "running")
            )
        ).scalar() or 0

        # Blocked IPs
        blocked_ips = (
            await session.execute(
                select(func.count(BlocklistEntry.id)).where(BlocklistEntry.is_active)
            )
        ).scalar() or 0

        # Events in last hour
        events_last_hour = (
            await session.execute(
                select(func.count(Event.id)).where(Event.timestamp >= one_hour_ago)
            )
        ).scalar() or 0

        # Events in last 24h
        events_last_24h = (
            await session.execute(
                select(func.count(Event.id)).where(Event.timestamp >= twenty_four_hours_ago)
            )
        ).scalar() or 0

        # Top attacking countries (from attacker geo data)
        top_countries_result = await session.execute(
            select(
                func.json_extract_path_text(Attacker.geo, "country").label("country"),
                func.count(Attacker.id).label("count"),
            )
            .where(Attacker.geo.isnot(None))
            .group_by(text("country"))
            .order_by(text("count DESC"))
            .limit(10)
        )
        top_countries = [
            {"country": row.country, "count": row.count}
            for row in top_countries_result
            if row.country
        ]

        # Top techniques
        top_techniques_result = await session.execute(
            select(Event.technique, func.count(Event.id).label("count"))
            .where(Event.technique.isnot(None))
            .group_by(Event.technique)
            .order_by(text("count DESC"))
            .limit(10)
        )
        top_techniques = [
            {"technique": row.technique, "count": row.count}
            for row in top_techniques_result
        ]

        # Severity breakdown
        severity_result = await session.execute(
            select(Event.severity, func.count(Event.id).label("count"))
            .group_by(Event.severity)
        )
        severity_breakdown = {row.severity: row.count for row in severity_result}

        # Events per honeypot
        honeypot_result = await session.execute(
            select(Event.honeypot_type, func.count(Event.id).label("count"))
            .group_by(Event.honeypot_type)
        )
        events_per_honeypot = {row.honeypot_type: row.count for row in honeypot_result}

        # Attack timeline (hourly buckets for last 24h)
        timeline_result = await session.execute(
            select(
                func.date_trunc("hour", Event.timestamp).label("hour"),
                func.count(Event.id).label("count"),
            )
            .where(Event.timestamp >= twenty_four_hours_ago)
            .group_by(text("hour"))
            .order_by(text("hour"))
        )
        attack_timeline = [
            {"timestamp": row.hour.isoformat() if row.hour else "", "count": row.count}
            for row in timeline_result
        ]

    return {
        "total_events": total_events,
        "total_attackers": total_attackers,
        "active_honeypots": active_honeypots,
        "blocked_ips": blocked_ips,
        "events_last_hour": events_last_hour,
        "events_last_24h": events_last_24h,
        "top_attacking_countries": top_countries,
        "top_techniques": top_techniques,
        "severity_breakdown": severity_breakdown,
        "events_per_honeypot": events_per_honeypot,
        "attack_timeline": attack_timeline,
    }
