"""Kafka consumer service — section 1.4 of the implementation plan.

Consumes raw honeypot events from Kafka, normalizes/enriches them,
writes to Postgres, and publishes to the normalized-events topic.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.enrichment.normalizer import normalize_event

log = get_logger(__name__)

# Global reference for graceful shutdown
_consumer_task: asyncio.Task | None = None


async def _write_to_db(event: dict[str, Any]) -> None:
    """Write a normalized event to Postgres and update attacker aggregates."""
    from datetime import datetime

    from sqlalchemy import select

    from app.db.session import async_session_factory
    from app.models.models import Attacker, Event

    async with async_session_factory() as session:
        # Insert event
        db_event = Event(
            id=event["id"],
            honeypot_id=event["honeypot_id"],
            honeypot_type=event["honeypot_type"],
            attacker_ip=event["attacker_ip"],
            geo=event.get("geo"),
            reputation=event.get("reputation"),
            event_type=event["event_type"],
            technique=event.get("technique"),
            mitre_attck_id=event.get("mitre_attck_id"),
            payload=event.get("payload"),
            session_id=event.get("session_id"),
            timestamp=(
                datetime.fromisoformat(event["timestamp"])
                if isinstance(event.get("timestamp"), str)
                else datetime.now(UTC)
            ),
            severity=event.get("severity", "low"),
            summary_text=event.get("summary_text"),
        )
        session.add(db_event)

        if event.get("session_id"):
            from app.services.enrichment.session_builder import upsert_session_from_event
            await upsert_session_from_event(session, event, db_event.timestamp)

        # Upsert attacker record
        result = await session.execute(
            select(Attacker).where(Attacker.ip == event["attacker_ip"])
        )
        attacker = result.scalar_one_or_none()

        if attacker:
            attacker.last_seen = datetime.now(UTC)
            attacker.total_events = (attacker.total_events or 0) + 1
            # Update honeypots_hit list
            honeypots = set(attacker.honeypots_hit or [])
            honeypots.add(event["honeypot_id"])
            attacker.honeypots_hit = list(honeypots)
            # Update techniques list
            techniques = set(attacker.techniques_used or [])
            if event.get("technique"):
                techniques.add(event["technique"])
            attacker.techniques_used = list(techniques)
            # Update geo/reputation with latest
            attacker.geo = event.get("geo")
            attacker.reputation = event.get("reputation")
            # Recalculate threat score
            attacker.threat_score = _calculate_threat_score(attacker)
        else:
            attacker = Attacker(
                ip=event["attacker_ip"],
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
                total_events=1,
                honeypots_hit=[event["honeypot_id"]],
                techniques_used=[event["technique"]] if event.get("technique") else [],
                geo=event.get("geo"),
                reputation=event.get("reputation"),
                threat_score=0.0,
            )
            attacker.threat_score = _calculate_threat_score(attacker)
            session.add(attacker)

        await session.commit()


def _calculate_threat_score(attacker: Any) -> float:
    """Calculate a composite threat score for an attacker (0-100)."""
    score = 0.0

    # Volume factor (more events = higher score, diminishing returns)
    event_count = attacker.total_events or 0
    score += min(30.0, event_count * 2.0)

    # Breadth factor (hitting more honeypots indicates reconnaissance)
    honeypots_count = len(attacker.honeypots_hit or [])
    score += min(20.0, honeypots_count * 5.0)

    # Technique diversity factor
    technique_count = len(attacker.techniques_used or [])
    score += min(20.0, technique_count * 4.0)

    # Reputation factor
    rep = attacker.reputation or {}
    abuse_score = rep.get("abuseipdb_score", 0)
    score += min(30.0, abuse_score * 0.3)

    return min(100.0, score)


async def _publish_normalized(event: dict[str, Any], producer) -> None:
    """Publish a normalized event to the normalized-events Kafka topic."""
    settings = get_settings()
    try:
        value = json.dumps(event, default=str).encode("utf-8")
        await producer.send_and_wait(settings.kafka_normalized_topic, value)
    except Exception as exc:
        log.error("kafka_publish_failed", error=str(exc))


async def start_consumer() -> None:
    """Start the Kafka consumer loop.

    This runs as a long-lived async task, consuming from raw-honeypot-events,
    normalizing, writing to DB, and publishing to normalized-events.
    """
    global _consumer_task

    settings = get_settings()
    log.info(
        "kafka_consumer_starting",
        bootstrap=settings.kafka_bootstrap_servers,
        topic=settings.kafka_raw_topic,
    )

    try:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

        consumer = AIOKafkaConsumer(
            settings.kafka_raw_topic,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            auto_offset_reset="latest",
            value_deserializer=lambda v: v.decode("utf-8"),
            enable_auto_commit=True,
            auto_commit_interval_ms=5000,
        )

        producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
        )

        await consumer.start()
        await producer.start()
        log.info("kafka_consumer_started")

        try:
            async for msg in consumer:
                try:
                    normalized = await normalize_event(msg.value)
                    if normalized is None:
                        continue

                    # Write to database
                    await _write_to_db(normalized)

                    # Publish to normalized-events for WebSocket broadcaster
                    await _publish_normalized(normalized, producer)

                    # Also push to WebSocket broadcaster directly
                    from app.api.websocket.broadcaster import broadcast_event
                    await broadcast_event(normalized)

                    # Evaluate response rules
                    from app.services.response_engine.engine import evaluate_rules
                    await evaluate_rules(normalized)

                    log.debug(
                        "event_processed",
                        event_id=normalized["id"],
                        attacker_ip=normalized["attacker_ip"],
                        severity=normalized["severity"],
                    )

                except Exception as exc:
                    log.error("event_processing_failed", error=str(exc), raw=str(msg.value)[:200])

        finally:
            await consumer.stop()
            await producer.stop()

    except ImportError:
        log.warning("aiokafka_not_available", msg="Running without Kafka — use direct ingestion endpoint instead")
    except Exception as exc:
        log.error("kafka_consumer_fatal_error", error=str(exc))


async def stop_consumer() -> None:
    """Gracefully stop the Kafka consumer."""
    global _consumer_task
    if _consumer_task and not _consumer_task.done():
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass
        _consumer_task = None
        log.info("kafka_consumer_stopped")
