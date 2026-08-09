"""Session builder helper for Session replay feature."""

import json
from datetime import datetime
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Session as SessionModel

async def upsert_session_from_event(session: AsyncSession, event: dict[str, Any], ts: datetime) -> None:
    """Upsert a Session record based on an incoming event and build synthetic tty logs for cowrie."""
    if not event.get("session_id"):
        return

    result = await session.execute(
        select(SessionModel).where(SessionModel.id == event["session_id"])
    )
    sess = result.scalar_one_or_none()
    
    if sess:
        sess.ended_at = ts
        sess.event_count = (sess.event_count or 0) + 1
        sess.duration_seconds = (ts - sess.started_at).total_seconds()
    else:
        sess = SessionModel(
            id=event["session_id"],
            attacker_ip=event["attacker_ip"],
            honeypot_id=event["honeypot_id"],
            honeypot_type=event["honeypot_type"],
            started_at=ts,
            ended_at=ts,
            event_count=1,
            duration_seconds=0,
        )
        session.add(sess)

    # Synthesize tty_log for Cowrie session replays
    # Note: This is a synthetic transcript (command lines, not raw keystrokes/output).
    # Real cowrie raw TTY logs are separate binary files per session.
    if event["honeypot_type"] == "cowrie" and event["event_type"] == "command_exec" and event.get("payload"):
        offset_ms = (ts - sess.started_at).total_seconds() * 1000
        frame = {"offset_ms": offset_ms, "data": f"$ {event['payload']}\r\n"}
        frames = json.loads(sess.tty_log) if sess.tty_log else []
        frames.append(frame)
        sess.tty_log = json.dumps(frames)
        sess.commands = (sess.commands or []) + [event["payload"]]
