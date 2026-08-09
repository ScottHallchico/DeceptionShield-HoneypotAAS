import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.enrichment.session_builder import upsert_session_from_event


@pytest.mark.asyncio
async def test_session_builder_cowrie_commands():
    """Verify that two command_exec events two seconds apart produce a session with event_count == 2 and a second frame with offset_ms ≈ 2000."""
    session_mock = AsyncMock()

    ts1 = datetime.now(timezone.utc)
    event1 = {
        "session_id": "test-session-123",
        "attacker_ip": "1.2.3.4",
        "honeypot_id": "hp1",
        "honeypot_type": "cowrie",
        "event_type": "command_exec",
        "payload": "whoami",
    }

    # First execution: session does not exist (scalar_one_or_none returns None)
    mock_result1 = MagicMock()
    mock_result1.scalar_one_or_none.return_value = None
    session_mock.execute.return_value = mock_result1

    await upsert_session_from_event(session_mock, event1, ts1)

    # Find the added session
    added_sess = session_mock.add.call_args[0][0]
    assert added_sess.event_count == 1
    assert "whoami" in added_sess.commands

    # Now simulate second event 2 seconds later
    ts2 = ts1 + timedelta(seconds=2)
    event2 = {
        "session_id": "test-session-123",
        "attacker_ip": "1.2.3.4",
        "honeypot_id": "hp1",
        "honeypot_type": "cowrie",
        "event_type": "command_exec",
        "payload": "ls -la",
    }

    # Second execution: session exists (scalar_one_or_none returns added_sess)
    mock_result2 = MagicMock()
    mock_result2.scalar_one_or_none.return_value = added_sess
    session_mock.execute.return_value = mock_result2

    await upsert_session_from_event(session_mock, event2, ts2)

    assert added_sess.event_count == 2

    # Verify tty_log parsing
    frames = json.loads(added_sess.tty_log)
    assert len(frames) == 2
    assert frames[0]["data"] == "$ whoami\r\n"
    assert frames[0]["offset_ms"] == 0.0
    assert frames[1]["data"] == "$ ls -la\r\n"
    assert pytest.approx(frames[1]["offset_ms"], abs=100) == 2000.0
