"""AI Threat Assistant — section 1.11 of the implementation plan.

Hybrid RAG system combining:
- Structured path (SQL): countable/aggregate questions
- Semantic path (pgvector): exploratory/fuzzy questions

Uses OpenAI embeddings + Claude API for grounded answers with citations.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import async_session_factory
from app.models.models import (
    AssistantConversation,
    AssistantMessage,
    Attacker,
    Event,
)

log = get_logger(__name__)


# ─── Intent parsing (matches frontend's assistantRetrieval.ts) ────────────────


def parse_intent(question: str) -> dict[str, Any]:
    """Parse a natural-language question for structured intent fields.

    Extracts: IP, honeypot, severity, technique, time_window.
    Same logic as the frontend mock, so behavior is consistent.
    """
    intent: dict[str, Any] = {}

    # IP address extraction
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", question)
    if ip_match:
        intent["ip"] = ip_match.group(1)

    # Honeypot type extraction
    honeypot_patterns = {
        "cowrie": r"\bcowrie\b",
        "dionaea": r"\bdionaea\b",
        "wp-decoy": r"\b(wordpress|wp[- ]?decoy|wp[- ]?admin)\b",
        "rdp-decoy": r"\b(rdp[- ]?decoy|rdp)\b",
        "smb-decoy": r"\b(smb[- ]?decoy|smb|samba)\b",
    }
    for hp_type, pattern in honeypot_patterns.items():
        if re.search(pattern, question, re.I):
            intent["honeypot_type"] = hp_type
            break

    # Severity extraction
    for severity in ("critical", "high", "medium", "low"):
        if severity in question.lower():
            intent["severity"] = severity
            break

    # Technique extraction
    technique_patterns = {
        "brute_force": r"\bbrute[- ]?force\b",
        "credential_reuse": r"\bcredential[- ]?reuse\b",
        "payload_drop": r"\b(payload[- ]?drop|malware|download)\b",
        "cve_exploit_attempt": r"\b(cve|exploit)\b",
    }
    for technique, pattern in technique_patterns.items():
        if re.search(pattern, question, re.I):
            intent["technique"] = technique
            break

    # Time window extraction
    time_patterns = [
        (r"\b(?:last|past)\s+(\d+)\s*min(?:ute)?s?\b", "minutes"),
        (r"\b(?:last|past)\s+(\d+)\s*hours?\b", "hours"),
        (r"\b(?:last|past)\s+(\d+)\s*days?\b", "days"),
        (r"\b(?:last|past)\s+hour\b", "hours", 1),
        (r"\btoday\b", "hours", 24),
        (r"\byesterday\b", "hours", 48),
    ]
    for pattern_info in time_patterns:
        pattern = pattern_info[0]
        unit = pattern_info[1]
        match = re.search(pattern, question, re.I)
        if match:
            if len(pattern_info) == 3:
                amount = pattern_info[2]
            else:
                amount = int(match.group(1))
            intent["time_window"] = {unit: amount}
            break

    # Question type classification
    q_lower = question.lower()
    if any(w in q_lower for w in ("how many", "count", "total", "number of")):
        intent["query_type"] = "count"
    elif any(w in q_lower for w in ("top", "most", "highest", "worst")):
        intent["query_type"] = "top_n"
    elif any(w in q_lower for w in ("which ip", "who", "what ip")):
        intent["query_type"] = "identify"
    elif any(w in q_lower for w in ("unusual", "anomal", "weird", "strange", "suspicious")):
        intent["query_type"] = "anomaly"
    elif any(w in q_lower for w in ("summary", "overview", "what's happening", "status")):
        intent["query_type"] = "summary"
    else:
        intent["query_type"] = "general"

    return intent


# ─── Structured SQL retrieval ────────────────────────────────────────────────


async def structured_retrieval(intent: dict[str, Any]) -> tuple[list[dict], dict[str, Any]]:
    """Run structured SQL queries based on parsed intent.

    Returns (events_list, aggregate_stats).
    """
    async with async_session_factory() as session:
        # Base query
        query = select(Event)
        count_query = select(func.count(Event.id))

        # Apply filters from intent
        if intent.get("ip"):
            query = query.where(Event.attacker_ip == intent["ip"])
            count_query = count_query.where(Event.attacker_ip == intent["ip"])

        if intent.get("honeypot_type"):
            query = query.where(Event.honeypot_type == intent["honeypot_type"])
            count_query = count_query.where(Event.honeypot_type == intent["honeypot_type"])

        if intent.get("severity"):
            query = query.where(Event.severity == intent["severity"])
            count_query = count_query.where(Event.severity == intent["severity"])

        if intent.get("technique"):
            query = query.where(Event.technique == intent["technique"])
            count_query = count_query.where(Event.technique == intent["technique"])

        if intent.get("time_window"):
            tw = intent["time_window"]
            delta = timedelta(**tw)
            cutoff = datetime.now(UTC) - delta
            query = query.where(Event.timestamp >= cutoff)
            count_query = count_query.where(Event.timestamp >= cutoff)

        # Get total count
        total = (await session.execute(count_query)).scalar() or 0

        # Get events (limit for context assembly)
        query = query.order_by(Event.timestamp.desc()).limit(20)
        result = await session.execute(query)
        events = result.scalars().all()

        events_list = []
        for e in events:
            events_list.append({
                "id": str(e.id),
                "honeypot_id": e.honeypot_id,
                "honeypot_type": e.honeypot_type,
                "attacker_ip": e.attacker_ip,
                "event_type": e.event_type,
                "technique": e.technique,
                "mitre_attck_id": e.mitre_attck_id,
                "severity": e.severity,
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "summary_text": e.summary_text or "",
                "session_id": str(e.session_id) if e.session_id else None,
                "payload": (e.payload or "")[:200],  # Truncate payload for context
            })

        # Compute aggregate stats for the filtered set
        agg_stats: dict[str, Any] = {"total_matching": total}

        if total > 0:
            # Unique attackers in filtered set
            unique_ips_q = select(func.count(func.distinct(Event.attacker_ip)))
            if intent.get("honeypot_type"):
                unique_ips_q = unique_ips_q.where(Event.honeypot_type == intent["honeypot_type"])
            if intent.get("time_window"):
                unique_ips_q = unique_ips_q.where(Event.timestamp >= cutoff)
            unique_ips = (await session.execute(unique_ips_q)).scalar() or 0
            agg_stats["unique_attackers"] = unique_ips

            # Severity distribution
            sev_q = select(Event.severity, func.count(Event.id))
            if intent.get("honeypot_type"):
                sev_q = sev_q.where(Event.honeypot_type == intent["honeypot_type"])
            if intent.get("time_window"):
                sev_q = sev_q.where(Event.timestamp >= cutoff)
            sev_q = sev_q.group_by(Event.severity)
            sev_result = await session.execute(sev_q)
            agg_stats["severity_breakdown"] = {r[0]: r[1] for r in sev_result}

    return events_list, agg_stats


# ─── Semantic (vector) retrieval ─────────────────────────────────────────────


async def embed_text(text_input: str) -> list[float]:
    """Generate an embedding vector using OpenAI's embedding model."""
    settings = get_settings()
    if not settings.openai_api_key:
        log.warning("openai_api_key_not_set")
        return []

    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=settings.openai_api_key)
        response = await client.embeddings.create(
            model=settings.embedding_model,
            input=text_input,
        )
        return response.data[0].embedding

    except Exception as exc:
        log.error("embedding_failed", error=str(exc))
        return []


async def semantic_retrieval(
    question: str,
    candidate_ids: list[str] | None = None,
    limit: int = 8,
) -> list[dict]:
    """Run pgvector cosine-similarity search over event embeddings.

    If candidate_ids is provided, scopes the search to that set
    (structured filtering → semantic ranking, per section 1.11).
    """
    question_embedding = await embed_text(question)
    if not question_embedding:
        return []

    async with async_session_factory() as session:
        # Build vector similarity query
        # pgvector cosine distance: embedding <=> query_embedding
        query = (
            select(
                Event.id,
                Event.honeypot_id,
                Event.honeypot_type,
                Event.attacker_ip,
                Event.event_type,
                Event.technique,
                Event.severity,
                Event.timestamp,
                Event.summary_text,
                Event.session_id,
                Event.mitre_attck_id,
            )
            .where(Event.embedding.isnot(None))
            .order_by(Event.embedding.cosine_distance(question_embedding))
            .limit(limit)
        )

        if candidate_ids:
            query = query.where(Event.id.in_(candidate_ids))

        result = await session.execute(query)
        rows = result.all()

        return [
            {
                "id": str(r.id),
                "honeypot_id": r.honeypot_id,
                "honeypot_type": r.honeypot_type,
                "attacker_ip": r.attacker_ip,
                "event_type": r.event_type,
                "technique": r.technique,
                "severity": r.severity,
                "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                "summary_text": r.summary_text or "",
                "session_id": str(r.session_id) if r.session_id else None,
                "mitre_attck_id": r.mitre_attck_id,
            }
            for r in rows
        ]


# ─── Context assembly & Claude API call ─────────────────────────────────────


SYSTEM_PROMPT = """You are a cybersecurity threat analyst assistant for an SMB honeypot network.
You analyze honeypot event data to answer questions about network threats and attacks.

RULES:
1. Answer ONLY from the provided context data. Never speculate or invent data.
2. Cite specific event IDs or attacker IPs when making claims.
3. If the context doesn't contain enough information to answer, say so clearly.
4. Use clear, non-jargon language since your audience is SMB owners, not SOC analysts.
5. When discussing MITRE ATT&CK techniques, briefly explain what they mean in plain terms.
6. Highlight anything that looks particularly concerning or unusual.
7. Format your response with markdown for readability."""


async def query_claude(
    question: str,
    context_events: list[dict],
    aggregate_stats: dict[str, Any],
    conversation_history: list[dict] | None = None,
) -> str:
    """Send the grounded query to Claude API.

    Per section 1.11: explicit system instructions to answer only from
    provided context and cite specific event IDs.
    """
    settings = get_settings()

    # Assemble context
    context_parts = []
    if aggregate_stats:
        context_parts.append(f"**Aggregate Statistics:**\n{_format_stats(aggregate_stats)}")

    if context_events:
        context_parts.append("**Relevant Events:**")
        for evt in context_events[:12]:  # Cap context size
            context_parts.append(
                f"- [{evt.get('severity', '?').upper()}] Event {evt['id'][:8]}: "
                f"{evt.get('summary_text', 'no summary')} "
                f"(at {evt.get('timestamp', '?')})"
            )

    context = "\n".join(context_parts)

    # Build messages
    messages = []
    if conversation_history:
        # Include last 2-3 turns for multi-turn context
        for turn in conversation_history[-3:]:
            messages.append({"role": turn["role"], "content": turn["content"]})

    messages.append({
        "role": "user",
        "content": f"Context data from honeypot network:\n\n{context}\n\n---\n\nQuestion: {question}",
    })

    if not settings.anthropic_api_key:
        # Fallback: generate a structured response without Claude
        return _fallback_response(question, context_events, aggregate_stats)

    try:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        response = await client.messages.create(
            model=settings.claude_model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        return response.content[0].text

    except Exception as exc:
        log.error("claude_api_failed", error=str(exc))
        return _fallback_response(question, context_events, aggregate_stats)


def _format_stats(stats: dict[str, Any]) -> str:
    """Format aggregate stats for inclusion in Claude context."""
    parts = []
    if "total_matching" in stats:
        parts.append(f"Total matching events: {stats['total_matching']}")
    if "unique_attackers" in stats:
        parts.append(f"Unique attacker IPs: {stats['unique_attackers']}")
    if "severity_breakdown" in stats:
        sev = stats["severity_breakdown"]
        parts.append(f"Severity breakdown: {', '.join(f'{k}: {v}' for k, v in sev.items())}")
    return "\n".join(parts)


def _fallback_response(
    question: str,
    events: list[dict],
    stats: dict[str, Any],
) -> str:
    """Generate a structured response without Claude (when API key is unavailable)."""
    total = stats.get("total_matching", len(events))
    unique = stats.get("unique_attackers", len({e["attacker_ip"] for e in events}))

    parts = [f"Found **{total}** matching events from **{unique}** distinct attacker IPs."]

    if stats.get("severity_breakdown"):
        sev = stats["severity_breakdown"]
        parts.append(f"\n**Severity breakdown:** {', '.join(f'{k}: {v}' for k, v in sev.items())}")

    if events:
        parts.append("\n**Most recent events:**")
        for evt in events[:5]:
            parts.append(
                f"- `{evt['attacker_ip']}` → {evt.get('event_type', '?')} "
                f"on {evt.get('honeypot_id', '?')} ({evt.get('severity', '?')})"
            )

    return "\n".join(parts)


# ─── Main query handler ─────────────────────────────────────────────────────


async def handle_assistant_query(
    question: str,
    conversation_id: uuid.UUID | None = None,
    user_id: str = "anonymous",
) -> dict[str, Any]:
    """Full query pipeline for POST /api/assistant/query.

    1. Parse structured intent
    2. Run structured SQL filter
    3. Run semantic search scoped to candidates
    4. Assemble context
    5. Call Claude
    6. Store conversation, return response

    Returns the AssistantQueryResponse shape.
    """
    # Parse intent
    intent = parse_intent(question)
    log.info("assistant_query", question=question[:100], intent=intent)

    # Structured retrieval
    structured_events, agg_stats = await structured_retrieval(intent)

    # Semantic retrieval (scoped to structured candidates if available)
    candidate_ids = [e["id"] for e in structured_events] if structured_events else None
    semantic_events = await semantic_retrieval(question, candidate_ids, limit=8)

    # Merge: prefer semantic-ranked events, but include all structured results
    seen_ids = set()
    merged_events = []
    for evt in semantic_events + structured_events:
        if evt["id"] not in seen_ids:
            seen_ids.add(evt["id"])
            merged_events.append(evt)

    # Get conversation history for multi-turn context
    conversation_history: list[dict] = []
    if conversation_id:
        async with async_session_factory() as session:
            conv = await session.get(AssistantConversation, conversation_id)
            if conv:
                msgs_result = await session.execute(
                    select(AssistantMessage)
                    .where(AssistantMessage.conversation_id == conversation_id)
                    .order_by(AssistantMessage.created_at)
                )
                for msg in msgs_result.scalars().all():
                    conversation_history.append({"role": msg.role, "content": msg.content})

    # Query Claude (or fallback)
    answer = await query_claude(question, merged_events, agg_stats, conversation_history)

    # Build citations from referenced events
    citations = []
    for evt in merged_events[:8]:
        label_parts = [evt.get("severity", ""), evt.get("honeypot_id", ""), evt.get("attacker_ip", "")]
        citations.append({
            "label": " · ".join(p for p in label_parts if p),
            "event_id": evt["id"],
            "session_id": evt.get("session_id"),
            "attacker_ip": evt.get("attacker_ip"),
        })

    # Persist conversation
    new_conversation = conversation_id is None
    if new_conversation:
        conversation_id = uuid.uuid4()

    async with async_session_factory() as session:
        if new_conversation:
            conv = AssistantConversation(
                id=conversation_id,
                user_id=user_id,
                title=question[:100],
            )
            session.add(conv)

        # Store user message
        user_msg = AssistantMessage(
            conversation_id=conversation_id,
            role="user",
            content=question,
        )
        session.add(user_msg)

        # Store assistant response
        assistant_msg_id = uuid.uuid4()
        assistant_msg = AssistantMessage(
            id=assistant_msg_id,
            conversation_id=conversation_id,
            role="assistant",
            content=answer,
            citations=citations,
            retrieved_event_count=len(merged_events),
        )
        session.add(assistant_msg)

        await session.commit()

    return {
        "conversation_id": str(conversation_id),
        "retrieved_event_count": len(merged_events),
        "message": {
            "id": str(assistant_msg_id),
            "role": "assistant",
            "content": answer,
            "citations": citations,
            "created_at": datetime.now(UTC).isoformat(),
        },
    }


# ─── Embedding pipeline (section 1.11) ──────────────────────────────────────


async def embed_event(event_id: str, summary_text: str) -> None:
    """Generate and store an embedding for an event's summary text."""
    embedding = await embed_text(summary_text)
    if not embedding:
        return

    async with async_session_factory() as session:
        event = await session.get(Event, event_id)
        if event:
            event.embedding = embedding
            await session.commit()
            log.debug("event_embedded", event_id=event_id)


async def update_attacker_summary(attacker_ip: str) -> None:
    """Update the rolling summary embedding for an attacker."""
    async with async_session_factory() as session:
        result = await session.execute(
            select(Attacker).where(Attacker.ip == attacker_ip)
        )
        attacker = result.scalar_one_or_none()
        if not attacker:
            return

        # Generate summary text
        events_result = await session.execute(
            select(Event)
            .where(Event.attacker_ip == attacker_ip)
            .order_by(Event.timestamp.desc())
            .limit(20)
        )
        events_result.scalars().all()

        summary_parts = [
            f"Attacker {attacker_ip} has been seen {attacker.total_events} times.",
            f"Honeypots targeted: {', '.join(attacker.honeypots_hit or [])}.",
            f"Techniques: {', '.join(attacker.techniques_used or [])}.",
        ]
        if attacker.geo:
            geo = attacker.geo
            summary_parts.append(
                f"Origin: {geo.get('city', '')}, {geo.get('country', '')} ({geo.get('org', '')})"
            )
        if attacker.is_blocked:
            summary_parts.append("Currently blocked.")

        summary = " ".join(summary_parts)
        attacker.summary_text = summary

        embedding = await embed_text(summary)
        if embedding:
            attacker.summary_embedding = embedding

        await session.commit()
