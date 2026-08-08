"""SQLAlchemy ORM models — matches section 1.5 of the implementation plan."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all models."""
    pass


# ─── Enums ───────────────────────────────────────────────────────────────────

class HoneypotType(str):
    COWRIE = "cowrie"
    DIONAEA = "dionaea"
    WP_DECOY = "wp-decoy"
    RDP_DECOY = "rdp-decoy"
    SMB_DECOY = "smb-decoy"


class EventType(str):
    LOGIN_ATTEMPT = "login_attempt"
    COMMAND_EXEC = "command_exec"
    FILE_DOWNLOAD = "file_download"
    EXPLOIT_PROBE = "exploit_probe"
    PORT_SCAN = "port_scan"


class Severity(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HoneypotStatus(str):
    RUNNING = "running"
    STOPPED = "stopped"
    DEPLOYING = "deploying"
    ERROR = "error"


# ─── Models ──────────────────────────────────────────────────────────────────


class Event(Base):
    """Enriched honeypot event — hypertable partitioned by timestamp in TimescaleDB."""

    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    honeypot_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    honeypot_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    attacker_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)

    # GeoIP enrichment (stored as JSONB for flexibility)
    geo: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # IP reputation
    reputation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    technique: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mitre_attck_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), index=True
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low", index=True)

    # pgvector embedding for RAG (section 1.11)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)

    # Natural-language summary for embedding
    summary_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    session: Mapped[Session | None] = relationship("Session", back_populates="events")

    __table_args__ = (
        Index("ix_events_timestamp_severity", "timestamp", "severity"),
        Index("ix_events_attacker_technique", "attacker_ip", "technique"),
    )


class Attacker(Base):
    """Deduplicated attacker record aggregated by IP."""

    __tablename__ = "attackers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ip: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    honeypots_hit: Mapped[list | None] = mapped_column(JSONB, default=list)
    techniques_used: Mapped[list | None] = mapped_column(JSONB, default=list)
    geo: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    reputation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)

    # Rolling summary embedding for RAG
    summary_embedding: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    summary_text: Mapped[str | None] = mapped_column(Text, nullable=True)


class Session(Base):
    """Groups related events from one attacker's continuous interaction."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    attacker_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    honeypot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    honeypot_type: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    commands: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    tty_log: Mapped[str | None] = mapped_column(Text, nullable=True)  # For Cowrie session replay

    events: Mapped[list[Event]] = relationship("Event", back_populates="session")


class BlocklistEntry(Base):
    """IP block record with audit trail."""

    __tablename__ = "blocklist"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    rule_triggered: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action_taken: Mapped[str | None] = mapped_column(Text, nullable=True)  # SG rule ID or pfSense rule ID
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    unblocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    unblocked_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class HoneypotInstance(Base):
    """Deployed honeypot instance for fleet management."""

    __tablename__ = "honeypot_instances"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    deployed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    region: Mapped[str] = mapped_column(String(32), default="us-east-1")
    status: Mapped[str] = mapped_column(String(16), default="running")
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class ResponseRule(Base):
    """Configurable auto-response threshold rules."""

    __tablename__ = "response_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    honeypot_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    threshold_count: Mapped[int] = mapped_column(Integer, default=3)
    threshold_window_seconds: Mapped[int] = mapped_column(Integer, default=60)
    block_duration_hours: Mapped[int] = mapped_column(Integer, default=24)
    severity_filter: Mapped[str | None] = mapped_column(String(16), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class Allowlist(Base):
    """IPs that should never be blocked (office ranges, known partners)."""

    __tablename__ = "allowlist"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ip_cidr: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class AssistantConversation(Base):
    """Conversation thread for the AI Threat Assistant."""

    __tablename__ = "assistant_conversations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
    title: Mapped[str | None] = mapped_column(String(256), nullable=True)

    messages: Mapped[list[AssistantMessage]] = relationship(
        "AssistantMessage", back_populates="conversation", order_by="AssistantMessage.created_at"
    )


class AssistantMessage(Base):
    """Individual message in a Threat Assistant conversation."""

    __tablename__ = "assistant_messages"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assistant_conversations.id"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text, nullable=False)
    citations: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    retrieved_event_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    conversation: Mapped[AssistantConversation] = relationship(
        "AssistantConversation", back_populates="messages"
    )
