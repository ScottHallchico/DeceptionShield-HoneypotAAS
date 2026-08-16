"""Pydantic schemas for API request/response validation.

Matches the unified event schema (section 1.4) and REST endpoint contracts
(section 1.6) from the implementation plan.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

# ─── Shared sub-schemas ──────────────────────────────────────────────────────


class GeoInfo(BaseModel):
    country: str = ""
    city: str = ""
    lat: float = 0.0
    lon: float = 0.0
    asn: str = ""
    org: str = ""


class ReputationInfo(BaseModel):
    abuseipdb_score: int = 0
    known_malicious: bool = False


# ─── Event schemas ───────────────────────────────────────────────────────────


HoneypotTypeEnum = str  # Accept any honeypot type string from the DB
EventTypeEnum = str  # Accept any event type string
TechniqueEnum = str  # Accept any technique string (seed data has free-form names)
SeverityEnum = Literal["low", "medium", "high", "critical"]


class EventBase(BaseModel):
    honeypot_id: str
    honeypot_type: HoneypotTypeEnum
    attacker_ip: str
    event_type: EventTypeEnum
    technique: TechniqueEnum | None = None
    mitre_attck_id: str | None = None
    payload: str | None = None
    session_id: uuid.UUID | None = None
    severity: SeverityEnum = "low"


class EventCreate(EventBase):
    """Raw event from a honeypot, before enrichment."""
    geo: GeoInfo | None = None
    reputation: ReputationInfo | None = None
    timestamp: datetime | None = None


class EventResponse(EventBase):
    """Enriched event returned by the API."""
    id: uuid.UUID
    geo: GeoInfo | None = None
    reputation: ReputationInfo | None = None
    timestamp: datetime
    summary_text: str | None = None

    model_config = {"from_attributes": True}


class EventListResponse(BaseModel):
    """Paginated event list."""
    items: list[EventResponse]
    total: int
    page: int
    page_size: int
    has_more: bool


# ─── Attacker schemas ───────────────────────────────────────────────────────


class AttackerResponse(BaseModel):
    id: uuid.UUID
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_events: int
    honeypots_hit: list[str] = []
    techniques_used: list[str] = []
    geo: GeoInfo | None = None
    reputation: ReputationInfo | None = None
    threat_score: float
    is_blocked: bool
    sessions: list[str] = []

    model_config = {"from_attributes": True}


class AttackerListResponse(BaseModel):
    items: list[AttackerResponse]
    total: int


# ─── Session schemas ────────────────────────────────────────────────────────


class SessionResponse(BaseModel):
    id: uuid.UUID
    attacker_ip: str
    honeypot_id: str
    honeypot_type: str
    started_at: datetime
    ended_at: datetime | None = None
    duration_seconds: float | None = None
    event_count: int
    commands: list[str] | None = None
    tty_log: str | None = None
    terminal_frames: list[dict] = []
    events: list[EventResponse] = []

    model_config = {"from_attributes": True}


# ─── Stats schemas ───────────────────────────────────────────────────────────


class DashboardStats(BaseModel):
    total_events: int = 0
    total_attackers: int = 0
    active_honeypots: int = 0
    blocked_ips: int = 0
    events_last_hour: int = 0
    events_last_24h: int = 0
    top_attacking_countries: list[dict] = []
    top_techniques: list[dict] = []
    severity_breakdown: dict[str, int] = {}
    events_per_honeypot: dict[str, int] = {}
    attack_timeline: list[dict] = []


# ─── Honeypot schemas ───────────────────────────────────────────────────────


HoneypotStatusEnum = Literal["running", "stopped", "deploying", "error"]


class HoneypotInstanceResponse(BaseModel):
    id: str
    type: str
    deployed_at: datetime
    region: str
    status: HoneypotStatusEnum
    ip_address: str | None = None
    last_heartbeat: datetime | None = None
    event_count: int = 0

    model_config = {"from_attributes": True}


class HoneypotRedeployRequest(BaseModel):
    rotate_ip: bool = True


# ─── Blocklist schemas ──────────────────────────────────────────────────────


class BlocklistEntryResponse(BaseModel):
    id: uuid.UUID
    ip: str
    blocked_at: datetime
    expires_at: datetime | None = None
    reason: str
    rule_triggered: str | None = None
    action_taken: str | None = None
    is_active: bool
    midnight_tx_hash: str | None = None
    midnight_attestation_status: str | None = None  # "pending" | "confirmed" | "failed"

    model_config = {"from_attributes": True}


class BlocklistResponse(BaseModel):
    items: list[BlocklistEntryResponse]
    total: int


class UnblockRequest(BaseModel):
    reason: str = "Manual unblock"


# ─── Response Rule schemas ──────────────────────────────────────────────────


class ResponseRuleBase(BaseModel):
    name: str
    description: str | None = None
    event_type: str | None = None
    honeypot_type: str | None = None
    threshold_count: int = 3
    threshold_window_seconds: int = 60
    block_duration_hours: int = 24
    severity_filter: str | None = None
    is_enabled: bool = True


class ResponseRuleCreate(ResponseRuleBase):
    pass


class ResponseRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    event_type: str | None = None
    honeypot_type: str | None = None
    threshold_count: int | None = None
    threshold_window_seconds: int | None = None
    block_duration_hours: int | None = None
    severity_filter: str | None = None
    is_enabled: bool | None = None


class ResponseRuleResponse(ResponseRuleBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ─── Auth schemas ────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ─── AI Assistant schemas (section 1.11 endpoint contract) ───────────────────


class AssistantQueryRequest(BaseModel):
    question: str
    conversation_id: uuid.UUID | None = None


class AssistantCitation(BaseModel):
    label: str
    event_id: str | None = None
    session_id: str | None = None
    attacker_ip: str | None = None


class AssistantMessageResponse(BaseModel):
    id: uuid.UUID
    role: str
    content: str
    citations: list[AssistantCitation] = []
    created_at: datetime


class AssistantQueryResponse(BaseModel):
    conversation_id: uuid.UUID
    retrieved_event_count: int
    message: AssistantMessageResponse


# ─── WebSocket schemas ───────────────────────────────────────────────────────


class LiveEventMessage(BaseModel):
    """Message pushed over WebSocket /ws/live."""
    type: Literal["event", "stats_heartbeat"] = "event"
    data: EventResponse | DashboardStats
