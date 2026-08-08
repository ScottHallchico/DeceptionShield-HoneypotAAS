"""Core configuration — loads all settings from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings sourced from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://honeypot:honeypot_secret@localhost:5432/honeypot_db"
    database_sync_url: str = "postgresql://honeypot:honeypot_secret@localhost:5432/honeypot_db"

    # ── Kafka ─────────────────────────────────────────────────
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_raw_topic: str = "raw-honeypot-events"
    kafka_normalized_topic: str = "normalized-events"
    kafka_consumer_group: str = "honeypot-normalizer"

    # ── Auth ──────────────────────────────────────────────────
    jwt_secret_key: str = "CHANGE_ME"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # ── GeoIP ─────────────────────────────────────────────────
    maxmind_db_path: str = "./data/GeoLite2-City.mmdb"
    maxmind_asn_db_path: str = "./data/GeoLite2-ASN.mmdb"
    maxmind_license_key: str = ""

    # ── AbuseIPDB ─────────────────────────────────────────────
    abuseipdb_api_key: str = ""

    # ── AWS ────────────────────────────────────────────────────
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_default_region: str = "us-east-1"
    aws_security_group_id: str = ""

    # ── pfSense ───────────────────────────────────────────────
    pfsense_api_url: str = ""
    pfsense_api_key: str = ""
    pfsense_api_secret: str = ""

    # ── AI / Embeddings ───────────────────────────────────────
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    embedding_model: str = "text-embedding-3-small"
    claude_model: str = "claude-sonnet-4-20250514"

    # ── Alerting ──────────────────────────────────────────────
    slack_webhook_url: str = ""
    alert_email_smtp_host: str = ""
    alert_email_smtp_port: int = 587
    alert_email_from: str = ""
    alert_email_to: str = ""
    alert_email_password: str = ""

    # ── Application ───────────────────────────────────────────
    app_env: Literal["development", "staging", "production"] = "development"
    app_debug: bool = True
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    log_level: str = "INFO"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
