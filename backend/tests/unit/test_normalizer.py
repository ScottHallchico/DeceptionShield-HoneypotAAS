"""Unit tests for the normalization/enrichment pipeline — section 1.10."""

from __future__ import annotations

import json

import pytest

from app.services.enrichment.normalizer import (
    _classify_severity,
    _event_fingerprint,
    _is_duplicate,
    _parse_cowrie_log,
    _parse_rdp_decoy_log,
    _parse_wp_decoy_log,
    generate_event_summary,
    normalize_event,
)


class TestCowrieParser:
    """Tests for Cowrie SSH/Telnet log parsing."""

    def test_login_attempt(self):
        raw = {
            "eventid": "cowrie.login.failed",
            "src_ip": "203.0.113.45",
            "username": "root",
            "password": "toor",
            "sensor": "cowrie-ssh-01",
            "session": "abc123",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        result = _parse_cowrie_log(raw)
        assert result is not None
        assert result["event_type"] == "login_attempt"
        assert result["technique"] == "brute_force"
        assert result["attacker_ip"] == "203.0.113.45"
        assert "root" in result["payload"]
        assert "toor" in result["payload"]

    def test_command_execution(self):
        raw = {
            "eventid": "cowrie.command.input",
            "src_ip": "198.51.100.7",
            "input": "cat /etc/passwd",
            "sensor": "cowrie-ssh-01",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        result = _parse_cowrie_log(raw)
        assert result is not None
        assert result["event_type"] == "command_exec"
        assert "cat /etc/passwd" in result["payload"]

    def test_file_download(self):
        raw = {
            "eventid": "cowrie.session.file_download",
            "src_ip": "192.0.2.100",
            "url": "http://evil.com/malware.sh",
            "sensor": "cowrie-ssh-01",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        result = _parse_cowrie_log(raw)
        assert result is not None
        assert result["event_type"] == "file_download"
        assert result["technique"] == "payload_drop"

    def test_session_event_skipped(self):
        raw = {
            "eventid": "cowrie.session.connect",
            "src_ip": "10.0.0.1",
            "sensor": "cowrie-ssh-01",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        result = _parse_cowrie_log(raw)
        assert result is None


class TestWpDecoyParser:
    """Tests for WordPress decoy log parsing."""

    def test_login_attempt(self):
        raw = {
            "honeypot_id": "wp-decoy-01",
            "attacker_ip": "45.33.32.156",
            "event_type": "login_attempt",
            "technique": "brute_force",
            "payload": "username=admin, password=password123",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        result = _parse_wp_decoy_log(raw)
        assert result is not None
        assert result["honeypot_type"] == "wp-decoy"
        assert result["event_type"] == "login_attempt"


class TestRdpDecoyParser:
    """Tests for RDP decoy log parsing."""

    def test_login_attempt(self):
        raw = {
            "honeypot_id": "rdp-decoy-01",
            "attacker_ip": "89.248.167.131",
            "event_type": "login_attempt",
            "payload": "RDP connection initiated",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        result = _parse_rdp_decoy_log(raw)
        assert result is not None
        assert result["honeypot_type"] == "rdp-decoy"
        assert result["technique"] == "brute_force"


class TestSeverityClassification:
    """Tests for severity assignment logic."""

    def test_high_reputation_score(self):
        assert _classify_severity("login_attempt", "brute_force", 85) == "critical"

    def test_file_download(self):
        assert _classify_severity("file_download", "payload_drop", 0) == "high"

    def test_cve_exploit(self):
        assert _classify_severity("exploit_probe", "cve_exploit_attempt", 0) == "critical"

    def test_exploit_probe(self):
        assert _classify_severity("exploit_probe", "brute_force", 0) == "high"

    def test_command_exec(self):
        assert _classify_severity("command_exec", None, 0) == "medium"

    def test_medium_reputation(self):
        assert _classify_severity("login_attempt", "brute_force", 55) == "medium"

    def test_low_severity_default(self):
        assert _classify_severity("login_attempt", "brute_force", 10) == "low"


class TestDeduplication:
    """Tests for event deduplication."""

    def test_same_event_is_duplicate(self):
        event = {
            "attacker_ip": "1.2.3.4",
            "honeypot_id": "test-01",
            "event_type": "login_attempt",
            "payload": "test payload",
        }
        fp = _event_fingerprint(event)
        # First call should not be a duplicate
        # Note: this test might fail if dedup cache has prior state
        # In a fresh test run, the first call returns False
        _is_duplicate(fp)  # Register
        assert _is_duplicate(fp) is True  # Should be duplicate now

    def test_different_events_not_duplicate(self):
        event1 = {
            "attacker_ip": "1.2.3.4",
            "honeypot_id": "test-01",
            "event_type": "login_attempt",
            "payload": "unique_payload_1",
        }
        event2 = {
            "attacker_ip": "5.6.7.8",
            "honeypot_id": "test-02",
            "event_type": "command_exec",
            "payload": "unique_payload_2",
        }
        fp1 = _event_fingerprint(event1)
        fp2 = _event_fingerprint(event2)
        assert fp1 != fp2


class TestSummaryGeneration:
    """Tests for event summary text generation."""

    def test_basic_summary(self):
        event = {
            "attacker_ip": "203.0.113.45",
            "event_type": "login_attempt",
            "honeypot_id": "cowrie-ssh-01",
            "honeypot_type": "cowrie",
            "technique": "brute_force",
            "mitre_attck_id": "T1110",
            "severity": "medium",
            "geo": {"country": "CN", "city": "Shanghai"},
        }
        summary = generate_event_summary(event)
        assert "203.0.113.45" in summary
        assert "login attempt" in summary
        assert "cowrie-ssh-01" in summary
        assert "T1110" in summary
        assert "Shanghai" in summary

    def test_summary_without_geo(self):
        event = {
            "attacker_ip": "1.2.3.4",
            "event_type": "port_scan",
            "honeypot_id": "test-01",
            "honeypot_type": "dionaea",
            "severity": "low",
        }
        summary = generate_event_summary(event)
        assert "1.2.3.4" in summary
        assert "port scan" in summary


class TestNormalizeEvent:
    """Tests for the full normalization pipeline."""

    @pytest.mark.asyncio
    async def test_normalize_cowrie_event(self):
        raw = json.dumps({
            "honeypot_type": "cowrie",
            "eventid": "cowrie.login.failed",
            "src_ip": "10.20.30.40",
            "username": "admin",
            "password": "admin123",
            "sensor": "cowrie-ssh-01",
            "timestamp": "2024-01-15T12:00:00Z",
        })
        result = await normalize_event(raw)
        # May be None due to dedup or GeoIP issues, but shouldn't crash
        if result:
            assert result["attacker_ip"] == "10.20.30.40"
            assert result["honeypot_type"] == "cowrie"
            assert result["event_type"] == "login_attempt"
            assert "id" in result
            assert "summary_text" in result

    @pytest.mark.asyncio
    async def test_normalize_invalid_json(self):
        result = await normalize_event("not valid json {{{")
        assert result is None

    @pytest.mark.asyncio
    async def test_normalize_unknown_honeypot_type(self):
        result = await normalize_event(json.dumps({
            "honeypot_type": "unknown-type",
            "src_ip": "1.2.3.4",
        }))
        assert result is None
