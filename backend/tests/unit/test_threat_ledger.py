"""Unit tests for the Midnight threat ledger pure logic.

Covers:
  - compute_indicator_hash: deterministic, same input → same hash
  - compute_severity_score: correct mapping per severity string
  - Bridge request/response shape validation
"""

from __future__ import annotations

import hashlib
import os
import sys

import pytest

# Ensure backend app is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.midnight.threat_ledger import (
    compute_indicator_hash,
    compute_severity_score,
)


# ─── compute_indicator_hash ─────────────────────────────────────────────────


class TestComputeIndicatorHash:
    """Tests for the one-way IP → hash function."""

    def test_deterministic_same_input(self):
        """Same IP + same salt → identical hash every time."""
        h1 = compute_indicator_hash("203.0.113.45", salt="test-salt-abc")
        h2 = compute_indicator_hash("203.0.113.45", salt="test-salt-abc")
        assert h1 == h2

    def test_deterministic_across_calls(self):
        """Calling 100 times with the same input yields the same hash."""
        hashes = {compute_indicator_hash("10.0.0.1", salt="s") for _ in range(100)}
        assert len(hashes) == 1

    def test_different_ips_different_hashes(self):
        """Different IPs with the same salt produce different hashes."""
        h1 = compute_indicator_hash("192.168.1.1", salt="salt")
        h2 = compute_indicator_hash("192.168.1.2", salt="salt")
        assert h1 != h2

    def test_different_salts_different_hashes(self):
        """Same IP with different salts produces different hashes."""
        h1 = compute_indicator_hash("10.0.0.1", salt="salt-a")
        h2 = compute_indicator_hash("10.0.0.1", salt="salt-b")
        assert h1 != h2

    def test_output_format(self):
        """Output is a 64-character lowercase hex string (SHA-256)."""
        h = compute_indicator_hash("1.2.3.4", salt="x")
        assert len(h) == 64
        assert h == h.lower()
        assert all(c in "0123456789abcdef" for c in h)

    def test_matches_manual_sha256(self):
        """Output matches a manually computed SHA-256 of 'ip+salt'."""
        ip = "198.51.100.7"
        salt = "my-salt"
        expected = hashlib.sha256(f"{ip}{salt}".encode("utf-8")).hexdigest()
        assert compute_indicator_hash(ip, salt=salt) == expected

    def test_empty_ip(self):
        """Empty IP still produces a valid hash (edge case)."""
        h = compute_indicator_hash("", salt="salt")
        assert len(h) == 64

    def test_ipv6(self):
        """IPv6 addresses are hashable too."""
        h = compute_indicator_hash("2001:db8::1", salt="salt")
        assert len(h) == 64


# ─── compute_severity_score ──────────────────────────────────────────────────


class TestComputeSeverityScore:
    """Tests for severity string → numeric score mapping."""

    def test_low(self):
        assert compute_severity_score("low") == 20

    def test_medium(self):
        assert compute_severity_score("medium") == 50

    def test_high(self):
        assert compute_severity_score("high") == 75

    def test_critical(self):
        assert compute_severity_score("critical") == 95

    def test_case_insensitive(self):
        """Severity strings are case-insensitive."""
        assert compute_severity_score("LOW") == 20
        assert compute_severity_score("Critical") == 95
        assert compute_severity_score("MEDIUM") == 50
        assert compute_severity_score("High") == 75

    def test_unknown_defaults_to_low(self):
        """Unknown severity strings default to 20 (low)."""
        assert compute_severity_score("unknown") == 20
        assert compute_severity_score("") == 20

    def test_high_confidence_threshold(self):
        """Only 'high' (75) and 'critical' (95) clear the ≥70 threshold
        used in the Compact contract for highConfidenceCount."""
        assert compute_severity_score("low") < 70
        assert compute_severity_score("medium") < 70
        assert compute_severity_score("high") >= 70
        assert compute_severity_score("critical") >= 70


# ─── Bridge request/response shape validation ───────────────────────────────


class TestBridgeRequestShapes:
    """Validate the expected request/response shapes for bridge API calls."""

    def test_attest_request_shape(self):
        """The attest endpoint expects indicatorHash (64-char hex) + severityScore (0-100)."""
        indicator_hash = compute_indicator_hash("1.2.3.4", salt="salt")
        severity_score = compute_severity_score("high")

        # Shape that would be sent to POST /attest
        request_body = {
            "indicatorHash": indicator_hash,
            "severityScore": severity_score,
        }

        assert isinstance(request_body["indicatorHash"], str)
        assert len(request_body["indicatorHash"]) == 64
        assert isinstance(request_body["severityScore"], int)
        assert 0 <= request_body["severityScore"] <= 100

    def test_attest_response_shape(self):
        """The attest endpoint returns txHash (string) + status (string)."""
        # Simulate a successful response
        response = {"txHash": "0x" + "a" * 64, "status": "confirmed"}

        assert isinstance(response["txHash"], str)
        assert response["status"] in ("confirmed", "pending", "failed")

    def test_query_response_shape(self):
        """The query endpoint returns corroborationCount + highConfidenceCount."""
        response = {"corroborationCount": 3, "highConfidenceCount": 2}

        assert isinstance(response["corroborationCount"], int)
        assert isinstance(response["highConfidenceCount"], int)
        assert response["corroborationCount"] >= response["highConfidenceCount"]

    def test_stats_response_shape(self):
        """The stats endpoint returns totalAttestations + uniqueIndicators + networkMode."""
        response = {
            "totalAttestations": 42,
            "uniqueIndicators": 17,
            "networkMode": "simulate",
        }

        assert isinstance(response["totalAttestations"], int)
        assert isinstance(response["uniqueIndicators"], int)
        assert isinstance(response["networkMode"], str)
