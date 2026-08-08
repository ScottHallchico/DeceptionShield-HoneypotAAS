"""Unit tests for the response engine rule evaluation — section 1.10."""

from __future__ import annotations

import ipaddress

import pytest


class TestAllowlistCheck:
    """Tests for IP allowlist logic."""

    def test_ip_in_cidr_range(self):
        """Test that an IP within a CIDR range is recognized."""
        network = ipaddress.ip_network("10.0.0.0/8", strict=False)
        ip = ipaddress.ip_address("10.0.1.5")
        assert ip in network

    def test_ip_not_in_cidr_range(self):
        """Test that an IP outside a CIDR range is not matched."""
        network = ipaddress.ip_network("10.0.0.0/8", strict=False)
        ip = ipaddress.ip_address("192.168.1.1")
        assert ip not in network

    def test_exact_ip_match(self):
        """Test exact IP matching (single host CIDR)."""
        network = ipaddress.ip_network("203.0.113.5/32", strict=False)
        ip = ipaddress.ip_address("203.0.113.5")
        assert ip in network

    def test_exact_ip_no_match(self):
        network = ipaddress.ip_network("203.0.113.5/32", strict=False)
        ip = ipaddress.ip_address("203.0.113.6")
        assert ip not in network


class TestThreatScoring:
    """Tests for threat score calculation."""

    def test_score_components(self):
        """Verify that each score component contributes correctly."""
        from app.services.log_shipping.consumer import _calculate_threat_score

        class MockAttacker:
            total_events = 10
            honeypots_hit = ["cowrie-01", "wp-decoy-01", "rdp-decoy-01"]
            techniques_used = ["brute_force", "credential_reuse"]
            reputation = {"abuseipdb_score": 80}

        attacker = MockAttacker()
        score = _calculate_threat_score(attacker)

        # Volume: min(30, 10*2) = 20
        # Breadth: min(20, 3*5) = 15
        # Technique: min(20, 2*4) = 8
        # Reputation: min(30, 80*0.3) = 24
        expected = 20 + 15 + 8 + 24
        assert score == pytest.approx(expected, abs=0.1)

    def test_score_caps_at_100(self):
        from app.services.log_shipping.consumer import _calculate_threat_score

        class MockAttacker:
            total_events = 1000
            honeypots_hit = ["a", "b", "c", "d", "e"]
            techniques_used = ["t1", "t2", "t3", "t4", "t5", "t6"]
            reputation = {"abuseipdb_score": 100}

        score = _calculate_threat_score(MockAttacker())
        assert score == 100.0

    def test_score_zero_baseline(self):
        from app.services.log_shipping.consumer import _calculate_threat_score

        class MockAttacker:
            total_events = 0
            honeypots_hit = []
            techniques_used = []
            reputation = {}

        score = _calculate_threat_score(MockAttacker())
        assert score == 0.0
