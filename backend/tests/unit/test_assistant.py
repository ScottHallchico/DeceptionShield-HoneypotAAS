"""Unit tests for the AI Threat Assistant intent parsing — section 1.10."""

from __future__ import annotations

from app.services.assistant.assistant import parse_intent


class TestIntentParsing:
    """Tests for natural-language question → structured intent extraction."""

    def test_ip_extraction(self):
        intent = parse_intent("What has 203.0.113.45 been doing?")
        assert intent["ip"] == "203.0.113.45"

    def test_honeypot_cowrie(self):
        intent = parse_intent("How many attacks hit cowrie?")
        assert intent["honeypot_type"] == "cowrie"

    def test_honeypot_wordpress(self):
        intent = parse_intent("Any login attempts on the WordPress decoy?")
        assert intent["honeypot_type"] == "wp-decoy"

    def test_honeypot_rdp(self):
        intent = parse_intent("What's happening on the RDP decoy?")
        assert intent["honeypot_type"] == "rdp-decoy"

    def test_honeypot_smb(self):
        intent = parse_intent("Show me SMB decoy events")
        assert intent["honeypot_type"] == "smb-decoy"

    def test_severity_critical(self):
        intent = parse_intent("Show me all critical events")
        assert intent["severity"] == "critical"

    def test_severity_high(self):
        intent = parse_intent("Any high severity alerts today?")
        assert intent["severity"] == "high"

    def test_technique_brute_force(self):
        intent = parse_intent("How many brute force attempts?")
        assert intent["technique"] == "brute_force"

    def test_technique_exploit(self):
        intent = parse_intent("Any CVE exploit attempts detected?")
        assert intent["technique"] == "cve_exploit_attempt"

    def test_time_window_hours(self):
        intent = parse_intent("What happened in the last 3 hours?")
        assert intent["time_window"] == {"hours": 3}

    def test_time_window_minutes(self):
        intent = parse_intent("Events in the last 30 minutes")
        assert intent["time_window"] == {"minutes": 30}

    def test_time_window_days(self):
        intent = parse_intent("Show events from the last 7 days")
        assert intent["time_window"] == {"days": 7}

    def test_time_window_last_hour(self):
        intent = parse_intent("What's hit us in the last hour?")
        assert intent["time_window"] == {"hours": 1}

    def test_count_query_type(self):
        intent = parse_intent("How many login attempts in the last hour?")
        assert intent["query_type"] == "count"

    def test_top_n_query_type(self):
        intent = parse_intent("Which are the top attacking IPs?")
        assert intent["query_type"] == "top_n"

    def test_anomaly_query_type(self):
        intent = parse_intent("Anything unusual happening today?")
        assert intent["query_type"] == "anomaly"

    def test_summary_query_type(self):
        intent = parse_intent("Give me an overview of the situation")
        assert intent["query_type"] == "summary"

    def test_combined_intent(self):
        intent = parse_intent("How many critical brute force attempts hit the RDP decoy in the last 2 hours?")
        assert intent["severity"] == "critical"
        assert intent["technique"] == "brute_force"
        assert intent["honeypot_type"] == "rdp-decoy"
        assert intent["time_window"] == {"hours": 2}
        assert intent["query_type"] == "count"

    def test_ip_and_honeypot(self):
        intent = parse_intent("What has 192.0.2.100 done to cowrie?")
        assert intent["ip"] == "192.0.2.100"
        assert intent["honeypot_type"] == "cowrie"

    def test_no_structured_intent(self):
        intent = parse_intent("Tell me something interesting")
        assert "ip" not in intent
        assert "honeypot_type" not in intent
        assert "severity" not in intent
        assert intent["query_type"] == "general"
