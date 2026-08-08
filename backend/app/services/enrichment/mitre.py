"""MITRE ATT&CK technique mapping for honeypot events.

Per the implementation plan (section 1.4): a lookup table matching Cowrie
command patterns to common ATT&CK techniques — small addition with
disproportionate credibility payoff.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ─── MITRE ATT&CK technique definitions ─────────────────────────────────────


@dataclass(frozen=True)
class MitreTechnique:
    id: str
    name: str
    tactic: str


TECHNIQUES = {
    "T1110": MitreTechnique("T1110", "Brute Force", "Credential Access"),
    "T1110.001": MitreTechnique("T1110.001", "Password Guessing", "Credential Access"),
    "T1110.003": MitreTechnique("T1110.003", "Password Spraying", "Credential Access"),
    "T1078": MitreTechnique("T1078", "Valid Accounts", "Defense Evasion"),
    "T1059": MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1059.004": MitreTechnique("T1059.004", "Unix Shell", "Execution"),
    "T1105": MitreTechnique("T1105", "Ingress Tool Transfer", "Command and Control"),
    "T1190": MitreTechnique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "T1046": MitreTechnique("T1046", "Network Service Discovery", "Discovery"),
    "T1021": MitreTechnique("T1021", "Remote Services", "Lateral Movement"),
    "T1021.001": MitreTechnique("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": MitreTechnique("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": MitreTechnique("T1021.004", "SSH", "Lateral Movement"),
    "T1071": MitreTechnique("T1071", "Application Layer Protocol", "Command and Control"),
    "T1571": MitreTechnique("T1571", "Non-Standard Port", "Command and Control"),
    "T1027": MitreTechnique("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    "T1053": MitreTechnique("T1053", "Scheduled Task/Job", "Execution"),
    "T1053.003": MitreTechnique("T1053.003", "Cron", "Execution"),
    "T1082": MitreTechnique("T1082", "System Information Discovery", "Discovery"),
    "T1083": MitreTechnique("T1083", "File and Directory Discovery", "Discovery"),
    "T1057": MitreTechnique("T1057", "Process Discovery", "Discovery"),
    "T1562": MitreTechnique("T1562", "Impair Defenses", "Defense Evasion"),
    "T1070": MitreTechnique("T1070", "Indicator Removal", "Defense Evasion"),
}


# ─── Pattern → Technique mappings ───────────────────────────────────────────

# Command patterns observed in Cowrie sessions
COMMAND_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # File downloads → T1105 Ingress Tool Transfer
    (re.compile(r"\b(wget|curl|tftp|scp|ftp)\b", re.I), "T1105", "payload_drop"),

    # Encoded/obfuscated payloads → T1027 Obfuscated Files (before shell interpreter — more specific)
    (re.compile(r"\b(base64|xxd|openssl\s+enc)\b", re.I), "T1027", "credential_reuse"),

    # Package/binary execution → T1059 Command Interpreter
    (re.compile(r"\b(sh|bash|python|perl|ruby|php|node)\b", re.I), "T1059.004", "credential_reuse"),

    # System enumeration → T1082 System Info Discovery
    (
        re.compile(r"\b(uname|cat\s+/etc/(os-release|issue|passwd)|hostname|id|whoami)\b", re.I),
        "T1082",
        "credential_reuse",
    ),

    # Process listing → T1057 Process Discovery
    (re.compile(r"\b(ps\s|top\b|htop)\b", re.I), "T1057", "credential_reuse"),

    # File system browsing → T1083 File/Directory Discovery
    (re.compile(r"\b(ls|find|locate|dir)\b", re.I), "T1083", "credential_reuse"),

    # Crontab manipulation → T1053.003 Cron
    (re.compile(r"\bcrontab\b|/etc/cron", re.I), "T1053.003", "credential_reuse"),

    # Defense evasion — history/log deletion → T1070 Indicator Removal
    (re.compile(r"\b(history\s+-c|rm\s+.*\.(log|bash_history)|unset\s+HISTFILE)\b", re.I), "T1070", "credential_reuse"),

    # Firewall manipulation → T1562 Impair Defenses
    (re.compile(r"\b(iptables|ufw|firewall-cmd|setenforce)\b", re.I), "T1562", "credential_reuse"),
]

# Event-type → Technique mappings (for non-Cowrie honeypots)
EVENT_TYPE_MAPPINGS: dict[str, dict[str, str]] = {
    "login_attempt": {
        "cowrie": "T1110",      # Brute Force (SSH/Telnet)
        "wp-decoy": "T1110",    # Brute Force (WordPress)
        "rdp-decoy": "T1110",   # Brute Force (RDP)
        "default": "T1110",
    },
    "exploit_probe": {
        "dionaea": "T1190",     # Exploit Public-Facing Application
        "wp-decoy": "T1190",
        "default": "T1190",
    },
    "file_download": {
        "default": "T1105",     # Ingress Tool Transfer
    },
    "port_scan": {
        "default": "T1046",     # Network Service Discovery
    },
    "command_exec": {
        "default": "T1059",     # Command and Scripting Interpreter
    },
}

# Honeypot type → base technique (for session-level classification)
HONEYPOT_SESSION_TECHNIQUES: dict[str, str] = {
    "cowrie": "T1021.004",      # SSH Remote Services
    "rdp-decoy": "T1021.001",   # RDP Remote Services
    "smb-decoy": "T1021.002",   # SMB Remote Services
    "dionaea": "T1190",         # Exploit Public-Facing Application
    "wp-decoy": "T1190",        # Exploit Public-Facing Application
}


def classify_command(command: str) -> tuple[str | None, str | None]:
    """Classify a shell command to a MITRE ATT&CK technique.

    Returns (mitre_attck_id, technique_name) or (None, None) if unclassified.
    """
    for pattern, technique_id, technique_label in COMMAND_PATTERNS:
        if pattern.search(command):
            tech = TECHNIQUES.get(technique_id)
            return technique_id, technique_label if not tech else technique_label
    return None, None


def classify_event(
    event_type: str,
    honeypot_type: str,
    payload: str | None = None,
) -> tuple[str | None, str | None]:
    """Classify an event to a MITRE ATT&CK technique based on event type and honeypot.

    If the event is a command_exec with a payload, also tries command-level
    classification for finer granularity.

    Returns (mitre_attck_id, technique_label).
    """
    # For command execution events with payload, try command-level first
    if event_type == "command_exec" and payload:
        mitre_id, technique = classify_command(payload)
        if mitre_id:
            return mitre_id, technique

    # Fall back to event-type × honeypot-type mapping
    type_map = EVENT_TYPE_MAPPINGS.get(event_type, {})
    mitre_id = type_map.get(honeypot_type, type_map.get("default"))

    if mitre_id:
        tech = TECHNIQUES.get(mitre_id)
        return mitre_id, tech.name if tech else None

    return None, None


def get_technique_info(mitre_id: str) -> MitreTechnique | None:
    """Look up full technique info by MITRE ATT&CK ID."""
    return TECHNIQUES.get(mitre_id)
