"""Automated response engine — section 1.7 of the implementation plan.

Rule evaluation service that:
1. Evaluates configurable threshold-based rules against incoming events
2. On rule trigger: blocks the IP via AWS Security Group + pfSense
3. Maintains audit trail and TTL-based expiry
4. Checks allowlist before blocking to prevent self-lockout
"""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import async_session_factory
from app.models.models import Allowlist, Attacker, BlocklistEntry, Event, ResponseRule

log = get_logger(__name__)


# ─── Allowlist check ─────────────────────────────────────────────────────────


async def is_allowlisted(ip: str) -> bool:
    """Check if an IP is in the allowlist (office ranges, known partners)."""
    async with async_session_factory() as session:
        result = await session.execute(select(Allowlist))
        allowlist_entries = result.scalars().all()

        try:
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for entry in allowlist_entries:
            try:
                network = ipaddress.ip_network(entry.ip_cidr, strict=False)
                if ip_addr in network:
                    log.info("ip_allowlisted", ip=ip, allowlist_entry=entry.ip_cidr)
                    return True
            except ValueError:
                continue

        return False


# ─── AWS Security Group blocking ─────────────────────────────────────────────


async def block_via_aws_sg(ip: str) -> str | None:
    """Block an IP by revoking/authorizing AWS Security Group ingress rules.

    Returns the Security Group rule description for audit trail, or None on failure.
    """
    settings = get_settings()
    if not settings.aws_security_group_id or not settings.aws_access_key_id:
        log.debug("aws_sg_not_configured")
        return None

    try:
        import boto3

        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            region_name=settings.aws_default_region,
        )

        # Add a deny rule (in practice, revoke the IP's access)
        ec2.authorize_security_group_ingress(
            GroupId=settings.aws_security_group_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",  # All protocols
                    "IpRanges": [
                        {
                            "CidrIp": f"{ip}/32",
                            "Description": f"HoneypotAAS auto-block: {ip}",
                        }
                    ],
                }
            ],
        )

        rule_id = f"sg-rule:{settings.aws_security_group_id}:{ip}/32"
        log.info("aws_sg_blocked", ip=ip, sg_id=settings.aws_security_group_id)
        return rule_id

    except Exception as exc:
        log.error("aws_sg_block_failed", ip=ip, error=str(exc))
        return None


async def unblock_via_aws_sg(ip: str) -> bool:
    """Remove an AWS Security Group block rule for an IP."""
    settings = get_settings()
    if not settings.aws_security_group_id or not settings.aws_access_key_id:
        return False

    try:
        import boto3

        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            region_name=settings.aws_default_region,
        )

        ec2.revoke_security_group_ingress(
            GroupId=settings.aws_security_group_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": f"{ip}/32"}],
                }
            ],
        )

        log.info("aws_sg_unblocked", ip=ip)
        return True

    except Exception as exc:
        log.error("aws_sg_unblock_failed", ip=ip, error=str(exc))
        return False


# ─── pfSense blocking ───────────────────────────────────────────────────────


async def block_via_pfsense(ip: str) -> str | None:
    """Block an IP via pfSense REST API.

    Returns the pfSense rule ID for audit trail, or None on failure.
    """
    settings = get_settings()
    if not settings.pfsense_api_url or not settings.pfsense_api_key:
        log.debug("pfsense_not_configured")
        return None

    try:
        import httpx

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.post(
                f"{settings.pfsense_api_url}/firewall/rule",
                headers={
                    "Authorization": f"{settings.pfsense_api_key} {settings.pfsense_api_secret}",
                    "Content-Type": "application/json",
                },
                json={
                    "type": "block",
                    "interface": "wan",
                    "ipprotocol": "inet",
                    "protocol": "any",
                    "src": ip,
                    "srcmask": 32,
                    "dst": "any",
                    "descr": f"HoneypotAAS auto-block: {ip}",
                    "top": True,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            rule_id = f"pfsense-rule:{data.get('data', {}).get('tracker', 'unknown')}"
            log.info("pfsense_blocked", ip=ip, rule_id=rule_id)
            return rule_id

    except Exception as exc:
        log.error("pfsense_block_failed", ip=ip, error=str(exc))
        return None


async def unblock_via_pfsense(ip: str) -> bool:
    """Remove a pfSense block rule for an IP."""
    settings = get_settings()
    if not settings.pfsense_api_url or not settings.pfsense_api_key:
        return False

    try:
        import httpx

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # List rules to find the one matching this IP
            resp = await client.get(
                f"{settings.pfsense_api_url}/firewall/rule",
                headers={
                    "Authorization": f"{settings.pfsense_api_key} {settings.pfsense_api_secret}",
                },
            )
            resp.raise_for_status()
            rules = resp.json().get("data", [])

            for rule in rules:
                if rule.get("src") == ip and "HoneypotAAS" in rule.get("descr", ""):
                    tracker = rule.get("tracker")
                    if tracker:
                        del_resp = await client.delete(
                            f"{settings.pfsense_api_url}/firewall/rule",
                            headers={
                                "Authorization": f"{settings.pfsense_api_key} {settings.pfsense_api_secret}",
                            },
                            params={"tracker": tracker},
                        )
                        del_resp.raise_for_status()
                        log.info("pfsense_unblocked", ip=ip, tracker=tracker)
                        return True

        return False

    except Exception as exc:
        log.error("pfsense_unblock_failed", ip=ip, error=str(exc))
        return False


# ─── Rule evaluation engine ─────────────────────────────────────────────────


async def evaluate_rules(event: dict[str, Any]) -> None:
    """Evaluate all enabled response rules against an incoming event.

    If a rule triggers (threshold exceeded), block the attacker's IP.
    """
    attacker_ip = event.get("attacker_ip", "")
    if not attacker_ip:
        return

    # Safety: check allowlist first
    if await is_allowlisted(attacker_ip):
        return

    # Check if already blocked
    async with async_session_factory() as session:
        existing_block = await session.execute(
            select(BlocklistEntry).where(
                BlocklistEntry.ip == attacker_ip,
                BlocklistEntry.is_active,
            )
        )
        if existing_block.scalar_one_or_none():
            return  # Already blocked

        # Load enabled rules
        rules_result = await session.execute(
            select(ResponseRule).where(ResponseRule.is_enabled)
        )
        rules = rules_result.scalars().all()

    for rule in rules:
        # Check if this rule applies to this event type/honeypot
        if rule.event_type and rule.event_type != event.get("event_type"):
            continue
        if rule.honeypot_type and rule.honeypot_type != event.get("honeypot_type"):
            continue
        if rule.severity_filter and rule.severity_filter != event.get("severity"):
            continue

        # Count events from this IP within the rule's time window
        window_start = datetime.now(UTC) - timedelta(seconds=rule.threshold_window_seconds)

        async with async_session_factory() as session:
            count_query = select(func.count(Event.id)).where(
                Event.attacker_ip == attacker_ip,
                Event.timestamp >= window_start,
            )
            if rule.event_type:
                count_query = count_query.where(Event.event_type == rule.event_type)
            if rule.honeypot_type:
                count_query = count_query.where(Event.honeypot_type == rule.honeypot_type)

            count = (await session.execute(count_query)).scalar() or 0

        if count >= rule.threshold_count:
            log.info(
                "rule_triggered",
                rule_name=rule.name,
                ip=attacker_ip,
                count=count,
                threshold=rule.threshold_count,
            )
            await block_ip(
                ip=attacker_ip,
                reason=(
                    f"Rule '{rule.name}' triggered: {count} events in "
                    f"{rule.threshold_window_seconds}s (threshold: {rule.threshold_count})"
                ),
                rule_name=rule.name,
                duration_hours=rule.block_duration_hours,
            )
            break  # One block per event evaluation


async def block_ip(
    ip: str,
    reason: str,
    rule_name: str | None = None,
    duration_hours: int = 24,
) -> BlocklistEntry | None:
    """Block an IP: write to blocklist, call AWS SG + pfSense APIs."""
    # Safety check
    if await is_allowlisted(ip):
        log.warning("block_prevented_allowlist", ip=ip)
        return None

    # Execute blocks in parallel
    sg_result, pf_result = await asyncio.gather(
        block_via_aws_sg(ip),
        block_via_pfsense(ip),
        return_exceptions=True,
    )

    actions = []
    if isinstance(sg_result, str):
        actions.append(sg_result)
    if isinstance(pf_result, str):
        actions.append(pf_result)

    # Write blocklist entry
    now = datetime.now(UTC)
    async with async_session_factory() as session:
        entry = BlocklistEntry(
            ip=ip,
            blocked_at=now,
            expires_at=now + timedelta(hours=duration_hours),
            reason=reason,
            rule_triggered=rule_name,
            action_taken="; ".join(actions) if actions else "no external actions taken",
            is_active=True,
        )
        session.add(entry)

        # Update attacker record
        result = await session.execute(select(Attacker).where(Attacker.ip == ip))
        attacker = result.scalar_one_or_none()
        if attacker:
            attacker.is_blocked = True

        await session.commit()
        await session.refresh(entry)

    # Send alert
    await _send_block_alert(ip, reason, rule_name)

    log.info("ip_blocked", ip=ip, reason=reason, expires_at=entry.expires_at.isoformat())
    return entry


async def unblock_ip(ip: str, unblocked_by: str = "system") -> bool:
    """Unblock an IP: update blocklist, remove AWS SG + pfSense rules."""
    # Remove external blocks in parallel
    await asyncio.gather(
        unblock_via_aws_sg(ip),
        unblock_via_pfsense(ip),
        return_exceptions=True,
    )

    async with async_session_factory() as session:
        result = await session.execute(
            select(BlocklistEntry).where(
                BlocklistEntry.ip == ip,
                BlocklistEntry.is_active,
            )
        )
        entries = result.scalars().all()

        for entry in entries:
            entry.is_active = False
            entry.unblocked_at = datetime.now(UTC)
            entry.unblocked_by = unblocked_by

        # Update attacker record
        attacker_result = await session.execute(select(Attacker).where(Attacker.ip == ip))
        attacker = attacker_result.scalar_one_or_none()
        if attacker:
            attacker.is_blocked = False

        await session.commit()

    log.info("ip_unblocked", ip=ip, by=unblocked_by)
    return True


async def expire_blocks() -> int:
    """Expire blocks past their TTL. Returns count of expired blocks."""
    now = datetime.now(UTC)
    expired_count = 0

    async with async_session_factory() as session:
        result = await session.execute(
            select(BlocklistEntry).where(
                BlocklistEntry.is_active,
                BlocklistEntry.expires_at <= now,
            )
        )
        expired = result.scalars().all()

        for entry in expired:
            await unblock_ip(entry.ip, unblocked_by="ttl_expiry")
            expired_count += 1

    if expired_count:
        log.info("blocks_expired", count=expired_count)

    return expired_count


# ─── Alerting ────────────────────────────────────────────────────────────────


async def _send_block_alert(ip: str, reason: str, rule_name: str | None) -> None:
    """Send alert on block action (Slack webhook / email) — section 1.9."""
    settings = get_settings()

    # Slack notification
    if settings.slack_webhook_url:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    settings.slack_webhook_url,
                    json={
                        "text": f"🚨 *HoneypotAAS Auto-Block*\n"
                        f"• IP: `{ip}`\n"
                        f"• Rule: {rule_name or 'manual'}\n"
                        f"• Reason: {reason}",
                    },
                )
        except Exception as exc:
            log.error("slack_alert_failed", error=str(exc))

    # Email notification (basic SMTP)
    if settings.alert_email_smtp_host and settings.alert_email_to:
        try:
            import smtplib
            from email.message import EmailMessage

            msg = EmailMessage()
            msg["Subject"] = f"[HoneypotAAS] IP Blocked: {ip}"
            msg["From"] = settings.alert_email_from
            msg["To"] = settings.alert_email_to
            msg.set_content(
                f"IP {ip} has been automatically blocked.\n\n"
                f"Rule: {rule_name or 'manual'}\n"
                f"Reason: {reason}\n"
            )

            with smtplib.SMTP(settings.alert_email_smtp_host, settings.alert_email_smtp_port) as server:
                server.starttls()
                if settings.alert_email_password:
                    server.login(settings.alert_email_from, settings.alert_email_password)
                server.send_message(msg)

        except Exception as exc:
            log.error("email_alert_failed", error=str(exc))
