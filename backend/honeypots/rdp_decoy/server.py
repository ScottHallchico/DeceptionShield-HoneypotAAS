"""Custom RDP decoy honeypot — section 1.1 of the implementation plan.

Implements a minimal RDP handshake stub using Python asyncio to capture
RDP brute-force scanners (extremely common SMB attack vector).

This does NOT implement the full RDP protocol — just enough of the
initial connection negotiation to log the attacker's IP and capture
the NLA/CredSSP negotiation attempt before dropping the connection.
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
import sys
from datetime import datetime, timezone

HONEYPOT_ID = os.getenv("HONEYPOT_ID", "rdp-decoy-01")
LOG_FILE = os.getenv("LOG_FILE", "/var/log/honeypot/rdp-decoy.json")
PORT = int(os.getenv("PORT", "3389"))


def _log_event(event: dict) -> None:
    """Write a structured JSON log line."""
    event.update({
        "honeypot_id": HONEYPOT_ID,
        "honeypot_type": "rdp-decoy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    log_line = json.dumps(event)
    print(log_line, flush=True)

    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(log_line + "\n")
    except OSError:
        pass


# ─── RDP protocol constants ─────────────────────────────────────────────────

# TPKT header (RFC 1006)
# Version=3, Reserved=0, Length=variable
TPKT_HEADER = b"\x03\x00"

# X.224 Connection Confirm TPDU
# Length indicator, CR TPDU code, Dst-ref, Src-ref, Class
X224_CC = b"\x0e\xd0\x00\x00\x12\x34\x00"

# RDP Negotiation Response
# Type=0x02 (RSP), Flags, Length=8, Protocol (TLS)
RDP_NEG_RSP = struct.pack("<BBHI", 0x02, 0x00, 8, 0x00000001)  # PROTOCOL_SSL


def build_connection_confirm() -> bytes:
    """Build a minimal RDP Connection Confirm PDU."""
    payload = X224_CC + RDP_NEG_RSP
    length = len(payload) + 4  # +4 for TPKT header
    return TPKT_HEADER + struct.pack(">H", length) + payload


# ─── Async handler ───────────────────────────────────────────────────────────


async def handle_rdp_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Handle a single RDP connection attempt."""
    peer = writer.get_extra_info("peername")
    attacker_ip = peer[0] if peer else "unknown"

    _log_event({
        "attacker_ip": attacker_ip,
        "event_type": "login_attempt",
        "technique": "brute_force",
        "payload": "RDP connection initiated",
    })

    try:
        # Read the initial Connection Request (TPKT + X.224 CR)
        data = await asyncio.wait_for(reader.read(1024), timeout=10.0)

        if data:
            # Log the raw connection request
            _log_event({
                "attacker_ip": attacker_ip,
                "event_type": "exploit_probe",
                "payload": f"RDP handshake data ({len(data)} bytes): {data[:64].hex()}",
            })

            # Extract any cookies/credentials from the CR PDU
            # RDP cookies look like: "Cookie: mstshash=username\r\n"
            try:
                decoded = data.decode("ascii", errors="ignore")
                if "Cookie:" in decoded or "mstshash=" in decoded:
                    cookie_start = decoded.find("Cookie:")
                    if cookie_start >= 0:
                        cookie_end = decoded.find("\r\n", cookie_start)
                        cookie = decoded[cookie_start:cookie_end if cookie_end > 0 else cookie_start + 64]
                        _log_event({
                            "attacker_ip": attacker_ip,
                            "event_type": "login_attempt",
                            "technique": "brute_force",
                            "payload": f"RDP credential: {cookie}",
                        })
            except Exception:
                pass

            # Send Connection Confirm to keep the attacker engaged
            writer.write(build_connection_confirm())
            await writer.drain()

            # Try to read more data (TLS handshake / CredSSP)
            try:
                more_data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                if more_data:
                    _log_event({
                        "attacker_ip": attacker_ip,
                        "event_type": "exploit_probe",
                        "payload": f"RDP post-handshake ({len(more_data)} bytes): {more_data[:64].hex()}",
                    })
            except asyncio.TimeoutError:
                pass

    except asyncio.TimeoutError:
        _log_event({
            "attacker_ip": attacker_ip,
            "event_type": "port_scan",
            "payload": "RDP connection timeout (likely port scan)",
        })
    except Exception as exc:
        _log_event({
            "attacker_ip": attacker_ip,
            "event_type": "exploit_probe",
            "payload": f"RDP error: {str(exc)[:200]}",
        })
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    """Start the RDP decoy server."""
    server = await asyncio.start_server(handle_rdp_connection, "0.0.0.0", PORT)
    print(f"RDP decoy listening on port {PORT}", flush=True)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
