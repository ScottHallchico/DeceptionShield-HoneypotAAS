"""Custom WordPress Admin decoy honeypot — section 1.1 of the implementation plan.

Simulates a WordPress /wp-admin login page plus fake plugin directories
to capture credential stuffing and CMS exploit probes (XML-RPC abuse,
plugin enumeration).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

HONEYPOT_ID = os.getenv("HONEYPOT_ID", "wp-decoy-01")
LOG_FILE = os.getenv("LOG_FILE", "/var/log/honeypot/wp-decoy.json")


def _log_event(event: dict) -> None:
    """Write a structured JSON log line for consumption by Filebeat."""
    event.update({
        "honeypot_id": HONEYPOT_ID,
        "honeypot_type": "wp-decoy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    log_line = json.dumps(event)
    print(log_line, flush=True)

    # Also append to log file for Filebeat
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(log_line + "\n")
    except OSError:
        pass


# ─── Fake WordPress login page ──────────────────────────────────────────────

WP_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In &lsaquo; WordPress</title>
    <style>
        body { background: #f1f1f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .login { width: 320px; margin: 100px auto; }
        .login h1 { text-align: center; }
        .login h1 a { background-image: url('data:image/svg+xml,...'); width: 84px; height: 84px; display: block; margin: auto; }
        .login form { background: #fff; border: 1px solid #ccd0d4; border-radius: 4px; padding: 26px 24px; margin-top: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
        .login label { font-size: 14px; font-weight: 600; display: block; margin-bottom: 8px; }
        .login input[type="text"], .login input[type="password"] { width: 100%; padding: 8px; border: 1px solid #8c8f94; border-radius: 4px; font-size: 14px; box-sizing: border-box; margin-bottom: 16px; }
        .login input[type="submit"] { background: #2271b1; border: none; color: #fff; padding: 10px 24px; font-size: 14px; border-radius: 4px; cursor: pointer; width: 100%; }
        .login input[type="submit"]:hover { background: #135e96; }
        .login .message { background: #fff; border-left: 4px solid #72aee6; padding: 12px; margin-bottom: 20px; box-shadow: 0 1px 1px rgba(0,0,0,.04); }
    </style>
</head>
<body>
    <div class="login">
        <h1><a href="#">WordPress</a></h1>
        <form method="post" action="/wp-login.php">
            <label for="user_login">Username or Email Address</label>
            <input type="text" name="log" id="user_login" autocomplete="username" />
            <label for="user_pass">Password</label>
            <input type="password" name="pwd" id="user_pass" autocomplete="current-password" />
            <input type="submit" value="Log In" />
        </form>
    </div>
</body>
</html>
"""


@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET"])
@app.route("/wp-admin", methods=["GET"])
def wp_login():
    if request.method == "POST":
        username = request.form.get("log", "")
        password = request.form.get("pwd", "")
        _log_event({
            "attacker_ip": request.remote_addr,
            "event_type": "login_attempt",
            "technique": "brute_force",
            "payload": f"username={username}, password={password}",
        })
        # Always fail, but with a realistic-looking delay and error
        return WP_LOGIN_HTML.replace(
            '<form',
            '<div class="message"><strong>Error:</strong> The username or password you entered is incorrect.</div><form'
        ), 200

    _log_event({
        "attacker_ip": request.remote_addr,
        "event_type": "exploit_probe",
        "technique": "credential_reuse",
        "payload": f"GET {request.path}",
    })
    return WP_LOGIN_HTML, 200


# ─── Fake XML-RPC endpoint (common attack vector) ───────────────────────────

@app.route("/xmlrpc.php", methods=["GET", "POST"])
def xmlrpc():
    _log_event({
        "attacker_ip": request.remote_addr,
        "event_type": "exploit_probe",
        "technique": "cve_exploit_attempt",
        "payload": request.get_data(as_text=True)[:1024],
    })

    return Response(
        '<?xml version="1.0"?><methodResponse><fault><value><struct>'
        '<member><name>faultCode</name><value><int>-32601</int></value></member>'
        '<member><name>faultString</name><value><string>Requested method not found.</string></value></member>'
        '</struct></value></fault></methodResponse>',
        mimetype="text/xml",
    )


# ─── Fake plugin directory (triggers plugin enumeration scanners) ────────────

FAKE_PLUGINS = ["contact-form-7", "woocommerce", "elementor", "yoast-seo", "akismet"]

@app.route("/wp-content/plugins/<path:plugin_path>", methods=["GET"])
def wp_plugin(plugin_path: str):
    _log_event({
        "attacker_ip": request.remote_addr,
        "event_type": "exploit_probe",
        "technique": "cve_exploit_attempt",
        "payload": f"Plugin probe: /wp-content/plugins/{plugin_path}",
    })

    # Return a fake readme for known plugins, 404 for others
    plugin_name = plugin_path.split("/")[0]
    if plugin_name in FAKE_PLUGINS:
        return f"=== {plugin_name} ===\nStable tag: 5.7.2\nTested up to: 6.4\n", 200
    return "Not Found", 404


# ─── Catch-all for other WordPress paths ─────────────────────────────────────

@app.route("/wp-includes/<path:path>", methods=["GET"])
@app.route("/wp-json/<path:path>", methods=["GET"])
@app.route("/wp-cron.php", methods=["GET", "POST"])
def wp_catchall(path: str = ""):
    _log_event({
        "attacker_ip": request.remote_addr,
        "event_type": "exploit_probe",
        "payload": f"{request.method} {request.path}",
    })
    return "", 404


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
