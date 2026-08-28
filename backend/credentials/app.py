"""
Credentials + read-back service for the Connection Checker.

This is the public-facing API the browser talks to. It does two jobs:

  1. Mint a short-lived TURN REST credential (HMAC-SHA1 over the coturn
     static-auth-secret) that the browser adds as an extra ICE server. The
     secret never leaves the server; the browser only ever sees the derived,
     time-limited credential.

  2. Proxy the read-back queries to the internal `turn-readback` service, which
     is bound to localhost and guarded by a shared internal secret. The browser
     cannot reach that service directly; it asks here, and this service forwards
     the request with the internal secret.

Endpoints (this is the frontend's `apiBase`; paths match the browser client):

  GET  /healthz                          liveness
  GET  /ip                               the caller's exit IP
  GET  /ip/<ip>                          enrich an IP (ISP/ASN if a provider is wired)
  GET  /webrtc/turn-credentials          mint UDP + TCP creds (+ a STUN session)
  GET  /webrtc/turn-observed?username=…  what coturn observed for a minted credential
  GET  /webrtc/stun-observed?token=…     what the STUN-observe service saw for a session

Everything is configured through environment variables — see .env.example.

Author: Salama Malek
"""

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import time

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# --- configuration (all from the environment) -------------------------------
TURN_HOST = os.environ["TURN_HOST"]                       # e.g. turn.example.com
TURN_SECRET = os.environ["TURN_SECRET"]                   # coturn static-auth-secret
TURN_PORT = int(os.environ.get("TURN_PORT", "3478"))
CRED_TTL = int(os.environ.get("CRED_TTL", "120"))         # seconds a credential is valid

READBACK_URL = os.environ["READBACK_URL"].rstrip("/")     # internal turn-readback base
READBACK_SECRET = os.environ["READBACK_SECRET"]           # X-Internal-Secret shared value

# The frontend is served from a different origin, so it needs CORS to call this.
# Set this to your frontend's exact origin in production instead of "*".
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

# Shapes the mint step produces, validated before any value reaches the upstream.
USERNAME_RE = re.compile(r"^\d{1,20}:[a-f0-9]{24}(-tcp)?$")
TOKEN_RE = re.compile(r"^[a-f0-9]{24}$")


def _hmac_credential(username: str) -> str:
    """coturn REST credential: base64(HMAC-SHA1(username, static-auth-secret))."""
    digest = hmac.new(TURN_SECRET.encode(), username.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    return response


@app.get("/healthz")
def healthz():
    return jsonify(ok=True)


def _client_ip() -> str:
    """Caller's public IP. Behind a reverse proxy the socket peer is the proxy,
    so prefer the last public X-Forwarded-For entry; never return a private one."""
    xff = request.headers.get("X-Forwarded-For", "")
    for candidate in reversed([p.strip() for p in xff.split(",") if p.strip()]):
        try:
            if ipaddress.ip_address(candidate).is_global:
                return candidate
        except ValueError:
            continue
    return request.remote_addr or ""


@app.get("/ip")
def ip():
    return jsonify(ip=_client_ip())


@app.get("/ip/<path:addr>")
def ip_enrich(addr):
    """Enrich an IP with ISP/ASN. This ships as a pass-through returning just the
    IP; wire your own geo/ASN provider here if you want richer output (the
    frontend degrades gracefully to showing the IP alone)."""
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return jsonify(error={"code": "invalid_ip", "message": "Invalid IP."}), 400
    return jsonify(ip=addr)


@app.get("/webrtc/turn-credentials")
def turn_credentials():
    """Mint a short-lived UDP + TCP TURN credential and a STUN-observe session."""
    # Random session id, not derived from anything request-identifiable, so the
    # credential cannot be replayed to correlate a visitor beyond this one test.
    session_id = secrets.token_hex(12)          # 24 hex chars
    expiry = int(time.time()) + CRED_TTL
    username = f"{expiry}:{session_id}"

    # A second credential for the TCP-relay channel, keyed by a "-tcp" suffix so
    # coturn stores its observed address under its own key and the read-back can
    # report the UDP and TCP observations separately.
    tcp_username = f"{username}-tcp"

    payload = {
        "username": username,
        "credential": _hmac_credential(username),
        "ttl": CRED_TTL,
        "urls": [
            f"stun:{TURN_HOST}:{TURN_PORT}",
            f"turn:{TURN_HOST}:{TURN_PORT}?transport=udp",
        ],
        "tcp": {
            "username": tcp_username,
            "credential": _hmac_credential(tcp_username),
            "urls": [f"turn:{TURN_HOST}:{TURN_PORT}?transport=tcp"],
        },
    }

    # Best-effort STUN observation session. If it fails, we simply omit the block
    # and the browser degrades to the other checks — it must never break minting.
    stun = _allocate_stun_session()
    if stun is not None:
        payload["stun"] = stun

    return jsonify(payload)


def _allocate_stun_session():
    """Ask the internal read-back service for a per-session STUN observe port."""
    try:
        resp = requests.post(
            f"{READBACK_URL}/stun/session",
            headers={"X-Internal-Secret": READBACK_SECRET},
            timeout=4,
        )
        if resp.status_code != 200:
            return None
        body = resp.json()
    except (requests.RequestException, ValueError):
        return None
    if not body.get("url") or not body.get("token"):
        return None
    return {"url": str(body["url"]), "token": str(body["token"])}


@app.get("/webrtc/turn-observed")
def turn_observed():
    """Read back the IP coturn actually saw for a credential we minted."""
    username = request.args.get("username", "")
    if not USERNAME_RE.match(username):
        return jsonify(error={"code": "invalid_username", "message": "Invalid or missing username."}), 400
    return _proxy_readback("/allocation-status", {"user": username}, "TURN")


@app.get("/webrtc/stun-observed")
def stun_observed():
    """Read back the source the STUN-observe service saw for a session token."""
    token = request.args.get("token", "")
    if not TOKEN_RE.match(token):
        return jsonify(error={"code": "invalid_token", "message": "Invalid or missing token."}), 400
    return _proxy_readback("/stun/observed", {"token": token}, "STUN")


def _proxy_readback(path: str, params: dict, label: str):
    try:
        resp = requests.get(
            f"{READBACK_URL}{path}",
            params=params,
            headers={"X-Internal-Secret": READBACK_SECRET},
            timeout=5,
        )
    except requests.RequestException:
        return jsonify(error={"code": "upstream_unreachable",
                              "message": f"Could not reach the {label} server."}), 502
    try:
        body = resp.json()
    except ValueError:
        body = None
    if resp.status_code != 200 or not isinstance(body, dict):
        return jsonify(error={"code": "upstream_error",
                              "message": f"The {label} server returned an unexpected response."}), 502
    return jsonify(found=bool(body.get("found", False)),
                   ip=body["ip"] if isinstance(body.get("ip"), str) else None)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8006")))
