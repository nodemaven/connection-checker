"""Measurement endpoints for the proxy-quality study.

Three routes, deliberately dumb, so that anything the study measures is a
property of the network path and not of this service:

    GET /ip           observed requester IP + timestamp (JSON)
    GET /ping         small fixed response
    GET /download/1mb fixed 1 MiB body

Everything is served uncompressed and uncacheable. See README.md for the Caddy
block, which must NOT carry the `encode` directive the other sites use.

@author Salama Malek
"""

import json
import os
import random
import re
from datetime import datetime, timezone

from flask import Flask, Response, request

app = Flask(__name__)

# Exactly 1 MiB. Built once at import from a fixed seed, so:
#   - it is identical on every request and across restarts and both boxes,
#     which is what "a fixed 1 MB response" has to mean for a measurement,
#   - it is random-looking and therefore incompressible, so if compression is
#     ever switched on by accident the transfer size does not silently shrink
#     and quietly inflate the measured throughput.
PAYLOAD_BYTES = 1024 * 1024
PAYLOAD = random.Random(0).randbytes(PAYLOAD_BYTES)

PING_BODY = b"pong\n"


# The study's own design records "the exit IP, time and session ID" per proxy
# session, and its stop condition is that the exit IP cannot be reliably linked
# to its requests. Without a session key the before / during / after checks can
# only be joined by wall-clock order, which is the weakest possible join for the
# session-stability hypothesis. So every route accepts an optional ?session= and
# echoes it back, giving the collector an unambiguous key.
SESSION_MAX_LEN = 64
_SESSION_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,%d}$" % SESSION_MAX_LEN)


def session_id() -> str:
    """The caller-supplied session key, or "" when absent or unacceptable.

    Whitelist-validated rather than escaped. The value is echoed into a response
    header, and a value containing CR/LF would otherwise let a caller inject
    headers of their own.
    """
    raw = request.args.get("session", "")
    return raw if _SESSION_SAFE.match(raw or "") else ""


def _no_store(response: Response) -> Response:
    """Make every response uncacheable, at our end and at any intermediary."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    # Echoed on every route, including the binary download where there is no
    # body to put it in, so speed records join to IP records on the same key.
    sid = session_id()
    if sid:
        response.headers["X-Session"] = sid
    return response


app.after_request(_no_store)


def observed_ip() -> str:
    """The address this request actually arrived from.

    Caddy fronts this service, so the socket peer is always 127.0.0.1 and the
    real address arrives in X-Forwarded-For. The Caddy block overwrites that
    header with the connecting peer rather than appending to it, so a client
    cannot inject a fake value.

    Belt and braces for the case where that directive is ever dropped: read the
    LAST entry rather than the first. Caddy appends the peer it observed to
    whatever the client sent, so the last entry is the trustworthy one and the
    earlier ones are client-supplied.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
    # Last PUBLIC entry. Caddy appends the real peer last, but over HTTP/3 it
    # has been observed to leave the header empty, which would drop us to the
    # container's Docker-gateway peer (172.22.0.1) — a useless internal address
    # that corrupts both the checker and the study. Never report a private one:
    # return the last public XFF entry, else "" so callers know it is unknown.
    for ip in reversed(candidates):
        if not _is_private_address(ip):
            return ip
    remote = request.remote_addr or ""
    return "" if _is_private_address(remote) else remote


def _is_private_address(ip: str) -> bool:
    """RFC 1918 / loopback / link-local / Docker-internal, plus IPv6 locals.

    Kept in step with the widget's isLocalAddress so both ends agree on what is
    never a real, routable client address.
    """
    if not ip:
        return True
    if ":" in ip:
        low = ip.lower()
        return (
            low in ("::1", "::")
            or low.startswith("fe8")
            or low.startswith("fe9")
            or low.startswith("fea")
            or low.startswith("feb")
            or low.startswith("fc")
            or low.startswith("fd")
        )
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if a in (10, 127, 0):
        return True
    if a == 169 and b == 254:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    return False


@app.get("/ip")
def ip():
    body = json.dumps(
        {
            "ip": observed_ip(),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "session": session_id(),
        }
    )
    response = Response(body, mimetype="application/json")
    # This host is DNS-only with no AAAA record, so a browser can only reach it
    # over IPv4. The connection checker fetches it cross-origin to resolve the
    # visitor's IPv4 exit explicitly (the WP /ip host is dual-stack and often
    # answers over IPv6, which would never match the IPv4 WebRTC channels and
    # would flag a false leak). CORS lets that cross-origin read succeed.
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.get("/ping")
def ping():
    return Response(PING_BODY, mimetype="text/plain")


@app.get("/download/1mb")
def download_1mb():
    response = Response(PAYLOAD, mimetype="application/octet-stream")
    # Explicit, so the client can verify it received the whole body and can
    # tell a truncated transfer from a slow one.
    response.headers["Content-Length"] = str(PAYLOAD_BYTES)
    response.headers["X-Payload-Bytes"] = str(PAYLOAD_BYTES)
    return response


@app.get("/h3probe")
def h3probe():
    """Probe target for the Connection Detectability Checker's HTTP/3 check.

    The checker fetches this route twice from the browser: the first response
    teaches the browser this origin speaks HTTP/3 (Caddy adds the Alt-Svc
    header itself), the second may then travel over QUIC. The page learns
    which by reading the second fetch's Resource Timing entry.

    Two headers make that work cross-origin, and both are scoped to this
    route so the study's measurement routes stay untouched:
      - Timing-Allow-Origin: without it, nextHopProtocol reads as an empty
        string on every cross-origin entry and the check cannot conclude
        anything.
      - Access-Control-Allow-Origin: the checker page lives on another
        origin, so the fetch itself needs CORS to succeed.

    The body deliberately reports nothing about the negotiated protocol:
    Flask sits behind the Caddy reverse proxy and only ever sees the h2/h1
    hop from Caddy, so anything it claimed about the client's protocol would
    be wrong. The browser-side timing entry is the only honest source.

    It DOES report the observed source IP. This turns the QUIC path into an
    IP-observing channel: a browser whose HTTP rides a proxy but whose QUIC
    goes direct (HTTP proxies cannot carry QUIC) arrives here from a different
    address on the h3 attempt than on the h2 attempt. The checker compares the
    two and treats a difference as the real address leaking around the proxy.
    Same trust basis as /ip: the address comes from Caddy's overwritten
    X-Forwarded-For, not from anything the client can set.
    """
    body = json.dumps(
        {
            "ok": True,
            "n": request.args.get("n", ""),
            "ip": observed_ip(),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    )
    response = Response(body, mimetype="application/json")
    response.headers["Timing-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.get("/healthz")
def healthz():
    return Response("ok\n", mimetype="text/plain")


if __name__ == "__main__":  # pragma: no cover - local dev only
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8000)))
