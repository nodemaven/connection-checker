"""
@author Salama Malek

Tiny read-only HTTP service in front of coturn's Redis allocation store.

Redis is bound to 127.0.0.1 only, on purpose — nothing outside this box can
reach it. The public credentials service needs a way to read back
"what source address did coturn observe for this session", which is the whole
point of the check: the answer has to come from something the browser
cannot influence. This service is that narrow window — it exposes exactly one
read, keyed by the exact TURN username the credentials service minted, nothing else.

Auth: a shared secret header, separate from the TURN static-auth-secret. A
caller who doesn't have it gets 401. A caller who does can only read back an
allocation for a username they'd have to already know (the credentials service mints it),
not enumerate arbitrary sessions.
"""
import os
import re
import secrets
import redis
from flask import Flask, request, jsonify

app = Flask(__name__)

REDIS_PASSWORD = os.environ["REDIS_PASSWORD"]
INTERNAL_SECRET = os.environ["INTERNAL_SECRET"]
REALM = os.environ.get("TURN_REALM", "example.com")

# Session-keyed STUN observation (see stun-observe). This service hands out a
# unique pool port per session; the stun-observe responder records the source
# of any Binding request that lands on that port under the session token.
STUN_HOST = os.environ.get("STUN_HOST", "turn.example.com")
STUN_PORT_START = int(os.environ.get("STUN_PORT_START", "20000"))
STUN_PORT_END = int(os.environ.get("STUN_PORT_END", "20063"))
STUN_TTL = int(os.environ.get("STUN_OBS_TTL", "120"))

r = redis.Redis(host="127.0.0.1", port=6380, password=REDIS_PASSWORD, decode_responses=True)

# Token shape the STUN allocator mints: 24 hex chars, same guard as the readback.
STUN_TOKEN_RE = re.compile(r"^[a-f0-9]{24}$")

# TURN-REST usernames are "<unix_expiry>:<session_id>". Reject anything that
# doesn't fit before it ever reaches a Redis key pattern.
USERNAME_RE = re.compile(r"^\d{1,20}:[A-Za-z0-9._-]{1,128}$")

STATUS_RE = re.compile(
    r"local=(?P<local>[^,]+),\s*remote=(?P<remote>[^,]+),"
)


@app.get("/allocation-status")
def allocation_status():
    if request.headers.get("X-Internal-Secret") != INTERNAL_SECRET:
        return jsonify(error="unauthorized"), 401

    username = request.args.get("user", "")
    if not USERNAME_RE.match(username):
        return jsonify(error="invalid_username"), 400

    pattern = f"turn/realm/{REALM}/user/{username}/allocation/*/status"
    # A session can hold more than one allocation (IPv4 + IPv6, or a retry).
    # Take the most recently written one — that's the one the browser is
    # actually still using.
    best_key, best_val, best_ttl = None, None, -2
    for key in r.scan_iter(match=pattern, count=50):
        val = r.get(key)
        if not val:
            continue
        ttl = r.ttl(key)
        # Higher TTL remaining from the *same* 777s lifetime = written later.
        if ttl > best_ttl:
            best_key, best_val, best_ttl = key, val, ttl

    if not best_val:
        return jsonify(found=False), 200

    m = STATUS_RE.search(best_val)
    if not m:
        return jsonify(found=False), 200

    remote = m.group("remote")
    ip, _, port = remote.rpartition(":")
    return jsonify(found=True, ip=ip, port=port), 200


@app.post("/stun/session")
def stun_session():
    """Assign a session a unique pool port for STUN observation.

    The port is the correlation key: the stun-observe responder attributes any
    Binding request on this port to the token we mint here. Round-robin over the
    pool via an atomic counter; the mapping carries the same TTL as the test.
    """
    if request.headers.get("X-Internal-Secret") != INTERNAL_SECRET:
        return jsonify(error="unauthorized"), 401

    pool_size = STUN_PORT_END - STUN_PORT_START + 1
    if pool_size <= 0:
        return jsonify(error="pool_unconfigured"), 503

    try:
        n = r.incr("stunport_counter")
        port = STUN_PORT_START + (n % pool_size)
        token = secrets.token_hex(12)
        r.setex(f"stunport:{port}", STUN_TTL, token)
    except redis.RedisError:
        return jsonify(error="store_unavailable"), 503

    return jsonify(
        host=STUN_HOST,
        port=port,
        token=token,
        url=f"stun:{STUN_HOST}:{port}",
    ), 200


@app.get("/stun/observed")
def stun_observed():
    """Return the source address the STUN responder saw for this token."""
    if request.headers.get("X-Internal-Secret") != INTERNAL_SECRET:
        return jsonify(error="unauthorized"), 401

    token = request.args.get("token", "")
    if not STUN_TOKEN_RE.match(token):
        return jsonify(error="invalid_token"), 400

    try:
        ip = r.get(f"stunobs:{token}")
    except redis.RedisError:
        return jsonify(error="store_unavailable"), 503

    if not ip:
        return jsonify(found=False), 200
    return jsonify(found=True, ip=ip), 200


@app.get("/healthz")
def healthz():
    try:
        r.ping()
        return jsonify(ok=True), 200
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 503
