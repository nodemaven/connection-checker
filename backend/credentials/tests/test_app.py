"""Offline tests for the credentials service: HMAC minting + input validators."""
import base64
import hashlib
import hmac
import os

os.environ.setdefault("TURN_HOST", "turn.example.com")
os.environ.setdefault("TURN_SECRET", "test-secret")
os.environ.setdefault("READBACK_URL", "http://127.0.0.1:8004")
os.environ.setdefault("READBACK_SECRET", "internal")

import app as svc  # noqa: E402


def test_hmac_matches_coturn_rest_scheme():
    username = "1700000000:abcdef0123456789abcdef01"
    expected = base64.b64encode(
        hmac.new(b"test-secret", username.encode(), hashlib.sha1).digest()
    ).decode()
    assert svc._hmac_credential(username) == expected


def test_username_regex_accepts_udp_and_tcp():
    assert svc.USERNAME_RE.match("1700000000:abcdef0123456789abcdef01")
    assert svc.USERNAME_RE.match("1700000000:abcdef0123456789abcdef01-tcp")


def test_username_regex_rejects_junk():
    assert not svc.USERNAME_RE.match("../etc/passwd")
    assert not svc.USERNAME_RE.match("1700000000:XYZ")
    assert not svc.USERNAME_RE.match("")


def test_token_regex():
    assert svc.TOKEN_RE.match("abcdef0123456789abcdef01")
    assert not svc.TOKEN_RE.match("abc")
    assert not svc.TOKEN_RE.match("abcdef0123456789abcdef01-tcp")


def test_credentials_endpoint_shape(monkeypatch):
    monkeypatch.setattr(svc, "_allocate_stun_session", lambda: None)
    client = svc.app.test_client()
    r = client.get("/webrtc/turn-credentials")
    assert r.status_code == 200
    body = r.get_json()
    assert set(["username", "credential", "ttl", "urls", "tcp"]).issubset(body)
    assert body["tcp"]["username"].endswith("-tcp")
    assert any("transport=udp" in u for u in body["urls"])
