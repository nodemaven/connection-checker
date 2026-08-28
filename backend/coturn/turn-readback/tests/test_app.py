"""Offline tests for turn-readback: auth guard, input validation, redis-backed
paths (with a fake redis so no server is needed)."""
import os

os.environ.setdefault("REDIS_PASSWORD", "pw")
os.environ.setdefault("INTERNAL_SECRET", "secret")
os.environ.setdefault("TURN_REALM", "example.com")

import app as svc  # noqa: E402

AUTH = {"X-Internal-Secret": "secret"}


class FakeRedis:
    def __init__(self):
        self.store = {}
        self.ttls = {}
        self.counter = 0
    def scan_iter(self, match=None, count=None):
        return list(self.store.keys())
    def get(self, k):
        return self.store.get(k)
    def ttl(self, k):
        return self.ttls.get(k, -2)
    def incr(self, k):
        self.counter += 1
        return self.counter
    def setex(self, k, ttl, v):
        self.store[k] = v
        self.ttls[k] = ttl
    def ping(self):
        return True


def client(monkeypatch, fake=None):
    monkeypatch.setattr(svc, "r", fake or FakeRedis())
    return svc.app.test_client()


def test_endpoints_require_secret(monkeypatch):
    c = client(monkeypatch)
    assert c.get("/allocation-status?user=1:a").status_code == 401
    assert c.post("/stun/session").status_code == 401
    assert c.get("/stun/observed?token=" + "a" * 24).status_code == 401


def test_allocation_status_rejects_bad_username(monkeypatch):
    c = client(monkeypatch)
    assert c.get("/allocation-status?user=../etc", headers=AUTH).status_code == 400
    assert c.get("/allocation-status?user=", headers=AUTH).status_code == 400


def test_allocation_status_not_found(monkeypatch):
    c = client(monkeypatch, FakeRedis())
    r = c.get("/allocation-status?user=1700000000:abc", headers=AUTH)
    assert r.status_code == 200 and r.get_json() == {"found": False}


def test_allocation_status_parses_remote_ip(monkeypatch):
    fake = FakeRedis()
    key = "turn/realm/example.com/user/1700000000:abc/allocation/1/status"
    fake.store[key] = "local=10.0.0.1:5000, remote=203.0.113.7:41000, ..."
    fake.ttls[key] = 700
    c = client(monkeypatch, fake)
    body = c.get("/allocation-status?user=1700000000:abc", headers=AUTH).get_json()
    assert body["found"] is True and body["ip"] == "203.0.113.7" and body["port"] == "41000"


def test_stun_session_mints_token_and_port(monkeypatch):
    c = client(monkeypatch, FakeRedis())
    body = c.post("/stun/session", headers=AUTH).get_json()
    assert 20000 <= body["port"] <= 20063
    assert len(body["token"]) == 24
    assert body["url"].startswith("stun:")


def test_stun_observed_validates_and_reads(monkeypatch):
    c = client(monkeypatch)
    assert c.get("/stun/observed?token=short", headers=AUTH).status_code == 400
    fake = FakeRedis(); fake.store["stunobs:" + "a" * 24] = "198.51.100.5"
    c2 = client(monkeypatch, fake)
    body = c2.get("/stun/observed?token=" + "a" * 24, headers=AUTH).get_json()
    assert body == {"found": True, "ip": "198.51.100.5"}
