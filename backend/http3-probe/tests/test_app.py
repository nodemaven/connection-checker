"""Tests for the proxy-quality study measurement endpoints.

    pytest tools/research-endpoints/tests

@author Salama Malek
"""

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import PAYLOAD_BYTES, app  # noqa: E402


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


# --- /ip -------------------------------------------------------------------

def test_ip_returns_ip_and_timestamp(client):
    r = client.get("/ip")
    assert r.status_code == 200
    assert r.mimetype == "application/json"
    body = json.loads(r.data)
    assert set(body) == {"ip", "timestamp", "session"}
    # ISO-8601 UTC with a Z suffix, so the study can parse it without guessing.
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z", body["timestamp"])


def test_ip_uses_last_forwarded_entry_not_the_client_supplied_one(client):
    # Caddy appends the peer it observed, so a client that sends its own
    # X-Forwarded-For gets its value pushed to the left. Reporting the first
    # entry would let anyone claim any IP, which would quietly corrupt the study.
    r = client.get("/ip", headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.9"})
    assert json.loads(r.data)["ip"] == "203.0.113.9"


def test_ip_falls_back_to_public_peer_when_no_forwarded_header(client):
    r = client.get("/ip", environ_base={"REMOTE_ADDR": "203.0.113.5"})
    assert json.loads(r.data)["ip"] == "203.0.113.5"


def test_ip_is_empty_when_only_a_private_peer_is_available(client):
    # No XFF and a private/loopback peer (the HTTP/3 failure mode) reports
    # nothing rather than a useless internal address.
    r = client.get("/ip", environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert json.loads(r.data)["ip"] == ""


# --- /ping -----------------------------------------------------------------

def test_ping_is_small_and_fixed(client):
    first = client.get("/ping")
    second = client.get("/ping")
    assert first.status_code == 200
    assert first.data == second.data
    assert len(first.data) < 32


# --- /download/1mb ---------------------------------------------------------

def test_download_is_exactly_one_mebibyte(client):
    r = client.get("/download/1mb")
    assert r.status_code == 200
    assert len(r.data) == PAYLOAD_BYTES == 1024 * 1024
    assert r.headers["Content-Length"] == str(PAYLOAD_BYTES)


def test_download_is_byte_identical_between_requests(client):
    assert client.get("/download/1mb").data == client.get("/download/1mb").data


def test_download_payload_is_incompressible(client):
    # If the body were compressible, any compression accidentally enabled on
    # the path would shrink the transfer and inflate the measured throughput.
    import zlib

    data = client.get("/download/1mb").data
    assert len(zlib.compress(data, 9)) > 0.99 * len(data)


# --- headers ---------------------------------------------------------------

@pytest.mark.parametrize("path", ["/ip", "/ping", "/download/1mb"])
def test_responses_are_uncacheable(client, path):
    r = client.get(path)
    assert "no-store" in r.headers["Cache-Control"]


@pytest.mark.parametrize("path", ["/ip", "/ping", "/download/1mb"])
def test_responses_are_not_compressed(client, path):
    r = client.get(path, headers={"Accept-Encoding": "gzip, deflate, br, zstd"})
    assert "Content-Encoding" not in r.headers


def test_healthz(client):
    assert client.get("/healthz").status_code == 200


# --- session key ------------------------------------------------------------

def test_ip_echoes_session_when_supplied(client):
    body = json.loads(client.get("/ip?session=nm-abc_123.4").data)
    assert body["session"] == "nm-abc_123.4"


def test_ip_session_is_empty_when_absent(client):
    assert json.loads(client.get("/ip").data)["session"] == ""


@pytest.mark.parametrize("path", ["/ip", "/ping", "/download/1mb"])
def test_session_echoed_in_header_on_every_route(client, path):
    sep = "&" if "?" in path else "?"
    r = client.get(f"{path}{sep}session=sess-42")
    assert r.headers["X-Session"] == "sess-42"


@pytest.mark.parametrize(
    "bad",
    [
        "a\r\nX-Injected: 1",   # header injection
        "a b",                  # space
        "x" * 65,               # over length
        "sess;drop",            # punctuation outside the whitelist
    ],
)
def test_unsafe_session_values_are_rejected_not_echoed(client, bad):
    r = client.get("/ip", query_string={"session": bad})
    assert json.loads(r.data)["session"] == ""
    assert "X-Session" not in r.headers
    assert "X-Injected" not in r.headers


# --- /h3probe --------------------------------------------------------------

def test_h3probe_carries_timing_allow_origin(client):
    # Without this header, nextHopProtocol reads as "" cross-origin and the
    # HTTP/3 check cannot conclude anything.
    r = client.get("/h3probe")
    assert r.status_code == 200
    assert r.headers["Timing-Allow-Origin"] == "*"


def test_h3probe_carries_cors_header(client):
    assert client.get("/h3probe").headers["Access-Control-Allow-Origin"] == "*"


def test_h3probe_is_uncacheable(client):
    # A cached first response would skip the Alt-Svc learning step.
    assert "no-store" in client.get("/h3probe").headers["Cache-Control"]


def test_h3probe_echoes_fetch_number(client):
    body = json.loads(client.get("/h3probe?n=2").data)
    assert body["ok"] is True
    assert body["n"] == "2"


def test_h3probe_claims_nothing_about_the_protocol(client):
    # Flask only sees the hop from Caddy, so any protocol claim in the body
    # would be wrong by construction. The browser timing entry is the source.
    body = json.loads(client.get("/h3probe").data)
    assert "protocol" not in body


def test_h3probe_echoes_observed_ip(client):
    # The QUIC channel compares the source IP on the h3 attempt against the
    # h2 one; the body has to carry the observed address for that to work.
    body = json.loads(
        client.get("/h3probe", headers={"X-Forwarded-For": "198.51.100.7"}).data
    )
    assert body["ip"] == "198.51.100.7"


def test_h3probe_ip_uses_last_forwarded_entry(client):
    # Same trust basis as /ip: Caddy appends the real peer last, so a
    # client-supplied earlier entry must not win.
    body = json.loads(
        client.get(
            "/h3probe", headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.7"}
        ).data
    )
    assert body["ip"] == "198.51.100.7"


def test_ip_carries_cors_for_cross_origin_ipv4_resolve(client):
    # The connection checker reads /ip cross-origin to force an IPv4 exit;
    # without CORS that read fails and the family-mismatch false leak returns.
    assert client.get("/ip").headers["Access-Control-Allow-Origin"] == "*"


def test_ip_never_reports_a_private_docker_address(client):
    # Over HTTP/3 the edge has left XFF empty, dropping observed_ip() to the
    # container's Docker gateway. That internal address must never be reported.
    r = client.get("/ip", headers={"X-Forwarded-For": "172.22.0.1"})
    assert json.loads(r.data)["ip"] == ""


def test_ip_returns_last_public_entry_skipping_private_tail(client):
    r = client.get("/ip", headers={"X-Forwarded-For": "203.0.113.9, 172.22.0.1"})
    assert json.loads(r.data)["ip"] == "203.0.113.9"
