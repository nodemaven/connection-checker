"""Tests for the STUN binding responder's wire encoding.

    pytest tools/coturn/stun-observe

@author Salama Malek
"""
import os
import socket
import struct
import sys
from pathlib import Path

# The module reads REDIS_PASSWORD at import; supply a dummy for the unit tests,
# which only exercise pure encoding functions and never open a socket.
os.environ.setdefault("REDIS_PASSWORD", "test")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stun_observe as so  # noqa: E402


def _binding_request(txid: bytes) -> bytes:
    return struct.pack("!HH", so.BINDING_REQUEST, 0) + so.MAGIC_COOKIE_BYTES + txid


def test_recognises_a_binding_request():
    assert so.is_binding_request(_binding_request(b"\x00" * 12))


def test_rejects_short_or_wrong_magic():
    assert not so.is_binding_request(b"\x00" * 10)
    bad = struct.pack("!HH", so.BINDING_REQUEST, 0) + b"\xde\xad\xbe\xef" + b"\x00" * 12
    assert not so.is_binding_request(bad)


def test_response_echoes_transaction_id_and_is_success():
    txid = bytes(range(12))
    resp = so.build_binding_response(txid, ("203.0.113.9", 54321))
    msg_type, _length = struct.unpack("!HH", resp[0:4])
    assert msg_type == so.BINDING_SUCCESS
    assert resp[4:8] == so.MAGIC_COOKIE_BYTES
    assert resp[8:20] == txid


def _decode_xor_mapped_ipv4(resp: bytes):
    # header(20) then attr header(4) then value.
    attr_type, attr_len = struct.unpack("!HH", resp[20:24])
    assert attr_type == so.ATTR_XOR_MAPPED_ADDRESS
    value = resp[24 : 24 + attr_len]
    _reserved, family, xport = struct.unpack("!BBH", value[0:4])
    port = xport ^ (so.MAGIC_COOKIE >> 16)
    xaddr = value[4:8]
    raw = bytes(b ^ m for b, m in zip(xaddr, so.MAGIC_COOKIE_BYTES))
    return family, socket.inet_ntop(socket.AF_INET, raw), port


def test_xor_mapped_address_round_trips_ipv4():
    # A conformant client XORs the address back out; it must match the peer.
    resp = so.build_binding_response(bytes(range(12)), ("198.51.100.7", 40000))
    family, ip, port = _decode_xor_mapped_ipv4(resp)
    assert family == 0x01
    assert ip == "198.51.100.7"
    assert port == 40000


def test_ipv6_source_encodes_without_error():
    # The v6 branch uses the full magic-cookie+txid mask; just confirm it
    # produces a family-2 attribute of the right length.
    resp = so.build_binding_response(bytes(range(12)), ("2001:db8::1234", 40000))
    attr_type, attr_len = struct.unpack("!HH", resp[20:24])
    assert attr_type == so.ATTR_XOR_MAPPED_ADDRESS
    _reserved, family, _xport = struct.unpack("!BBH", resp[24:28])
    assert family == 0x02
    assert attr_len == 4 + 16
