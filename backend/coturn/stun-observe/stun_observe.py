"""
@author Salama Malek

Session-keyed STUN observation server for the Connection Detectability Checker.

Why this exists
---------------
An anti-detect browser (Mimic and friends) can block the TURN relay allocation
over UDP AND rewrite the srflx candidate it hands to page JavaScript, so neither
the browser-reported address nor our TURN readback ever sees the real UDP path.
But the browser still has to send a plain STUN Binding request over UDP to learn
its own reflexive address, and that request leaves from the real UDP source. A
STUN server that records the source of that request catches the address the
browser tried to hide. This is the one channel the reference tool
(ipbinding.notsosmart.dev) had that we did not.

Correlation
-----------
Plain STUN Binding requests carry no session identifier, so the SESSION IS THE
PORT: the allocator (turn-readback POST /stun/session) hands each session a
unique UDP port from the pool and records `stunport:<port> = <token>` in Redis.
Any Binding request arriving on that port is attributed to that session's token,
and its source address is written to `stunobs:<token>`. The widget reads it back
through turn-readback GET /stun/observed.

This binds the pool ports on the host (the container runs network_mode: host),
so those UDP ports must be open inbound in the security group.
"""
import os
import selectors
import socket
import struct
import sys

import redis

MAGIC_COOKIE = 0x2112A442
MAGIC_COOKIE_BYTES = struct.pack("!I", MAGIC_COOKIE)

BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_XOR_MAPPED_ADDRESS = 0x0020

OBS_TTL = int(os.environ.get("STUN_OBS_TTL", "120"))

PORT_START = int(os.environ.get("STUN_PORT_START", "20000"))
PORT_END = int(os.environ.get("STUN_PORT_END", "20063"))

REDIS_PASSWORD = os.environ["REDIS_PASSWORD"]


def _redis():
    return redis.Redis(
        host="127.0.0.1", port=6380, password=REDIS_PASSWORD, decode_responses=True
    )


def build_binding_response(txid: bytes, addr: tuple) -> bytes:
    """A STUN Binding success response carrying XOR-MAPPED-ADDRESS.

    The browser needs a valid response to complete its srflx gather; we need the
    source address, which we take from the UDP peer, not from anything the client
    put in the request.
    """
    ip, port = addr[0], addr[1]
    is_v6 = ":" in ip
    family = 0x02 if is_v6 else 0x01

    xport = port ^ (MAGIC_COOKIE >> 16)

    if is_v6:
        raw = socket.inet_pton(socket.AF_INET6, ip)
        mask = MAGIC_COOKIE_BYTES + txid  # 16 bytes
        xaddr = bytes(b ^ m for b, m in zip(raw, mask))
    else:
        raw = socket.inet_pton(socket.AF_INET, ip)
        xaddr = bytes(b ^ m for b, m in zip(raw, MAGIC_COOKIE_BYTES))

    # XOR-MAPPED-ADDRESS value: reserved(1) family(1) x-port(2) x-address(n)
    value = struct.pack("!BBH", 0, family, xport) + xaddr
    attr = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(value)) + value

    header = struct.pack("!HH", BINDING_SUCCESS, len(attr)) + MAGIC_COOKIE_BYTES + txid
    return header + attr


def is_binding_request(data: bytes) -> bool:
    if len(data) < 20:
        return False
    msg_type, _msg_len = struct.unpack("!HH", data[0:4])
    return msg_type == BINDING_REQUEST and data[4:8] == MAGIC_COOKIE_BYTES


def handle_packet(sock: socket.socket, port: int, r) -> None:
    try:
        data, addr = sock.recvfrom(2048)
    except OSError:
        return
    if not is_binding_request(data):
        return

    txid = data[8:20]
    try:
        sock.sendto(build_binding_response(txid, addr), addr)
    except OSError:
        pass

    # The pool sockets are dual-stack, so an IPv4 source arrives as an
    # IPv4-mapped IPv6 address (::ffff:1.2.3.4). Unwrap it to the bare IPv4 so
    # the stored and reported address matches what every other channel shows.
    src = addr[0]
    if src.startswith("::ffff:") and "." in src:
        src = src[len("::ffff:"):]

    # Attribute the source to whichever session currently holds this port.
    try:
        token = r.get(f"stunport:{port}")
        if token:
            r.setex(f"stunobs:{token}", OBS_TTL, src)
    except redis.RedisError:
        pass


def main() -> int:
    r = _redis()
    sel = selectors.DefaultSelector()

    bound = 0
    for port in range(PORT_START, PORT_END + 1):
        # Dual-stack: one socket per port, accepting both v4 and v6 sources.
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        try:
            sock.bind(("::", port))
        except OSError as exc:
            print(f"stun-observe: cannot bind {port}: {exc}", file=sys.stderr)
            sock.close()
            continue
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, port)
        bound += 1

    if bound == 0:
        print("stun-observe: no ports bound, exiting", file=sys.stderr)
        return 1

    print(
        f"stun-observe: listening on UDP {PORT_START}-{PORT_END} ({bound} ports)",
        flush=True,
    )
    while True:
        for key, _mask in sel.select(timeout=None):
            handle_packet(key.fileobj, key.data, r)


if __name__ == "__main__":
    raise SystemExit(main())
