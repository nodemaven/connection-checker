# API

The frontend talks to two backends, configured in `frontend/config.js`:

- `NM_TOOLS_API.base` → the **credentials service** (`backend/credentials`)
- `NM_CONNCHECK_H3_BASE` → the **HTTP/3 probe** (`backend/http3-probe`)

All responses are JSON. CORS is enabled so the frontend can be served from a
different origin than the backends.

## Credentials service (`NM_TOOLS_API.base`)

### `GET /ip`
Returns the caller's public exit IP.
```json
{ "ip": "203.0.113.9" }
```

### `GET /ip/<ip>`
Enrich an IP (ISP/ASN). Ships as a pass-through returning just the IP; wire a
geo provider in `ip_enrich()` for richer output. The frontend degrades to
showing the IP alone.
```json
{ "ip": "203.0.113.9" }
```

### `GET /webrtc/turn-credentials`
Mint a short-lived TURN REST credential (UDP + TCP) and a STUN-observe session.
```json
{
  "username": "1700000000:<hex>",
  "credential": "<base64 HMAC-SHA1>",
  "ttl": 120,
  "urls": ["stun:turn.example.com:3478", "turn:turn.example.com:3478?transport=udp"],
  "tcp": { "username": "...-tcp", "credential": "...", "urls": ["turn:...?transport=tcp"] },
  "stun": { "url": "stun:turn.example.com:20002", "token": "<hex>" }
}
```

### `GET /webrtc/turn-observed?username=<username>`
What coturn observed on the TURN relay for a minted credential.
```json
{ "found": true, "ip": "203.0.113.9" }
```

### `GET /webrtc/stun-observed?token=<token>`
What the STUN-observe service saw for a session token.
```json
{ "found": true, "ip": "203.0.113.9" }
```

## HTTP/3 probe (`NM_CONNCHECK_H3_BASE`)

### `GET /ip`
Forced-IPv4 exit IP (host must have no AAAA record). Used by the frontend to
resolve a v4 baseline so it doesn't false-flag a dual-stack line.

### `GET /h3probe`
A tiny endpoint the browser fetches repeatedly; the client reads the negotiated
protocol from its own Resource Timing entry (this host must serve HTTP/3 and
send `Alt-Svc` + `Timing-Allow-Origin: *`).

## Internal (not public)

`turn-readback` (`/allocation-status`, `/stun/session`, `/stun/observed`) is
bound to localhost and guarded by `X-Internal-Secret`; only the credentials
service calls it.
