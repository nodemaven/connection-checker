# Self-hosting the Connection Checker

The frontend is static and runs anywhere. The checks that compare *what your
browser reports* with *what the server observes* need a small backend on a host
with a **public IP and reachable UDP ports** — that is what makes the tool
trustworthy, and it is why a CDN in front of these endpoints will break them.

## What runs where

| Service | Port (localhost) | Public as | Purpose |
|---|---|---|---|
| coturn | UDP/TCP 3478 + relay range | `turn.example.com` (direct) | STUN/TURN relay |
| coturn redis | 6380 | — (internal) | per-session allocation store |
| stun-observe | UDP 20000–20063 | direct | records the real UDP source per session |
| turn-readback | 8004 | — (internal) | read-only view of what the relay saw |
| http3-probe | 8005 | `probe.example.com` | HTTP/3 (QUIC) + exit-IP probe |
| credentials | 8006 | `api.example.com` | mints TURN creds + proxies read-back |

The browser only ever talks to **`api.example.com`** and **`probe.example.com`**
(plus raw STUN/TURN to `turn.example.com`). `turn-readback` and `redis` stay on
localhost.

## Prerequisites

- A Linux server with a **public IPv4** and root/docker access.
- Docker + Docker Compose v2.
- A domain you control, and the ability to open UDP ports on the host/firewall.

## 1. DNS

Point three subdomains at your server. If your DNS is behind a proxy/CDN
(Cloudflare orange-cloud), set these **DNS-only** (grey-cloud) — TURN and QUIC
need to reach your box directly over UDP:

```
turn.example.com    A   YOUR_SERVER_IP
api.example.com     A   YOUR_SERVER_IP
probe.example.com   A   YOUR_SERVER_IP
```

## 2. Open the firewall / security-group ports

```
UDP  3478              STUN/TURN
TCP  3478              TURN over TCP
UDP  49160-51159       TURN relay range (matches turnserver.conf)
UDP  20000-20063       stun-observe pool
UDP  443               HTTP/3 (QUIC) for the probe
TCP  80, 443           your TLS reverse proxy
```

## 3. Configure secrets

```bash
cp .env.example .env
# generate and paste:
#   openssl rand -hex 32   -> TURN_STATIC_AUTH_SECRET  and  TURN_READBACK_SECRET
#   openssl rand -hex 24   -> REDIS_PASSWORD
# set TURN_HOST=turn.example.com and ALLOWED_ORIGIN=https://your-frontend-origin

# coturn's config is host-managed (it holds the shared secret) and git-ignored:
cp backend/coturn/turnserver.conf.example backend/coturn/turnserver.conf
# in that file set:
#   external-ip = YOUR_SERVER_IP/PRIVATE_IP
#   realm       = example.com
#   static-auth-secret = <same TURN_STATIC_AUTH_SECRET>
#   redis password     = <same REDIS_PASSWORD>
```

## 4. TLS reverse proxy

Terminate TLS for the two public HTTP services. `turn.example.com` is **not**
proxied — coturn speaks raw STUN/TURN on 3478.

The probe host **must** serve HTTP/3 and let the browser read timing
cross-origin. With Caddy this is essentially automatic:

```
api.example.com {
    reverse_proxy 127.0.0.1:8006
}

probe.example.com {
    reverse_proxy 127.0.0.1:8005
    # Caddy serves HTTP/3 and adds Alt-Svc automatically.
    # The app sets Access-Control-Allow-Origin and Timing-Allow-Origin — do not strip them.
}
```

## 5. Start the backend

```bash
docker compose up -d --build
docker compose ps        # everything healthy?
```

## 6. Point the frontend at your backend

Edit `frontend/config.js`:

```js
window.NM_TOOLS_API = { base: "https://api.example.com" };
window.NM_CONNCHECK_H3_BASE = "https://probe.example.com";
```

Then serve the `frontend/` folder from any static host (Netlify, GitHub Pages,
nginx, `python -m http.server`, …).

## 7. Verify

Open the page and run the check. On a normal connection every channel should
agree (green). Run it again through a proxy or VPN and watch the channels that
leak turn red.

### Troubleshooting

- **Everything "Unavailable"** — the frontend can't reach `api.example.com`.
  Check CORS (`ALLOWED_ORIGIN`) and that the proxy forwards to `:8006`.
- **HTTP/3 always "Could not measure"** — the probe host isn't serving QUIC on
  UDP 443, or a CDN is in front of it, or `Timing-Allow-Origin` is being
  stripped.
- **TURN always "Unavailable"** — the relay UDP range or 3478 is closed, or
  `external-ip` / `static-auth-secret` in `turnserver.conf` don't match `.env`.

## Optional: enable the TCP-relay channel

`turnserver.conf.example` ships with `no-tcp-relay` (TURN over TCP disabled) as a
safe default, because a TCP relay is a broader abuse surface. The tool's
**TCP-relay check** only works if you enable it: comment out `no-tcp-relay` in
your `turnserver.conf` and open **TCP 3478** on your firewall. Leave it off if
you don't need that channel — the other checks are unaffected.
