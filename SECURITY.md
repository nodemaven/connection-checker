# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Email
**security@nodemaven.com** with details and steps to reproduce. We'll
acknowledge within a few business days.

## Notes for self-hosters

- All secrets are read from the environment. Generate fresh values
  (`openssl rand -hex 32`) and never reuse them across environments.
- `turn-readback` and `redis` must stay bound to localhost — only the
  `credentials` and `http3-probe` services are meant to be public.
- Set `ALLOWED_ORIGIN` to your exact frontend origin in production rather than
  `*`.
- The minted TURN credentials are short-lived (120s) and single-session by
  design; don't lengthen the TTL without understanding the trade-off.
