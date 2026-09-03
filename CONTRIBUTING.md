# Contributing

Thanks for your interest in improving the Connection Checker.

## Ground rules

- Open an issue before a large change so we can agree on the approach.
- Keep pull requests focused, one concern per PR.
- Match the surrounding style. The backend is Python (Flask); the frontend is
  dependency-free vanilla JS on purpose, please keep it that way.

## Running the tests

```bash
# credentials service
cd backend/credentials && pip install -r requirements.txt pytest && python -m pytest -q

# http3-probe
cd backend/http3-probe && pip install -r requirements.txt pytest && python -m pytest -q

# stun-observe
cd backend/coturn/stun-observe && pip install -r requirements.txt pytest && python -m pytest -q

# turn-readback
cd backend/coturn/turn-readback && pip install -r requirements.txt pytest && python -m pytest -q
```

These four suites are what the `tests` badge on the README reflects. CI runs the
same four, plus a parse-only syntax check of the frontend.

## Help wanted

**Frontend tests.** `frontend/app.js` holds all of the leak-detection logic and
currently has no behavioural tests, only a `node --check` parse in CI. The pure
helpers near the top of the file are the obvious place to start: `classifyFamily`,
`normalizeAddress`, `toIpv6Bytes`, `sameIpv6Prefix64`, `isLocalAddress`,
`dedupeCandidates` and `inferTypeFromCandidateString`. They take strings and
return values, so they can be tested without a browser. Any test runner is fine
as long as it stays a dev dependency and the shipped frontend remains
dependency-free.

## Local frontend

Serve `frontend/` from any static server and point `frontend/config.js` at a
running backend (see [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)).

## Never commit

Secrets, `.env` files, TLS keys, or `turnserver.conf`. See [SECURITY.md](SECURITY.md).
