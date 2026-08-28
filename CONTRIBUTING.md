# Contributing

Thanks for your interest in improving the Connection Checker.

## Ground rules

- Open an issue before a large change so we can agree on the approach.
- Keep pull requests focused — one concern per PR.
- Match the surrounding style. The backend is Python (Flask); the frontend is
  dependency-free vanilla JS on purpose — please keep it that way.

## Running the tests

```bash
# credentials service
cd backend/credentials && pip install -r requirements.txt pytest && python -m pytest -q

# http3-probe
cd backend/http3-probe && pip install -r requirements.txt pytest && python -m pytest -q

# stun-observe
cd backend/coturn/stun-observe && pip install -r requirements.txt pytest && python -m pytest -q
```

## Local frontend

Serve `frontend/` from any static server and point `frontend/config.js` at a
running backend (see [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)).

## Never commit

Secrets, `.env` files, TLS keys, or `turnserver.conf`. See [SECURITY.md](SECURITY.md).
