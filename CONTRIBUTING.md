# Contributing

1. `python -m pytest -q` must pass offline. The guard in `conftest.py` fails the session if a test reaches the network,
   Docker or another program; a new test file that does so needs an entry in `config/offline-test-policy.json`.
2. Never commit credentials, real workflow exports, client data, instance ids or URLs of real instances. Use
   `*.invalid` emails and `127.0.0.1` in fixtures.
3. Keep the tool honest: a change must not let a report claim more than its evidence (no "verified", no readiness).
4. Prefer refusing over guessing. New node types or Data Table operations need a probe that proves them first.
