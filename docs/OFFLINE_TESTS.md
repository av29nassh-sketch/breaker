# Offline test policy

`python -m pytest` must never contact n8n, Docker, a mail sink or any other service, whatever credentials or settings
the shell happens to hold.

## What happens on every test run

1. `conftest.py` imports `tools/offline_guard.py` and installs the guard **before anything else is imported**, so
   collection and import-time side effects are covered, not only test bodies.
2. Credentials and service settings (names matching `N8N`, `MCP_`, `DOCKER`, `*API_KEY`, `*TOKEN`, `*SECRET`,
   `*PASSW*`, cloud and provider prefixes, ...) are removed from the process environment. Only the names are reported.
3. The guard refuses, raises `OfflineViolation` (an `OSError`) and **records** every attempt; the session exits non-zero
   if anything was recorded, even when a test caught the exception:
   - socket connects, except to a loopback port bound by the test process tree itself (a test's own fake server) and
     the closed loopback port 1; well-known service ports (n8n 5678, mail 25/587/1025/8025, Docker 2375/2376,
     databases) stay blocked even if something bound them; DNS lookups of non-loopback names;
   - asyncio connects, UDP sends, and opens of Docker's named pipe or socket;
   - every subprocess except local `git` sub-commands and Python children (which get the same guard);
   - `os.system`, `os.popen`, `os.startfile`, `os.spawn*` and `webbrowser` opens.

This public suite has no live tests. `config/offline-test-policy.json` lists, for every test file that mentions a
construct able to reach outside the process, what it actually does; an unlisted one fails the check.

## The protection boundary

This is a Python-level guard, not operating-system network isolation. It cannot see C extensions that open sockets
themselves, `_winapi`/`ctypes` calls, pipe handles opened by other low-level APIs, or programs started by something it
does not wrap. For absolute isolation, also run the suite in a network-less container or VM.
