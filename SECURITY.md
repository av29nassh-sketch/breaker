# Security

## Reporting a vulnerability
Please report suspected vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab) rather
than in a public issue. Include the Breaker commit, the command you ran, and what happened. Do not include API keys or
real workflow data.

## Design boundaries (what Breaker promises)
- It contacts only a loopback n8n origin you name, and only for a run armed with `BREAKER_S4_APPROVAL`.
- It never writes a workflow or Data Table it did not create in that run; creations are journalled and deleted by id.
- It never follows HTTP redirects (they could carry the API key elsewhere).
- Credentials are read from environment variables and never written to reports or logs.

Anything that breaks one of these is a security bug. The offline test guard is a Python-level safeguard for the test
suite, not operating-system isolation.
