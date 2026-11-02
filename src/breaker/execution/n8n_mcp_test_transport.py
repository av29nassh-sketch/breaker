"""Minimal MCP (JSON-RPC over streamable HTTP) client for n8n's first-party MCP server.

Why this transport: n8n's queue+CLI path reports execution mode `production`/`cli`, which the
Lead Qualification engine deliberately rejects for its controlled-input hook (the hook is
honoured only in `test`/`manual`). n8n's MCP server executes a workflow through the same
first-party test path the editor uses, so it yields `test` mode and can drive the frozen
workflow unmodified. This is a transport only: it starts executions and reads them back.

The bearer token is read from the named environment variable `MCP_N8N_API_KEY` and is never
logged, stored, or echoed.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

#: No endpoint is compiled in. Supply the instance you are allowed to use, either as a full MCP endpoint
#: (``BREAKER_N8N_MCP_ENDPOINT``) or as a base URL for the instance (``N8N_BASE_URL``).
ENV_MCP_ENDPOINT = "BREAKER_N8N_MCP_ENDPOINT"
DEFAULT_ENDPOINT = ""
ENV_VAR = "MCP_N8N_API_KEY"


class McpTransportError(RuntimeError):
    pass


def _default_endpoint() -> str:
    """The instance's own MCP endpoint, from configuration; nothing is compiled in."""
    configured = (os.environ.get(ENV_MCP_ENDPOINT) or "").strip()
    if configured:
        return configured.rstrip("/")
    base = (os.environ.get("N8N_BASE_URL") or "").strip().rstrip("/")
    if base:
        return f"{base}/mcp-server/http"
    raise McpTransportError(
        f"no n8n MCP endpoint configured: set {ENV_MCP_ENDPOINT} to the full endpoint or N8N_BASE_URL to the "
        f"instance's base URL.")


class N8nMcpTestTransport:
    """Start and follow workflow test executions on an n8n instance via its MCP server."""

    def __init__(self, endpoint: str | None = None, *, timeout: int = 180):
        self.endpoint = (endpoint or os.environ.get("N8N_MCP_ENDPOINT") or _default_endpoint()).rstrip("/")
        self.timeout = timeout
        self._session_id: str | None = None
        self._next_id = 1

    # ---- plumbing -------------------------------------------------------
    def _token(self) -> str:
        token = os.environ.get(ENV_VAR)
        if not token:
            raise McpTransportError(
                f"{ENV_VAR} is not set; the n8n MCP transport cannot authenticate. "
                "Set it in the environment (never in code or in a committed file)."
            )
        return token

    def _post(self, payload: dict) -> tuple[int, dict | None, dict]:
        request = urllib.request.Request(self.endpoint, method="POST")
        request.add_header("Authorization", f"Bearer {self._token()}")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json, text/event-stream")
        if self._session_id:
            request.add_header("Mcp-Session-Id", self._session_id)
        raw = json.dumps(payload).encode()
        try:
            with urllib.request.urlopen(request, raw, timeout=self.timeout) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                text = response.read().decode("utf-8", "replace")
                return response.status, _decode_body(text), headers
        except urllib.error.HTTPError as error:
            text = error.read().decode("utf-8", "replace")
            return error.code, _decode_body(text), {}

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        message_id = self._next_id
        self._next_id += 1
        body = {"jsonrpc": "2.0", "id": message_id, "method": method}
        if params is not None:
            body["params"] = params
        status, decoded, headers = self._post(body)
        if headers.get("mcp-session-id"):
            self._session_id = headers["mcp-session-id"]
        if decoded is None:
            raise McpTransportError(f"{method} failed: HTTP {status}")
        if "error" in decoded:
            raise McpTransportError(f"{method} error: {json.dumps(decoded['error'])[:400]}")
        return decoded.get("result", {})

    # ---- MCP surface ----------------------------------------------------
    def initialize(self) -> dict:
        result = self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "breaker", "version": "1.0.0"},
        })
        self._notify("notifications/initialized")
        return result

    def _notify(self, method: str) -> None:
        self._post({"jsonrpc": "2.0", "method": method})

    def list_tools(self) -> list[dict]:
        if self._session_id is None:
            self.initialize()
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> dict:
        if self._session_id is None:
            self.initialize()
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        for entry in result.get("content", []) or []:
            if isinstance(entry, dict) and entry.get("type") == "text":
                decoded = _decode_body(entry.get("text") or "")
                if isinstance(decoded, dict):
                    return decoded
        return result

    def call_tool_retrying(self, name: str, arguments: dict, *, attempts: int = 3,
                           base_delay: float = 2.0, require: tuple[str, ...] = ()) -> tuple[dict, dict]:
        """Call a tool, retrying transient transport faults, and report the attempt trail.

        Returns (result, trail). A response that lacks a required key is treated as a
        transient fault, never as target evidence: a failed read-back must not be allowed to
        look like a wrong result.
        """
        import time

        trail: list[dict] = []
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                result = self.call_tool(name, arguments)
                missing = [key for key in require if not result.get(key)]
                if missing:
                    last_error = McpTransportError(f"INCOMPLETE_RESPONSE missing={missing}")
                    trail.append({"attempt": attempt, "outcome": "INCOMPLETE_RESPONSE", "missing": missing})
                else:
                    trail.append({"attempt": attempt, "outcome": "OK"})
                    return result, {"attempts": len(trail), "trail": trail}
            except Exception as error:  # noqa: BLE001 - classify, then retry or re-raise
                last_error = error
                transient = _is_transient(error)
                trail.append({"attempt": attempt, "outcome": "TRANSIENT" if transient else "FATAL",
                              "error": f"{type(error).__name__}: {str(error)[:200]}"})
                if not transient:
                    break
            if attempt < attempts:
                self._session_id = None
                time.sleep(base_delay * attempt)
        raise McpTransportError(f"TRANSPORT_FAILURE after {len(trail)} attempt(s): {last_error}")


def _is_transient(error: Exception) -> bool:
    text = f"{type(error).__name__}: {error}".lower()
    markers = ("ssl", "eof", "timed out", "timeout", "connection", "reset", "unreachable",
               "temporarily", "502", "503", "504", "incomplete_response")
    return any(marker in text for marker in markers)


def _decode_body(text: str) -> dict | None:
    """Accept a plain JSON body or a streamable-HTTP SSE frame."""
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    for line in text.splitlines():
        if line.startswith("data:"):
            candidate = line[5:].strip()
            if candidate.startswith("{"):
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    continue
    return None
