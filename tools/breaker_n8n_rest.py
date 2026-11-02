"""Minimal n8n public-API helpers used by the guarded backend (REST side).

Reads ``N8N_BASE_URL`` and ``N8N_API_KEY`` from the environment; never logs either. The guarded backend in
``breaker_n8n_backend.py`` replaces ``api`` with a redirect-refusing copy and checks ownership before every write,
so nothing here should be called directly by other code.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

DEFINITION_KEYS = ("name", "description", "nodes", "connections", "settings")

#: Table ids the backend refuses to write whatever the run declares, on top of ``--protect-table``.
#: ponytail: empty in the public build; add your own instance's critical tables here or pass --protect-table.
CANONICAL_TABLES: dict[str, str] = {}


class LaneError(RuntimeError):
    """An n8n API invariant failed; nothing further may be inferred from the run."""


def base_url() -> str:
    url = os.environ.get("N8N_BASE_URL", "").rstrip("/")
    if not url:
        raise LaneError("N8N_BASE_URL is not configured")
    return url


def api_key() -> str:
    key = os.environ.get("N8N_API_KEY", "")
    if not key:
        raise LaneError("N8N_API_KEY is not configured")
    return key


def api(method: str, path: str, payload=None) -> tuple[int, object]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(base_url() + path, method=method, data=data)
    request.add_header("X-N8N-API-KEY", api_key())
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, (json.loads(body) if body.strip() else None)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")[:600]


def must(method: str, path: str, payload=None) -> object:
    status, body = api(method, path, payload)
    if status not in (200, 201):
        raise LaneError(f"{method} {path} -> HTTP {status}: {str(body)[:400]}")
    return body


def canonical_digest(payload: dict) -> str:
    projection = {key: payload.get(key) for key in DEFINITION_KEYS}
    blob = json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def create_workflow(definition: dict) -> dict:
    # The n8n public API refuses unknown body properties, so only send what it accepts.
    allowed = ("name", "nodes", "connections", "settings", "staticData", "pinData")
    body = {key: definition[key] for key in allowed
            if key in definition and definition[key] is not None}
    if "settings" not in body:
        body["settings"] = {"executionOrder": "v1"}
    created = must("POST", "/api/v1/workflows", body)
    if not isinstance(created, dict) or not created.get("id"):
        raise LaneError(f"workflow creation returned no id: {str(created)[:300]}")
    return created


def read_workflow(workflow_id: str) -> dict:
    return must("GET", f"/api/v1/workflows/{workflow_id}")


def rows(table_id: str, limit: int = 250) -> list[dict]:
    collected: list[dict] = []
    path = f"/api/v1/data-tables/{table_id}/rows?limit={limit}"
    while path:
        status, body = api("GET", path)
        if status != 200 or not isinstance(body, dict):
            raise LaneError(f"row read failed for {table_id}: HTTP {status} {str(body)[:200]}")
        page = body.get("data") or []
        if not isinstance(page, list):
            raise LaneError(f"row read for {table_id} did not return a list")
        collected.extend(page)
        cursor = body.get("nextCursor")
        path = (f"/api/v1/data-tables/{table_id}/rows?limit={limit}&cursor="
                f"{urllib.parse.quote(str(cursor), safe='')}" if cursor else "")
    return collected


def insert_rows(table_id: str, columns: list[str], seeds: list[dict]) -> int:
    if not seeds:
        return 0
    payload = [{key: seed.get(key) for key in columns} for seed in seeds]
    status, body = api("POST", f"/api/v1/data-tables/{table_id}/rows",
                       {"data": payload, "returnType": "count"})
    if status not in (200, 201):
        raise LaneError(f"seed write failed: HTTP {status} {str(body)[:300]}")
    visible = len(rows(table_id))
    if visible < len(payload):
        raise LaneError(f"seed write did not land: {visible} rows visible, expected {len(payload)}")
    return len(payload)


def clear_rows(table_id: str) -> None:
    if table_id in CANONICAL_TABLES.values():
        raise LaneError("refusing to clear a canonical data table")
    status, body = api("DELETE", f"/api/v1/data-tables/{table_id}/rows/clear")
    if status not in (200, 201, 204):
        raise LaneError(f"clear failed: HTTP {status} {str(body)[:300]}")
