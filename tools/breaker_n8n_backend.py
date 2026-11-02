"""Real n8n wiring for the generic simulation runner, DISARMED by default.

The runner takes an injected ``backend`` and ``transport``. This module supplies the real ones with the smallest
possible surface, reusing the Ops lane's REST helpers (``api``/``must``/``create_workflow``/``read_workflow``) and
Core's ``N8nMcpTestTransport``; it never uses the lane's MCP helpers.

Every method that would contact n8n raises ``BackendDisarmed`` unless the operator has armed the backend: the
``approval`` string passed to the constructor must equal the ``BREAKER_S4_APPROVAL`` environment variable, which
only the operator sets, and ``N8N_BASE_URL`` must equal the base URL the operator approved. The backend can create
only disposable workflows named ``[BREAKER SIMULATE]`` or ``[BREAKER PROBE]``, and can read, run or delete only the
workflows it created itself. It has no update, activate or archive operation, so an existing workflow cannot be
changed through it. It can also create, seed, read and delete only disposable ``breaker_sim_`` data tables it
created itself; it cannot write to operator-protected or canonical tables. ``snapshot`` and ``diff_snapshots`` are
the read-only evidence that nothing else moved.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

_ROOT = pathlib.Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_lane = _load("breaker_n8n_rest_backend", "breaker_n8n_rest.py")
NAME_PREFIXES = ("[BREAKER SIMULATE]", "[BREAKER PROBE]")
TRANSPORT_OPERATIONS = frozenset({"test_workflow", "get_workflow_execution"})
ENV_APPROVAL = "BREAKER_S4_APPROVAL"
TABLE_PREFIX = "breaker_sim_"
COLUMN_TYPES = ("string", "number", "boolean", "date")
SYSTEM_COLUMNS = frozenset({"id", "createdAt", "updatedAt"})


LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MCP_PATH = "/mcp-server/http"
MCP_ENDPOINT_ENV = ("BREAKER_N8N_MCP_ENDPOINT", "N8N_MCP_ENDPOINT", "MCP_N8N_ENDPOINT")


class BackendDisarmed(RuntimeError):
    pass


class BackendRefused(RuntimeError):
    pass


class VersionNotExposed(BackendRefused):
    """The instance answered like n8n (its public settings block) but that block carries no application version."""


def approved_origin(url):
    """The one local origin a run may talk to: ``scheme://loopback-host[:port]`` and nothing else."""
    parts = urlsplit(str(url).strip())
    try:
        port = parts.port
    except ValueError:
        raise BackendRefused(f"unusable port in {url!r}") from None
    if (parts.scheme not in ("http", "https") or parts.hostname not in LOOPBACK_HOSTS or parts.username
            or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment):
        raise BackendRefused(f"{url!r} is not a plain local base URL (loopback host only, no path, no credentials)")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def mcp_endpoint_for(base_url):
    return approved_origin(base_url) + MCP_PATH


def check_endpoint_environment(base_url):
    """Refuse a configuration in which the REST and MCP sides could point at different instances."""
    wanted = mcp_endpoint_for(base_url)
    for name in MCP_ENDPOINT_ENV:
        value = (os.environ.get(name) or "").strip()
        if value and value.rstrip("/") != wanted:
            raise BackendRefused(f"{name} points somewhere other than the approved instance")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the API key to a host nobody approved, so none is ever followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(*extra_handlers):
    return urllib.request.build_opener(_NoRedirect, *extra_handlers)


def install_no_redirects():
    """Make the process-wide opener refuse redirects, so Core's MCP transport (which uses the default opener) cannot follow one."""
    urllib.request.install_opener(make_opener())


_OPENER = make_opener()


def _api(method, path, payload=None):
    """The lane's ``api`` with one change: a redirect response is refused, never followed."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(_lane.base_url() + path, method=method, data=data)
    request.add_header("X-N8N-API-KEY", _lane.api_key())
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(request, timeout=180) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, (json.loads(body) if body.strip() else None)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise BackendRefused(f"{method} {path}: the server answered with a redirect (HTTP {error.code}); refused") from None
        return error.code, error.read().decode("utf-8", "replace")[:600]


def read_application_version(base_url, opener=None):
    """The n8n APPLICATION version (``versionCli``), read from the approved origin's public settings. One GET, no API key sent,
    no redirect followed. This is independent of the MCP server's own version, which says nothing about the application build."""
    request = urllib.request.Request(approved_origin(base_url) + "/rest/settings", method="GET")
    request.add_header("Accept", "application/json")
    try:
        with (opener or _OPENER).open(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as error:
        raise BackendRefused(f"application version unreadable: GET /rest/settings answered HTTP {error.code}") from None
    except (OSError, ValueError) as error:
        raise BackendRefused(f"application version unreadable: {type(error).__name__}") from None
    data = body.get("data", body) if isinstance(body, dict) else None
    version = data.get("versionCli") if isinstance(data, dict) else None
    if not isinstance(version, str) or not version.strip():
        if isinstance(data, dict) and ("settingsMode" in data or "userManagement" in data) and not data.get("versionCli"):
            raise VersionNotExposed("application version unreadable: the settings response has no versionCli")
        raise BackendRefused("application version unreadable: the settings response has no versionCli")
    return version.strip()


_lane.api = _api  # this module's private copy of the lane only; the lane's file is unchanged


class N8nBackend:
    def __init__(self, *, expected_base_url, approval, protected_ids=(), journal_path=None, max_creates=None,
                 max_tables=None, protected_table_ids=(), table_project_id=None):
        self.expected_base_url = approved_origin(expected_base_url)
        self.max_creates, self.create_attempts = max_creates, 0
        self.armed = bool(approval) and approval == os.environ.get(ENV_APPROVAL, "")
        self.protected = frozenset(protected_ids)
        self.created = {}
        self.max_tables, self.protected_table_ids = max_tables, frozenset(str(i) for i in protected_table_ids)
        self.table_project_id = table_project_id
        self.created_tables = {}
        self.possible_orphans = []  # names of tables a create may have made but that could not be located to own
        self.table_create_attempts = 0
        self.journal_path = pathlib.Path(journal_path) if journal_path else None

    def check(self):
        if not self.armed:
            raise BackendDisarmed("backend is not armed: no n8n call was made")
        if approved_origin(_lane.base_url()) != self.expected_base_url:
            raise BackendRefused("N8N_BASE_URL differs from the approved base URL: no n8n call was made")

    def _journal(self, event, workflow_id, name):
        if self.journal_path is not None:  # append-only, flushed per event, so a crash still names every created id
            with self.journal_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"event": event, "id": workflow_id, "name": name}, sort_keys=True) + "\n")

    def _own(self, workflow_id):
        if workflow_id in self.protected or workflow_id not in self.created:
            raise BackendRefused(f"workflow {workflow_id!r} was not created by this backend")

    def _own_table(self, table_id):
        table_id = str(table_id)
        if (table_id in self.protected_table_ids or table_id in {str(i) for i in _lane.CANONICAL_TABLES.values()}
                or table_id not in self.created_tables):
            raise BackendRefused(f"table {table_id!r} was not created by this backend")
        return table_id

    @staticmethod
    def _table_refusal(call):
        try:
            return call()
        except BackendRefused:
            raise
        except Exception as error:
            raise BackendRefused(str(error)) from None

    def create_table(self, name, columns):
        self.check()
        if not isinstance(name, str) or not re.fullmatch(r"breaker_sim_[A-Za-z0-9_]{1,51}", name):
            raise BackendRefused("table name must match breaker_sim_[A-Za-z0-9_]{1,51}")
        if not isinstance(columns, list) or not columns:
            raise BackendRefused("table columns must be a non-empty list")
        seen = set()
        for column in columns:
            if not isinstance(column, dict) or not isinstance(column.get("name"), str):
                raise BackendRefused("each table column needs a name and type")
            col_name, col_type = column["name"], column.get("type")
            if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", col_name) or col_name in SYSTEM_COLUMNS
                    or col_name in seen or col_type not in COLUMN_TYPES):
                raise BackendRefused("invalid, duplicate, or unsupported table column")
            seen.add(col_name)
        if self.max_tables is not None and self.table_create_attempts >= self.max_tables:
            raise BackendRefused(f"table create budget of {self.max_tables} is spent")
        self.table_create_attempts += 1
        payload = {"name": name, "columns": columns}
        if self.table_project_id is not None:
            payload["projectId"] = self.table_project_id
        try:
            status, body = _lane.api("POST", "/api/v1/data-tables", payload)
        except BackendRefused:
            raise
        except Exception as error:  # no answer: the server may still have created the table
            self._adopt_table_named(name)
            raise BackendRefused(f"table create did not complete ({type(error).__name__})") from None
        if status not in (200, 201) or not isinstance(body, dict) or body.get("id") in (None, ""):
            if status in (200, 201) or status >= 500:  # answered without a usable id: it may exist all the same
                self._adopt_table_named(name)
            raise BackendRefused(f"table create failed: HTTP {status}")
        table_id = str(body["id"])
        if (table_id in self.protected_table_ids or table_id in {str(i) for i in _lane.CANONICAL_TABLES.values()}
                or table_id in self.created_tables):
            raise BackendRefused(f"created table id {table_id!r} collides with a protected or owned table")
        # Own immediately after a usable POST id so verification failure cannot orphan an undeletable table.
        self.created_tables[table_id] = name
        try:
            current = _lane.must("GET", f"/api/v1/data-tables/{table_id}")
            actual_columns = [c.get("name") for c in (current.get("columns") or [])]
            if current.get("name") != name or actual_columns != [c["name"] for c in columns]:
                raise BackendRefused("created table verification differed from the requested name or columns")
        except Exception as error:
            self._journal("table_created", table_id, name)
            if isinstance(error, BackendRefused):
                raise
            raise BackendRefused(str(error)) from None
        self._journal("table_created", table_id, name)
        return table_id

    def _adopt_table_named(self, name):
        """After a create whose outcome is unknown, own the table the server holds under this run-unique name so that
        teardown can remove it; if it cannot be located, record the name as a possible orphan instead of hiding it."""
        canonical = {str(i) for i in _lane.CANONICAL_TABLES.values()}
        try:
            cursor = ""
            for _ in range(5):
                page = _lane.must("GET", "/api/v1/data-tables?limit=100" + (f"&cursor={cursor}" if cursor else ""))
                for item in page.get("data") or []:
                    table_id = str(item.get("id"))
                    if (item.get("name") == name and table_id not in self.protected_table_ids and table_id not in canonical
                            and table_id not in self.created_tables):
                        self.created_tables[table_id] = name
                        self._journal("table_created", table_id, name)
                        return table_id
                cursor = page.get("nextCursor") or ""
                if not cursor:
                    return None  # the whole listing was read and nothing carries this name: nothing was created
        except Exception:
            pass
        self.possible_orphans.append(name)
        return None

    def table_rows(self, table_id):
        self.check()
        table_id = self._own_table(table_id)
        return self._table_refusal(lambda: _lane.rows(table_id))

    @staticmethod
    def _canonical_table_row(row, columns):
        from decimal import Decimal, InvalidOperation
        def normalize(value):
            if isinstance(value, bool) or value is None:
                return value
            if isinstance(value, (int, float)):
                try:
                    return {"__number__": format(Decimal(str(value)).normalize(), "f")}
                except InvalidOperation:
                    return value
            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items()}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            return value
        return json.dumps({key: normalize(row.get(key)) for key in columns}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False)

    def reset_table(self, table_id, columns, seed_rows):
        self.check()
        table_id = self._own_table(table_id)
        if not isinstance(columns, list) or not all(isinstance(c, str) for c in columns):
            raise BackendRefused("columns must be a list of column names")
        if not isinstance(seed_rows, list):
            raise BackendRefused("seed_rows must be a list")
        def reset():
            _lane.clear_rows(table_id)
            if seed_rows:
                try:
                    _lane.insert_rows(table_id, columns, seed_rows)
                except Exception as error:
                    if "seed write did not land" in str(error):
                        raise BackendRefused("table reset did not land the requested rows") from None
                    raise
            actual = _lane.rows(table_id)
            expected_counts, actual_counts = {}, {}
            for row in seed_rows:
                key = self._canonical_table_row(row, columns)
                expected_counts[key] = expected_counts.get(key, 0) + 1
            for row in actual:
                key = self._canonical_table_row(row, columns)
                actual_counts[key] = actual_counts.get(key, 0) + 1
            if len(actual) != len(seed_rows) or actual_counts != expected_counts:
                raise BackendRefused("table reset did not land the requested rows")
            return len(seed_rows)
        return self._table_refusal(reset)

    def delete_table(self, table_id):
        self.check()
        table_id = self._own_table(table_id)
        name = self.created_tables[table_id]
        def delete():
            status, current = _lane.api("GET", f"/api/v1/data-tables/{table_id}")
            if status != 200 or not isinstance(current, dict):
                raise BackendRefused(f"table identity check failed: HTTP {status}")
            if current.get("name") != name or not str(current.get("name", "")).startswith(TABLE_PREFIX):
                raise BackendRefused("server table identity differs from what this backend created: not deleted")
            status, _ = _lane.api("DELETE", f"/api/v1/data-tables/{table_id}")
            if status not in (200, 204):
                raise BackendRefused(f"table delete failed: HTTP {status}")
            status, _ = _lane.api("GET", f"/api/v1/data-tables/{table_id}")
            if status != 404:
                raise BackendRefused("table is still present after delete")
            del self.created_tables[table_id]
            self._journal("table_deleted", table_id, name)
        return self._table_refusal(delete)

    def create(self, definition):
        self.check()
        name = definition.get("name")
        if not isinstance(name, str) or not name.startswith(NAME_PREFIXES):
            raise BackendRefused("only disposable [BREAKER SIMULATE] / [BREAKER PROBE] workflows may be created")
        if definition.get("active"):
            raise BackendRefused("an active definition may not be created")
        if self.max_creates is not None and self.create_attempts >= self.max_creates:
            raise BackendRefused(f"create budget of {self.max_creates} is spent")
        self.create_attempts += 1  # counted before the request, so a create that failed in flight still uses budget
        workflow_id = str(_lane.create_workflow(definition)["id"])
        if workflow_id in self.protected or workflow_id in self.created:
            raise BackendRefused(f"created id {workflow_id!r} collides with an existing workflow")
        self.created[workflow_id] = name
        self._journal("created", workflow_id, name)
        return workflow_id

    def read(self, workflow_id):
        self.check()
        self._own(workflow_id)
        return _lane.read_workflow(workflow_id)

    def delete(self, workflow_id):
        self.check()
        self._own(workflow_id)
        current = _lane.read_workflow(workflow_id)
        if current.get("name") != self.created[workflow_id] or current.get("active") is not False:
            raise BackendRefused("server identity differs from what this backend created: not deleted")
        status, _ = _lane.api("DELETE", f"/api/v1/workflows/{workflow_id}")
        if status not in (200, 204):
            raise BackendRefused(f"delete failed: HTTP {status}")
        if _lane.api("GET", f"/api/v1/workflows/{workflow_id}")[0] != 404:
            raise BackendRefused("workflow is still present after delete")
        name = self.created.pop(workflow_id)
        self._journal("deleted", workflow_id, name)

    def snapshot(self, digest_ids=(), *, include_tables=False, table_digest_ids=()):
        """Read-only record of every workflow on the instance, plus a definition digest for ``digest_ids``."""
        self.check()
        records, cursor = {}, ""
        for _ in range(50):
            page = _lane.must("GET", "/api/v1/workflows?limit=100" + (f"&cursor={cursor}" if cursor else ""))
            for item in page.get("data") or []:
                records[str(item["id"])] = {key: item.get(key) for key in ("name", "active", "updatedAt", "versionId")}
            cursor = page.get("nextCursor") or ""
            if not cursor:
                break
        else:
            raise BackendRefused("workflow listing did not finish within 50 pages")
        digests = {i: (_lane.canonical_digest(_lane.read_workflow(i)) if i in records else None) for i in digest_ids}
        result = {"workflows": records, "definition_digests": digests}
        if include_tables:
            tables, cursor = {}, ""
            for _ in range(50):
                page = _lane.must("GET", "/api/v1/data-tables?limit=100" + (f"&cursor={cursor}" if cursor else ""))
                for item in page.get("data") or []:
                    tables[str(item["id"])] = {key: item.get(key) for key in ("name", "createdAt", "updatedAt")}
                cursor = page.get("nextCursor") or ""
                if not cursor:
                    break
            else:
                raise BackendRefused("table listing did not finish within 50 pages")
            row_digests = {}
            for table_id in table_digest_ids:
                table_id = str(table_id)
                if table_id not in tables:
                    row_digests[table_id] = None
                    continue
                rows = self._table_refusal(lambda: _lane.rows(table_id))
                serialized = json.dumps(sorted(rows, key=lambda row: json.dumps(row, sort_keys=True,
                                   separators=(",", ":"))), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                row_digests[table_id] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            result["tables"] = tables
            result["table_row_digests"] = row_digests
        return result


def diff_snapshots(before, after):
    """Differences between two snapshots; an empty list means nothing on the instance changed."""
    problems = []
    for workflow_id, record in before["workflows"].items():
        if workflow_id not in after["workflows"]:
            problems.append(f"workflow {workflow_id} disappeared")
        elif after["workflows"][workflow_id] != record:
            problems.append(f"workflow {workflow_id} changed: {record} -> {after['workflows'][workflow_id]}")
    for workflow_id in after["workflows"].keys() - before["workflows"].keys():
        problems.append(f"workflow {workflow_id} appeared")
    if before["definition_digests"] != after["definition_digests"]:
        problems.append("a protected definition digest changed")
    if "tables" in before and "tables" in after:
        for table_id, record in before["tables"].items():
            if table_id not in after["tables"]:
                problems.append(f"table {table_id} disappeared")
            elif after["tables"][table_id] != record:
                problems.append(f"table {table_id} changed: {record} -> {after['tables'][table_id]}")
        for table_id in after["tables"].keys() - before["tables"].keys():
            problems.append(f"table {table_id} appeared")
    if ("table_row_digests" in before and "table_row_digests" in after
            and before["table_row_digests"] != after["table_row_digests"]):
        problems.append("a protected table row digest changed")
    return problems


class GuardedTransport:
    """Core's transport restricted to two operations on workflows this backend created."""

    def __init__(self, transport, backend, max_executions=None):
        self.max_executions, self.execution_attempts = max_executions, 0
        if str(getattr(transport, "endpoint", "")).rstrip("/") != backend.expected_base_url + MCP_PATH:
            raise BackendRefused("transport endpoint is not exactly the approved instance's MCP endpoint")
        self._transport, self._backend = transport, backend

    def preflight(self):
        """Read-only MCP discovery: server identity and the tool names it offers."""
        self._backend.check()
        info = self._transport.initialize()
        names = sorted(str(tool.get("name")) for tool in self._transport.list_tools())
        return {"serverInfo": (info or {}).get("serverInfo"), "protocolVersion": (info or {}).get("protocolVersion"),
                "tools": names}

    def call_tool_retrying(self, name, arguments, **kwargs):
        self._backend.check()
        if name not in TRANSPORT_OPERATIONS:
            raise BackendRefused(f"operation {name!r} is not permitted")
        self._backend._own(arguments.get("workflowId"))
        if name == "test_workflow":  # an execution is never re-sent: a retry after a timeout could run the workflow twice
            if self.max_executions is not None and self.execution_attempts >= self.max_executions:
                raise BackendRefused(f"execution budget of {self.max_executions} is spent")
            self.execution_attempts += 1
            kwargs["attempts"] = 1
        return self._transport.call_tool_retrying(name, arguments, **kwargs)


def make_transport(backend, max_executions=None):
    """Core's real transport, constructed only once the backend is armed, wrapped in the guard."""
    backend.check()
    check_endpoint_environment(backend.expected_base_url)
    install_no_redirects()
    from breaker.execution.n8n_mcp_test_transport import N8nMcpTestTransport
    return GuardedTransport(N8nMcpTestTransport(endpoint=mcp_endpoint_for(backend.expected_base_url)), backend, max_executions)
