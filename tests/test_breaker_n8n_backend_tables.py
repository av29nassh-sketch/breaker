"""Offline tests for guarded disposable data-table operations."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import socket
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5678"
APPROVAL = "approve-tables"
SCHEMA = [{"name": "label", "type": "string"}, {"name": "count", "type": "number"}]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


be = load("backend_tables_under_test", ROOT / "tools" / "breaker_n8n_backend.py")



@pytest.fixture(autouse=True)
def one_canonical_table(monkeypatch):
    """The public build ships no canonical table ids; give the protection rule one to refuse."""
    monkeypatch.setitem(be._lane.CANONICAL_TABLES, "canonical", "CanonicalTableFake01")

class FakeTables:
    def __init__(self, **knobs):
        self.knobs, self.calls, self.tables, self.n = knobs, [], {}, 0
        self.protected = {"protected": {"id": "protected", "name": "client_data", "columns": SCHEMA,
                                         "createdAt": "c0", "updatedAt": "u0"}}

    def api(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path.startswith("/api/v1/workflows?"):
            return 200, {"data": [], "nextCursor": None}
        if method == "POST" and path == "/api/v1/data-tables":
            if self.knobs.get("post_status"):
                return self.knobs["post_status"], "failed"
            self.n += 1
            table_id = self.knobs.get("forced_id", f"table-{self.n}")
            self.tables[table_id] = {"id": table_id, "name": payload["name"], "columns": payload["columns"],
                                     "createdAt": "c1", "updatedAt": "u1", "rows": []}
            return 201, {"id": table_id}
        if path == "/api/v1/data-tables?limit=100" or path.startswith("/api/v1/data-tables?limit=100&cursor="):
            values = [*self.protected.values(), *({k: v for k, v in t.items() if k != "rows"}
                                                    for t in self.tables.values())]
            offset = int(path.split("cursor=")[1]) if "cursor=" in path else 0
            page = values[offset:offset + 2]
            return 200, {"data": page, "nextCursor": str(offset + 2) if offset + 2 < len(values) else None}
        if path.startswith("/api/v1/data-tables/"):
            tail = path[len("/api/v1/data-tables/"):]
            if tail.endswith("/rows?limit=250"):
                table_id = tail.split("/", 1)[0]
                table = self.tables.get(table_id) or self.protected.get(table_id)
                if table is None:
                    return 404, "not found"
                return 200, {"data": list(table.get("rows", [])), "nextCursor": None}
            if tail.endswith("/rows/clear"):
                table_id = tail.split("/", 1)[0]
                self.tables[table_id]["rows"] = []
                return 204, None
            if tail.endswith("/rows") and method == "POST":
                table_id = tail.split("/", 1)[0]
                rows = payload.get("data", payload.get("rows", []))
                if not self.knobs.get("drop_rows"):
                    self.tables[table_id]["rows"].extend(rows)
                return 201, {"count": len(rows)}
            table_id = tail
            table = self.tables.get(table_id) or self.protected.get(table_id)
            if method == "GET":
                if table is None:
                    return 404, "not found"
                record = {k: v for k, v in table.items() if k != "rows"}
                if self.knobs.get("verification_mismatch") and table_id in self.tables:
                    record["name"] = "breaker_sim_elsewhere"
                if self.knobs.get("rename") and table_id in self.tables:
                    record["name"] = "breaker_sim_other"
                return 200, record
            if method == "DELETE":
                if not self.knobs.get("ghost_delete"):
                    self.tables.pop(table_id, None)
                return self.knobs.get("delete_status", 200), {}
        raise AssertionError(f"unexpected request {method} {path}")


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("real network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


@pytest.fixture
def fake(monkeypatch):
    rest = FakeTables()
    monkeypatch.setattr(be._lane, "api", rest.api)
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    monkeypatch.setenv(be.ENV_APPROVAL, APPROVAL)
    monkeypatch.setenv("N8N_API_KEY", "synthetic-not-a-key")
    return rest


def backend(**kwargs):
    return be.N8nBackend(expected_base_url=BASE, approval=kwargs.pop("approval", APPROVAL), **kwargs)


def create(b, rest, **knobs):
    rest.knobs.update(knobs)
    return b.create_table("breaker_sim_unit", SCHEMA)


def test_disarmed_new_methods_refuse_without_calls(fake, monkeypatch):
    b = backend(approval="wrong", protected_table_ids=("protected",))
    for call in (lambda: b.create_table("breaker_sim_a", SCHEMA), lambda: b.table_rows("table-1"),
                 lambda: b.reset_table("table-1", ["label"], []), lambda: b.delete_table("table-1"),
                 lambda: b.snapshot(include_tables=True, table_digest_ids=["protected"])):
        with pytest.raises(be.BackendDisarmed):
            call()
    assert fake.calls == []


@pytest.mark.parametrize("name,columns", [
    ("other", SCHEMA), ("breaker_sim_", SCHEMA), ("breaker_sim_bad-", SCHEMA),
    ("breaker_sim_ok", []), ("breaker_sim_ok", [{"name": "id", "type": "string"}]),
    ("breaker_sim_ok", [{"name": "bad-name", "type": "string"}]),
    ("breaker_sim_ok", [{"name": "x", "type": "object"}]),
    ("breaker_sim_ok", [{"name": "x", "type": "string"}, {"name": "x", "type": "number"}]),
    ("breaker_sim_ok", [{"name": "createdAt", "type": "date"}]),
])
def test_invalid_names_and_columns_refuse_before_requests(fake, name, columns):
    with pytest.raises(be.BackendRefused):
        backend().create_table(name, columns)
    assert fake.calls == []


def test_table_budget_is_spent_before_even_failed_post(fake):
    b = backend(max_tables=1)
    with pytest.raises(be.BackendRefused, match="create failed"):
        create(b, fake, post_status=400)  # a client error: nothing was created, so no listing follows
    with pytest.raises(be.BackendRefused, match="budget"):
        b.create_table("breaker_sim_next", SCHEMA)
    assert b.table_create_attempts == 1
    assert [c[0] for c in fake.calls] == ["POST"]


@pytest.mark.parametrize("forced,protected", [("protected", ("protected",)),
                                              ("CanonicalTableFake01", ()), ("table-1", ())])
def test_protected_canonical_and_colliding_ids_are_not_owned(fake, forced, protected):
    original = {}
    if forced == "table-1":
        b = backend()
        create(b, fake)
        original = dict(b.created_tables)
        fake.knobs["forced_id"] = forced
    else:
        b = backend(protected_table_ids=protected)
        fake.knobs["forced_id"] = forced
    with pytest.raises(be.BackendRefused, match="collid"):
        b.create_table("breaker_sim_unit", SCHEMA)
    assert b.created_tables == original
    assert len([c for c in fake.calls if c[0] == "POST"]) == (2 if forced == "table-1" else 1)


def test_verification_failure_keeps_table_owned_for_cleanup(fake, tmp_path):
    b = backend(journal_path=tmp_path / "events.jsonl")
    with pytest.raises(be.BackendRefused, match="verification"):
        create(b, fake, verification_mismatch=True)
    assert b.created_tables == {"table-1": "breaker_sim_unit"}
    fake.knobs.pop("verification_mismatch")
    b.delete_table("table-1")
    assert not b.created_tables


def test_create_payload_project_id_and_event_journal(fake, tmp_path):
    b = backend(table_project_id="proj-1", journal_path=tmp_path / "events.jsonl")
    table_id = create(b, fake)
    assert fake.calls[0] == ("POST", "/api/v1/data-tables", {"name": "breaker_sim_unit", "columns": SCHEMA,
                                                                  "projectId": "proj-1"})
    b.delete_table(table_id)
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert [(e["event"], e["id"], e["name"]) for e in events] == [
        ("table_created", table_id, "breaker_sim_unit"), ("table_deleted", table_id, "breaker_sim_unit")]


def test_reset_clears_seeds_projects_and_verifies_numeric_equivalence(fake):
    b = backend()
    table_id = create(b, fake)
    fake.tables[table_id]["rows"] = [{"label": "old", "count": 9}]
    seeds = [{"label": "a", "count": 1}, {"label": "b", "count": 2, "extra": "ignored"}]
    assert b.reset_table(table_id, ["label", "count"], seeds) == 2
    fake.tables[table_id]["rows"][0]["count"] = 1.0
    assert b.table_rows(table_id) == [{"label": "a", "count": 1.0}, {"label": "b", "count": 2}]
    assert b.reset_table(table_id, ["label", "count"], []) == 0


def test_reset_refuses_when_fake_drops_rows(fake):
    b = backend()
    table_id = create(b, fake, drop_rows=True)
    with pytest.raises(be.BackendRefused, match="table reset did not land"):
        b.reset_table(table_id, ["label", "count"], [{"label": "a", "count": 1}])


@pytest.mark.parametrize("method", ["table_rows", "reset_table", "delete_table"])
@pytest.mark.parametrize("target", ["foreign", "protected", "canonical"])
def test_non_owned_protected_and_canonical_tables_refuse_without_requests(fake, method, target):
    ids = {"foreign": "foreign", "protected": "protected", "canonical": "CanonicalTableFake01"}
    b = backend(protected_table_ids=(ids["protected"],))
    fn = getattr(b, method)
    args = (ids[target], ["label"], []) if method == "reset_table" else (ids[target],)
    with pytest.raises(be.BackendRefused):
        fn(*args)
    assert fake.calls == []


def test_delete_identity_and_still_present_guards(fake, monkeypatch):
    b = backend()
    table_id = create(b, fake)
    fake.knobs["rename"] = True
    count = len(fake.calls)
    with pytest.raises(be.BackendRefused, match="identity"):
        b.delete_table(table_id)
    assert not any(c[0] == "DELETE" for c in fake.calls[count:])
    fake.knobs.pop("rename")
    fake.knobs["ghost_delete"] = True
    with pytest.raises(be.BackendRefused, match="still present"):
        b.delete_table(table_id)
    assert table_id in b.created_tables


def test_snapshot_tables_pagination_named_digests_and_diff(fake):
    b = backend(protected_table_ids=("protected",))
    table_id = create(b, fake)
    fake.tables["unowned-page"] = {"id": "unowned-page", "name": "breaker_sim_other", "columns": SCHEMA,
                                    "rows": [], "createdAt": "c", "updatedAt": "u"}
    fake.tables[table_id]["rows"] = [{"count": 1, "label": "a"}]
    before = b.snapshot(include_tables=True, table_digest_ids=["protected", table_id, "absent"])
    assert before["tables"]["protected"] == {"name": "client_data", "createdAt": "c0", "updatedAt": "u0"}
    assert set(before["table_row_digests"]) == {"protected", table_id, "absent"}
    assert before["table_row_digests"]["absent"] is None
    assert len(before["table_row_digests"][table_id]) == 64
    assert "/api/v1/data-tables?limit=100&cursor=2" in [c[1] for c in fake.calls]
    after = b.snapshot(include_tables=True, table_digest_ids=["protected"])
    fake.protected["protected"]["updatedAt"] = "u1"
    fake.protected["protected"]["rows"] = [{"label": "changed", "count": 7}]
    changed = b.snapshot(include_tables=True, table_digest_ids=["protected"])
    messages = be.diff_snapshots(after, changed)
    assert any("table protected changed" in m for m in messages)
    assert any("protected table row digest changed" in m for m in messages)
    extra = {**changed, "tables": {**changed["tables"], "new": {"name": "x"}}}
    assert any("table new appeared" in m for m in be.diff_snapshots(changed, extra))
    gone = {**changed, "tables": {k: v for k, v in changed["tables"].items() if k != "protected"}}
    assert any("table protected disappeared" in m for m in be.diff_snapshots(changed, gone))


def test_created_and_deleted_table_is_absent_from_diff_and_snapshot_default_shape(fake):
    b = backend()
    before = b.snapshot()
    assert set(before) == {"workflows", "definition_digests"}
    table_id = create(b, fake)
    b.delete_table(table_id)
    after = b.snapshot()
    assert be.diff_snapshots(before, after) == []
    assert be.diff_snapshots(b.snapshot(include_tables=True), b.snapshot(include_tables=True)) == []


def test_prefix_of_another_disposable_table_is_not_ownership(fake):
    fake.tables["someone-elses"] = {"id": "someone-elses", "name": "breaker_sim_foreign", "columns": SCHEMA,
                                     "rows": [], "createdAt": "c", "updatedAt": "u"}
    b = backend()
    with pytest.raises(be.BackendRefused):
        b.delete_table("someone-elses")
    assert not fake.calls



def test_ownership_check_refuses_protected_and_canonical_ids_even_if_state_were_corrupted(monkeypatch):
    backend = be.N8nBackend(expected_base_url="http://127.0.0.1:5678", approval="x", protected_table_ids=["client-table"])
    canonical = str("CanonicalTableFake01")
    backend.created_tables["client-table"] = "breaker_sim_x"
    backend.created_tables[canonical] = "breaker_sim_y"
    for table_id in ("client-table", canonical):
        with pytest.raises(be.BackendRefused):
            backend._own_table(table_id)


# ---- a create whose outcome is unknown must never leave a table nobody owns ---------------------------------------------
def unknown_outcome(fake, monkeypatch, mode, list_fails=False):
    original = fake.api

    def api(method, path, payload=None):
        if method == "POST" and path == "/api/v1/data-tables":
            if mode != "never_created":
                original(method, path, payload)  # the server did create the table
            if mode == "no_id":
                return 201, {}
            if mode in ("bad_gateway", "never_created"):
                return 502, "bad gateway"
            if mode == "timeout":
                raise OSError("timed out")
        if list_fails and path.startswith("/api/v1/data-tables?limit=100"):
            raise OSError("listing failed")
        return original(method, path, payload)

    monkeypatch.setattr(be._lane, "api", api)


@pytest.mark.parametrize("mode", ["no_id", "bad_gateway", "timeout"])
def test_an_unanswered_create_is_adopted_by_its_unique_name_so_teardown_can_delete_it(fake, monkeypatch, mode):
    unknown_outcome(fake, monkeypatch, mode)
    b = backend(max_tables=2)
    with pytest.raises(be.BackendRefused):
        b.create_table("breaker_sim_run1_0_leads", SCHEMA)
    assert list(b.created_tables.values()) == ["breaker_sim_run1_0_leads"] and not b.possible_orphans
    b.delete_table(next(iter(b.created_tables)))
    assert not b.created_tables and not [t for t in fake.tables]


def test_an_unlocatable_table_is_recorded_as_a_possible_orphan_not_hidden(fake, monkeypatch):
    unknown_outcome(fake, monkeypatch, "timeout", list_fails=True)
    b = backend()
    with pytest.raises(be.BackendRefused):
        b.create_table("breaker_sim_run1_0_leads", SCHEMA)
    assert b.possible_orphans == ["breaker_sim_run1_0_leads"] and not b.created_tables


def test_a_refused_or_never_created_table_is_not_adopted_and_is_not_an_orphan(fake, monkeypatch):
    unknown_outcome(fake, monkeypatch, "never_created")
    b = backend()
    with pytest.raises(be.BackendRefused):
        b.create_table("breaker_sim_run1_0_leads", SCHEMA)
    assert not b.created_tables and not b.possible_orphans
    fake.knobs["post_status"] = 400  # a client error means nothing was created: no listing is even attempted
    monkeypatch.setattr(be._lane, "api", fake.api)
    seen = len(fake.calls)
    b2 = backend()
    with pytest.raises(be.BackendRefused):
        b2.create_table("breaker_sim_run1_0_leads", SCHEMA)
    assert [c[0] for c in fake.calls[seen:]] == ["POST"] and not b2.possible_orphans


def test_adoption_never_takes_a_protected_or_foreign_table_of_the_same_name(fake, monkeypatch):
    unknown_outcome(fake, monkeypatch, "no_id")
    fake.protected["protected"]["name"] = "breaker_sim_run1_0_leads"  # a protected table that happens to carry the name
    fake.tables.clear()
    b = backend(protected_table_ids=["protected"])
    with pytest.raises(be.BackendRefused):
        b.create_table("breaker_sim_run1_0_leads", SCHEMA)
    assert "protected" not in b.created_tables
    assert set(b.created_tables) == {t for t in fake.tables}  # only the table this request created
