"""Tests for the disarmed-by-default n8n wiring. No real n8n: the lane's REST function is replaced by an in-memory fake."""
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
APPROVAL = "approve-run-1"
CANONICAL = {"CANON1": "Canonical One", "CANON2": "Canonical Two"}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


be = load("backend_under_test", ROOT / "tools" / "breaker_n8n_backend.py")
sim_tests = load("sim_tests_for_backend", ROOT / "tests" / "test_breaker_simulate.py")


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("real network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


class FakeRest:
    """In-memory stand-in for the lane's api(); ``store`` mirrors what a transport fake needs."""

    def __init__(self, **knobs):
        self.knobs, self.calls, self.store, self.n = knobs, [], {}, 0
        self.canonical = {i: {"id": i, "name": n, "active": False, "updatedAt": "t0", "versionId": "v0",
                              "nodes": [], "connections": {}, "settings": {}} for i, n in CANONICAL.items()}

    def api(self, method, path, payload=None):
        self.calls.append((method, path))
        if method == "POST" and path == "/api/v1/workflows":
            self.n += 1
            workflow_id = self.knobs.get("forced_id") or f"new-{self.n}"
            self.store[workflow_id] = json.loads(json.dumps(payload))
            return 200, {"id": workflow_id}
        if method == "GET" and path.startswith("/api/v1/workflows?"):
            everything = [*self.canonical.values(), *({"id": i, "name": d["name"], "active": False, "updatedAt": "t1",
                                                       "versionId": "v1"} for i, d in self.store.items())]
            cursor = int(path.split("cursor=")[1]) if "cursor=" in path else 0
            page = everything[cursor:cursor + 2]
            more = cursor + 2 < len(everything)
            return 200, {"data": page, "nextCursor": str(cursor + 2) if more else None}
        if path.startswith("/api/v1/workflows/"):
            workflow_id = path.rsplit("/", 1)[1]
            if method == "GET":
                if workflow_id in self.canonical:
                    return 200, dict(self.canonical[workflow_id])
                if workflow_id in self.store:
                    stored = json.loads(json.dumps(self.store[workflow_id]))
                    stored.update({"id": workflow_id, "versionId": "v1", "createdAt": "t1", "active": False})
                    if self.knobs.get("rename_on_read"):
                        stored["name"] = "renamed elsewhere"
                    return 200, stored
                return 404, "not found"
            if method == "DELETE":
                if self.knobs.get("delete_status"):
                    return self.knobs["delete_status"], "refused"
                if self.knobs.get("ghost"):
                    return 200, {}
                self.store.pop(workflow_id, None)
                return 200, {}
        raise AssertionError(f"unexpected request {method} {path}")


def definition(name="[BREAKER SIMULATE] abc", **extra):
    return {"name": name, "description": "", "nodes": [], "connections": {}, "settings": {"executionOrder": "v1"}, **extra}


@pytest.fixture
def rest(monkeypatch):
    fake = FakeRest()
    monkeypatch.setattr(be._lane, "api", fake.api)
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    monkeypatch.setenv(be.ENV_APPROVAL, APPROVAL)
    monkeypatch.setenv("N8N_API_KEY", "synthetic-not-a-key")
    return fake


def backend(**kw):
    return be.N8nBackend(expected_base_url=BASE, approval=kw.pop("approval", APPROVAL),
                         protected_ids=kw.pop("protected_ids", CANONICAL), **kw)


def test_disarmed_by_default_and_on_a_wrong_approval_makes_no_call(rest, monkeypatch):
    for approval in ("", "wrong"):
        b = backend(approval=approval)
        assert not b.armed
        for call in (lambda: b.create(definition()), lambda: b.read("x"), lambda: b.delete("x"), lambda: b.snapshot(),
                     lambda: be.make_transport(b)):
            with pytest.raises(be.BackendDisarmed):
                call()
    monkeypatch.delenv(be.ENV_APPROVAL)
    assert not backend().armed and not backend(approval="").armed
    assert rest.calls == []


def test_base_url_mismatch_is_refused_before_any_call(rest, monkeypatch):
    monkeypatch.setenv("N8N_BASE_URL", "http://somewhere-else.invalid")
    with pytest.raises(be.BackendRefused):
        backend().create(definition())
    assert rest.calls == []


@pytest.mark.parametrize("bad", [definition("Not Breaker"), definition(active=True), {"nodes": []}, definition(name=7)])
def test_only_disposable_inactive_workflows_can_be_created(rest, bad):
    with pytest.raises(be.BackendRefused):
        backend().create(bad)
    assert rest.calls == []


def test_create_read_delete_cycle_is_identity_checked_and_journaled(rest, tmp_path):
    b = backend(journal_path=tmp_path / "created.jsonl")
    workflow_id = b.create(definition())
    assert b.read(workflow_id)["name"] == "[BREAKER SIMULATE] abc"
    b.delete(workflow_id)
    assert workflow_id not in rest.store and workflow_id not in b.created
    lines = [json.loads(x) for x in (tmp_path / "created.jsonl").read_text().splitlines()]
    assert [x["event"] for x in lines] == ["created", "deleted"] and lines[0]["id"] == workflow_id


@pytest.mark.parametrize("target", ["CANON1", "CANON2", "never-created"])
def test_canonical_and_foreign_workflows_cannot_be_read_or_deleted(rest, target):
    b = backend()
    for call in (b.read, b.delete):
        with pytest.raises(be.BackendRefused):
            call(target)
    assert rest.calls == [] and set(rest.canonical) == set(CANONICAL)


def test_a_created_id_that_collides_with_a_protected_one_is_refused(monkeypatch):
    fake = FakeRest(forced_id="CANON1")
    monkeypatch.setattr(be._lane, "api", fake.api)
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    monkeypatch.setenv(be.ENV_APPROVAL, APPROVAL)
    monkeypatch.setenv("N8N_API_KEY", "synthetic-not-a-key")
    with pytest.raises(be.BackendRefused):
        backend().create(definition())


def test_delete_refuses_when_server_identity_differs_or_delete_does_not_take_effect(monkeypatch):
    for knobs, text in (({"rename_on_read": True}, "identity"), ({"delete_status": 400}, "delete failed"),
                        ({"ghost": True}, "still present")):
        fake = FakeRest()
        monkeypatch.setattr(be._lane, "api", fake.api)
        monkeypatch.setenv("N8N_BASE_URL", BASE)
        monkeypatch.setenv(be.ENV_APPROVAL, APPROVAL)
        monkeypatch.setenv("N8N_API_KEY", "synthetic-not-a-key")
        b = backend()
        workflow_id = b.create(definition())
        fake.knobs.update(knobs)
        with pytest.raises(be.BackendRefused, match=text):
            b.delete(workflow_id)
        assert workflow_id in b.created


def test_snapshot_paginates_and_diff_detects_any_movement(rest):
    b = backend()
    before = b.snapshot(digest_ids=["CANON1"])
    assert set(before["workflows"]) == set(CANONICAL) and before["definition_digests"]["CANON1"]
    assert be.diff_snapshots(before, b.snapshot(digest_ids=["CANON1"])) == []
    workflow_id = b.create(definition())
    assert any("appeared" in p for p in be.diff_snapshots(before, b.snapshot(digest_ids=["CANON1"])))
    b.delete(workflow_id)
    assert be.diff_snapshots(before, b.snapshot(digest_ids=["CANON1"])) == []
    rest.canonical["CANON1"]["updatedAt"] = "t9"
    assert any("changed" in p for p in be.diff_snapshots(before, b.snapshot(digest_ids=["CANON1"])))
    rest.canonical["CANON1"]["updatedAt"] = "t0"
    rest.canonical["CANON1"]["nodes"] = [{"name": "x"}]
    assert any("digest" in p for p in be.diff_snapshots(before, b.snapshot(digest_ids=["CANON1"])))
    del rest.canonical["CANON2"]
    assert any("disappeared" in p for p in be.diff_snapshots(before, b.snapshot(digest_ids=["CANON1"])))


class RecordingTransport:
    endpoint = BASE + "/mcp-server/http"

    def __init__(self):
        self.calls = []

    def call_tool_retrying(self, name, arguments, **kwargs):
        self.calls.append((name, arguments))
        return {}, {}


def test_guarded_transport_allows_only_two_operations_on_created_workflows(rest):
    b = backend()
    workflow_id = b.create(definition())
    inner = RecordingTransport()
    guarded = be.GuardedTransport(inner, b)
    guarded.call_tool_retrying("test_workflow", {"workflowId": workflow_id})
    guarded.call_tool_retrying("get_workflow_execution", {"workflowId": workflow_id, "executionId": "1"})
    assert len(inner.calls) == 2
    for name, target in (("test_workflow", "CANON1"), ("test_workflow", "never-created"),
                         ("update_workflow", workflow_id), ("execute_workflow", workflow_id),
                         ("archive_workflow", workflow_id), ("publish_workflow", workflow_id)):
        with pytest.raises(be.BackendRefused):
            guarded.call_tool_retrying(name, {"workflowId": target})
    assert len(inner.calls) == 2 and not hasattr(guarded, "call_tool")
    other = RecordingTransport()
    other.endpoint = "http://elsewhere.invalid/mcp"
    with pytest.raises(be.BackendRefused):
        be.GuardedTransport(other, b)


class KwargTransport(RecordingTransport):
    def call_tool_retrying(self, name, arguments, **kwargs):
        self.calls.append((name, kwargs))
        return {}, {}


def test_executions_are_never_retried_and_the_budget_is_enforced(rest):
    b = backend()
    workflow_id = b.create(definition())
    inner = KwargTransport()
    guarded = be.GuardedTransport(inner, b, max_executions=3)
    for _ in range(3):
        guarded.call_tool_retrying("test_workflow", {"workflowId": workflow_id}, attempts=3)
    with pytest.raises(be.BackendRefused):
        guarded.call_tool_retrying("test_workflow", {"workflowId": workflow_id})
    assert [kw for _, kw in inner.calls] == [{"attempts": 1}] * 3
    guarded.call_tool_retrying("get_workflow_execution", {"workflowId": workflow_id, "executionId": "1"})
    assert inner.calls[-1] == ("get_workflow_execution", {})  # reads may still retry; they cannot run anything


def test_create_budget_counts_attempts_even_when_the_request_failed(rest):
    b = backend(max_creates=2)
    first, second = b.create(definition()), b.create(definition())
    with pytest.raises(be.BackendRefused):
        b.create(definition())
    assert len({first, second}) == 2 and rest.n == 2
    failing = backend(max_creates=1)
    rest.knobs["forced_id"] = "CANON1"
    with pytest.raises(be.BackendRefused):
        failing.create(definition())  # id collision after the request: still spent
    with pytest.raises(be.BackendRefused, match="budget"):
        failing.create(definition())


def test_guarded_transport_refuses_everything_when_disarmed(rest):
    armed = backend()
    workflow_id = armed.create(definition())
    disarmed = backend(approval="")
    disarmed.created[workflow_id] = "[BREAKER SIMULATE] abc"
    inner = RecordingTransport()
    with pytest.raises(be.BackendDisarmed):
        be.GuardedTransport(inner, disarmed).call_tool_retrying("test_workflow", {"workflowId": workflow_id})
    assert inner.calls == []


def test_runner_works_end_to_end_over_the_real_wiring_with_fakes(rest, tmp_path):
    path = sim_tests.write_cases(tmp_path)
    b = backend()
    inner = sim_tests.FakeTransport(rest, route=lambda n, i: 1 if i.get("route") == "normal" or i.get("misroute") else 0,
                                    transform=lambda n, i: i)
    inner.endpoint = BASE + "/mcp-server/http"
    guarded = be.GuardedTransport(inner, b)
    before = b.snapshot(digest_ids=list(CANONICAL))
    result = sim_tests.sim.simulate(path, backend=b, transport=guarded, mechanism=sim_tests.MECHANISM,
                                    out_root=tmp_path / "runs", run_id="wired", check_ids={"misrouted": "SYNTHETIC-CHECK"})
    statuses = {c.case_id: c.status for g in result.groups for c in g.cases}
    assert result.status == "COMPLETED" and statuses["misrouted"] == "PRODUCT_FAIL" and statuses["urgent"] == "CONFORMS"
    assert all(g.cleanup == "DELETED" for g in result.groups) and not b.created and not rest.store
    assert be.diff_snapshots(before, b.snapshot(digest_ids=list(CANONICAL))) == []
    assert not any(method in ("PUT", "PATCH") for method, _ in rest.calls)
    assert all(path.endswith(("/workflows", "limit=100")) or "/workflows" in path for _, path in rest.calls)


def test_module_policy_gate():
    source = (ROOT / "tools" / "breaker_n8n_backend.py").read_text(encoding="utf-8").lower()
    for token in ("ngrok", "mcp_call_tool", "urlopen", "lead", "customer", "invoice", "pindata", '"put"', '"patch"', "/activate"):
        assert token not in source, token
