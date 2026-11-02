"""Synthetic, offline coverage for the generic simulation runner and evidence adapter."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import pathlib
import socket
import sys
import urllib.request

import pytest
from breaker.execution.n8n_mcp_test_transport import N8nMcpTestTransport
from breaker.readiness.model import (CheckModelError, CheckOutcome, CheckStatus, EvidenceClass,
                                     EvidenceProvenance)
from breaker.verification.taxonomy import Verdict

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sim = load("sim_under_test", ROOT / "tools" / "breaker_simulate.py")
evidence = load("sim_evidence_under_test", ROOT / "tools" / "breaker_sim_evidence.py")
neutralise = load("sim_neutralise_fixture", ROOT / "tools" / "breaker_neutralise.py")
B = "n8n-nodes-base."
MECHANISM_RECORD = {"execution_id": "SYNTHETIC-TEST-RECORD-NOT-A-REAL-EXECUTION",
                    "observed_output_equals_declared": True, "node_type": "n8n-nodes-base.set",
                    "type_version": 3.4, "synthetic": True}
MECHANISM = neutralise.Mechanism("n8n-nodes-base.set", 3.4,
    lambda stub: {"mode": "raw", "jsonOutput": json.dumps(stub, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                  "includeOtherFields": False, "options": {}}, MECHANISM_RECORD)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


class FakeBackend:
    def __init__(self, **knobs):
        self.store = {}
        self.calls = []
        self.knobs = knobs
        self.n = 0

    def create(self, definition):
        self.calls.append(("create", definition))
        if self.knobs.get("fail_create"):
            raise RuntimeError("create failed")
        self.n += 1
        clone_id = f"clone-{self.n}"
        self.store[clone_id] = json.loads(json.dumps(definition))
        return clone_id

    def read(self, clone_id):
        self.calls.append(("read", clone_id))
        if self.knobs.get("refuse_delete_name") and self.knobs.get("rename_on_read"):
            self.store[clone_id]["name"] = "changed"
        value = json.loads(json.dumps(self.store[clone_id]))
        value.update({"id": clone_id, "versionId": "server-version", "createdAt": "synthetic", "active": self.knobs.get("active_on_read", False)})
        if self.knobs.get("tamper_on_read"):
            value["description"] = "tampered"
        return value

    def delete(self, clone_id):
        self.calls.append(("delete", clone_id))
        if self.knobs.get("refuse_delete_name"):
            raise RuntimeError("delete refused")
        del self.store[clone_id]


class FakeTransport:
    def __init__(self, backend, **knobs):
        self.backend, self.knobs = backend, knobs
        self.calls, self.runs, self.n = [], {}, 0

    def call_tool_retrying(self, name, arguments, *, attempts=3, base_delay=2.0, require=()):
        self.calls.append((name, arguments))
        if self.knobs.get("raise_on") == name:
            raise RuntimeError("transport failure")
        if name == "test_workflow":
            self.n += 1
            eid = f"exec-{self.n}"
            if self.knobs.get("no_execution_id"):
                return {}, {}
            definition = self.backend.store[arguments["workflowId"]]
            entry = arguments["triggerNodeName"]
            payload = arguments["pinData"][entry][0]["json"]
            nodes = {n["name"]: n for n in definition["nodes"]}
            run_data, outputs, queue = {}, {}, [(entry, payload)]
            while queue:
                name_now, item = queue.pop(0)
                node = nodes[name_now]
                typ = node["type"]
                if typ == B + "set" and "jsonOutput" in node.get("parameters", {}):
                    out = json.loads(node["parameters"]["jsonOutput"])
                elif typ == B + "switch":
                    idx = self.knobs.get("route", lambda n, i: 0)(name_now, item)
                    outputs[name_now] = [item]
                    run_data[name_now] = [{"data": {"main": [[{"json": item}]]}}]
                    queue.extend((edge["node"], item) for edge in definition["connections"].get(name_now, {}).get("main", [[], []])[idx])
                    continue
                else:
                    out = self.knobs.get("transform", lambda n, i: i)(name_now, item)
                if name_now in {"Notify On-call", "Queue Ticket"} and self.knobs.get("tamper_stub_output"):
                    out = {"wrong": True}
                items = out if isinstance(out, list) else [out]
                outputs[name_now] = items
                run_data[name_now] = [{"data": {"main": [[{"json": x} for x in items]]}}]
                for ports in definition["connections"].get(name_now, {}).get("main", []):
                    queue.extend((edge["node"], item_out) for edge in ports for item_out in items)
            if self.knobs.get("drop_entry"):
                run_data.pop(entry, None)
            if self.knobs.get("extra_unknown_node_in_run_data"):
                run_data["Ghost"] = [{"data": {"main": [[{"json": {}}]]}}]
            self.runs[eid] = {"status": self.knobs.get("status", "success"),
                              "data": {"resultData": {"runData": run_data}}}
            return {"executionId": eid}, {}
        if name == "get_workflow_execution":
            if self.knobs.get("odd_shape"):
                return {"status": "success", "data": {}}, {}
            response = self.runs[arguments["executionId"]]
            if self.knobs.get("status") == "error":
                response["status"] = "error"
            return response, {}
        raise AssertionError(f"unexpected transport operation {name}")


def workflow():
    return {"name": "W3", "nodes": [
        {"id": "src-intake", "name": "Intake", "type": B + "webhook", "parameters": {}},
        {"id": "src-triage", "name": "Triage", "type": B + "switch", "parameters": {}},
        {"id": "src-notify", "name": "Notify On-call", "type": B + "httpRequest", "parameters": {},
         "credentials": {"httpHeaderAuth": {"id": "credential-secret-id", "name": "Distinctive Secret Name"}}},
        {"id": "src-queue", "name": "Queue Ticket", "type": B + "httpRequest", "parameters": {}},
        {"id": "src-summary", "name": "Summarise", "type": B + "set", "parameters": {"mode": "manual"}},
    ], "connections": {
        "Intake": {"main": [[{"node": "Triage", "type": "main", "index": 0}]]},
        "Triage": {"main": [[{"node": "Notify On-call", "type": "main", "index": 0}],
                             [{"node": "Queue Ticket", "type": "main", "index": 0}]]},
        "Notify On-call": {"main": [[{"node": "Summarise", "type": "main", "index": 0}]]},
        "Queue Ticket": {"main": [[{"node": "Summarise", "type": "main", "index": 0}]]}}, "settings": {}}


def write_cases(tmp_path, *, cases=None, definition=None):
    definition = definition or workflow()
    wf = tmp_path / "workflow.json"
    raw = json.dumps(definition, separators=(",", ":"), ensure_ascii=False).encode()
    wf.write_bytes(raw)
    rows = cases or [
        {"id": "urgent", "input": {"route": "urgent"}, "stubs": {"Notify On-call": {"ok": True}, "Queue Ticket": {"queued": True}},
         "output_assertions": [{"node": "Summarise", "item": 0, "path": "ok", "equals": True}], "must_run": ["Notify On-call"], "must_not_run": ["Queue Ticket"]},
        {"id": "normal", "input": {"route": "normal"}, "stubs": {"Notify On-call": {"ok": True}, "Queue Ticket": {"queued": True}},
         "output_assertions": [{"node": "Summarise", "item": 0, "path": "queued", "equals": True}], "must_run": ["Queue Ticket"], "must_not_run": ["Notify On-call"]},
        {"id": "other-stub", "input": {"route": "normal"}, "stubs": {"Notify On-call": {"ok": True}, "Queue Ticket": {"queued": "other"}},
         "must_run": ["Queue Ticket"]},
        {"id": "misrouted", "input": {"route": "urgent", "misroute": True}, "stubs": {"Notify On-call": {"ok": True}, "Queue Ticket": {"queued": True}},
         "output_assertions": [{"node": "Summarise", "item": 0, "path": "ok", "equals": True}], "must_run": ["Notify On-call"]},
    ]
    doc = {"schema_version": 1, "workflow": {"path": "workflow.json", "sha256": hashlib.sha256(raw).hexdigest()},
           "entry_node": "Intake", "cases": rows}
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return path


def fixture(tmp_path, **backend_knobs):
    path = write_cases(tmp_path)
    backend = FakeBackend(**backend_knobs)
    transport = FakeTransport(backend, route=lambda name, item: 1 if item.get("route") == "normal" or item.get("misroute") else 0,
                              transform=lambda name, item: item)
    return path, backend, transport


def run(tmp_path, **kw):
    path, backend, transport = fixture(tmp_path, **kw.pop("backend_knobs", {}))
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id=kw.pop("run_id", "one"), **kw)
    return result, backend, transport


def test_end_to_end_groups_cleanup_and_evidence_ingest(tmp_path):
    result, backend, transport = run(tmp_path, check_ids={"misrouted": "CHECK-1"})
    assert result.status == "COMPLETED"
    statuses = {case.case_id: case.status for group in result.groups for case in group.cases}
    assert statuses == {"urgent": "CONFORMS", "normal": "CONFORMS", "other-stub": "CONFORMS", "misrouted": "PRODUCT_FAIL"}
    assert len([call for call in backend.calls if call[0] == "create"]) == 2
    assert all(group.cleanup == "DELETED" for group in result.groups) and not backend.store
    assert len(transport.calls) == 8
    assert all(list(args["pinData"]) == ["Intake"] for name, args in transport.calls if name == "test_workflow")
    assert (result.run_dir / "run.json").exists() and (result.run_dir / "campaigns" / "simulate.json").exists()
    report = json.loads((result.run_dir / "run.json").read_text())
    assert report["run_id"] == result.run_id and report["source_sha256"] and report["source_definition_digest"]
    assert all(group["transformed_definition_digest"] and group["manifest"] for group in report["groups"])
    text = "".join(p.read_text(encoding="utf-8") for p in result.run_dir.rglob("*") if p.is_file())
    assert "credential-secret-id" not in text and "Distinctive Secret Name" not in text
    ingested = evidence.ingest(result.run_dir)
    assert ingested.accepted == ("CHECK-1",)
    records = list(ingested.book.records)
    assert len(records) == 1 and str(records[0].provenance) == "SYNTHETIC_FIXTURE"
    assert records[0].recorded_verdict == Verdict.PRODUCT_FAIL
    assert all(record.recorded_verdict != Verdict.PASS for record in records)


def test_all_conforms_and_unique_run_directories(tmp_path):
    path, backend, transport = fixture(tmp_path)
    # All rows are conforming under the synthetic route.
    doc = json.loads(path.read_text())
    doc["cases"] = doc["cases"][:3]
    doc["cases"][2]["output_assertions"] = [{"node": "Summarise", "item": 0, "path": "queued", "equals": "other"}]
    path.write_text(json.dumps(doc), encoding="utf-8")
    first = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM, out_root=tmp_path / "runs", run_id="a")
    before = {p.relative_to(first.run_dir): p.read_bytes() for p in first.run_dir.rglob("*") if p.is_file()}
    second = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM, out_root=tmp_path / "runs", run_id="b")
    assert first.run_dir != second.run_dir
    assert all((first.run_dir / p).read_bytes() == data for p, data in before.items())
    campaign = json.loads((first.run_dir / "campaigns" / "simulate.json").read_text())
    assert campaign["environment"] == evidence.ENVIRONMENT == "SIMULATED"
    assert campaign["verdicts"] == [] and evidence.ingest(first.run_dir).accepted == ()
    with pytest.raises(FileExistsError):
        sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM, out_root=tmp_path / "runs", run_id="a")
    assert all((first.run_dir / p).read_bytes() == data for p, data in before.items())


@pytest.mark.parametrize("knobs", [
    {"raise_on": "test_workflow"}, {"raise_on": "get_workflow_execution"}, {"no_execution_id": True},
    {"status": "error"}, {"odd_shape": True}, {"tamper_stub_output": True},
    {"extra_unknown_node_in_run_data": True}, {"drop_entry": True},
])
def test_untrusted_observations_are_inconclusive_and_never_verdict(tmp_path, knobs):
    path, backend, transport = fixture(tmp_path)
    transport.knobs.update(knobs)
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="bad", check_ids={"urgent": "C"})
    cases = [case for group in result.groups for case in group.cases]
    assert all(case.status != "PRODUCT_FAIL" for case in cases)
    assert json.loads((result.run_dir / "campaigns" / "simulate.json").read_text())["verdicts"] == []


def test_case_without_assertions_is_inconclusive(tmp_path):
    path = write_cases(tmp_path, cases=[{"id": "empty", "input": {"route": "urgent"},
        "stubs": {"Notify On-call": {"ok": True}, "Queue Ticket": {"queued": True}}}])
    backend, transport = FakeBackend(), None
    transport = FakeTransport(backend, route=lambda n, i: 0, transform=lambda n, i: i)
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM, out_root=tmp_path / "runs")
    assert result.groups[0].cases[0].status == "INCONCLUSIVE"


@pytest.mark.parametrize("kind", ["tamper", "active"])
def test_clone_safety_reread_blocks_execution_but_deletes_clone(tmp_path, kind):
    path, backend, transport = fixture(tmp_path, **({"tamper_on_read": True} if kind == "tamper" else {"active_on_read": True}))
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id=kind)
    assert all(group.status == "BLOCKED" for group in result.groups)
    assert not transport.calls and all(group.cleanup == "DELETED" for group in result.groups)


def test_blocked_preconditions_never_call_adapters_and_write_report(tmp_path):
    path, backend, transport = fixture(tmp_path)
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=neutralise.SET_RAW_JSON,
                          out_root=tmp_path / "runs", run_id="unverified")
    assert result.status == "BLOCKED" and not backend.calls and not transport.calls
    assert (result.run_dir / "run.json").exists()
    wrong = neutralise.Mechanism(MECHANISM.node_type, 3.4, MECHANISM.parameters_for,
        {**MECHANISM_RECORD, "node_type": "other"})
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=wrong,
                          out_root=tmp_path / "runs", run_id="wrong")
    assert result.status == "BLOCKED" and not backend.calls and not transport.calls


def test_invalid_cases_hash_mismatch_and_unsafe_workflow_block_without_calls(tmp_path):
    path, backend, transport = fixture(tmp_path)
    path.write_text("{}", encoding="utf-8")
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="invalid")
    assert result.status == "BLOCKED" and not backend.calls and not transport.calls
    path = write_cases(tmp_path)
    doc = json.loads(path.read_text())
    doc["workflow"]["sha256"] = "0" * 64
    path.write_text(json.dumps(doc), encoding="utf-8")
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="hash-mismatch")
    assert result.status == "BLOCKED" and not backend.calls and not transport.calls
    path = write_cases(tmp_path, definition={"name": "unsafe", "nodes": [
        {"name": "Intake", "type": B + "webhook", "parameters": {}},
        {"name": "Code", "type": B + "code", "parameters": {}},
        {"name": "Form", "type": B + "formTrigger", "parameters": {}},
        {"name": "DB", "type": "n8n-nodes-base.supabase", "parameters": {}},
        {"name": "Call", "type": B + "httpRequest", "parameters": {}}], "connections": {}, "settings": {}},
        cases=[{"id": "x", "input": {}, "stubs": {"Call": {"ok": True}}}])
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="unsafe")
    assert result.status == "BLOCKED" and not backend.calls and not transport.calls
    assert result.reasons


def test_create_failure_cleanup_failure_and_strict_json_comparison(tmp_path):
    path, backend, transport = fixture(tmp_path, fail_create=True)
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="create-fail")
    assert all(group.status == "INCONCLUSIVE" for group in result.groups)
    path, backend, transport = fixture(tmp_path, refuse_delete_name=True)
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="delete-fail")
    assert all(group.cleanup.startswith("FAILED:") for group in result.groups)
    assert sim._json_equal(True, 1) is False
    path, backend, transport = fixture(tmp_path, refuse_delete_name=True, rename_on_read=True)
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="identity-mismatch")
    assert all(group.cleanup == "FAILED: identity mismatch, not deleted" for group in result.groups)


def test_contract_environment_and_core_guard():
    assert {"attempts", "base_delay", "require"} <= set(inspect.signature(N8nMcpTestTransport.call_tool_retrying).parameters)
    assert evidence.ENVIRONMENT == "SIMULATED"
    class DynamicEvidence:
        pass
    with pytest.raises(CheckModelError):
        CheckOutcome("C", CheckStatus.PASS, Verdict.PASS, None, "", (), ("e",),
                     (EvidenceClass.DYNAMIC,), "SIMULATED", provenance=(EvidenceProvenance.SYNTHETIC_FIXTURE,))


def test_campaign_environment_and_module_policy_gate():
    assert evidence.ENVIRONMENT == "SIMULATED"
    for filename in ("breaker_simulate.py", "breaker_sim_evidence.py"):
        source = (ROOT / "tools" / filename).read_text(encoding="utf-8").lower()
        for token in ("ngrok", "mcp_call_tool", "mcp_endpoint", "urllib", "socket", "requests", "lead",
                      "customer", "invoice", "support_", "qualif"):
            assert token not in source, (filename, token)

