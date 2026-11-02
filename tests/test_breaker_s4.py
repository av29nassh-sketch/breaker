"""Offline tests for the mechanism probe, the w3-mini fixture and the operator CLI. Fakes only: no n8n is contacted."""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import socket
import sys
import types
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5678"
LABEL = "t1"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cli = load("s4_cli_under_test", ROOT / "tools" / "breaker_s4_run.py")
backend_tests = load("backend_tests_for_s4", ROOT / "tests" / "test_breaker_n8n_backend.py")
be, probe, neutralise = cli.be, cli.probe, cli.neutralise
B = "n8n-nodes-base."
CANON = tuple(backend_tests.CANONICAL)


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("real network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    for name in ("N8N_BASE_URL", "N8N_API_KEY", "MCP_N8N_API_KEY", *be.MCP_ENDPOINT_ENV, be.ENV_APPROVAL):
        monkeypatch.delenv(name, raising=False)


class NormalisingRest(backend_tests.FakeRest):
    """A server that stores Set-node parameters differently from what was sent."""

    def api(self, method, path, payload=None):
        status, body = super().api(method, path, payload)
        if method == "GET" and status == 200 and isinstance(body, dict) and body.get("id") in self.store:
            for node in body["nodes"]:
                if node["type"].endswith(".set"):
                    node["parameters"]["addedByServer"] = True
        return status, body


class Executor:
    """A small n8n stand-in over the stored definition: entry passes items, Set emits its JSON (once if executeOnce),
    If routes on ``kind``, NoOp passes through. Anything else is an error, so a surprise node cannot go unnoticed."""

    def __init__(self, rest, **knobs):
        self.rest, self.knobs, self.calls, self.runs, self.n = rest, knobs, [], {}, 0
        self.endpoint = BASE + "/mcp-server/http"

    def initialize(self):
        self.calls.append("initialize")
        return {"serverInfo": {"name": "synthetic", "version": "0"}, "protocolVersion": "synthetic"}

    def list_tools(self):
        self.calls.append("list_tools")
        return [{"name": "test_workflow"}, {"name": "get_workflow_execution"}]

    def call_tool_retrying(self, name, arguments, *, attempts=3, base_delay=2.0, require=()):
        self.calls.append(name)
        if self.knobs.get("raise_on") == name:
            raise RuntimeError("transport failure")
        if name == "test_workflow":
            self.n += 1
            eid = f"exec-{self.n}"
            if self.knobs.get("no_execution_id"):
                return {}, {}
            self.runs[eid] = {"status": self.knobs.get("status", "success"),
                              "data": {"resultData": {"runData": self._run(arguments)}}}
            return {"executionId": eid}, {}
        if name == "get_workflow_execution":
            if self.knobs.get("odd_shape"):
                return {"status": "success", "data": {}}, {}
            return self.runs[arguments["executionId"]], {}
        raise AssertionError(f"unexpected operation {name}")

    def _run(self, arguments):
        definition = self.rest.store[arguments["workflowId"]]
        nodes = {n["name"]: n for n in definition["nodes"]}
        entry = arguments["triggerNodeName"]
        queue, run_data = [(entry, [x["json"] for x in arguments["pinData"][entry]])], {}
        while queue:
            current, items = queue.pop(0)
            node = nodes[current]
            kind, port = node["type"], 0
            if kind == B + "executeWorkflowTrigger" or kind == B + "noOp":
                out = items
            elif kind == B + "set" and "jsonOutput" in node["parameters"]:
                payload = json.loads(node["parameters"]["jsonOutput"])
                count = 1 if node.get("executeOnce") and not self.knobs.get("two_items") else len(items)
                out = [({**payload, **items[0]} if self.knobs.get("leak_sentinel") else payload) for _ in range(count)]
            elif kind == B + "if":
                port = 0 if items[0].get("kind") == "urgent" else 1
                out = items
            else:
                raise AssertionError(f"executor met an unexpected node type {kind}")
            run_data[current] = [{"data": {"main": [[{"json": x} for x in out]]}}]
            ports = definition["connections"].get(current, {}).get("main", [])
            if kind == B + "if":
                ports = [ports[port]] if len(ports) > port else []
            for edges in ports:
                queue.extend((edge["node"], out) for edge in edges)
        if self.knobs.get("extra_node"):
            run_data["Ghost"] = [{"data": {"main": [[{"json": {}}]]}}]
        return run_data


def make(tmp_path, monkeypatch, rest_class=backend_tests.FakeRest, approval=None, **knobs):
    rest = rest_class()
    monkeypatch.setattr(be._lane, "api", rest.api)
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    monkeypatch.setenv("N8N_API_KEY", "synthetic-not-a-key")
    monkeypatch.setenv(be.ENV_APPROVAL, approval or "armed")
    backend = be.N8nBackend(expected_base_url=BASE, approval="armed", protected_ids=CANON,
                            journal_path=tmp_path / "created.jsonl")
    executor = Executor(rest, **knobs)
    return rest, backend, executor, be.GuardedTransport(executor, backend)


def good_record(base_url=BASE):
    return {"execution_id": "exec-1", "run_ids": ["exec-1", "exec-2"], "observed_output_equals_declared": True,
            "executeOnce_confirmed": True, "stored_matches_sent": True, "node_type": "n8n-nodes-base.set",
            "type_version": 3.4, "base_url": base_url}


# ---------------------------------------------------------------- fixture
def test_w3_mini_fixture_is_valid_credential_free_and_classified_without_blocks():
    loaded = cli.cases_mod.load_cases(cli.FIXTURE)
    result = cli.probe._pf.evaluate(loaded.definition)
    assert not result.blocked and set(result.needs_neutralisation) == {"Notify On-call", "Queue Ticket"}
    assert [c.id for c in loaded.cases] == ["urgent", "normal", "deliberate-fail"]
    assert "DELIBERATE FAILING FIXTURE" in next(c for c in loaded.cases if c.id == "deliberate-fail").description
    assert "credentials" not in json.dumps(loaded.definition)
    assert len(cli.cases_mod.group_by_stubs(loaded)) == 1


# ---------------------------------------------------------------- probe definition
def test_probe_definition_is_inert_exact_and_valid():
    definition = probe.build_probe_definition(neutralise.SET_RAW_JSON, "r1")
    assert probe.strict_problems(definition, neutralise.SET_RAW_JSON, "r1") == []
    assert [n["type"] for n in definition["nodes"]] == [B + "executeWorkflowTrigger", B + "set", B + "noOp"]
    assert json.loads(definition["nodes"][1]["parameters"]["jsonOutput"]) == probe.STUB_OUTPUT


def _mutations():
    def add_node(d): d["nodes"].append({"id": "x", "name": "Extra", "type": B + "noOp", "typeVersion": 1, "position": [0, 0], "parameters": {}})
    def http(d): d["nodes"][2].update(type=B + "httpRequest")
    def code(d): d["nodes"][2].update(type=B + "code")
    def creds(d): d["nodes"][1]["credentials"] = {"httpBasicAuth": {"id": "1", "name": "n"}}
    def expr(d): d["nodes"][2]["parameters"] = {"value": "={{ $json.x }}"}
    def mustache(d): d["nodes"][2]["parameters"] = {"value": "{{ $json.x }}"}
    def url(d): d["nodes"][2]["parameters"] = {"value": "https://outside.invalid"}
    def extra_param(d): d["nodes"][1]["parameters"]["extra"] = 1
    def stub_changed(d): d["nodes"][1]["parameters"]["jsonOutput"] = '{"probe":"other"}'
    def once(d): d["nodes"][1].pop("executeOnce")
    def node_key(d): d["nodes"][1]["retryOnFail"] = True
    def err(d): d["settings"]["errorWorkflow"] = "abc"
    def avail(d): d["settings"]["availableInMCP"] = False
    def edge(d): d["connections"]["Probe Observe"] = {"main": [[{"node": "Probe Entry", "type": "main", "index": 0}]]}
    def active(d): d["active"] = True
    def top(d): d["pinData"] = {}
    def entry_type(d): d["nodes"][0]["type"] = B + "webhook"
    return [add_node, http, code, creds, expr, mustache, url, extra_param, stub_changed, once, node_key, err, avail, edge,
            active, top, entry_type]


@pytest.mark.parametrize("mutate", _mutations(), ids=lambda f: f.__name__)
def test_every_deviation_from_the_exact_probe_definition_is_rejected(mutate):
    definition = probe.build_probe_definition(neutralise.SET_RAW_JSON, "r1")
    mutate(definition)
    assert probe.strict_problems(definition, neutralise.SET_RAW_JSON, "r1")


# ---------------------------------------------------------------- probe runs
def test_probe_verifies_the_mechanism_records_evidence_and_cleans_up(tmp_path, monkeypatch):
    rest, backend, executor, transport = make(tmp_path, monkeypatch)
    before = backend.snapshot(digest_ids=list(CANON))
    report = probe.run_probe(backend=backend, transport=transport, mechanism=neutralise.SET_RAW_JSON,
                             out_root=tmp_path / "scratch", run_id="p1", server_info={"name": "synthetic"})
    assert report["status"] == "VERIFIED" and report["cleanup"] == "DELETED" and not rest.store
    assert executor.calls == ["test_workflow", "get_workflow_execution"] * 2
    record = json.loads((tmp_path / "scratch" / "probe-p1" / "mechanism-record.json").read_text())
    assert record["observed_output_equals_declared"] and record["executeOnce_confirmed"] and record["stored_matches_sent"]
    assert record["base_url"] == BASE and len(record["run_ids"]) == 2
    assert {p.name for p in (tmp_path / "scratch" / "probe-p1" / "raw").iterdir()} == {
        "reread.json", "runA.test_workflow.json", "runA.get_workflow_execution.json",
        "runB.test_workflow.json", "runB.get_workflow_execution.json"}
    assert be.diff_snapshots(before, backend.snapshot(digest_ids=list(CANON))) == []
    assert {m for m, _ in rest.calls} <= {"GET", "POST", "DELETE"}
    verified = probe.mechanism_from_record(record, neutralise.SET_RAW_JSON, BASE)
    assert verified.verification["execution_id"] == record["execution_id"]
    with pytest.raises(FileExistsError):
        probe.run_probe(backend=backend, transport=transport, mechanism=neutralise.SET_RAW_JSON,
                        out_root=tmp_path / "scratch", run_id="p1")


@pytest.mark.parametrize("knobs, rest_class, fragment, executed", [
    ({}, NormalisingRest, "differs from what was sent", False),
    ({"two_items": True}, backend_tests.FakeRest, "run B did not match", True),
    ({"leak_sentinel": True}, backend_tests.FakeRest, "run A did not match", True),
    ({"status": "error"}, backend_tests.FakeRest, "run A did not match", True),
    ({"odd_shape": True}, backend_tests.FakeRest, "not in the expected shape", True),
    ({"no_execution_id": True}, backend_tests.FakeRest, "no execution id", True),
    ({"raise_on": "test_workflow"}, backend_tests.FakeRest, "test_workflow failed", True),
    ({"raise_on": "get_workflow_execution"}, backend_tests.FakeRest, "get_workflow_execution failed", True),
    ({"extra_node": True}, backend_tests.FakeRest, "run A did not match", True),
])
def test_probe_stops_and_reports_on_any_deviation_without_guessing(tmp_path, monkeypatch, knobs, rest_class, fragment, executed):
    rest, backend, executor, transport = make(tmp_path, monkeypatch, rest_class=rest_class, **knobs)
    before = backend.snapshot(digest_ids=list(CANON))
    report = probe.run_probe(backend=backend, transport=transport, mechanism=neutralise.SET_RAW_JSON,
                             out_root=tmp_path / "scratch", run_id="p2")
    assert report["status"] == "STOPPED" and fragment in report["stopped_because"] and report["record"] is None
    assert not (tmp_path / "scratch" / "probe-p2" / "mechanism-record.json").exists()
    assert bool(executor.calls) is executed  # a stored definition that differs is never executed
    assert report["cleanup"] == "DELETED" and not rest.store
    assert be.diff_snapshots(before, backend.snapshot(digest_ids=list(CANON))) == []
    assert not any(c.startswith("update") for c in executor.calls) and len(executor.calls) <= 4


def test_normalisation_is_reported_verbatim_in_the_raw_capture(tmp_path, monkeypatch):
    rest, backend, executor, transport = make(tmp_path, monkeypatch, rest_class=NormalisingRest)
    report = probe.run_probe(backend=backend, transport=transport, mechanism=neutralise.SET_RAW_JSON,
                             out_root=tmp_path / "scratch", run_id="p3")
    assert "addedByServer" in report["stopped_because"]
    reread = json.loads((tmp_path / "scratch" / "probe-p3" / "raw" / "reread.json").read_text())
    assert any(n["parameters"].get("addedByServer") for n in reread["nodes"])


def test_a_disarmed_backend_stops_the_probe_with_zero_n8n_calls(tmp_path, monkeypatch):
    rest, backend, executor, transport = make(tmp_path, monkeypatch)
    monkeypatch.setenv(be.ENV_APPROVAL, "something else")
    disarmed = be.N8nBackend(expected_base_url=BASE, approval="armed", protected_ids=CANON)
    report = probe.run_probe(backend=disarmed, transport=transport, mechanism=neutralise.SET_RAW_JSON,
                             out_root=tmp_path / "scratch", run_id="p4")
    assert report["status"] == "STOPPED" and "BackendDisarmed" in report["stopped_because"]
    assert rest.calls == [] and executor.calls == []


@pytest.mark.parametrize("change", [{"observed_output_equals_declared": False}, {"executeOnce_confirmed": False},
                                    {"stored_matches_sent": False}, {"node_type": "x"}, {"type_version": 3.3},
                                    {"base_url": "http://127.0.0.1:9999"}, {"execution_id": ""}])
def test_a_probe_record_that_does_not_verify_the_mechanism_here_is_refused(change):
    with pytest.raises(ValueError):
        probe.mechanism_from_record({**good_record(), **change}, neutralise.SET_RAW_JSON, BASE)
    assert probe.mechanism_from_record(good_record(), neutralise.SET_RAW_JSON, BASE).verification["execution_id"] == "exec-1"


# ---------------------------------------------------------------- gates with fakes
def test_gate0_is_strictly_read_only(tmp_path, monkeypatch):
    rest, backend, executor, transport = make(tmp_path, monkeypatch)
    run_dir = tmp_path / "scratch" / "gate0-t1"
    run_dir.mkdir(parents=True)
    report = cli.run_gate0(backend, transport, run_dir, CANON)
    assert report["ok"] and report["missing_tools"] == [] and all(report["protected_present"].values())
    assert {m for m, _ in rest.calls} == {"GET"} and executor.calls == ["initialize", "list_tools"]
    assert report["offline"]["fixture_classification"]["Notify On-call"] == "SUBSTITUTE"
    assert (run_dir / "gate0.json").exists() and not rest.store


def test_gate0_reports_missing_tools_and_a_blocked_fixture_as_not_ok(tmp_path, monkeypatch):
    rest, backend, executor, transport = make(tmp_path, monkeypatch)
    executor.list_tools = lambda: [{"name": "test_workflow"}]
    run_dir = tmp_path / "scratch" / "gate0-t2"
    run_dir.mkdir(parents=True)
    report = cli.run_gate0(backend, transport, run_dir, CANON)
    assert not report["ok"] and report["missing_tools"] == ["get_workflow_execution"]


def test_gate1_then_gate2_end_to_end_with_scratch_only_labelled_evidence(tmp_path, monkeypatch):
    rest, backend, executor, transport = make(tmp_path, monkeypatch)
    g1 = tmp_path / "scratch" / "gate1-t1"
    g1.mkdir(parents=True)
    summary1 = cli.run_probe_gate(backend, transport, g1, CANON)
    assert summary1["ok"] and summary1["snapshot_differences"] == []
    record_path = next(g1.rglob("mechanism-record.json"))

    g2 = tmp_path / "scratch" / "gate2-t1"
    g2.mkdir(parents=True)
    summary2 = cli.run_e2e_gate(backend, transport, g2, CANON, record_path)
    assert summary2["ok"], summary2
    assert summary2["case_statuses"] == cli.EXPECTED_CASES and summary2["cleanup"] == ["DELETED"] and not rest.store
    assert summary2["scratch_ingest"] == {"accepted": [cli.SYNTHETIC_CHECK], "rejected": [], "provenance": ["SYNTHETIC_FIXTURE"]}
    run_json = json.loads(next(g2.rglob("run.json")).read_text())
    campaign = json.loads(next(g2.rglob("simulate.json")).read_text())
    assert run_json["labels"] == campaign["candidate"]["labels"] == cli.LABELS
    assert campaign["environment"] == "SIMULATED" and [v["status"] for v in campaign["verdicts"]] == ["FAIL"]
    assert campaign["verdicts"][0]["check_id"] == cli.SYNTHETIC_CHECK
    assert run_json["mechanism_verification"]["execution_id"] == json.loads(record_path.read_text())["execution_id"]
    group = run_json["groups"][0]
    assert group["manifest"]["source_definition_digest"] and group["transformed_definition_digest"]
    assert run_json["source_sha256"] == json.loads(cli.FIXTURE.read_text())["workflow"]["sha256"]
    assert all(p.is_relative_to(tmp_path / "scratch") for p in g2.rglob("*.json"))


def test_gate2_refuses_a_record_from_another_instance_before_any_call(tmp_path, monkeypatch):
    rest, backend, executor, transport = make(tmp_path, monkeypatch)
    record = tmp_path / "record.json"
    record.write_text(json.dumps(good_record("http://127.0.0.1:9999")), encoding="utf-8")
    g2 = tmp_path / "scratch" / "gate2-t2"
    g2.mkdir(parents=True)
    with pytest.raises(ValueError):
        cli.run_e2e_gate(backend, transport, g2, CANON, record)
    assert rest.calls == [] and executor.calls == []


# ---------------------------------------------------------------- operator surface
def test_evidence_must_go_to_a_scratch_directory(tmp_path):
    for good in (tmp_path / "scratch-s4", tmp_path / "scratch"):
        assert cli.assert_scratch(good) == good
    for bad in (pathlib.Path("scratch"), tmp_path / "other", tmp_path / "artifacts" / "readiness" / "scratch",
                tmp_path / "mission" / "scratch", tmp_path / "scratch" / "artifacts" / "x"):
        with pytest.raises(cli.OperatorError):
            cli.assert_scratch(bad)

def test_each_gate_needs_its_own_exact_approval_string(monkeypatch):
    args = types.SimpleNamespace(base_url=BASE, run_label=LABEL, protect=list(CANON))
    strings = {g: cli.approval_for(g, BASE, LABEL) for g in ("gate0", "gate1", "gate2")}
    assert len(set(strings.values())) == 3 and strings["gate1"] == f"gate1:{BASE}:{LABEL}"
    for armed in strings:
        monkeypatch.setenv(be.ENV_APPROVAL, strings[armed])
        for gate in strings:
            if gate == armed:
                assert cli.build_real(args, gate)[0].armed
            else:
                with pytest.raises(cli.OperatorError, match="disarmed"):
                    cli.build_real(args, gate)
    monkeypatch.setenv(be.ENV_APPROVAL, strings["gate1"])
    assert (cli.GATE1_MAX_CREATES, cli.GATE1_MAX_EXECUTIONS) == (2, 3)
    assert cli.build_real(args, "gate1")[0].max_creates == 2  # the operator's Gate 1 cap is set in code, not by convention
    monkeypatch.setenv(be.ENV_APPROVAL, strings["gate2"])
    assert (cli.GATE2_MAX_CREATES, cli.GATE2_MAX_EXECUTIONS) == (1, 3)
    assert cli.build_real(args, "gate2")[0].max_creates == 1  # one disposable workflow for the end-to-end gate
    monkeypatch.setenv(be.ENV_APPROVAL, strings["gate0"])
    assert cli.build_real(args, "gate0")[0].max_creates is None
    monkeypatch.delenv(be.ENV_APPROVAL)
    with pytest.raises(cli.OperatorError):
        cli.build_real(args, "gate0")
    with pytest.raises(cli.OperatorError):
        cli.approval_for("gate0", BASE, "bad label!")
    with pytest.raises(be.BackendRefused):
        cli.approval_for("gate0", "https://x.ngrok-free.dev", LABEL)


def test_plan_prints_everything_and_contacts_nothing(tmp_path, capsys):
    out = tmp_path / "scratch-plan"
    code = cli.main(["plan", "--base-url", BASE, "--out-root", str(out), "--run-label", LABEL])
    printed = json.loads(capsys.readouterr().out)
    assert code == 0 and printed["contacts_n8n"] is False and printed["mcp_endpoint"] == BASE + "/mcp-server/http"
    assert printed["gate1"]["approval_env_value"] == f"gate1:{BASE}:{LABEL}"
    assert set(printed["protected_ids"]) >= set(cli.PROTECTED_DEFAULT) and printed["offline"]["probe_definition_problems"] == []
    assert not out.exists()


@pytest.mark.parametrize("command", ["gate0", "probe", "e2e"])
def test_real_commands_are_disarmed_without_the_exact_approval_and_refuse_bad_targets(tmp_path, capsys, command):
    out = tmp_path / "scratch-run"
    assert cli.main([command, "--base-url", BASE, "--out-root", str(out), "--run-label", LABEL]) == 2
    assert "disarmed" in capsys.readouterr().err and not out.exists()
    for bad in ("https://example-tunnel.ngrok-free.dev", "https://example.com", "http://10.0.0.5:5678"):
        assert cli.main([command, "--base-url", bad, "--out-root", str(out), "--run-label", LABEL]) == 2
    assert cli.main([command, "--base-url", BASE, "--out-root", str(tmp_path / "artifacts"), "--run-label", LABEL]) == 2


def test_module_policy_gate():
    for name in ("breaker_mechanism_probe.py", "breaker_s4_run.py"):
        source = (ROOT / "tools" / name).read_text(encoding="utf-8").lower()
        for token in ("ngrok", "mcp_call_tool", "urllib.request", "customer", "invoice"):
            assert token not in source, (name, token)

def test_missing_credentials_stop_cleanly_before_any_request(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    monkeypatch.setenv(be.ENV_APPROVAL, cli.approval_for("gate0", BASE, LABEL))
    out = tmp_path / "scratch-creds"
    code = cli.main(["gate0", "--base-url", BASE, "--out-root", str(out), "--run-label", LABEL])
    err = capsys.readouterr().err
    assert code == 2 and "MCP_N8N_API_KEY" in err and "Traceback" not in err
    assert not list(out.rglob("gate0.json"))  # nothing was reached, nothing was reported as a result
