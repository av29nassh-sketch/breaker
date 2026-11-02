"""Offline tests for the general front door: any workflow JSON + cases in, an honest report out. No network."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import socket
import sys
import types
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
B = "n8n-nodes-base."
W3_DIR = ROOT / "fixtures" / "simulate" / "w3-mini"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


front = load("front_under_test", ROOT / "tools" / "breaker_verify_workflow.py")
sim_tests = load("sim_tests_for_front", ROOT / "tests" / "test_breaker_simulate.py")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


@pytest.fixture
def no_backend(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("a backend was built for a workflow that must stay blocked")
    monkeypatch.setattr(front.be, "N8nBackend", boom)


class MiniFake:
    """Executes a neutralised definition the way n8n would for these node kinds; routing is decided by ``route``."""

    def __init__(self, backend, route):
        self.backend, self.route, self.runs, self.n, self.calls = backend, route, {}, 0, []

    def call_tool_retrying(self, name, arguments, **kwargs):
        self.calls.append(name)
        if name == "test_workflow":
            self.n += 1
            eid = f"e{self.n}"
            definition = self.backend.store[arguments["workflowId"]]
            entry = arguments["triggerNodeName"]
            nodes = {n["name"]: n for n in definition["nodes"]}
            run, queue = {}, [(entry, arguments["pinData"][entry][0]["json"])]
            while queue:
                current, item = queue.pop(0)
                node = nodes[current]
                out = json.loads(node["parameters"]["jsonOutput"]) if node["type"] == B + "set" and "jsonOutput" in node["parameters"] else item
                items = out if isinstance(out, list) else [out]
                run[current] = [{"data": {"main": [[{"json": x} for x in items]]}}]
                ports = definition["connections"].get(current, {}).get("main", [])
                if node["type"] in (B + "if", B + "switch"):
                    idx = self.route(current, item)
                    queue.extend((e["node"], item) for e in (ports[idx] if idx < len(ports) else []))
                else:
                    queue.extend((e["node"], x) for port in ports for e in port for x in items)
            self.runs[eid] = {"status": "success", "data": {"resultData": {"runData": run}}}
            return {"executionId": eid}, {}
        if name == "get_workflow_execution":
            return self.runs[arguments["executionId"]], {}
        raise AssertionError(f"unexpected operation {name}")


def mechanism():
    n = front.neutralise
    record = {"execution_id": "SYNTHETIC-TEST-RECORD", "observed_output_equals_declared": True,
              "node_type": "n8n-nodes-base.set", "type_version": 3.4, "synthetic": True}
    return n.Mechanism("n8n-nodes-base.set", 3.4, n.SET_RAW_JSON.parameters_for, record)


def order_workflow():
    """A deliberately different shape from the W3 fixture: other node names, webhook entry, switch, credentials."""
    return {"name": "Order triage", "nodes": [
        {"id": "a", "name": "Order In", "type": B + "webhook", "typeVersion": 2, "position": [0, 0], "parameters": {}},
        {"id": "b", "name": "Route By Type", "type": B + "switch", "typeVersion": 3, "position": [200, 0], "parameters": {}},
        {"id": "c", "name": "Call CRM", "type": B + "httpRequest", "typeVersion": 4.2, "position": [400, -80], "parameters": {},
         "credentials": {"httpHeaderAuth": {"id": "secret-id-1", "name": "Secret Name 1"}}},
        {"id": "d", "name": "Send Receipt", "type": B + "emailSend", "typeVersion": 2.1, "position": [400, 80], "parameters": {},
         "credentials": {"smtp": {"id": "secret-id-2", "name": "Secret Name 2"}}},
        {"id": "e", "name": "Collect", "type": B + "noOp", "typeVersion": 1, "position": [600, 0], "parameters": {}},
    ], "connections": {
        "Order In": {"main": [[{"node": "Route By Type", "type": "main", "index": 0}]]},
        "Route By Type": {"main": [[{"node": "Call CRM", "type": "main", "index": 0}], [{"node": "Send Receipt", "type": "main", "index": 0}]]},
        "Call CRM": {"main": [[{"node": "Collect", "type": "main", "index": 0}]]},
        "Send Receipt": {"main": [[{"node": "Collect", "type": "main", "index": 0}]]}}, "settings": {"executionOrder": "v1"}}


ORDER_CASES = {"schema_version": 1, "entry_node": "Order In",
               "stubs": {"Call CRM": {"crm": "ok"}, "Send Receipt": {"sent": True}},
               "cases": [
                   {"id": "lead", "input": {"type": "lead"}, "output_assertions": [{"node": "Collect", "path": "crm", "equals": "ok"}],
                    "must_run": ["Call CRM"], "must_not_run": ["Send Receipt"]},
                   {"id": "receipt", "input": {"type": "receipt"}, "output_assertions": [{"node": "Collect", "path": "sent", "equals": True}],
                    "must_run": ["Send Receipt"], "must_not_run": ["Call CRM"]}]}


def write(tmp_path, definition=None, cases=None, wrap=False, name="wf.json"):
    wf = tmp_path / name
    payload = definition if definition is not None else order_workflow()
    wf.write_text(json.dumps([payload] if wrap else payload), encoding="utf-8")
    cases_path = None
    if cases is not None:
        cases_path = tmp_path / "cases.json"
        cases_path.write_text(json.dumps(cases), encoding="utf-8")
    return wf, cases_path


def check(tmp_path, definition=None, cases=ORDER_CASES, label="chk", **kw):
    wf, cases_path = write(tmp_path, definition, cases, **kw)
    out = tmp_path / "scratch"
    out.mkdir(exist_ok=True)
    run_dir = out / label
    run_dir.mkdir()
    return front.analyse(wf, cases_path, kw.get("entry"), run_dir, label) + (run_dir,)


def run_fake(tmp_path, definition, cases, route, label="run", files=None):
    if files:  # real files on disk, untouched, so the cases file's own sha256 is checked against the original bytes
        run_dir = tmp_path / "scratch" / label
        run_dir.mkdir(parents=True)
        report, context = front.analyse(files[0], files[1], None, run_dir, label)
    else:
        report, context, run_dir = check(tmp_path, definition, cases, label=label)
    assert context["loaded"] is not None, report.get("cases_problems") or report["problems"]
    backend = sim_tests.FakeBackend()
    transport = MiniFake(backend, route)
    report = front.run_simulation(report, context, backend=backend, transport=transport, mechanism=mechanism(), run_dir=run_dir)
    return report, backend, transport, run_dir


def results(report):
    return {r["id"]: r["status"] for r in report["cases"]["results"]}


# ---- W3, previously executed for real: the same fixture through the general interface --------------------------------
W3_ROUTE = lambda name, item: 0 if item.get("kind") == "urgent" else 1  # noqa: E731


def test_w3_through_the_general_interface_offline_check_only(tmp_path, capsys, no_backend):
    code = front.main([str(W3_DIR / "workflow.json"), "--cases", str(W3_DIR / "cases.json"),
                       "--out-root", str(tmp_path / "scratch"), "--label", "w3"])
    out = capsys.readouterr().out
    report = json.loads((tmp_path / "scratch" / "w3" / "report.json").read_text(encoding="utf-8"))
    assert code == 1 and "overall: NOT VERIFIED" in out  # nothing was executed, so nothing is claimed
    assert report["overall"]["status"] == "NOT VERIFIED" and report["mode"] == "CHECK_ONLY"
    sims = {c["capability"]: c for c in report["capabilities"]}
    assert sims["Simulated execution on a disposable neutralised copy"]["status"] == "SUPPORTED"
    assert sims["External HTTP/email calls"]["status"] == "SIMULATED_ONLY"
    assert sims["Code nodes"]["status"] == "NOT_PRESENT"
    assert report["entry"]["chosen"] == "Harness Intake" and report["cases"]["supplied"] == 3
    assert (tmp_path / "scratch" / "w3" / "report.md").exists() and (tmp_path / "scratch" / "w3" / "inputs" / "workflow.json").exists()


def test_w3_simulated_run_with_fakes_reports_each_status_and_cleans_up(tmp_path):
    report, backend, transport, run_dir = run_fake(tmp_path, None, None, W3_ROUTE,
                                                   files=(W3_DIR / "workflow.json", W3_DIR / "cases.json"))
    assert results(report) == {"urgent": "CONFORMS", "normal": "CONFORMS", "deliberate-fail": "PRODUCT_FAIL"}
    assert report["overall"]["status"] == "PRODUCT_FAIL" and report["mode"] == "SIMULATED_RUN"
    assert not backend.store and all(d["cleanup"] == "DELETED" for d in report["disposable_copies"])
    assert report["evidence"]["readiness_verdicts_booked"] == 0 and len(transport.calls) == 6
    campaign = json.loads((pathlib.Path(report["evidence"]["run_dir"]) / "run.json").read_text())
    assert campaign["labels"]["readiness_record"] == "NOT_FOR_INGESTION_INTO_ANY_READINESS_RECORD"


# ---- a different Code-free workflow: other names, entry type, node mix; no runner edits -----------------------------
def test_a_different_code_free_workflow_runs_with_only_supplied_cases(tmp_path):
    route = lambda name, item: 0 if item.get("type") == "lead" else 1  # noqa: E731
    report, backend, _, _ = run_fake(tmp_path, order_workflow(), ORDER_CASES, route)
    assert results(report) == {"lead": "CONFORMS", "receipt": "CONFORMS"}
    assert report["overall"]["status"] == "CONFORMS" and not backend.store
    text = json.dumps(report)
    assert "secret-id-1" not in text and "Secret Name 2" not in text  # credential ids and names never reach a report
    notes = " ".join(report["not_verified"])
    assert "Call CRM" in notes and "Send Receipt" in notes and "httpHeaderAuth" in notes and "smtp" in notes
    md = front.render_markdown(report)
    assert "Overall: CONFORMS" in md and "Overall: PASS" not in md and "NOT VERIFIED" in md


def test_a_wrong_expectation_is_product_fail_and_outranks_inconclusive(tmp_path):
    cases = json.loads(json.dumps(ORDER_CASES))
    cases["cases"][0]["output_assertions"][0]["equals"] = "wrong"
    cases["cases"].append({"id": "asserts-nothing", "input": {"type": "lead"}})
    route = lambda name, item: 0 if item.get("type") == "lead" else 1  # noqa: E731
    report, _, _, _ = run_fake(tmp_path, order_workflow(), cases, route)
    assert results(report) == {"lead": "PRODUCT_FAIL", "receipt": "CONFORMS", "asserts-nothing": "INCONCLUSIVE"}
    assert report["overall"]["status"] == "PRODUCT_FAIL"


def test_only_inconclusive_cases_never_become_a_pass(tmp_path):
    cases = {"schema_version": 1, "entry_node": "Order In", "stubs": ORDER_CASES["stubs"],
             "cases": [{"id": "asserts-nothing", "input": {"type": "lead"}}]}
    report, _, _, _ = run_fake(tmp_path, order_workflow(), cases, lambda n, i: 0)
    assert report["overall"]["status"] == "INCONCLUSIVE"


def test_unwrapped_single_item_export_and_no_entry_flag_needed(tmp_path):
    report, context, _ = check(tmp_path, wrap=True)
    assert report["workflow"]["unwrapped_single_item_list"] is True and context["loaded"] is not None
    assert report["overall"]["status"] == "NOT VERIFIED"


# ---- Code-heavy and otherwise unsupported: BLOCKED, explained, never executed ----------------------------------------
def heavy_workflow():
    nodes = [{"id": "t", "name": "Start", "type": B + "executeWorkflowTrigger", "typeVersion": 1.1, "position": [0, 0], "parameters": {}}]
    for i in range(3):
        nodes.append({"id": f"c{i}", "name": f"Logic {i}", "type": B + "code", "typeVersion": 2, "position": [i, 0], "parameters": {"jsCode": "return $input.all();"}})
    nodes += [
        {"id": "d", "name": "Ledger", "type": B + "dataTable", "typeVersion": 1.1, "position": [9, 0],
         "parameters": {"dataTableId": {"__rl": True, "mode": "id", "value": "CANON"}}},
        {"id": "x", "name": "Shell", "type": B + "executeCommand", "typeVersion": 1, "position": [9, 1], "parameters": {}},
        {"id": "u", "name": "Chat", "type": B + "slack", "typeVersion": 2, "position": [9, 2], "parameters": {}},
        {"id": "k", "name": "Books", "type": B + "quickbooks", "typeVersion": 1, "position": [9, 3], "parameters": {},
         "credentials": {"quickBooksOAuth2Api": {"id": "q", "name": "Q"}}}]
    return {"name": "Heavy", "nodes": nodes, "connections": {}, "settings": {}}


def test_code_heavy_workflow_is_blocked_with_exact_reasons_and_no_n8n_object(tmp_path, capsys, no_backend, monkeypatch):
    wf, _ = write(tmp_path, heavy_workflow())
    monkeypatch.setenv("BREAKER_S4_APPROVAL", "ignored")
    code = front.main([str(wf), "--out-root", str(tmp_path / "scratch"), "--label", "heavy", "--run",
                       "--base-url", "http://127.0.0.1:5678", "--mechanism-record", str(tmp_path / "none.json")])
    report = json.loads((tmp_path / "scratch" / "heavy" / "report.json").read_text(encoding="utf-8"))
    assert code == 1 and report["overall"]["status"] == "BLOCKED" and report["mode"] == "CHECK_ONLY"
    by = {b["category"]: b for b in report["inventory"]["blockers"]}
    assert by["CODE_NODE"]["count"] == 3 and by["DATA_TABLE_NEEDS_DECLARATION"]["nodes"] == ["Ledger"]
    assert by["HOST_ACCESS_OR_UNCLASSIFIED_CALL"]["nodes"] == ["Shell"]
    assert by["UNSUPPORTED_NODE_TYPE"]["nodes"] == ["Chat"]
    assert by["CREDENTIALED_NODE_NO_SAFE_STAND_IN"]["nodes"] == ["Books"]
    assert any("--run was requested but nothing was executed" in w for w in report["warnings"])
    md = (tmp_path / "scratch" / "heavy" / "report.md").read_text(encoding="utf-8")
    assert "Why it is BLOCKED" in md and "Logic 0" in md and "BLOCKED" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["not json {", json.dumps({"hello": "world"}), json.dumps([1, 2]), json.dumps({"nodes": [], "connections": {}})])
def test_unusable_workflow_files_get_a_blocked_report(tmp_path, content):
    wf = tmp_path / "bad.json"
    wf.write_text(content, encoding="utf-8")
    run_dir = tmp_path / "scratch" / "bad"
    run_dir.mkdir(parents=True)
    report, context = front.analyse(wf, None, None, run_dir, "bad")
    assert report["overall"]["status"] == "BLOCKED" and report["overall"]["why"] and context["loaded"] is None
    front.write_report(report, run_dir)


def test_ambiguous_entry_missing_stub_unknown_node_and_stale_cases_are_blocked_not_guessed(tmp_path):
    two_entries = order_workflow()
    two_entries["nodes"].append({"id": "m", "name": "Manual", "type": B + "manualTrigger", "typeVersion": 1, "position": [0, 9], "parameters": {}})
    no_entry_cases = {k: v for k, v in ORDER_CASES.items() if k != "entry_node"}
    report, _, _ = check(tmp_path, two_entries, no_entry_cases, label="amb")
    assert report["overall"]["status"] == "BLOCKED" and any("entry" in w for w in report["overall"]["why"])

    missing = json.loads(json.dumps(ORDER_CASES))
    del missing["stubs"]["Send Receipt"]
    report, context, _ = check(tmp_path, order_workflow(), missing, label="stub")
    assert report["overall"]["status"] == "BLOCKED" and any("Send Receipt" in p for p in report["cases_problems"])
    assert context["loaded"] is None

    unknown = json.loads(json.dumps(ORDER_CASES))
    unknown["cases"][0]["must_run"] = ["No Such Node"]
    report, _, _ = check(tmp_path, order_workflow(), unknown, label="unk")
    assert report["overall"]["status"] == "BLOCKED" and any("No Such Node" in p for p in report["cases_problems"])

    stale = json.loads(json.dumps(ORDER_CASES))
    stale["workflow"] = {"path": "x.json", "sha256": "0" * 64}
    report, _, _ = check(tmp_path, order_workflow(), stale, label="stale")
    assert report["overall"]["status"] == "BLOCKED" and any("different version" in p for p in report["problems"])


def test_inventory_only_report_says_what_to_supply(tmp_path):
    report, context, _ = check(tmp_path, cases=None, label="inv")
    assert report["overall"]["status"] == "NOT VERIFIED" and context["loaded"] is None
    needs = " ".join(report["needs_from_you"])
    assert "Call CRM" in needs and "Send Receipt" in needs and "test cases" in needs
    caps = {c["capability"]: c["status"] for c in report["capabilities"]}
    assert caps["Simulated execution on a disposable neutralised copy"] == "NEEDS_INPUT"
    assert caps["Verification of real integrations, credentials or production behaviour"] == "NOT_SUPPORTED"


# ---- arming and the status vocabulary ----------------------------------------------------------------------------------
def test_run_is_refused_without_arming_or_target_before_any_n8n_call(tmp_path, capsys, monkeypatch):
    wf, cases_path = write(tmp_path, order_workflow(), ORDER_CASES)
    base = [str(wf), "--cases", str(cases_path), "--out-root", str(tmp_path / "scratch")]
    assert front.main(base + ["--label", "r1", "--run"]) == 2
    monkeypatch.delenv(front.be.ENV_APPROVAL, raising=False)
    record = tmp_path / "rec.json"
    record.write_text("{}", encoding="utf-8")
    assert front.main(base + ["--label", "r2", "--run", "--base-url", "http://127.0.0.1:5678", "--mechanism-record", str(record)]) == 2
    assert "disarmed" in capsys.readouterr().err
    assert front.main(base + ["--label", "r3", "--run", "--base-url", "https://example.ngrok-free.dev", "--mechanism-record", str(record)]) == 2


def result_of(statuses, status="COMPLETED", cleanup="DELETED", group_status="EXECUTED"):
    cases = tuple(types.SimpleNamespace(status=s) for s in statuses)
    group = types.SimpleNamespace(cases=cases, clone_id="id", cleanup=cleanup, status=group_status, reasons=())
    return types.SimpleNamespace(status=status, reasons=("why",), groups=(group,))


@pytest.mark.parametrize("statuses,kw,changes,expected", [
    (["CONFORMS", "CONFORMS"], {}, [], "CONFORMS"),
    (["CONFORMS", "PRODUCT_FAIL", "INCONCLUSIVE"], {}, [], "PRODUCT_FAIL"),
    (["CONFORMS", "INCONCLUSIVE"], {}, [], "INCONCLUSIVE"),
    (["CONFORMS", "BLOCKED"], {}, [], "INCONCLUSIVE"),
    (["BLOCKED", "BLOCKED"], {}, [], "BLOCKED"),
    (["CONFORMS"], {"cleanup": "FAILED: x"}, [], "INCONCLUSIVE"),
    (["CONFORMS"], {}, ["workflow x changed"], "INCONCLUSIVE"),
    ([], {}, [], "INCONCLUSIVE"),
    (["CONFORMS"], {"status": "BLOCKED"}, [], "BLOCKED"),
])
def test_overall_status_precedence(statuses, kw, changes, expected):
    status, why, warnings = front.overall_from(result_of(statuses, **kw), changes)
    assert status == expected and status in front.STATUSES and why


def test_vocabulary_and_module_policy():
    assert front.STATUSES == ("CONFORMS", "PRODUCT_FAIL", "BLOCKED", "INCONCLUSIVE", "NOT VERIFIED") and set(front.LEGEND) == set(front.STATUSES)
    source = (ROOT / "tools" / "breaker_verify_workflow.py").read_text(encoding="utf-8").lower()
    for token in ("ngrok", "harness intake", "w3-mini", "pindata", "urlopen"):
        assert token not in source, token
    assert '"pass"' not in source and "'pass'" not in source


def test_a_workflow_without_data_tables_gets_a_report_without_any_table_fields(tmp_path):
    report, *_ = run_fake(tmp_path, order_workflow(), ORDER_CASES, lambda n, i: 0 if i.get("type") == "lead" else 1)
    assert not ({"tables", "disposable_tables"} & set(report)) and "data_tables" not in report["inventory"]
    caps = {c["capability"]: c for c in report["capabilities"]}
    assert caps["Data Tables / database read-back"]["status"] == "NOT_PRESENT"
    assert not any("Data Tables" in item for item in report["not_verified"])
