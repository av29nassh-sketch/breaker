"""Front door with Data Tables: declaration drives BLOCKED vs ready, a fake run cleans up tables, arming needs a table record."""
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
BASE = "http://127.0.0.1:5678"
SERVER = {"name": "n8n MCP Server", "version": "1.1.0"}
APP = "2.35.4"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


front = load("front_tables_under_test", ROOT / "tools" / "breaker_verify_workflow.py")
env = load("front_tables_env", ROOT / "tests" / "test_breaker_simulate_tables.py")
probe = front.table_probe


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


def cases_doc(tables="default", cases=None):
    doc = {"schema_version": 1, "entry_node": "Intake", "cases": cases or env.default_cases()}
    if tables == "default":
        tables = {"leads": {"nodes": ["Find Lead", "Save Lead"], "columns": env.COLUMNS}}
    if tables is not None:
        doc["tables"] = tables
    return doc


def check(tmp_path, definition=None, doc="default", label="chk"):
    wf = tmp_path / "wf.json"
    wf.write_text(json.dumps(definition or env.workflow()), encoding="utf-8")
    cases_path = None
    if doc is not None:
        cases_path = tmp_path / "cases.json"
        cases_path.write_text(json.dumps(cases_doc() if doc == "default" else doc), encoding="utf-8")
    run_dir = tmp_path / "scratch" / label
    run_dir.mkdir(parents=True)
    return front.analyse(wf, cases_path, None, run_dir, label) + (run_dir,)


def caps(report):
    return {c["capability"]: c for c in report["capabilities"]}


def test_declared_tables_make_the_workflow_ready_to_run(tmp_path):
    report, context, _ = check(tmp_path)
    assert report["overall"]["status"] == "NOT VERIFIED" and context["loaded"] is not None
    assert not report["inventory"]["blockers"] and report["tables"]["leads"]["nodes"] == ["Find Lead", "Save Lead"]
    tables = caps(report)["Data Tables / database read-back"]
    assert tables["status"] == "SIMULATED_ONLY" and "never touched" in tables["detail"]
    assert caps(report)["Simulated execution on a disposable neutralised copy"]["status"] == "SUPPORTED"
    assert any("real Data Tables" in item for item in report["not_verified"])
    assert [d["declared"] for d in report["inventory"]["data_tables"]] == [True, True]


@pytest.mark.parametrize("doc", ["inventory", "no_tables"])
def test_undeclared_data_tables_block_and_say_what_to_supply(tmp_path, doc):
    cases = None if doc == "inventory" else cases_doc(tables=None)
    report, context, _ = check(tmp_path, doc=cases)
    blockers = {b["category"]: b for b in report["inventory"]["blockers"]}
    assert blockers["DATA_TABLE_NEEDS_DECLARATION"]["count"] == 2
    assert report["overall"]["status"] == "BLOCKED"
    assert caps(report)["Data Tables / database read-back"]["status"] == "NEEDS_INPUT"
    assert any("'tables' declaration" in n for n in report["needs_from_you"])
    assert not any("nothing you supply unblocks" in n for n in report["needs_from_you"])


def test_a_dynamic_table_reference_cannot_be_declared_into_support(tmp_path):
    ref = {"__rl": True, "mode": "id", "value": "={{ $json.table }}"}
    report, context, _ = check(tmp_path, definition=env.workflow(find_ref=ref))
    assert report["overall"]["status"] == "BLOCKED" and context["loaded"] is None
    assert any("no static source id" in p for p in report["cases_problems"])


def test_a_partly_declared_workflow_names_the_uncovered_node(tmp_path):
    doc = cases_doc(tables={"leads": {"nodes": ["Find Lead"], "columns": env.COLUMNS}})
    report, _, _ = check(tmp_path, doc=doc)
    assert report["overall"]["status"] == "BLOCKED"
    assert any("'Save Lead' is not covered" in p for p in report["cases_problems"])


def test_a_declaration_of_an_unprobed_operation_is_refused(tmp_path):
    definition = env.workflow()
    definition["nodes"][2]["parameters"]["operation"] = "deleteRows"
    report, _, _ = check(tmp_path, definition=definition)
    assert report["overall"]["status"] == "BLOCKED" and any("no probed mechanism" in p for p in report["cases_problems"])


def run_fake(tmp_path, **backend_knobs):
    report, context, run_dir = check(tmp_path)
    backend = env.TableBackend(**backend_knobs)
    transport = env.TableTransport(backend)
    report = front.run_simulation(report, context, backend=backend, transport=transport,
                                  mechanism=env.MECHANISM, run_dir=run_dir)
    return report, backend, run_dir


def test_a_fake_run_reports_the_disposable_tables_and_their_cleanup(tmp_path):
    report, backend, run_dir = run_fake(tmp_path)
    assert report["overall"]["status"] == "CONFORMS", report["overall"]
    assert [t["cleanup"] for t in report["disposable_tables"]] == ["DELETED"] and not backend.tables
    front.write_report(report, run_dir)
    markdown = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Disposable tables:" in markdown and "breaker_sim_" in markdown and "real Data Tables" in markdown
    assert env.CLIENT_TABLE not in markdown and env.CLIENT_TABLE not in (run_dir / "report.json").read_text(encoding="utf-8")


def test_a_table_that_could_not_be_deleted_makes_the_run_inconclusive(tmp_path):
    report, backend, _ = run_fake(tmp_path, fail_delete_table=True)
    assert report["overall"]["status"] == "INCONCLUSIVE"
    assert any("disposable table" in w and "breaker_sim_" in w for w in report["warnings"]) and backend.tables


def test_a_product_failure_in_a_table_assertion_is_reported_as_product_fail(tmp_path):
    cases = env.default_cases()
    cases[0]["table_assertions"] = [{"table": "leads", "count": 5}]
    report, context, run_dir = check(tmp_path, doc=cases_doc(cases=cases))
    backend = env.TableBackend()
    report = front.run_simulation(report, context, backend=backend, transport=env.TableTransport(backend),
                                  mechanism=env.MECHANISM, run_dir=run_dir)
    assert report["overall"]["status"] == "PRODUCT_FAIL"
    failed = [r for r in report["cases"]["results"] if r["status"] == "PRODUCT_FAIL"]
    assert [r["id"] for r in failed] == ["new-lead"] and failed[0]["failed_assertions"] == ["table leads count == 5"]


# ---- arming -------------------------------------------------------------------------------------------------------------
def set_record():
    return {"execution_id": "5625", "observed_output_equals_declared": True, "executeOnce_confirmed": True,
            "stored_matches_sent": True, "node_type": "n8n-nodes-base.set", "type_version": 3.4, "base_url": BASE,
            "server_info": dict(SERVER)}


def table_record(base_url=BASE):
    return {"kind": "data_table_mechanism", "execution_id": "6001", **{k: True for k in probe.REQUIRED_TRUE},
            "node_type": probe.tables.DATA_TABLE, "type_version": probe.tables.PROBED_TYPE_VERSION,
            "operations": list(probe.tables.PROBED_OPERATIONS), "base_url": base_url, "server_info": dict(SERVER)}


class IdentityTransport:
    """Stands in for the guarded transport: only the read-only discovery call exists, so any other use fails loudly."""

    def __init__(self, server=None, tools=None):
        self.server = SERVER if server is None else server
        self.tools = list(front.be.TRANSPORT_OPERATIONS) if tools is None else tools

    def preflight(self):
        return {"serverInfo": self.server, "protocolVersion": "2025-03-26", "tools": self.tools}


def main_args(tmp_path, *extra, label="r1"):
    wf = tmp_path / "wf.json"
    wf.write_text(json.dumps(env.workflow()), encoding="utf-8")
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps(cases_doc()), encoding="utf-8")
    rec = tmp_path / "set-record.json"
    rec.write_text(json.dumps(set_record()), encoding="utf-8")
    return [str(wf), "--cases", str(cases), "--out-root", str(tmp_path / "scratch"), "--label", label, "--run",
            "--base-url", BASE, "--mechanism-record", str(rec), *extra]


def test_a_run_with_declared_tables_refuses_without_a_table_mechanism_record(tmp_path, capsys, no_backend):
    assert front.main(main_args(tmp_path)) == 2
    assert "--table-mechanism-record" in capsys.readouterr().err


def test_a_table_record_for_another_instance_or_missing_observations_is_refused(tmp_path, capsys, no_backend, monkeypatch):
    monkeypatch.setenv(front.be.ENV_APPROVAL, f"run:{BASE}:r2")
    for n, record in enumerate((table_record("http://127.0.0.1:9999"), {**table_record(), "workflow_insert_landed": False})):
        path = tmp_path / f"tr{n}.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        sub = tmp_path / f"s{n}"
        sub.mkdir()
        assert front.main(main_args(sub, "--table-mechanism-record", str(path), label=f"r{n + 2}")) == 2


def test_real_wiring_protects_the_clients_table_and_caps_tables(tmp_path, monkeypatch):
    monkeypatch.setenv(front.be.ENV_APPROVAL, f"run:{BASE}:wire")
    monkeypatch.setenv("N8N_BASE_URL", BASE)  # so the arming check passes; the refusal below happens before any request
    report, context, run_dir = check(tmp_path, label="wire")
    rec, trec = tmp_path / "s.json", tmp_path / "t.json"
    rec.write_text(json.dumps(set_record()), encoding="utf-8")
    trec.write_text(json.dumps(table_record()), encoding="utf-8")
    monkeypatch.setattr(front.be, "read_application_version", lambda base_url, opener=None: APP)
    sentinel = IdentityTransport()
    monkeypatch.setattr(front.be, "make_transport", lambda backend, max_executions=None: sentinel)
    args = types.SimpleNamespace(base_url=BASE, mechanism_record=str(rec), table_mechanism_record=str(trec), label="wire",
                                 protect=["wfX"], protect_table=["existing-table"], table_project="proj1", expect_n8n_version=APP)
    backend, transport, mechanism, snapshot = front.real_wiring(args, run_dir, report, context)
    assert transport is sentinel and backend.armed
    assert backend.max_creates == 1 and backend.max_tables == 1
    assert backend.protected_table_ids == {"existing-table", env.CLIENT_TABLE}
    assert backend.table_project_id == "proj1" and report["table_mechanism_execution_id"] == "6001"
    assert report["instance_identity"]["mcp_server_info"] == SERVER
    assert report["instance_identity"]["application_version"] == APP
    with pytest.raises(front.be.BackendRefused):
        backend.delete_table(env.CLIENT_TABLE)  # the client's own table is unreachable even by id


# ---- instance identity preflight (before any create) --------------------------------------------------------------------
def test_identity_check_accepts_the_instance_the_records_were_observed_on():
    got = front.check_instance_identity(IdentityTransport(), [("mechanism record", set_record()), ("table mechanism record", table_record())])
    assert got["mcp_server_info"] == SERVER and got["tools_checked"] == sorted(front.be.TRANSPORT_OPERATIONS)


@pytest.mark.parametrize("server", [{"name": "n8n MCP Server", "version": "1.2.0"}, {"name": "other", "version": "1.1.0"}, None])
def test_identity_check_refuses_a_different_or_unknown_server(server):
    with pytest.raises(front.cli.OperatorError, match="differs from"):
        front.check_instance_identity(IdentityTransport(server=server or {}), [("mechanism record", set_record())])


@pytest.mark.parametrize("recorded", [None, {}, {"name": "n8n MCP Server"}, "1.1.0"])
def test_identity_check_refuses_a_record_with_no_server_identity(recorded):
    rec = {**set_record(), "server_info": recorded}
    with pytest.raises(front.cli.OperatorError, match="no server identity"):
        front.check_instance_identity(IdentityTransport(), [("mechanism record", rec)])


def test_identity_check_refuses_when_one_of_two_records_is_from_another_build():
    stale = {**table_record(), "server_info": {"name": "n8n MCP Server", "version": "1.0.0"}}
    with pytest.raises(front.cli.OperatorError, match="table mechanism record"):
        front.check_instance_identity(IdentityTransport(), [("mechanism record", set_record()), ("table mechanism record", stale)])


def test_identity_check_refuses_when_a_required_tool_is_missing():
    with pytest.raises(front.cli.OperatorError, match="required MCP tools"):
        front.check_instance_identity(IdentityTransport(tools=["test_workflow"]), [("mechanism record", set_record())])


def test_real_wiring_stops_on_identity_drift_before_returning_a_backend(tmp_path, monkeypatch):
    monkeypatch.setenv(front.be.ENV_APPROVAL, f"run:{BASE}:drift")
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    report, context, run_dir = check(tmp_path, label="drift")
    rec, trec = tmp_path / "s.json", tmp_path / "t.json"
    rec.write_text(json.dumps(set_record()), encoding="utf-8")
    trec.write_text(json.dumps(table_record()), encoding="utf-8")
    monkeypatch.setattr(front.be, "read_application_version", lambda base_url, opener=None: APP)
    drifted = IdentityTransport(server={"name": "n8n MCP Server", "version": "9.9.9"})
    monkeypatch.setattr(front.be, "make_transport", lambda backend, max_executions=None: drifted)
    args = types.SimpleNamespace(base_url=BASE, mechanism_record=str(rec), table_mechanism_record=str(trec), label="drift",
                                 protect=[], protect_table=[], table_project=None, expect_n8n_version=APP)
    with pytest.raises(front.cli.OperatorError, match="differs from"):
        front.real_wiring(args, run_dir, report, context)
    assert not (run_dir / "created.jsonl").exists() or (run_dir / "created.jsonl").read_text() == ""  # nothing was created
