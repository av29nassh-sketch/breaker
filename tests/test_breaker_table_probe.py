"""Offline coverage for the Data Table mechanism probe: a faithful fake passes, every deviation stops it, nothing real is touched."""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import socket
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tp = load("table_probe_under_test", ROOT / "tools" / "breaker_table_probe.py")
env = load("table_probe_fakes", ROOT / "tests" / "test_breaker_simulate_tables.py")
BASE = "http://127.0.0.1:5678"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


class ProbeBackend(env.TableBackend):
    expected_base_url = BASE

    def read(self, clone_id):
        value = super().read(clone_id)
        if self.knobs.get("rewrite_reference"):
            for node in value["nodes"]:
                if node["type"] == "n8n-nodes-base.dataTable":
                    node["parameters"]["dataTableId"]["cachedResultUrl"] = "/projects/x/datatables/" + "y"
        return value


class ProbeTransport(env.base.FakeTransport):
    """Interprets the probe workflow the way a faithful n8n would, with knobs for each way a real one could differ."""

    def call_tool_retrying(self, name, arguments, **kwargs):
        if name != "test_workflow":
            return super().call_tool_retrying(name, arguments, **kwargs)
        self.calls.append((name, arguments))
        definition = self.backend.store[arguments["workflowId"]]
        nodes = {n["name"]: n for n in definition["nodes"]}
        rows = self.backend.tables[nodes[tp.READ]["parameters"]["dataTableId"]["value"]]["rows"]
        k = self.knobs
        run = {tp.ENTRY: [{"sentinel": "T"}]}
        run[tp.READ] = [] if k.get("read_nothing") else [dict(r) for r in rows if r["k"] == "seed"]
        if not k.get("skip_insert"):
            rows.append({"k": "inserted", "n": 2, "id": 90})
        run[tp.INSERT] = [{"k": "inserted", "n": 2}]
        if k.get("upsert_duplicates"):
            rows.append({"k": "seed", "n": 10, "id": 91})
        else:
            for row in rows:
                if row["k"] == "seed":
                    row["n"] = 10
        run[tp.UPSERT] = [{"k": "seed", "n": 10}]
        run[tp.OBSERVE] = [{"k": "seed", "n": 10}]
        self.n += 1
        eid = f"exec-{self.n}"
        self.runs[eid] = {"status": k.get("status", "success"), "data": {"resultData": {"runData": {
            n: [{"data": {"main": [[{"json": x} for x in items]]}}] for n, items in run.items()}}}}
        return {"executionId": eid}, {}


def run(tmp_path, **knobs):
    backend = ProbeBackend(**{k: v for k, v in knobs.items() if k in (
        "fail_create_table", "fail_after_create_table", "fail_reset", "rewrite_reference", "fail_delete_table")})
    transport = ProbeTransport(backend, **knobs)
    report = tp.run_probe(backend=backend, transport=transport, out_root=tmp_path, run_id="p1")
    return report, backend, transport


def test_faithful_run_verifies_and_cleans_up_workflow_then_table(tmp_path):
    report, backend, transport = run(tmp_path)
    assert report["status"] == "VERIFIED" and report["stopped_because"] is None
    assert report["cleanup"] == {"workflow": "DELETED", "table": "DELETED"}
    assert not backend.tables and not backend.store
    assert [e[0] for e in backend.events if e[0].startswith("delete")] == ["delete_clone", "delete_table"]
    assert len([c for c in transport.calls if c[0] == "test_workflow"]) == 1
    record = tp.table_mechanism_from_record(report["record"], BASE)
    assert set(record["operations"]) == {"get", "insert", "upsert"}
    run_dir = tmp_path / "tableprobe-p1"
    assert (run_dir / "table-mechanism-record.json").is_file() and (run_dir / "tableprobe.json").is_file()


def test_the_probe_workflow_references_only_the_disposable_table(tmp_path):
    report, backend, _ = run(tmp_path)
    created = [c[1] for c in backend.calls if c[0] == "create"][0]
    refs = {n["parameters"]["dataTableId"]["value"] for n in created["nodes"] if n["type"] == tp.tables.DATA_TABLE}
    assert refs == {"tbl-1"} and created["name"].startswith("[BREAKER PROBE]")
    assert tp.strict_problems(created, "tbl-1", report_name(created), "p1") == []


def report_name(definition):
    return definition["nodes"][1]["parameters"]["dataTableId"]["cachedResultName"]


@pytest.mark.parametrize("knobs,fragment", [
    ({"skip_insert": True}, "observations did not hold"),
    ({"upsert_duplicates": True}, "observations did not hold"),
    ({"read_nothing": True}, "observations did not hold"),
    ({"rewrite_reference": True}, "differs from what was sent"),
    ({"status": "error"}, "did not run exactly"),
    ({"fail_create_table": True}, "unexpected"),
    ({"fail_reset": True}, "unexpected"),
])
def test_every_deviation_stops_the_probe_with_no_record_and_still_cleans_up(tmp_path, knobs, fragment):
    report, backend, _ = run(tmp_path, **knobs)
    assert report["status"] == "STOPPED" and fragment in report["stopped_because"] and report["record"] is None
    assert not (tmp_path / "tableprobe-p1" / "table-mechanism-record.json").exists()
    assert not backend.tables and not backend.store


def test_a_half_created_table_is_still_deleted(tmp_path):
    report, backend, _ = run(tmp_path, fail_after_create_table=True)
    assert report["status"] == "STOPPED" and report["cleanup"]["table"] == "DELETED" and not backend.tables


def test_failed_table_cleanup_is_reported_and_downgrades_the_status(tmp_path):
    report, backend, _ = run(tmp_path, fail_delete_table=True)
    assert report["status"] == "VERIFIED_BUT_CLEANUP_FAILED" and report["cleanup"]["table"].startswith("FAILED")
    assert backend.tables


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(workflow_insert_landed=False),
    lambda r: r.update(rest_readback_matches="yes"),
    lambda r: r.pop("reset_empties_table"),
    lambda r: r.update(base_url="http://127.0.0.1:9999"),
    lambda r: r.update(type_version=1.0),
    lambda r: r.update(node_type="n8n-nodes-base.set"),
    lambda r: r.update(operations=["get", "insert"]),
    lambda r: r.update(execution_id=" "),
    lambda r: r.update(kind="mechanism"),
])
def test_a_record_that_did_not_observe_everything_is_refused(tmp_path, mutate):
    report, _, _ = run(tmp_path)
    record = copy.deepcopy(report["record"])
    mutate(record)
    with pytest.raises(ValueError):
        tp.table_mechanism_from_record(record, BASE)
    with pytest.raises(ValueError):
        tp.table_mechanism_from_record("not a record", BASE)


@pytest.mark.parametrize("mutate,fragment", [
    (lambda d: d["nodes"][1]["parameters"].update(returnAll="={{ 1 }}"), "expression"),
    (lambda d: d["nodes"][2].update(credentials={"x": {}}), "credentials"),
    (lambda d: d.update(active=True), "active"),
    (lambda d: d["nodes"].append(dict(d["nodes"][-1], name="Extra")), "five probe nodes"),
    (lambda d: d["nodes"][2]["parameters"]["columns"]["value"].update(k="https://elsewhere.invalid"), "destination"),
])
def test_strict_problems_names_what_is_wrong(mutate, fragment):
    definition = tp.build_probe_definition("tbl-1", "breaker_sim_probe_x", "p1")
    assert tp.strict_problems(definition, "tbl-1", "breaker_sim_probe_x", "p1") == []
    mutate(definition)
    assert any(fragment in p for p in tp.strict_problems(definition, "tbl-1", "breaker_sim_probe_x", "p1"))


def test_cli_is_disarmed_by_default_and_needs_a_scratch_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("BREAKER_S4_APPROVAL", raising=False)
    scratch = tmp_path / "scratch-tp"
    assert tp.main(["--base-url", BASE, "--out-root", str(scratch), "--label", "t1"]) == 2
    assert "disarmed" in capsys.readouterr().err
    assert tp.main(["--base-url", BASE, "--out-root", str(tmp_path / "elsewhere"), "--label", "t2"]) == 2
    assert tp.main(["--base-url", "https://x.ngrok-free.dev", "--out-root", str(scratch), "--label", "t3"]) == 2
