"""Offline coverage for disposable Data Table support in the generic simulation runner.

The fake backend and transport model just enough of n8n's table behaviour (create, seed, read back, delete, and a Data
Table node reading or upserting a row by id) to prove the orchestration: the client's table is never referenced or touched,
every case starts from its own seed, read-back is independent of the workflow, and cleanup deletes the clone then the tables.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib
import socket
import sys
import urllib.request

import pytest
from breaker.readiness.provenance import readback_surfaces

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sim = load("sim_tables_under_test", ROOT / "tools" / "breaker_simulate.py")
neutralise = load("sim_tables_neutralise", ROOT / "tools" / "breaker_neutralise.py")
base = load("sim_tables_base_tests", ROOT / "tests" / "test_breaker_simulate.py")
B = "n8n-nodes-base."
CLIENT_TABLE = "ClientLeadsTable0001"
MECHANISM = base.MECHANISM
COLUMNS = [{"name": "email", "type": "string"}, {"name": "status", "type": "string"}]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


class TableBackend(base.FakeBackend):
    """The workflow fake plus the table API of the guarded backend (ownership is the fake's own, like the real one)."""

    def __init__(self, **knobs):
        super().__init__(**knobs)
        self.tables, self.created_tables, self.table_n, self.events = {}, {}, 0, []

    def create_table(self, name, columns):
        self.events.append(("create_table", name))
        if self.knobs.get("fail_create_table"):
            raise RuntimeError("table create failed")
        self.table_n += 1
        table_id = f"tbl-{self.table_n}"
        self.tables[table_id] = {"name": name, "columns": [c["name"] for c in columns], "rows": []}
        self.created_tables[table_id] = name
        if self.knobs.get("fail_after_create_table"):
            raise RuntimeError("table verification failed after the table existed")
        return table_id

    def reset_table(self, table_id, columns, seed_rows):
        self.events.append(("reset_table", table_id))
        if self.knobs.get("fail_reset"):
            raise RuntimeError("reset failed")
        self.tables[table_id]["rows"] = [{c: row.get(c) for c in columns} | {"id": i + 1} for i, row in enumerate(seed_rows)]
        return len(seed_rows)

    def table_rows(self, table_id):
        self.events.append(("table_rows", table_id))
        if self.knobs.get("fail_readback"):
            raise RuntimeError("read-back failed")
        return copy.deepcopy(self.tables[table_id]["rows"])

    def delete_table(self, table_id):
        self.events.append(("delete_table", table_id))
        if self.knobs.get("fail_delete_table"):
            raise RuntimeError("table delete refused")
        del self.tables[table_id]
        del self.created_tables[table_id]

    def delete(self, clone_id):
        self.events.append(("delete_clone", clone_id))
        super().delete(clone_id)


class TableTransport(base.FakeTransport):
    """Runs Data Table nodes against the fake tables and refuses (as n8n would not) to touch any table not created here."""

    def __init__(self, backend, **knobs):
        super().__init__(backend, **knobs)
        self.touched = []

    def call_tool_retrying(self, name, arguments, **kwargs):
        if name == "test_workflow":
            definition = self.backend.store[arguments["workflowId"]]
            entry = arguments["triggerNodeName"]
            item = arguments["pinData"][entry][0]["json"]
            nodes = {n["name"]: n for n in definition["nodes"]}
            order, run_data, current = [entry], {}, entry
            while True:
                nxt = definition["connections"].get(current, {}).get("main", [[]])[0]
                if not nxt:
                    break
                current = nxt[0]["node"]
                order.append(current)
            for node_name in order:
                node = nodes[node_name]
                if node["type"] == B + "dataTable":
                    item = self.run_table_node(node, item)
                elif node["type"] == B + "set" and "jsonOutput" in node["parameters"]:
                    item = json.loads(node["parameters"]["jsonOutput"])
                run_data[node_name] = [{"data": {"main": [[{"json": item}]]}}]
            self.n += 1
            execution_id = f"exec-{self.n}"
            self.runs[execution_id] = {"status": "success", "data": {"resultData": {"runData": run_data}}}
            self.calls.append((name, arguments))
            return {"executionId": execution_id}, {}
        return super().call_tool_retrying(name, arguments, **kwargs)

    def run_table_node(self, node, item):
        table_id = node["parameters"]["dataTableId"]["value"]
        self.touched.append(table_id)
        table = self.backend.tables[table_id]  # KeyError == the workflow reached a table nobody here created
        params = node["parameters"]
        if params["operation"] == "get":
            found = [row for row in table["rows"] if row.get("email") == item.get("email")]
            return {**item, "known": bool(found), "found_status": found[0]["status"] if found else None}
        email = item["email"]
        row = {"email": email, "status": params["columns"]["value"]["status"]}
        table["rows"] = [r for r in table["rows"] if r.get("email") != email] + [row | {"id": len(table["rows"]) + 1}]
        return item


def dt(name, operation, extra=None):
    params = {"resource": "row", "operation": operation,
              "dataTableId": {"__rl": True, "mode": "list", "value": CLIENT_TABLE, "cachedResultName": "client_leads",
                              "cachedResultUrl": f"/projects/p1/datatables/{CLIENT_TABLE}"}}
    params.update(extra or {})
    return {"id": f"src-{name}", "name": name, "type": B + "dataTable", "typeVersion": 1.1, "position": [0, 0],
            "parameters": params}


def workflow(find_ref=None):
    find = dt("Find Lead", "get", {"filters": {"conditions": [{"keyName": "email", "condition": "eq",
                                                               "keyValue": "={{ $json.email }}"}]}})
    if find_ref is not None:
        find["parameters"]["dataTableId"] = find_ref
    save = dt("Save Lead", "upsert", {"columns": {"mappingMode": "defineBelow", "matchingColumns": ["email"],
                                                    "value": {"email": "={{ $json.email }}", "status": "CONTACTED"}}})
    return {"name": "Lead intake", "nodes": [
        {"id": "src-in", "name": "Intake", "type": B + "executeWorkflowTrigger", "position": [0, 0], "parameters": {}},
        find, save,
        {"id": "src-done", "name": "Done", "type": B + "noOp", "position": [0, 0], "parameters": {}}],
        "connections": {"Intake": {"main": [[{"node": "Find Lead", "type": "main", "index": 0}]]},
                        "Find Lead": {"main": [[{"node": "Save Lead", "type": "main", "index": 0}]]},
                        "Save Lead": {"main": [[{"node": "Done", "type": "main", "index": 0}]]}}, "settings": {}}


def default_cases():
    return [
        {"id": "new-lead", "input": {"email": "new@example.invalid"},
         "output_assertions": [{"node": "Done", "path": "known", "equals": False}],
         "table_assertions": [{"table": "leads", "equals": [{"email": "new@example.invalid", "status": "CONTACTED"}]}]},
        {"id": "known-lead", "input": {"email": "old@example.invalid"},
         "seed": {"leads": [{"email": "old@example.invalid", "status": "NEW"}]},
         "output_assertions": [{"node": "Done", "path": "found_status", "equals": "NEW"}],
         "table_assertions": [{"table": "leads", "count": 1},
                              {"table": "leads", "contains": [{"email": "old@example.invalid", "status": "CONTACTED"}]}]},
        {"id": "reset-proof", "input": {"email": "x@example.invalid"},
         "output_assertions": [{"node": "Done", "path": "known", "equals": False}],
         "table_assertions": [{"table": "leads", "count": 1}]},
    ]


def write_cases(tmp_path, *, definition=None, cases=None, tables="default"):
    definition = definition or workflow()
    raw = json.dumps(definition, separators=(",", ":"), ensure_ascii=False).encode()
    (tmp_path / "workflow.json").write_bytes(raw)
    if tables == "default":
        tables = {"leads": {"nodes": ["Find Lead", "Save Lead"], "columns": COLUMNS}}
    doc = {"schema_version": 1, "workflow": {"path": "workflow.json", "sha256": hashlib.sha256(raw).hexdigest()},
           "entry_node": "Intake", "cases": cases or default_cases()}
    if tables is not None:
        doc["tables"] = tables
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def run(tmp_path, *, backend_knobs=None, cases_kw=None, run_id="t1", check_ids=None):
    path = write_cases(tmp_path, **(cases_kw or {}))
    backend = TableBackend(**(backend_knobs or {}))
    transport = TableTransport(backend)
    result = sim.simulate(path, backend=backend, transport=transport, mechanism=MECHANISM, out_root=tmp_path / "runs",
                          run_id=run_id, check_ids=check_ids)
    return result, backend, transport


def statuses(result):
    return {c.case_id: c.status for g in result.groups for c in g.cases}


def test_cases_run_against_disposable_tables_and_every_case_starts_from_its_own_seed(tmp_path):
    result, backend, transport = run(tmp_path)
    assert result.status == "COMPLETED"
    assert statuses(result) == {"new-lead": "CONFORMS", "known-lead": "CONFORMS", "reset-proof": "CONFORMS"}
    # "reset-proof" saw count == 1 although two earlier cases had written rows: each case is reset to its own seed first
    assert set(transport.touched) == {"tbl-1"} and CLIENT_TABLE not in transport.touched
    assert not backend.tables and not backend.created_tables and not backend.store


def test_clone_never_references_the_client_table_and_is_rebound_to_the_created_one(tmp_path):
    result, backend, _ = run(tmp_path)
    created = [call[1] for call in backend.calls if call[0] == "create"]
    assert len(created) == 1
    blob = json.dumps(created[0])
    assert CLIENT_TABLE not in blob and "client_leads" not in blob and "cachedResultUrl" not in blob
    refs = {n["parameters"]["dataTableId"]["value"] for n in created[0]["nodes"] if n["type"] == B + "dataTable"}
    assert refs == {"tbl-1"}
    manifest = result.groups[0].manifest
    assert manifest["test_tables"][0]["table_id"] == "tbl-1"
    assert manifest["test_tables"][0]["source_table_id_sha256"] == hashlib.sha256(CLIENT_TABLE.encode()).hexdigest()
    run_text = (result.run_dir / "run.json").read_text(encoding="utf-8")
    assert CLIENT_TABLE not in run_text and "client_leads" not in run_text


def test_cleanup_deletes_the_clone_before_the_tables_and_records_both(tmp_path):
    result, backend, _ = run(tmp_path)
    order = [e[0] for e in backend.events if e[0].startswith("delete")]
    assert order == ["delete_clone", "delete_table"]
    group = result.groups[0]
    assert group.cleanup == "DELETED" and [t["cleanup"] for t in group.tables] == ["DELETED"]
    assert [t["logical"] for t in group.tables] == ["leads"]


def test_product_fail_when_the_workflow_writes_the_wrong_row(tmp_path):
    cases = default_cases()
    cases[0]["table_assertions"] = [{"table": "leads", "equals": [{"email": "new@example.invalid", "status": "SOMETHING_ELSE"}]}]
    result, _, _ = run(tmp_path, cases_kw={"cases": cases})
    case = next(c for g in result.groups for c in g.cases if c.case_id == "new-lead")
    assert case.status == "PRODUCT_FAIL" and any(f.startswith("table leads equals") for f in case.failed_assertions)


def test_table_readback_is_recorded_without_store_style_keys_and_never_promotable(tmp_path):
    result, _, _ = run(tmp_path, check_ids={"new-lead": "CHECK-1"})
    case = next(c for g in result.groups for c in g.cases if c.case_id == "new-lead")
    data = case.read_back["simulated_sandbox_data"]
    assert data["tables"]["leads"]["rows_after"] == [{"email": "new@example.invalid", "status": "CONTACTED"}]
    assert "not client data" in data["source"]
    assert readback_surfaces(case.read_back, case.observed) == frozenset()
    campaign = json.loads((result.run_dir / "campaigns" / "simulate.json").read_text(encoding="utf-8"))
    assert campaign["environment"] == "SIMULATED" and all(v["status"] == "FAIL" for v in campaign["verdicts"])


@pytest.mark.parametrize("ref", [
    {"__rl": True, "mode": "id", "value": "={{ $json.table }}"},
    {"__rl": True, "mode": "name", "value": ""}])
def test_dynamic_table_reference_blocks_before_any_call(tmp_path, ref):
    result, backend, _ = run(tmp_path, cases_kw={"definition": workflow(find_ref=ref)})
    assert result.status == "BLOCKED" and not backend.calls and not backend.events


def test_undeclared_or_missing_declaration_blocks_before_any_call(tmp_path):
    for tables in (None, {"leads": {"nodes": ["Find Lead"], "columns": COLUMNS}}):
        sub = tmp_path / str(bool(tables))
        sub.mkdir()
        cases = [c for c in default_cases() if c["id"] == "reset-proof"]
        for case in cases:
            case.pop("table_assertions", None)
            case["must_run"] = ["Done"]
        result, backend, _ = run(sub, cases_kw={"tables": tables, "cases": cases})
        assert result.status == "BLOCKED" and not backend.calls and not backend.events


def test_table_create_failure_is_inconclusive_and_no_clone_is_created(tmp_path):
    result, backend, _ = run(tmp_path, backend_knobs={"fail_create_table": True})
    assert set(statuses(result).values()) == {"INCONCLUSIVE"}
    assert not [c for c in backend.calls if c[0] == "create"] and result.groups[0].status == "INCONCLUSIVE"


def test_a_table_whose_creation_half_failed_is_still_deleted(tmp_path):
    result, backend, _ = run(tmp_path, backend_knobs={"fail_after_create_table": True})
    assert set(statuses(result).values()) == {"INCONCLUSIVE"}
    assert not backend.tables and ("delete_table", "tbl-1") in backend.events
    assert [t["cleanup"] for t in result.groups[0].tables] == ["DELETED"]


@pytest.mark.parametrize("knob,fragment", [("fail_reset", "reset failed"), ("fail_readback", "read-back failed")])
def test_reset_or_readback_failure_is_inconclusive_for_the_case(tmp_path, knob, fragment):
    result, _, _ = run(tmp_path, backend_knobs={knob: True})
    assert set(statuses(result).values()) == {"INCONCLUSIVE"}
    assert all(fragment in c.detail for g in result.groups for c in g.cases)


def test_table_delete_failure_is_reported_not_swallowed(tmp_path):
    result, backend, _ = run(tmp_path, backend_knobs={"fail_delete_table": True})
    group = result.groups[0]
    assert group.cleanup == "DELETED" and group.tables[0]["cleanup"].startswith("FAILED")
    assert backend.tables  # the leftover is visible to the operator, never hidden


def test_each_stub_group_gets_its_own_tables_and_all_are_deleted(tmp_path):
    definition = workflow()
    definition["nodes"].insert(3, {"id": "src-notify", "name": "Notify", "type": B + "httpRequest", "position": [0, 0],
                                   "parameters": {}})
    definition["connections"]["Save Lead"] = {"main": [[{"node": "Notify", "type": "main", "index": 0}]]}
    definition["connections"]["Notify"] = {"main": [[{"node": "Done", "type": "main", "index": 0}]]}
    cases = [{"id": "sent", "input": {"email": "a@example.invalid"}, "stubs": {"Notify": {"sent": True}},
              "table_assertions": [{"table": "leads", "count": 1}]},
             {"id": "not-sent", "input": {"email": "b@example.invalid"}, "stubs": {"Notify": {"sent": False}},
              "table_assertions": [{"table": "leads", "count": 1}]}]
    path = write_cases(tmp_path, definition=definition, cases=cases)
    document = json.loads(path.read_text(encoding="utf-8"))
    backend = TableBackend()
    result = sim.simulate(path, backend=backend, transport=TableTransport(backend), mechanism=MECHANISM,
                          out_root=tmp_path / "runs", run_id="two")
    assert statuses(result) == {"sent": "CONFORMS", "not-sent": "CONFORMS"} and document["tables"]
    assert [g.tables[0]["table_id"] for g in result.groups] == ["tbl-1", "tbl-2"]
    assert len({g.tables[0]["table_name"] for g in result.groups}) == 2
    assert not backend.tables and all(g.cleanup == "DELETED" for g in result.groups)


def test_workflow_without_tables_is_unchanged_manifest_and_no_table_calls(tmp_path):
    definition = {"name": "plain", "nodes": [
        {"id": "a", "name": "Intake", "type": B + "executeWorkflowTrigger", "parameters": {}},
        {"id": "b", "name": "Done", "type": B + "noOp", "parameters": {}}],
        "connections": {"Intake": {"main": [[{"node": "Done", "type": "main", "index": 0}]]}}, "settings": {}}
    cases = [{"id": "c", "input": {"x": 1}, "must_run": ["Done"]}]
    result, backend, _ = run(tmp_path, cases_kw={"definition": definition, "cases": cases, "tables": None})
    assert statuses(result) == {"c": "CONFORMS"}
    assert "test_tables" not in result.groups[0].manifest and result.groups[0].tables == ()
    assert not [e for e in backend.events if "table" in e[0]]


def test_a_group_that_never_reached_a_real_clone_records_no_digest_and_no_placeholder_manifest(tmp_path):
    result, _, _ = run(tmp_path, backend_knobs={"fail_create_table": True})
    group = result.groups[0]
    assert group.transformed_definition_digest == "" and group.manifest is None and group.clone_id is None
    run_text = (result.run_dir / "run.json").read_text(encoding="utf-8")
    assert "placeholder" not in run_text
    campaign = json.loads((result.run_dir / "campaigns" / "simulate.json").read_text(encoding="utf-8"))
    assert campaign["candidate"]["transformed_definition_digests"] == []


# ---- defence in depth: each guard is checked on its own, not only through the layer above it -------------------------------
def specs_for(definition):
    cases = sim._cases
    return cases.tables_mod.parse_declarations(
        {"leads": {"nodes": ["Find Lead", "Save Lead"], "columns": COLUMNS}}, definition)[0]


def neutralise_with(definition, ids=("tbl-9", "breaker_sim_x_0_leads")):
    specs = specs_for(definition)
    return neutralise.neutralise(definition, {}, mechanism=MECHANISM, tables=specs,
                                 table_bindings={"leads": {"id": ids[0], "name": ids[1]}})


def test_a_binding_to_the_clients_own_table_id_is_refused_by_the_neutraliser_itself():
    definition = workflow()
    with pytest.raises(neutralise.StubError, match="duplicate or source table id"):
        neutralise_with(definition, ids=(CLIENT_TABLE, "x"))
    with pytest.raises(neutralise.StubError, match="exactly match"):
        neutralise.neutralise(definition, {}, mechanism=MECHANISM, tables=specs_for(definition), table_bindings={})
    assert neutralise_with(definition).definition_digest  # the legitimate binding still works


def test_the_clients_table_id_anywhere_else_in_the_definition_blocks_the_transform():
    definition = workflow()
    definition["nodes"].append({"id": "s", "name": "Note", "type": B + "stickyNote", "position": [0, 0],
                                "parameters": {"content": f"table {CLIENT_TABLE} is the real one"}})
    with pytest.raises(neutralise.TransformError) as error:
        neutralise_with(definition)
    assert any("client table id" in p for p in error.value.problems) and CLIENT_TABLE not in str(error.value)


def test_s1_accepts_a_declared_static_reference_only_and_never_a_dynamic_or_undeclared_one():
    pf = sim._pf
    definition = workflow()
    declared = ["Find Lead", "Save Lead"]
    assert not pf.evaluate(definition, rebindable_nodes=declared).blocked
    assert pf.evaluate(definition, rebindable_nodes=["Find Lead"]).blocked  # Save Lead undeclared
    assert pf.evaluate(definition).blocked
    dynamic = workflow(find_ref={"__rl": True, "mode": "id", "value": "={{ $json.table }}"})
    blocked = pf.evaluate(dynamic, rebindable_nodes=declared)
    assert blocked.blocked and "Find Lead" in " ".join(blocked.reasons)
    # a rebound clone is judged by the ids this run created, never by the source declaration
    assert pf.evaluate(definition, rebindable_nodes=declared).blocked is False
    assert pf.evaluate(definition, isolated_tables=["tbl-1"]).blocked
