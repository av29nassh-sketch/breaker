"""Offline tests for generic disposable Data Table declarations."""
from __future__ import annotations

import importlib.util
import pathlib
import socket
import sys
import urllib.request

import pytest

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "breaker_tables.py"
spec = importlib.util.spec_from_file_location("breaker_tables_under_test", TOOL)
bt = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bt
spec.loader.exec_module(bt)
B = "n8n-nodes-base."
SOURCE = "ClientTable987654"
COLUMNS = [{"name": "message_key", "type": "string"}, {"name": "status", "type": "string"}]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


def node(name, operation="get", table_id=SOURCE, **extra):
    params = {"resource": "row", "operation": operation,
              "dataTableId": {"__rl": True, "mode": "id", "value": table_id}, **extra}
    return {"name": name, "type": bt.DATA_TABLE, "typeVersion": 1.1, "parameters": params}


def definition(*nodes):
    return {"nodes": list(nodes)}


def declaration(names=("Read", "Write"), seed=None, columns=None):
    result = {"nodes": list(names), "columns": COLUMNS if columns is None else columns}
    if seed is not None:
        result["seed"] = seed
    return result


def valid_definition():
    read = node("Read", filters={"conditions": [{"keyName": "message_key", "condition": "eq"}]})
    write = node("Write", "upsert", columns={"mappingMode": "defineBelow", "matchingColumns": ["message_key"],
                                               "value": {"message_key": "={{ $json.message_key }}", "status": "CLAIMED"}})
    return definition(read, write)


def test_realistic_get_upsert_declaration_and_extractors():
    wf = valid_definition()
    specs, problems = bt.parse_declarations({"support": declaration(seed=[{"message_key": "m1", "status": "NEW"}])}, wf)
    assert not problems
    assert specs["support"].nodes == ("Read", "Write")
    assert specs["support"].source_id == SOURCE
    assert bt.data_table_nodes(wf) == {"Read": wf["nodes"][0], "Write": wf["nodes"][1]}
    assert bt.static_source_id(wf["nodes"][0]) == SOURCE
    assert bt.referenced_columns(wf["nodes"][1]) == {"message_key", "status"}


def test_empty_declarations_and_reference_modes():
    assert bt.parse_declarations(None, {}) == ({}, [])
    assert bt.parse_declarations({}, {}) == ({}, [])
    for ref in ({"value": "= $json.id"}, {"mode": "name", "value": ""}, {}, None):
        assert bt.static_source_id({"parameters": {"dataTableId": ref}}) is None
    assert bt.static_source_id({"parameters": {"dataTableId": {"mode": "list", "value": "static"}}}) == "static"


@pytest.mark.parametrize("mutate, fragment", [
    (lambda wf, raw: raw.update({"Bad-Name": declaration()}), "logical name"),
    (lambda wf, raw: raw.update({"support": []}), "must be an object"),
    (lambda wf, raw: raw["support"].update(extra=1), "unknown key"),
    (lambda wf, raw: raw["support"].update(nodes=[]), "non-empty list"),
    (lambda wf, raw: raw["support"].update(nodes=["Read", "Read"]), "unique"),
    (lambda wf, raw: raw["support"].update(nodes=["Absent"]), "missing or non-Data Table"),
    (lambda wf, raw: raw["support"].update(columns=[]), "columns must be a non-empty list"),
    (lambda wf, raw: raw["support"].update(columns=[{"name": "bad-name", "type": "string"}]), "column name"),
    (lambda wf, raw: raw["support"].update(columns=[{"name": "id", "type": "string"}]), "system column"),
    (lambda wf, raw: raw["support"].update(columns=[{"name": "x", "type": "string"}, {"name": "x", "type": "string"}]), "duplicate column"),
    (lambda wf, raw: raw["support"].update(columns=[{"name": "x", "type": "money"}]), "invalid type"),
    (lambda wf, raw: raw["support"].update(columns=[{"name": "x", "type": "string", "extra": 1}]), "exact name/type"),
    (lambda wf, raw: raw["support"].update(seed=[{"unknown": 1}]), "undeclared column"),
    (lambda wf, raw: raw["support"].update(columns=[{"name": f"c{i}", "type": "string"} for i in range(51)]), "exceeds 50 columns"),
])
def test_declaration_problem_classes(mutate, fragment):
    wf = valid_definition()
    raw = {"support": declaration()}
    mutate(wf, raw)
    _, problems = bt.parse_declarations(raw, wf)
    assert any(fragment in p for p in problems), problems


def test_dynamic_mixed_and_uncovered_references_refuse_and_valid_other_spec_survives():
    dynamic = node("Dynamic", table_id="={{ $json.table }}")
    _, problems = bt.parse_declarations({"support": declaration(("Dynamic",))}, definition(dynamic))
    assert any("no static source id" in p for p in problems)

    mixed = valid_definition()
    mixed["nodes"][1]["parameters"]["dataTableId"]["value"] = "OtherTable"
    _, problems = bt.parse_declarations({"support": declaration()}, mixed)
    assert any("different static source ids" in p for p in problems)

    _, problems = bt.parse_declarations({"support": declaration(("Read",))}, valid_definition())
    assert any("not covered" in p and "Write" in p for p in problems)

    bad_ref = node("Read", filters={"conditions": [{"keyName": "not_declared"}]})
    wf = definition(bad_ref)
    _, problems = bt.parse_declarations({"support": declaration(("Read",))}, wf)
    assert any("undeclared column 'not_declared'" in p for p in problems)


def test_node_cannot_be_shared_and_source_role_cannot_be_split():
    wf = valid_definition()
    _, problems = bt.parse_declarations({"one": declaration(("Read",)), "two": declaration(("Read", "Write"))}, wf)
    assert any("appears in more than one" in p for p in problems)

    _, problems = bt.parse_declarations({"one": declaration(("Read",)), "two": declaration(("Write",))}, wf)
    assert any("share one client source id" in p for p in problems)


def test_validate_rows_types_limits_and_canonical_size():
    cols = (("text", "string"), ("number", "number"), ("flag", "boolean"), ("date", "date"))
    assert bt.validate_rows([{"text": "x", "number": 1, "flag": True, "date": "today"}], cols, "seed") == []
    assert any("must be a number" in p for p in bt.validate_rows([{"number": True}], cols, "seed"))
    assert any("must be a number" in p for p in bt.validate_rows([{"number": float("inf")}], cols, "seed"))
    assert any("must be a list" in p for p in bt.validate_rows({}, cols, "seed"))
    assert any("exceeds 1000 rows" in p for p in bt.validate_rows([{}] * 1001, cols, "seed"))
    assert any("exceeds 262144 bytes" in p for p in bt.validate_rows([{"text": "x" * 270000}], cols, "seed"))
    assert any("system column" in p or "undeclared column" in p for p in bt.validate_rows([{"id": 1}], cols, "seed"))


def test_case_seed_and_deep_copied_effective_seed():
    specs, problems = bt.parse_declarations({"support": declaration(("Read",), seed=[{"message_key": "base"}])},
                                              definition(node("Read")))
    assert not problems
    assert not bt.validate_case_seed(None, specs, "case seed")
    assert bt.validate_case_seed({"other": []}, specs, "case seed")
    assert bt.validate_case_seed({"support": [{"bad": 1}]}, specs, "case seed")
    override = {"support": [{"message_key": "override"}]}
    result = bt.effective_seed(specs["support"], override)
    result[0]["message_key"] = "changed"
    assert override["support"][0]["message_key"] == "override"
    assert bt.effective_seed(specs["support"], {}) == [{"message_key": "base"}]


def test_assertion_validation_and_comparison_semantics():
    specs, problems = bt.parse_declarations({"support": declaration()}, valid_definition())
    assert not problems
    assertions = [{"table": "support", "count": 2},
                  {"table": "support", "equals": [{"message_key": "a", "status": "one"}]},
                  {"table": "support", "contains": [{"status": "one"}, {"message_key": "b"}]}]
    clean, problems = bt.validate_table_assertions(assertions, specs, "case assertions")
    assert not problems and clean == assertions
    observed = {"support": [{"message_key": "a", "status": "one", "id": "sys", "createdAt": "now"}]}
    assert bt.check_table_assertions([assertions[1]], observed, specs) == []
    assert bt.check_table_assertions([assertions[2]], observed, specs) == [
        "table support contains {'message_key': 'b'}"]
    assert bt.check_table_assertions([{"table": "support", "count": 2}], observed, specs) == [
        "table support count == 2"]
    _, problems = bt.validate_table_assertions([{"table": "missing", "count": 0}], specs, "assert")
    assert any("undeclared table" in p for p in problems)
    for bad in ([{"table": "support", "count": True}], [{"table": "support", "contains": []}],
                [{"table": "support", "count": 1, "equals": []}], [{"table": "support", "count": 1, "extra": 1}]):
        assert bt.validate_table_assertions(bad, specs, "assert")[1]


def test_contains_requires_distinct_matches_and_numbers_normalise():
    specs, _ = bt.parse_declarations({"support": declaration(("Read",), columns=[{"name": "number", "type": "number"}])},
                                     definition(node("Read")))
    spec = specs["support"]
    assertions = [{"table": "support", "contains": [{"number": 1}, {"number": 1.0}]}]
    assert not bt.check_table_assertions([{"table": "support", "contains": [{"number": 1.0}]}],
                                         {"support": [{"number": 1.0}]}, specs)
    assert bt.check_table_assertions(assertions, {"support": [{"number": 1}]}, specs) == [
        "table support contains {'number': 1.0}"]
    assert bt.normalise_rows([{"number": 1.0, "id": "ignored"}], spec) == [{"number": 1}]


def test_contains_uses_a_maximum_matching_not_a_greedy_one():
    specs, _ = bt.parse_declarations({"support": declaration()}, valid_definition())
    stored = [{"message_key": "a", "status": "one"}, {"message_key": "a", "status": "two"}]
    # the looser row is listed first and would take the only stored row the stricter one can use if matching were greedy
    held = [{"table": "support", "contains": [{"message_key": "a"}, {"message_key": "a", "status": "one"}]}]
    assert not bt.check_table_assertions(held, {"support": stored}, specs)
    short = [{"table": "support", "contains": [{"message_key": "a", "status": "one"},
                                                {"message_key": "a", "status": "one"}]}]
    assert bt.check_table_assertions(short, {"support": stored}, specs) == [
        "table support contains {'message_key': 'a', 'status': 'one'}"]


def test_equals_one_cell_mutation_and_missing_readback():
    specs, _ = bt.parse_declarations({"support": declaration()}, valid_definition())
    expected = {"message_key": "a", "status": "one"}
    assert bt.check_table_assertions([{"table": "support", "equals": [expected]}],
                                     {"support": [{**expected, "status": "two"}]}, specs)
    assert bt.check_table_assertions([{"table": "support", "equals": [expected]}], {}, specs) == [
        "table support equals [{'message_key': 'a', 'status': 'one'}] (no readback)"]
    assert bt.check_table_assertions([{"table": "support", "count": 1}], {}, specs) == [
        "table support count == 1 (no readback)"]


def test_rebind_leak_detection_and_generated_names():
    first = bt.rebind_parameter("disposable", "breaker_sim")
    assert first == {"__rl": True, "mode": "id", "value": "disposable", "cachedResultName": "breaker_sim"}
    assert "cachedResultUrl" not in first
    first["value"] = "mutated"
    assert bt.rebind_parameter("disposable", "breaker_sim")["value"] == "disposable"

    issues = bt.leak_problems({"nodes": [{"id": SOURCE}]}, [SOURCE, "", SOURCE])
    assert len(issues) == 1 and SOURCE not in issues[0] and "Clie..." in issues[0]
    assert not bt.leak_problems({"nodes": []}, [SOURCE])

    name = bt.table_name("run-1", 0, "support")
    assert name.startswith("breaker_sim_") and name.endswith("_0_support") and len(name) <= 63
    with pytest.raises(ValueError):
        bt.table_name("x", -1, "support")
    with pytest.raises(ValueError):
        bt.table_name("x", True, "support")
    with pytest.raises(ValueError):
        bt.table_name("x", 0, "Bad")
    with pytest.raises(ValueError):
        bt.table_name("x", 10**80, "support")


@pytest.mark.parametrize("operation,ok", [("get", True), ("insert", True), ("upsert", True),
                                          ("update", False), ("deleteRows", False), ("rowExists", False)])
def test_only_operations_the_probe_exercises_are_accepted(operation, ok):
    wf = definition(node("Read", operation))
    specs, problems = bt.parse_declarations({"t": declaration(("Read",))}, wf)
    assert bool(specs) is ok and bool(problems) is (not ok)
    if not ok:
        assert "no probed mechanism" in problems[0]


def test_non_row_resource_is_refused():
    bad = node("Read")
    bad["parameters"]["resource"] = "table"
    specs, problems = bt.parse_declarations({"t": declaration(("Read",))}, definition(bad))
    assert not specs and "not a row operation" in problems[0]


def test_only_the_probed_node_version_is_accepted():
    other = node("Read")
    other["typeVersion"] = 1
    specs, problems = bt.parse_declarations({"t": declaration(("Read",))}, definition(other))
    assert not specs and "typeVersion" in problems[0]


def test_contains_cannot_pass_vacuously_with_an_empty_row():
    specs, _ = bt.parse_declarations({"support": declaration()}, valid_definition())
    clean, problems = bt.validate_table_assertions([{"table": "support", "contains": [{}]}], specs, "a")
    assert not clean and "non-empty rows" in problems[0]
    assert bt.check_table_assertions([{"table": "support", "contains": [{"status": None}]}], {"support": []}, specs)
