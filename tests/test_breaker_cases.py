"""Offline tests for the generic versioned cases loader."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import socket
import sys
import urllib.request

import pytest

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "breaker_cases.py"
spec = importlib.util.spec_from_file_location("breaker_cases_under_test", TOOL)
bc = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bc
spec.loader.exec_module(bc)
B = "n8n-nodes-base."


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


def write_case(tmp_path, *, nodes=None, overrides=None, source=None, case=None, root_extra=None):
    definition = source or {"name": "tiny", "nodes": nodes or [
        {"name": "Start", "type": B + "manualTrigger", "parameters": {}},
        {"name": "Call", "type": B + "httpRequest", "parameters": {}},
    ], "connections": {}, "settings": {}}
    workflow = tmp_path / "workflow.json"
    raw = json.dumps(definition, separators=(",", ":")).encode()
    workflow.write_bytes(raw)
    entry = {"id": "one", "input": {}, "stubs": {"Call": {"ok": True}}} if case is None else case
    document = {"schema_version": 1, "workflow": {"path": "workflow.json", "sha256": hashlib.sha256(raw).hexdigest()},
                "entry_node": "Start", "cases": [entry]}
    if overrides is not None:
        document["stubs"] = overrides
    if root_extra:
        document.update(root_extra)
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path, document


def test_load_expected_verbatim_and_effective_stubs_and_group_order(tmp_path):
    expected = {"nested": [{"x": [1, {"unicode": "é"}]}]}
    path, doc = write_case(tmp_path, overrides={"Call": {"base": 1}}, case={
        "id": "a", "input": {"v": 1}, "stubs": {"Call": {"case": 2}}, "expected": expected,
        "expected_sha256": hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()})
    doc["cases"].append({"id": "b", "input": {}, "stubs": {"Call": {"case": 2}}, "expected": expected})
    path.write_text(json.dumps(doc), encoding="utf-8")
    loaded = bc.load_cases(path)
    assert loaded.cases[0].expected == expected
    assert loaded.cases[0].stubs == {"Call": {"case": 2}}  # a per-case stub replaces the default, never merges into it
    assert list(bc.group_by_stubs(loaded).values()) == [("a", "b")]
    assert bc.stub_set_hash({"Call": {"x": 1, "y": 2}}) == bc.stub_set_hash({"Call": {"y": 2, "x": 1}})


@pytest.mark.parametrize("mutation, fragment", [
    (lambda d: d.update(schema_version=2), "schema_version"),
    (lambda d: d.update(extra=1), "unknown key"),
    (lambda d: d["cases"][0].update(id="bad id"), "id is invalid"),
    (lambda d: d["cases"].append(dict(d["cases"][0])), "duplicate case id"),
    (lambda d: d["cases"][0].update(input=[]), "input must be an object"),
    (lambda d: d["cases"][0].update(stubs={}), "missing effective stub"),
    (lambda d: d["cases"][0].update(must_run=["Start"], must_not_run=["Start"]), "overlap"),
    (lambda d: d["cases"][0].update(output_assertions=[{"node": "Ghost", "path": "x", "equals": 1}]), "unknown node"),
])
def test_schema_and_case_problems_are_reported(tmp_path, mutation, fragment):
    path, doc = write_case(tmp_path)
    mutation(doc)
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError) as error:
        bc.load_cases(path)
    assert any(fragment in p for p in error.value.problems)


@pytest.mark.parametrize("path_value", ["../escape.json", "C:\\escape.json", "."])
def test_unsafe_or_non_file_workflow_paths_refuse(tmp_path, path_value):
    path, doc = write_case(tmp_path)
    doc["workflow"]["path"] = path_value
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError):
        bc.load_cases(path)


def test_duplicate_json_keys_nan_malformed_and_hash_mismatch_refuse(tmp_path):
    path, doc = write_case(tmp_path)
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(bc.CasesError, match="duplicate"):
        bc.load_cases(path)
    path.write_text('{"x":NaN}', encoding="utf-8")
    with pytest.raises(bc.CasesError, match="non-finite"):
        bc.load_cases(path)
    path.write_text("{", encoding="utf-8")
    with pytest.raises(bc.CasesError):
        bc.load_cases(path)
    path, doc = write_case(tmp_path)
    doc["workflow"]["sha256"] = "0" * 64
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="mismatch"):
        bc.load_cases(path)


@pytest.mark.parametrize("mutation, fragment", [
    (lambda d: d.pop("entry_node"), "entry_node"),
    (lambda d: d["workflow"].update(extra=1), "workflow has unknown key"),
    (lambda d: d["cases"][0].update(extra=1), "case[0] has unknown key"),
    (lambda d: d["cases"][0].update(must_run=["Start", "Start"]), "duplicate"),
    (lambda d: d["cases"][0].update(must_run=["Missing"]), "unknown node"),
    (lambda d: d["cases"][0].update(output_assertions=[{"node": "Start", "path": "x", "equals": 1, "extra": 2}]), "unknown key"),
    (lambda d: d["cases"][0].update(output_assertions=[{"node": "Start", "path": "x", "equals": 1, "item": -1}]), "integer >= 0"),
    (lambda d: d["cases"][0].update(expected={}, expected_sha256="0" * 64), "expected_sha256 mismatch"),
])
def test_nested_schema_references_and_expectation_hash_are_checked(tmp_path, mutation, fragment):
    path, doc = write_case(tmp_path)
    mutation(doc)
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError) as error:
        bc.load_cases(path)
    assert any(fragment in p for p in error.value.problems)


def test_entry_type_missing_file_directory_and_missing_workflow_nodes_refuse(tmp_path):
    path, doc = write_case(tmp_path, nodes=[{"name": "Start", "type": B + "set", "parameters": {}}])
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="entry node type"):
        bc.load_cases(path)
    doc["entry_node"] = "Absent"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="existing workflow node"):
        bc.load_cases(path)
    doc["entry_node"] = "Start"
    doc["workflow"]["path"] = "missing.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="regular file"):
        bc.load_cases(path)
    workflow = tmp_path / "workflow.json"
    workflow.write_text("{}", encoding="utf-8")
    doc["workflow"]["path"] = "workflow.json"
    doc["workflow"]["sha256"] = hashlib.sha256(workflow.read_bytes()).hexdigest()
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="nodes must be a list"):
        bc.load_cases(path)


def test_stub_for_non_substitutable_node_is_rejected(tmp_path):
    path, doc = write_case(tmp_path, nodes=[{"name": "Start", "type": B + "manualTrigger", "parameters": {}},
                                            {"name": "Pure", "type": B + "set", "parameters": {}}],
                           overrides={"Pure": {}}, case={"id": "one", "input": {}})
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="non-substitutable"):
        bc.load_cases(path)


def test_per_case_override_does_not_invent_other_required_stub_and_workflow_json_must_parse(tmp_path):
    nodes = [{"name": "Start", "type": B + "manualTrigger", "parameters": {}},
             {"name": "Call", "type": B + "httpRequest", "parameters": {}},
             {"name": "Call2", "type": B + "emailSend", "parameters": {}}]
    path, doc = write_case(tmp_path, nodes=nodes, overrides={},
                           case={"id": "one", "input": {}, "stubs": {"Call": {"override": 1}}})
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="missing effective stub for 'Call2'"):
        bc.load_cases(path)
    workflow = tmp_path / "workflow.json"
    workflow.write_text("not json", encoding="utf-8")
    doc["workflow"]["sha256"] = hashlib.sha256(workflow.read_bytes()).hexdigest()
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(bc.CasesError, match="workflow JSON is invalid"):
        bc.load_cases(path)


def deep_stub():
    value = 1
    for _ in range(22):
        value = {"x": value}
    return value


@pytest.mark.parametrize("stub", [{"x": "=1"}, {"=x": 1}, "text", {"x": float("nan")}, {"x": "x" * 66000}, deep_stub()])
def test_invalid_stub_values_refuse(stub):
    assert bc.validate_stub("Call", stub)


def test_genericity_gate():
    source = TOOL.read_text(encoding="utf-8").lower()
    for token in ("lead", "customer", "invoice", "support_"):
        assert token not in source, token
