"""S1 tests: generic effect classification and the fail-closed preflight.

No n8n is contacted. Network entry points are replaced by functions that fail the test, and every refusal is shown
to leave a call counter at zero. The classifier is exercised on synthetic definitions only.
"""
from __future__ import annotations

import importlib.util
import pathlib
import socket
import sys
import urllib.request

import pytest
from breaker.semantic.safety import EffectDisposition as D

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "breaker_effect_preflight.py"
spec = importlib.util.spec_from_file_location("effect_preflight_under_test", TOOL)
pf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pf
spec.loader.exec_module(pf)

B = "n8n-nodes-base."
PLAN = {"entrypoint": "Start", "synthetic_input": {"x": 1}, "oracle": {"invariant": "route is chosen"},
        "business_rule_ids": ["R1"], "input_boundary": "trigger",
        "input_contract": {"boundary": "trigger", "field_path": "body.x"},
        "isolated": True, "deadline_seconds": 60, "cleanup_plan": ["delete clone"]}


def node(name, node_type, **extra):
    return {"name": name, "type": node_type, "parameters": {}, **extra}


def wf(*nodes, **extra):
    return {"name": "t", "nodes": list(nodes), "connections": {}, "settings": {}, **extra}


SAFE = wf(node("Start", B + "manualTrigger"), node("Pick", B + "switch"), node("Shape", B + "set"))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


def disposition(definition, name, **kw):
    return pf.evaluate(definition, **kw).nodes[name].disposition


def test_every_node_is_classified_including_disconnected_ones():
    definition = wf(node("Start", B + "manualTrigger"), node("Orphan", B + "executeCommand"),
                    node("Island", B + "set"))
    result = pf.evaluate(definition)
    assert set(result.nodes) == {"Start", "Orphan", "Island"}
    assert result.nodes["Orphan"].disposition == D.BLOCK and result.blocked


@pytest.mark.parametrize("node_type", sorted(pf.ENTRY | pf.PURE))
def test_entry_and_pure_types_are_allowed(node_type):
    assert disposition(wf(node("N", node_type)), "N") == D.ALLOW


@pytest.mark.parametrize("node_type", sorted(pf.SUBSTITUTABLE))
def test_external_calls_need_neutralisation_even_with_credentials(node_type):
    plain = wf(node("N", node_type))
    creds = wf(node("N", node_type, credentials={"httpBasicAuth": {"id": "1"}}))
    for definition in (plain, creds):
        result = pf.evaluate(definition)
        assert result.nodes["N"].disposition == D.SUBSTITUTE and result.needs_neutralisation == ("N",)


@pytest.mark.parametrize("node_type", sorted(pf.KNOWN_UNSAFE))
def test_known_unsafe_types_are_blocked_with_a_reason(node_type):
    verdict = pf.evaluate(wf(node("N", node_type))).nodes["N"]
    assert verdict.disposition == D.BLOCK and verdict.reason == pf.KNOWN_UNSAFE[node_type]


@pytest.mark.parametrize("node_type", [B + "postgres", B + "slack", "@n8n/n8n-nodes-langchain.agent",
                                       "n8n-nodes-community.thing", B + "somethingNew"])
def test_unknown_types_are_blocked_with_an_explicit_reason(node_type):
    verdict = pf.evaluate(wf(node("N", node_type))).nodes["N"]
    assert verdict.disposition == D.BLOCK and "unknown node type" in verdict.reason


def test_a_credentialed_node_without_a_stand_in_is_blocked():
    verdict = pf.evaluate(wf(node("N", B + "set", credentials={"x": {"id": "1"}}))).nodes["N"]
    assert verdict.disposition == D.BLOCK and "credentials" in verdict.reason


@pytest.mark.parametrize("code", ["return items;", "return this['help'+'ers'].httpRequest({url:'x'});"])
def test_code_nodes_are_always_blocked_whatever_their_code_or_attestation(code):
    attested = node("C", B + "code", parameters={"jsCode": code}, attestation={"sha256": "0" * 64})
    result = pf.evaluate(wf(attested))
    assert result.nodes["C"].disposition == D.BLOCK and "unproven" in result.nodes["C"].reason
    assert result.blocked


def test_data_table_is_allowed_only_when_bound_to_a_table_this_run_created():
    bound = node("T", B + "dataTable", parameters={"dataTableId": {"value": "run-table"}})
    assert disposition(wf(bound), "T", isolated_tables=["run-table"]) == D.ALLOW
    assert disposition(wf(bound), "T") == D.BLOCK
    assert disposition(wf(bound), "T", isolated_tables=["other-table"]) == D.BLOCK
    unbound = node("U", B + "dataTable")
    assert disposition(wf(unbound), "U", isolated_tables=["run-table"]) == D.BLOCK


@pytest.mark.parametrize("definition, text", [
    (wf(node("S", B + "set"), active=True), "active"),
    (wf(node("S", B + "set"), settings={"errorWorkflow": "abc"}), "error workflow"),
    (wf(node("S", B + "set"), node("S", B + "if")), "duplicate"),
    ({"nodes": []}, "no nodes"),
    ({"name": "t"}, "no nodes"),
])
def test_workflow_level_problems_block(definition, text):
    result = pf.evaluate(definition)
    assert result.blocked and any(text in reason for reason in result.reasons)


@pytest.mark.parametrize("bad", ["text", 3, {"type": B + "set"}, {"name": "N"}, {"name": "", "type": B + "set"}])
def test_malformed_nodes_are_blocked_not_raised(bad):
    assert pf.evaluate({"nodes": [bad]}).blocked


def test_safe_definition_with_a_valid_plan_passes_core_validation():
    result = pf.preflight(SAFE, PLAN)
    assert not result.blocked and result.plan_validation.status == "READY"


@pytest.mark.parametrize("change, text", [
    ({"isolated": False}, "isolated execution is required"),
    ({"deadline_seconds": 0}, "positive deadline"),
    ({"cleanup_plan": []}, "cleanup plan"),
    ({"synthetic_input": {}}, "synthetic input"),
    ({"oracle": {}}, "oracle invariant"),
])
def test_core_plan_validation_is_applied(change, text):
    result = pf.preflight(SAFE, {**PLAN, **change})
    assert result.blocked and any(text in reason for reason in result.reasons)


def test_unknown_effect_reaches_core_as_an_unknown_consequential_effect():
    result = pf.preflight(wf(node("Start", B + "manualTrigger"), node("X", B + "postgres")), PLAN)
    assert any("UNKNOWN_EXTERNAL_EFFECT" in reason for reason in result.reasons)


def test_substitutions_carry_proof_and_non_proof_statements():
    definition = wf(node("Start", B + "manualTrigger"), node("Call", B + "httpRequest"))
    result = pf.preflight(definition, PLAN)
    assert result.plan_validation.status == "READY" and result.needs_neutralisation == ("Call",)
    plan = pf.build_plan(pf.evaluate(definition), definition, PLAN)
    assert plan.substitutions[0]["what_this_proves"] and plan.substitutions[0]["does_not_prove"]


class Counter:
    def __init__(self):
        self.calls = 0

    def __call__(self, *a, **k):
        self.calls += 1
        return ("ran", a, k)


BLOCKING = [
    wf(node("Start", B + "manualTrigger"), node("C", B + "code")),
    wf(node("Start", B + "manualTrigger"), node("X", B + "somethingNew")),
    wf(node("Start", B + "manualTrigger"), node("T", B + "dataTable")),
    wf(node("Start", B + "manualTrigger"), node("Orphan", B + "executeCommand")),
    wf(node("Start", B + "manualTrigger"), active=True),
    wf(node("Start", B + "manualTrigger"), settings={"errorWorkflow": "abc"}),
    wf(node("Start", B + "manualTrigger"), node("Call", B + "httpRequest")),
    {"nodes": []},
]


@pytest.mark.parametrize("definition", BLOCKING)
def test_blocked_definitions_make_zero_n8n_calls(definition):
    action = Counter()
    with pytest.raises(pf.PreflightBlocked) as error:
        pf.gate(definition, PLAN, action, "workflow-id", timeout=5)
    assert action.calls == 0 and error.value.reasons


def test_an_invalid_plan_makes_zero_n8n_calls():
    action = Counter()
    with pytest.raises(pf.PreflightBlocked):
        pf.gate(SAFE, {**PLAN, "isolated": False}, action)
    assert action.calls == 0


def test_a_safe_definition_reaches_the_action_exactly_once():
    action = Counter()
    assert pf.gate(SAFE, PLAN, action, "id", timeout=5) == ("ran", ("id",), {"timeout": 5})
    assert action.calls == 1


def test_the_classifier_is_generic_and_produces_no_evidence():
    source = TOOL.read_text(encoding="utf-8").lower()
    for token in ("lead", "customer", "invoice", "support_",
                  "normalize", "pass", "closure"):
        assert token not in source.replace("passes", "").replace("bypass", ""), token
