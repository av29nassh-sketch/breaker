"""Offline tests for deterministic fail-closed neutralisation."""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import socket
import sys
import urllib.request

import pytest

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "breaker_neutralise.py"
spec = importlib.util.spec_from_file_location("breaker_neutralise_under_test", TOOL)
nt = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = nt
spec.loader.exec_module(nt)
B = "n8n-nodes-base."
VERIFIED = nt.Mechanism("n8n-nodes-base.set", 3.4,
    lambda stub: {"mode": "raw", "jsonOutput": json.dumps(stub, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                  "includeOtherFields": False, "options": {}},
    {"execution_id": "test-only-execution", "observed_output_equals_declared": True,
     "node_type": "n8n-nodes-base.set", "type_version": 3.4})


def test_verification_record_for_another_mechanism_is_refused():
    for bad in ({"node_type": "n8n-nodes-base.set", "type_version": 3.3}, {"node_type": "other", "type_version": 3.4}, {}):
        record = {"execution_id": "e", "observed_output_equals_declared": True, **bad}
        mechanism = nt.Mechanism(VERIFIED.node_type, VERIFIED.type_version, VERIFIED.parameters_for, record)
        with pytest.raises(nt.MechanismUnverified):
            nt.neutralise(base(), {"Call": {"ok": True}}, mechanism=mechanism)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


def node(name, kind, **extra):
    return {"id": "source-id", "name": name, "type": B + kind, "typeVersion": 1, "position": [2, 3], "parameters": {}, **extra}


def workflow(*nodes, **extra):
    return {"name": "synthetic", "description": "tiny", "nodes": list(nodes), "connections": {}, "settings": {}, **extra}


def base():
    return workflow(node("Start", "manualTrigger"), node("Call", "httpRequest", disabled=True,
                   credentials={"httpBasicAuth": {"id": "distinct-id-credential", "name": "distinct-name-credential"}},
                   parameters={"url": "https://example.invalid"}))


def make_mechanism():
    return VERIFIED


def test_unverified_shipped_mechanism_refuses_before_action():
    calls = []
    for mechanism in (nt.SET_RAW_JSON, nt.Mechanism("x", 1, lambda s: {}, None)):
        with pytest.raises(nt.MechanismUnverified):
            for group in nt.prepare_cases(type("Cases", (), {"cases": (type("Case", (), {"id": "a", "stubs": {"Call": {"ok": True}}})(),),
                                                                  "definition": base(), "workflow_sha256": None})(), mechanism):
                calls.append(group)
        assert calls == []


@pytest.mark.parametrize("bad", [
    workflow(node("Start", "manualTrigger"), node("X", "code")),
    workflow(node("Start", "manualTrigger"), node("X", "function")),
    workflow(node("Start", "manualTrigger"), node("X", "executeWorkflow")),
    workflow(node("Start", "manualTrigger"), node("X", "mystery")),
    workflow(node("Start", "manualTrigger"), node("X", "dataTable")),
    workflow(node("Start", "manualTrigger"), node("X", "set", credentials={"x": {"id": "id"}})),
    workflow(node("Start", "manualTrigger"), active=True),
    workflow(node("Start", "manualTrigger"), settings={"errorWorkflow": "x"}),
    workflow(node("Start", "manualTrigger"), node("Start", "set")),
])
def test_blocked_definitions_refuse_zero_action(bad):
    calls = []
    with pytest.raises(nt.NeutraliseBlocked) as error:
        for _ in [1]:
            nt.neutralise(bad, {}, mechanism=make_mechanism())
            calls.append(1)
    assert calls == [] and error.value.reasons


@pytest.mark.parametrize("stubs", [{}, {"Call": {} , "Extra": {}}, {"Call": "bad"}, {"Start": {}}])
def test_stub_set_and_shape_refuse(stubs):
    calls = []
    with pytest.raises(nt.StubError):
        for _ in [1]:
            nt.neutralise(base(), stubs, mechanism=make_mechanism())
            calls.append(1)
    assert calls == []


@pytest.mark.parametrize("definition, stubs, exception", [
    (base(), {}, nt.StubError),
    (base(), {"Call": {"x": 1}, "Extra": {}}, nt.StubError),
    (base(), {"Call": "bad"}, nt.StubError),
    (workflow(node("Start", "manualTrigger"), node("Bad", "code")), {}, nt.NeutraliseBlocked),
])
def test_prepare_refusals_never_reach_the_action(definition, stubs, exception):
    from types import SimpleNamespace
    case = SimpleNamespace(id="one", stubs=stubs)
    cases = SimpleNamespace(cases=(case,), definition=definition, workflow_sha256="c" * 64)
    calls = []
    action = lambda group: calls.append(group)
    with pytest.raises(exception):
        for group in nt.prepare_cases(cases, make_mechanism()):
            action(group)
    assert calls == []


def test_transform_is_deterministic_scrubs_credentials_and_records_safe_manifest():
    source = base()
    source["nodes"][1].update(retryOnFail=True, onError="continueRegularOutput", continueOnFail=True,
                               webhookId="distinct-webhook-value")
    source["connections"] = {"Start": {"main": [[{"node": "Call", "type": "main", "index": 0}]]}}
    first = nt.neutralise(source, {"Call": {"payload": [1, {"url": "https://stub.invalid"}]}}, mechanism=make_mechanism(), source_sha256="a" * 64)
    second = nt.neutralise(source, {"Call": {"payload": [1, {"url": "https://stub.invalid"}]}}, mechanism=make_mechanism(), source_sha256="a" * 64)
    assert json.dumps(first.definition, sort_keys=True) == json.dumps(second.definition, sort_keys=True)
    assert first.manifest == second.manifest
    blob = json.dumps(first.definition) + json.dumps(first.manifest)
    assert "distinct-id-credential" not in blob and "distinct-name-credential" not in blob
    assert "distinct-webhook-value" not in blob
    stub_row = first.manifest["stub_nodes"][0]
    assert stub_row["credential_types"] == ["httpBasicAuth"] and stub_row["had_credentials"]
    replacement = first.definition["nodes"][1]
    assert replacement["type"] == B + "set" and replacement["typeVersion"] == 3.4
    assert replacement["executeOnce"] is True and replacement["disabled"] is True
    assert replacement["position"] == [2, 3] and "credentials" not in replacement
    assert not ({"retryOnFail", "onError", "continueOnFail", "webhookId"} & set(replacement))
    assert first.definition["connections"] == source["connections"]
    assert json.loads(replacement["parameters"]["jsonOutput"]) == {"payload": [1, {"url": "https://stub.invalid"}]}


def test_source_key_order_does_not_change_digest_or_ids():
    source = base()
    reordered = json.loads(json.dumps(source, sort_keys=True))
    one = nt.neutralise(source, {"Call": {"x": 1}}, mechanism=make_mechanism())
    two = nt.neutralise(reordered, {"Call": {"x": 1}}, mechanism=make_mechanism())
    assert one.definition_digest == two.definition_digest
    assert [x["id"] for x in one.definition["nodes"]] == [x["id"] for x in two.definition["nodes"]]


def test_allowlist_removed_keys_connections_and_url_detection():
    source = base()
    source.update({"id": "source", "active": False, "pinData": {}, "staticData": {}, "tags": [], "meta": {}})
    source["settings"] = {"executionOrder": "v0", "saveDataErrorExecution": "all"}
    result = nt.neutralise(source, {"Call": {"x": 1}}, mechanism=make_mechanism())
    assert result.definition["settings"] == {"executionOrder": "v0", "availableInMCP": True}
    assert result.manifest["dropped_definition_keys"] == ["active", "description", "id", "meta", "pinData", "staticData", "tags"]
    assert "description" not in result.definition  # the public API does not store it, so it could never round-trip
    assert result.manifest["dropped_settings_keys"] == ["saveDataErrorExecution"]
    dangling = copy.deepcopy(result.definition)
    dangling["connections"] = {"Start": {"main": [[{"node": "Gone"}]]}}
    assert any("target" in problem for problem in nt.verify_transformed(dangling))
    url_source = workflow(node("Start", "manualTrigger"), node("Pure", "set", parameters={"value": "https://outside.invalid"}))
    assert any("external destination" in p for p in nt.verify_transformed(url_source))
    sticky = workflow(node("Start", "manualTrigger"), node("Note", "stickyNote", parameters={"content": "https://example.invalid"}))
    # The wrapper is allowed to keep the note's explanatory URL text.
    assert not any("external destination" in p for p in nt.verify_transformed(sticky))


def test_re_read_server_keys_require_explicit_allowance_and_no_network():
    result = nt.neutralise(base(), {"Call": {"x": 1}}, mechanism=make_mechanism())
    reread = {**result.definition, "id": "server-id", "versionId": "server-version", "createdAt": "now"}
    kw = {"manifest": result.manifest, "mechanism": make_mechanism()}
    assert nt.verify_transformed(reread, **kw)
    assert nt.verify_transformed(reread, allow_server_keys=True, **kw) == []


def stub_with_url():
    return nt.neutralise(base(), {"Call": {"link": "https://stub.invalid"}}, mechanism=make_mechanism())


def test_stub_marker_is_never_trusted_without_a_manifest_binding():
    result = stub_with_url()
    # no manifest: the stub's own URL data is an unexplained destination, and the marker itself is a problem
    problems = nt.verify_transformed(result.definition)
    assert any("stub marker" in p for p in problems) and any("external destination" in p for p in problems)
    # the same definition verifies once it is bound to its manifest and mechanism
    assert nt.verify_transformed(result.definition, manifest=result.manifest, mechanism=make_mechanism()) == []


def test_forged_marker_on_a_source_node_cannot_hide_a_destination():
    forged = node("Forged", "set", notes=nt.STUB_MARK + B + "httpRequest",
                  parameters={"mode": "raw", "jsonOutput": '{"u":"https://outside.invalid"}'})
    source = workflow(node("Start", "manualTrigger"), forged)
    with pytest.raises(nt.TransformError) as error:
        nt.neutralise(source, {}, mechanism=make_mechanism())
    assert any("stub marker" in p for p in error.value.problems)
    assert any("external destination" in p for p in error.value.problems)


@pytest.mark.parametrize("tamper", [
    lambda n: n.update(typeVersion=3.3),
    lambda n: n.update(type=B + "code"),
    lambda n: n["parameters"].update(extra=1),
    lambda n: n["parameters"].update(jsonOutput='{"other":true}'),
    lambda n: n["parameters"].update(jsonOutput="not json"),
    lambda n: n.pop("executeOnce"),
    lambda n: n.update(notes=nt.STUB_MARK + "something-else"),
    lambda n: n.update(id="another-id"),
    lambda n: n.update(retryOnFail=True),
])
def test_tampered_substituted_node_fails_verification_against_the_manifest(tamper):
    result = stub_with_url()
    changed = copy.deepcopy(result.definition)
    tamper(next(n for n in changed["nodes"] if n["name"] == "Call"))
    assert nt.verify_transformed(changed, manifest=result.manifest, mechanism=make_mechanism())


def test_manifest_naming_a_missing_substituted_node_is_a_problem():
    result = stub_with_url()
    changed = copy.deepcopy(result.definition)
    changed["nodes"] = [n for n in changed["nodes"] if n["name"] != "Call"]
    assert any("not in the definition" in p
               for p in nt.verify_transformed(changed, manifest=result.manifest, mechanism=make_mechanism()))


def test_prepare_groups_action_count_and_genericity_gate(tmp_path):
    from types import SimpleNamespace
    case = SimpleNamespace(id="one", stubs={"Call": {"x": 1}})
    case2 = SimpleNamespace(id="two", stubs={"Call": {"x": 1}})
    case3 = SimpleNamespace(id="three", stubs={"Call": {"x": 2}})
    cases = SimpleNamespace(cases=(case, case2, case3), definition=base(), workflow_sha256="b" * 64)
    prepared = nt.prepare_cases(cases, make_mechanism())
    assert len(prepared) == 2 and prepared[0].case_ids == ("one", "two")
    calls = []
    for group in prepared:
        calls.append(group.stub_hash)
    assert len(calls) == 2
    for path in (TOOL, TOOL.parent / "breaker_cases.py"):
        source = path.read_text(encoding="utf-8").lower()
        for token in ("lead", "customer", "invoice", "support_", "qualif"):
            assert token not in source, (path, token)
