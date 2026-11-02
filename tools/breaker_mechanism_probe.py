"""Mechanism probe: does the stub mechanism really emit its declared JSON on the approved n8n instance?

One disposable, inactive workflow of three inert nodes (entry -> stub -> observer). Nothing in it can reach outside n8n,
and the complete definition is validated before it is sent and again after the server returns it: exact nodes, exact
parameters, no credentials, no expressions, no URLs, exact settings and exact connections. Anything that differs from
what was sent - including any server-side normalisation - stops the probe and is reported verbatim; the probe never
tries a variant, retries a run or loosens a check. A verification record is produced only from observed executions.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import uuid
from datetime import datetime, timezone

_ROOT = pathlib.Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_neutralise = _load("breaker_neutralise_probe", "breaker_neutralise.py")
_sim = _load("breaker_simulate_probe", "breaker_simulate.py")
_pf = _sim._pf
canonical_digest = _neutralise.canonical_digest

B = "n8n-nodes-base."
ENTRY, STUB, OBSERVE = "Probe Entry", "Probe Stub", "Probe Observe"
STUB_OUTPUT = {"probe": "stub", "n": 1}
NODE_KEYS = {"id", "name", "type", "typeVersion", "position", "parameters", "executeOnce"}
CONNECTIONS = {ENTRY: {"main": [[{"node": STUB, "type": "main", "index": 0}]]},
               STUB: {"main": [[{"node": OBSERVE, "type": "main", "index": 0}]]}}


def _node_id(run_id, name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"breaker-probe\0{run_id}\0{name}"))


def build_probe_definition(mechanism, run_id):
    nodes = [
        {"id": _node_id(run_id, ENTRY), "name": ENTRY, "type": B + "executeWorkflowTrigger", "typeVersion": 1.1,
         "position": [0, 0], "parameters": {"inputSource": "passthrough"}},
        {"id": _node_id(run_id, STUB), "name": STUB, "type": mechanism.node_type, "typeVersion": mechanism.type_version,
         "position": [220, 0], "parameters": mechanism.parameters_for(dict(STUB_OUTPUT)), "executeOnce": True},
        {"id": _node_id(run_id, OBSERVE), "name": OBSERVE, "type": B + "noOp", "typeVersion": 1,
         "position": [440, 0], "parameters": {}},
    ]
    return {"name": f"[BREAKER PROBE] {run_id}", "nodes": nodes, "connections": json.loads(json.dumps(CONNECTIONS)),
            "settings": {"executionOrder": "v1", "availableInMCP": True}}


def _differences(sent, stored, path="$"):
    if isinstance(sent, dict) and isinstance(stored, dict):
        out = []
        for key in sorted(set(sent) | set(stored), key=str):
            if key not in stored:
                out.append(f"{path}.{key}: sent {sent[key]!r}, absent in stored")
            elif key not in sent:
                out.append(f"{path}.{key}: not sent, stored {stored[key]!r}")
            else:
                out.extend(_differences(sent[key], stored[key], f"{path}.{key}"))
        return out
    if isinstance(sent, list) and isinstance(stored, list) and len(sent) == len(stored):
        return [d for i, (a, b) in enumerate(zip(sent, stored)) for d in _differences(a, b, f"{path}[{i}]")]
    return [] if sent == stored else [f"{path}: sent {sent!r}, stored {stored!r}"]


def _strings(value, skip_key=None):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            if key != skip_key:
                yield from _strings(item, skip_key)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, skip_key)


def strict_problems(definition, mechanism, run_id, *, allow_server_keys=False):
    """Everything wrong with a probe definition; empty means acceptable to import or to run."""
    problems = []
    if not isinstance(definition, dict):
        return ["definition is not an object"]
    extra = set(definition) - {"name", "nodes", "connections", "settings"}
    if extra and not allow_server_keys:
        problems.append(f"unexpected top-level keys: {sorted(extra)}")
    result = _pf.evaluate(definition)
    problems.extend(result.reasons)
    if result.needs_neutralisation:
        problems.append("an external-call node is present")
    nodes = definition.get("nodes") if isinstance(definition.get("nodes"), list) else []
    if {n.get("name") for n in nodes if isinstance(n, dict)} != {ENTRY, STUB, OBSERVE} or len(nodes) != 3:
        problems.append("node set is not exactly the three probe nodes")
    for node in nodes:
        if isinstance(node, dict):
            if "credentials" in node:
                problems.append(f"node {node.get('name')!r} holds credentials")
            if set(node) - NODE_KEYS:
                problems.append(f"node {node.get('name')!r} has unexpected keys {sorted(set(node) - NODE_KEYS)}")
            skip = "jsonOutput" if node.get("name") == STUB else None
            for text in _strings(node.get("parameters", {}), skip):
                if text.startswith("=") or "{{" in text or _neutralise._has_destination(text):
                    problems.append(f"node {node.get('name')!r} has an expression or external destination")
                    break
    if definition.get("settings") != {"executionOrder": "v1", "availableInMCP": True}:
        problems.append("settings are not exactly executionOrder v1 and availableInMCP true")
    if definition.get("connections") != CONNECTIONS:
        problems.append("connections are not exactly the probe's two edges")
    if definition.get("active"):
        problems.append("definition is active")
    expected = build_probe_definition(mechanism, run_id)
    projected = {key: definition.get(key) for key in expected}
    problems.extend(f"stored differs from sent: {d}" for d in _differences(expected, projected))
    return problems


def mechanism_from_record(record, base, expected_base_url):
    """A verified Mechanism, built only from a probe record that observed everything it claims."""
    needed = {"observed_output_equals_declared": True, "executeOnce_confirmed": True, "stored_matches_sent": True,
              "node_type": base.node_type, "type_version": base.type_version, "base_url": expected_base_url}
    wrong = [key for key, value in needed.items() if record.get(key) != value]
    if wrong or not str(record.get("execution_id") or "").strip():
        raise ValueError(f"probe record does not verify this mechanism on this instance: {wrong or 'no execution id'}")
    return _neutralise.Mechanism(base.node_type, base.type_version, base.parameters_for, dict(record))


def _write(path, payload):
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _plan(run_id):
    return {"entrypoint": ENTRY, "synthetic_input": {"payload": {"sentinel": "A"}},
            "oracle": {"invariant": "the stub emits exactly its declared JSON"},
            "business_rule_ids": ["mechanism-probe"], "input_boundary": "entry_node",
            "input_contract": {"boundary": "entry_node", "field_path": ENTRY}, "isolated": True,
            "deadline_seconds": 120, "cleanup_plan": ("delete the probe workflow",)}


def _run_once(transport, clone_id, items, raw, label):
    """One execution and its read-back. Returns (execution_id, outputs, run_data, status, problem)."""
    args = {"workflowId": clone_id, "triggerNodeName": ENTRY,
            "pinData": {ENTRY: [{"json": item} for item in items]}, "timeout": 120}
    try:
        started, _ = transport.call_tool_retrying("test_workflow", args)
    except Exception as exc:  # transport boundary
        return None, None, None, None, f"{label}: test_workflow failed: {type(exc).__name__}"
    raw[f"{label}.test_workflow"] = started
    execution_id = started.get("executionId") or (started.get("execution") or {}).get("id") if isinstance(started, dict) else None
    if execution_id is None:
        return None, None, None, None, f"{label}: no execution id in the test_workflow response"
    try:
        response, _ = transport.call_tool_retrying(
            "get_workflow_execution", {"workflowId": clone_id, "executionId": str(execution_id), "includeData": True})
    except Exception as exc:  # transport boundary
        return str(execution_id), None, None, None, f"{label}: get_workflow_execution failed: {type(exc).__name__}"
    raw[f"{label}.get_workflow_execution"] = response
    status, run_data = _sim._execution_payload(response)
    outputs = _sim._node_outputs(run_data)
    if outputs is None:
        return str(execution_id), None, None, status, f"{label}: execution data is not in the expected shape (see raw capture)"
    return str(execution_id), outputs, run_data, status, None


def run_probe(*, backend, transport, mechanism, out_root, run_id=None, server_info=None):
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = pathlib.Path(out_root) / f"probe-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    raw: dict = {}
    report = {"run_id": run_id, "status": "STOPPED", "stopped_because": None, "observations": {}, "cleanup": "NOT_CREATED",
              "base_url": backend.expected_base_url, "server_info": server_info, "record": None}
    state = {"clone_id": None}
    record = None
    try:
        record = _probe(backend, transport, mechanism, run_id, server_info, report, raw, state)
    except Exception as exc:  # report and stop: nothing is retried or varied
        report["stopped_because"] = f"unexpected {type(exc).__name__}: {str(exc)[:200]}"
    finally:
        if state["clone_id"] is not None:
            try:
                backend.delete(state["clone_id"])  # identity-checked inside the backend, then confirmed absent
                report["cleanup"] = "DELETED"
            except Exception as exc:
                report["cleanup"] = f"FAILED: {type(exc).__name__}: {str(exc)[:200]}"
    report["clone_id"] = state["clone_id"]
    return _finish(run_dir, report, raw, record)


def _matches(outputs, run_data, status, expected_entry_items):
    return (status == "success" and set(run_data) == {ENTRY, STUB, OBSERVE}
            and len(outputs.get(ENTRY, ())) == expected_entry_items
            and outputs.get(STUB) == [STUB_OUTPUT] and outputs.get(OBSERVE) == [STUB_OUTPUT])


def _probe(backend, transport, mechanism, run_id, server_info, report, raw, state):
    definition = build_probe_definition(mechanism, run_id)
    problems = strict_problems(definition, mechanism, run_id)
    if problems:
        report["stopped_because"] = f"definition invalid before create: {problems}"
        return None
    report["probe_definition_digest"] = canonical_digest(definition)
    try:
        state["clone_id"] = _pf.gate(definition, _plan(run_id), backend.create, definition)
    except Exception as exc:
        report["stopped_because"] = f"create refused or failed: {type(exc).__name__}: {str(exc)[:200]}"
        return None
    clone_id = state["clone_id"]
    stored = backend.read(clone_id)
    raw["reread"] = stored
    problems = strict_problems(stored, mechanism, run_id, allow_server_keys=True)
    same = not problems and canonical_digest(stored) == report["probe_definition_digest"]
    report["observations"]["stored_matches_sent"] = same
    if not same:
        report["stopped_because"] = f"the server's stored definition differs from what was sent: {problems}"
        return None
    if stored.get("active") is not False:
        report["stopped_because"] = "the stored probe is not inactive"
        return None

    id_a, out_a, data_a, status_a, problem = _run_once(transport, clone_id, [{"sentinel": "A"}], raw, "runA")
    report["observations"]["runA"] = {"execution_id": id_a, "status": status_a, "nodes_run": sorted(data_a or {}),
                                       "outputs": out_a}
    if problem or not _matches(out_a, data_a, status_a, 1) or out_a.get(ENTRY) != [{"sentinel": "A"}]:
        report["stopped_because"] = problem or "run A did not match the expected observation (see observations and raw)"
        return None
    id_b, out_b, data_b, status_b, problem = _run_once(
        transport, clone_id, [{"sentinel": "B1"}, {"sentinel": "B2"}], raw, "runB")
    report["observations"]["runB"] = {"execution_id": id_b, "status": status_b, "nodes_run": sorted(data_b or {}),
                                       "outputs": out_b}
    if problem or not _matches(out_b, data_b, status_b, 2):
        report["stopped_because"] = problem or "run B did not match the expected observation (see observations and raw)"
        return None
    record = {"execution_id": id_a, "run_ids": [id_a, id_b], "observed_output_equals_declared": True,
              "executeOnce_confirmed": True, "stored_matches_sent": True, "node_type": mechanism.node_type,
              "type_version": mechanism.type_version, "base_url": backend.expected_base_url,
              "probe_definition_digest": report["probe_definition_digest"], "server_info": server_info,
              "recorded_at": datetime.now(timezone.utc).isoformat()}
    report["status"], report["record"] = "VERIFIED", record
    return record


def _finish(run_dir, report, raw, record):
    if record is not None and not str(report["cleanup"]).startswith("DELETED"):
        report["status"] = "VERIFIED_BUT_CLEANUP_FAILED"  # the record stays, but the run is not clean
    for name, payload in raw.items():
        (run_dir / "raw").mkdir(exist_ok=True)
        _write(run_dir / "raw" / f"{name}.json", payload)
    _write(run_dir / "probe.json", report)
    if record is not None:
        _write(run_dir / "mechanism-record.json", record)
    return report
