"""Table mechanism probe: does a Data Table node bound to a disposable table really read and write that table?

The Set-node probe proved the stub mechanism; this proves the other mechanism the generic runner now relies on. One
disposable table and one disposable workflow (entry -> get -> insert -> upsert -> observe, static values only) on the approved
instance, one execution. The probe checks, from observation only: the table was created with the requested columns, a
seed landed and reads back over REST, the stored workflow equals what was sent (so n8n did not rewrite the Data Table
reference), the node read the seeded row, the insert and the upsert landed in the disposable table (read back over REST,
independent of the workflow), and a reset empties the table again. Anything that differs stops the probe and is reported
verbatim; it never tries a variant, retries a run or loosens a check. A record is produced only from observed results, and
it names the operations it covers, so a node using any other operation stays refused.

    python breaker_table_probe.py --base-url http://127.0.0.1:5678 --out-root <absolute scratch* dir> --label L

Arming: BREAKER_S4_APPROVAL must equal ``tableprobe:<approved local origin>:<label>`` (set by the operator only).
"""
from __future__ import annotations

import argparse
import hashlib
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


mp = _load("breaker_mechanism_probe_tables", "breaker_mechanism_probe.py")
cli = _load("breaker_s4_run_tables", "breaker_s4_run.py")
tables = mp._sim._cases.tables_mod
_pf, _sim, be = mp._pf, mp._sim, cli.be
canonical_digest = mp.canonical_digest

B = "n8n-nodes-base."
ENTRY, READ, INSERT, UPSERT, OBSERVE = "Probe Entry", "Probe Read", "Probe Insert", "Probe Upsert", "Probe Observe"
COLUMNS = [{"name": "k", "type": "string"}, {"name": "n", "type": "number"}]
SEED = {"k": "seed", "n": 1}
FINAL_ROWS = [{"k": "inserted", "n": 2}, {"k": "seed", "n": 10}]
NODE_KEYS = {"id", "name", "type", "typeVersion", "position", "parameters"}
CHAIN = [ENTRY, READ, INSERT, UPSERT, OBSERVE]
CONNECTIONS = {a: {"main": [[{"node": b, "type": "main", "index": 0}]]} for a, b in zip(CHAIN, CHAIN[1:])}
REQUIRED_TRUE = ("table_created_and_verified", "reset_seeded", "stored_matches_sent", "workflow_read_seed_row",
                 "workflow_insert_landed", "workflow_upsert_updated_existing_row", "rest_readback_matches",
                 "reset_empties_table")


def _node_id(run_id, name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"breaker-table-probe\0{run_id}\0{name}"))


def _reference(table_id, table_name):
    return tables.rebind_parameter(table_id, table_name)


def build_probe_definition(table_id, table_name, run_id):
    ref = _reference(table_id, table_name)
    match = {"matchType": "allConditions",
             "filters": {"conditions": [{"keyName": "k", "condition": "eq", "keyValue": "seed"}]}}
    params = {
        READ: {"resource": "row", "operation": "get", "dataTableId": ref, "returnAll": True, **match},
        INSERT: {"resource": "row", "operation": "insert", "dataTableId": dict(ref),
                 "columns": {"mappingMode": "defineBelow", "value": {"k": "inserted", "n": 2}}},
        UPSERT: {"resource": "row", "operation": "upsert", "dataTableId": dict(ref), **match,
                 "columns": {"mappingMode": "defineBelow", "matchingColumns": ["k"], "value": {"k": "seed", "n": 10}}},
    }
    nodes = [{"id": _node_id(run_id, ENTRY), "name": ENTRY, "type": B + "executeWorkflowTrigger", "typeVersion": 1.1,
              "position": [0, 0], "parameters": {"inputSource": "passthrough"}}]
    for i, name in enumerate((READ, INSERT, UPSERT), 1):
        nodes.append({"id": _node_id(run_id, name), "name": name, "type": tables.DATA_TABLE,
                      "typeVersion": tables.PROBED_TYPE_VERSION, "position": [220 * i, 0], "parameters": params[name]})
    nodes.append({"id": _node_id(run_id, OBSERVE), "name": OBSERVE, "type": B + "noOp", "typeVersion": 1,
                  "position": [880, 0], "parameters": {}})
    return {"name": f"[BREAKER PROBE] table-{run_id}", "nodes": nodes, "connections": json.loads(json.dumps(CONNECTIONS)),
            "settings": {"executionOrder": "v1", "availableInMCP": True}}


def strict_problems(definition, table_id, table_name, run_id, *, allow_server_keys=False):
    """Everything wrong with a table-probe definition; empty means acceptable to import or to run."""
    problems = []
    if not isinstance(definition, dict):
        return ["definition is not an object"]
    extra = set(definition) - {"name", "nodes", "connections", "settings"}
    if extra and not allow_server_keys:
        problems.append(f"unexpected top-level keys: {sorted(extra)}")
    result = _pf.evaluate(definition, isolated_tables=[table_id])
    problems.extend(result.reasons)
    if result.needs_neutralisation:
        problems.append("an external-call node is present")
    nodes = definition.get("nodes") if isinstance(definition.get("nodes"), list) else []
    if [n.get("name") for n in nodes if isinstance(n, dict)] != CHAIN:
        problems.append("node set is not exactly the five probe nodes in order")
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if "credentials" in node:
            problems.append(f"node {node.get('name')!r} holds credentials")
        if set(node) - NODE_KEYS:
            problems.append(f"node {node.get('name')!r} has unexpected keys {sorted(set(node) - NODE_KEYS)}")
        for text in mp._strings(node.get("parameters", {})):
            if text.startswith("=") or "{{" in text or mp._neutralise._has_destination(text):
                problems.append(f"node {node.get('name')!r} has an expression or external destination")
                break
    if definition.get("settings") != {"executionOrder": "v1", "availableInMCP": True}:
        problems.append("settings are not exactly executionOrder v1 and availableInMCP true")
    if definition.get("connections") != CONNECTIONS:
        problems.append("connections are not exactly the probe's chain")
    if definition.get("active"):
        problems.append("definition is active")
    expected = build_probe_definition(table_id, table_name, run_id)
    projected = {key: definition.get(key) for key in expected}
    problems.extend(f"stored differs from sent: {d}" for d in mp._differences(expected, projected))
    return problems


def table_mechanism_from_record(record, expected_base_url):
    """The validated record, only if it observed everything it claims, on this instance, for the operations Breaker accepts."""
    if not isinstance(record, dict):
        raise ValueError("table mechanism record is not an object")
    wrong = [key for key in REQUIRED_TRUE if record.get(key) is not True]
    wrong += [key for key, value in (("node_type", tables.DATA_TABLE), ("type_version", tables.PROBED_TYPE_VERSION),
                                     ("base_url", expected_base_url), ("kind", "data_table_mechanism"))
              if record.get(key) != value]
    if not set(tables.PROBED_OPERATIONS) <= set(record.get("operations") or ()):
        wrong.append("operations")
    if wrong or not str(record.get("execution_id") or "").strip():
        raise ValueError(f"record does not verify the Data Table mechanism on this instance: {wrong or 'no execution id'}")
    return dict(record)


def _plan():
    return {"entrypoint": ENTRY, "synthetic_input": {"payload": {"sentinel": "T"}},
            "oracle": {"invariant": "the Data Table nodes act on the disposable table only"},
            "business_rule_ids": ["table-mechanism-probe"], "input_boundary": "entry_node",
            "input_contract": {"boundary": "entry_node", "field_path": ENTRY}, "isolated": True, "deadline_seconds": 120,
            "cleanup_plan": ("delete the probe workflow", "delete the probe table")}


def _project(rows):
    return sorted(({k: row.get(k) for k in ("k", "n")} for row in rows or ()), key=lambda r: json.dumps(r, sort_keys=True))


def _run_once(transport, workflow_id, raw):
    args = {"workflowId": workflow_id, "triggerNodeName": ENTRY,
            "pinData": {ENTRY: [{"json": {"sentinel": "T"}}]}, "timeout": 120}
    try:
        started, _ = transport.call_tool_retrying("test_workflow", args)
    except Exception as exc:  # transport boundary
        return None, None, None, None, f"test_workflow failed: {type(exc).__name__}"
    raw["test_workflow"] = started
    execution_id = (started.get("executionId") or (started.get("execution") or {}).get("id")) if isinstance(started, dict) else None
    if execution_id is None:
        return None, None, None, None, "no execution id in the test_workflow response"
    try:
        response, _ = transport.call_tool_retrying(
            "get_workflow_execution", {"workflowId": workflow_id, "executionId": str(execution_id), "includeData": True})
    except Exception as exc:  # transport boundary
        return str(execution_id), None, None, None, f"get_workflow_execution failed: {type(exc).__name__}"
    raw["get_workflow_execution"] = response
    status, run_data = _sim._execution_payload(response)
    outputs = _sim._node_outputs(run_data)
    if outputs is None:
        return str(execution_id), None, None, status, "execution data is not in the expected shape (see raw capture)"
    return str(execution_id), outputs, run_data, status, None


def run_probe(*, backend, transport, out_root, run_id=None, server_info=None):
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = pathlib.Path(out_root) / f"tableprobe-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    raw: dict = {}
    report = {"run_id": run_id, "status": "STOPPED", "stopped_because": None, "observations": {},
              "cleanup": {"workflow": "NOT_CREATED", "table": "NOT_CREATED"}, "base_url": backend.expected_base_url,
              "server_info": server_info, "record": None}
    state = {"workflow_id": None, "table_id": None}
    record = None
    try:
        record = _probe(backend, transport, run_id, server_info, report, raw, state)
    except Exception as exc:  # report and stop: nothing is retried or varied
        report["stopped_because"] = f"unexpected {type(exc).__name__}: {str(exc)[:200]}"
    finally:
        if state["workflow_id"] is not None:  # the workflow references the table, so it goes first
            try:
                backend.delete(state["workflow_id"])
                report["cleanup"]["workflow"] = "DELETED"
            except Exception as exc:
                report["cleanup"]["workflow"] = f"FAILED: {type(exc).__name__}: {str(exc)[:200]}"
        for table_id in list(getattr(backend, "created_tables", {})):  # includes a table whose creation half-failed
            try:
                backend.delete_table(table_id)
                report["cleanup"]["table"] = "DELETED"
            except Exception as exc:
                report["cleanup"]["table"] = f"FAILED: {type(exc).__name__}: {str(exc)[:200]}"
    report["workflow_id"], report["table_id"] = state["workflow_id"], state["table_id"]
    return _finish(run_dir, report, raw, record)


def _probe(backend, transport, run_id, server_info, report, raw, state):
    obs = report["observations"]
    table_name = "breaker_sim_probe_" + hashlib.sha256(run_id.encode()).hexdigest()[:8]
    state["table_id"] = table_id = backend.create_table(table_name, COLUMNS)
    obs["table_created_and_verified"] = True
    obs["reset_seeded"] = backend.reset_table(table_id, ["k", "n"], [dict(SEED)]) == 1
    obs["seed_rows_over_rest"] = _project(backend.table_rows(table_id))
    if obs["seed_rows_over_rest"] != [SEED]:
        report["stopped_because"] = "the seed did not read back over REST as written"
        return None
    definition = build_probe_definition(table_id, table_name, run_id)
    problems = strict_problems(definition, table_id, table_name, run_id)
    if problems:
        report["stopped_because"] = f"definition invalid before create: {problems}"
        return None
    report["probe_definition_digest"] = canonical_digest(definition)
    try:
        state["workflow_id"] = _pf.gate(definition, _plan(), backend.create, definition, isolated_tables=[table_id])
    except Exception as exc:
        report["stopped_because"] = f"create refused or failed: {type(exc).__name__}: {str(exc)[:200]}"
        return None
    workflow_id = state["workflow_id"]
    stored = backend.read(workflow_id)
    raw["reread"] = stored
    problems = strict_problems(stored, table_id, table_name, run_id, allow_server_keys=True)
    obs["stored_matches_sent"] = not problems and canonical_digest(stored) == report["probe_definition_digest"]
    if not obs["stored_matches_sent"] or stored.get("active") is not False:
        report["stopped_because"] = f"the server's stored definition differs from what was sent, or is active: {problems}"
        return None
    execution_id, outputs, run_data, status, problem = _run_once(transport, workflow_id, raw)
    obs["execution"] = {"execution_id": execution_id, "status": status, "nodes_run": sorted(run_data or {})}
    if problem or status != "success" or set(run_data) != set(CHAIN):
        report["stopped_because"] = problem or "the execution did not run exactly the five probe nodes successfully"
        return None
    obs["workflow_read_seed_row"] = _project(outputs.get(READ)) == [SEED]
    after = _project(backend.table_rows(table_id))
    obs["rows_after_run_over_rest"] = after
    obs["workflow_insert_landed"] = {"k": "inserted", "n": 2} in after
    obs["workflow_upsert_updated_existing_row"] = {"k": "seed", "n": 10} in after and SEED not in after
    obs["rest_readback_matches"] = after == FINAL_ROWS
    obs["reset_empties_table"] = backend.reset_table(table_id, ["k", "n"], []) == 0 and not backend.table_rows(table_id)
    failed = [key for key in REQUIRED_TRUE if obs.get(key) is not True]
    if failed:
        report["stopped_because"] = f"observations did not hold: {failed} (see observations and raw)"
        return None
    record = {"kind": "data_table_mechanism", "execution_id": execution_id, **{key: True for key in REQUIRED_TRUE},
              "node_type": tables.DATA_TABLE, "type_version": tables.PROBED_TYPE_VERSION,
              "operations": list(tables.PROBED_OPERATIONS), "base_url": backend.expected_base_url,
              "probe_definition_digest": report["probe_definition_digest"], "server_info": server_info,
              "recorded_at": datetime.now(timezone.utc).isoformat()}
    report["status"], report["record"] = "VERIFIED", record
    return record


def _finish(run_dir, report, raw, record):
    clean = report["cleanup"]["workflow"] in ("DELETED", "NOT_CREATED") and report["cleanup"]["table"] in ("DELETED", "NOT_CREATED")
    if record is not None and not clean:
        report["status"] = "VERIFIED_BUT_CLEANUP_FAILED"  # the record stays, but the run is not clean
    for name, payload in raw.items():
        (run_dir / "raw").mkdir(exist_ok=True)
        mp._write(run_dir / "raw" / f"{name}.json", payload)
    mp._write(run_dir / "tableprobe.json", report)
    if record is not None:
        mp._write(run_dir / "table-mechanism-record.json", record)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(prog="breaker_table_probe")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--table-project", help="project id for the disposable table, if the instance requires one")
    args = parser.parse_args(argv)
    try:
        out_root = cli.assert_scratch(args.out_root)
        run_dir = out_root / args.label
        run_dir.mkdir(parents=True, exist_ok=False)
        required = cli.approval_for("tableprobe", args.base_url, args.label)
        backend = be.N8nBackend(expected_base_url=args.base_url, approval=required, journal_path=run_dir / "created.jsonl",
                                max_creates=1, max_tables=1, table_project_id=args.table_project)
        if not backend.armed:
            raise cli.OperatorError(f"disarmed: set BREAKER_S4_APPROVAL to exactly {required!r} (only after you approved this run)")
        transport = be.make_transport(backend, 1)
        info = transport.preflight()
        before = backend.snapshot(include_tables=True)
        report = run_probe(backend=backend, transport=transport, out_root=run_dir, server_info=info.get("serverInfo"))
        differences = be.diff_snapshots(before, backend.snapshot(include_tables=True))
        ok = report["status"] == "VERIFIED" and not differences
        summary = {"ok": ok, "probe_status": report["status"], "stopped_because": report["stopped_because"],
                   "cleanup": report["cleanup"], "snapshot_differences": differences}
        mp._write(run_dir / "summary.json", summary)
        print(json.dumps(summary, indent=2))
        return 0 if ok else 1
    except (cli.OperatorError, ValueError, RuntimeError, FileExistsError, OSError) as exc:
        print(f"stopped ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
