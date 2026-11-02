"""Generic mocked execution runner for disposable, neutralised workflows."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import copy
import importlib.util
import json
from pathlib import Path
import sys
import uuid
from collections.abc import Mapping

_ROOT = Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_pf = _load("breaker_effect_preflight_simulate", "breaker_effect_preflight.py")
_cases = _load("breaker_cases_simulate", "breaker_cases.py")
_neutralise = _load("breaker_neutralise_simulate", "breaker_neutralise.py")
canonical_digest = _neutralise.canonical_digest
_tables = _cases.tables_mod


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    status: str
    detail: str
    execution_id: str | None
    failed_assertions: tuple
    observed: dict
    read_back: dict | None
    expected: object


@dataclass(frozen=True)
class GroupResult:
    stub_hash: str
    case_ids: tuple
    status: str
    reasons: tuple
    transformed_definition_digest: str
    manifest: dict | None
    clone_id: str | None
    cleanup: str
    cases: tuple[CaseResult, ...]
    tables: tuple = ()  # disposable test tables this group created: logical, table_id, table_name, cleanup


@dataclass(frozen=True)
class SimulationResult:
    run_id: str
    run_dir: Path
    status: str
    reasons: tuple
    source_sha256: str
    source_definition_digest: str
    mechanism_verification: object
    node_classification: dict
    groups: tuple[GroupResult, ...]
    labels: dict = field(default_factory=dict)


def _copy_expected(value):
    return copy.deepcopy(value)


def _case_result(case, status, detail, execution_id=None, failed=(), observed=None, read_back=None):
    return CaseResult(case.id, status, detail, execution_id, tuple(failed), observed or {}, read_back,
                      _copy_expected(case.expected))


def _json_equal(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _path_value(value, path):
    current = value
    for part in path.split("."):
        if isinstance(current, list):
            if not part.isdigit():
                raise (KeyError(part))
            current = current[int(part)]
        elif isinstance(current, Mapping):
            current = current[part]
        else:
            raise KeyError(part)
    return current


def _execution_payload(response):
    if not isinstance(response, Mapping):
        return None, None
    execution = response.get("execution")
    status = response.get("status") or (execution.get("status") if isinstance(execution, Mapping) else None)
    data = response.get("data")
    if not isinstance(data, Mapping) and isinstance(execution, Mapping):
        data = execution.get("data")
    try:
        run_data = data["resultData"]["runData"]
    except (TypeError, KeyError):
        return status, None
    return status, run_data


def _node_outputs(run_data):
    if not isinstance(run_data, Mapping):
        return None
    outputs = {}
    for name, runs in run_data.items():
        if not isinstance(name, str) or not isinstance(runs, list) or not runs:
            return None
        last = runs[-1]
        try:
            main = last["data"]["main"]
            items = main[0]
            if not isinstance(items, list):
                return None
            outputs[name] = [item["json"] for item in items if isinstance(item, Mapping) and "json" in item]
            if len(outputs[name]) != len(items):
                return None
        except (TypeError, KeyError, IndexError):
            return None
    return outputs


def _assertion_labels(case):
    labels = []
    for assertion in case.output_assertions:
        labels.append(f"output {assertion['node']}[{assertion.get('item', 0)}].{assertion['path']} == {assertion['equals']!r}")
    labels.extend(f"must_run {name}" for name in case.must_run)
    labels.extend(f"must_not_run {name}" for name in case.must_not_run)
    return labels


def _table_columns(spec):
    return [name for name, _ in spec.columns]


def _execute_case(case, *, clone_id, entry_node, timeout, transport, definition, manifest, table_ctx=None):
    seeded = {}
    if table_ctx:  # deterministic reset: every case starts from exactly its own seed, whatever ran before it
        try:
            for logical, spec in table_ctx["specs"].items():
                rows = _tables.effective_seed(spec, case.seed)
                seeded[logical] = table_ctx["backend"].reset_table(table_ctx["ids"][logical], _table_columns(spec), rows)
        except Exception as exc:  # backend boundary
            return _case_result(case, "INCONCLUSIVE", f"test table reset failed: {type(exc).__name__}")
    args = {"workflowId": clone_id, "triggerNodeName": entry_node,
            "pinData": {entry_node: [{"json": copy.deepcopy(case.input)}]}, "timeout": timeout}
    try:
        result, _ = transport.call_tool_retrying("test_workflow", args)
    except Exception as exc:  # transport boundary
        return _case_result(case, "INCONCLUSIVE", f"transport failure: {type(exc).__name__}")
    if not isinstance(result, Mapping):
        return _case_result(case, "INCONCLUSIVE", "unrecognised execution response shape")
    execution_id = result.get("executionId") or ((result.get("execution") or {}).get("id") if isinstance(result.get("execution"), Mapping) else None)
    if execution_id is None:
        return _case_result(case, "INCONCLUSIVE", "execution id missing")
    execution_id = str(execution_id)
    try:
        response, _ = transport.call_tool_retrying("get_workflow_execution", {
            "workflowId": clone_id, "executionId": execution_id, "includeData": True})
    except Exception as exc:  # transport boundary
        return _case_result(case, "INCONCLUSIVE", f"transport failure: {type(exc).__name__}", execution_id)

    status, run_data = _execution_payload(response)
    outputs = _node_outputs(run_data)
    if outputs is None:
        return _case_result(case, "INCONCLUSIVE", "unrecognised execution data shape", execution_id)
    node_names = {node.get("name") for node in definition.get("nodes", []) if isinstance(node, Mapping)}
    if status != "success":
        return _case_result(case, "INCONCLUSIVE", "execution status is not success", execution_id)
    if set(run_data) - node_names:
        return _case_result(case, "INCONCLUSIVE", "execution contains an unknown node", execution_id)
    if entry_node not in run_data:
        return _case_result(case, "INCONCLUSIVE", "entry node is absent from execution data", execution_id)

    stub_nodes = {row["name"] for row in manifest.get("stub_nodes", [])}
    declared = {}
    for node in definition.get("nodes", []):
        if isinstance(node, Mapping) and node.get("name") in stub_nodes:
            try:
                declared[node["name"]] = json.loads(node["parameters"]["jsonOutput"])
            except (TypeError, KeyError, ValueError):
                return _case_result(case, "INCONCLUSIVE", "unrecognised execution data shape", execution_id)
    for name in stub_nodes & set(run_data):
        if not _json_equal(outputs.get(name), [declared[name]]):
            return _case_result(case, "INCONCLUSIVE", "stub output did not match its declared value", execution_id)
    if not (case.output_assertions or case.must_run or case.must_not_run or case.table_assertions):
        return _case_result(case, "INCONCLUSIVE", "case asserts nothing", execution_id)
    observed_tables = None
    if table_ctx:  # independent read-back: straight from the table over REST, not through the workflow's own nodes
        try:
            observed_tables = {logical: table_ctx["backend"].table_rows(table_ctx["ids"][logical])
                               for logical in table_ctx["specs"]}
        except Exception as exc:  # backend boundary
            return _case_result(case, "INCONCLUSIVE", f"test table read-back failed: {type(exc).__name__}", execution_id)

    failed = []
    for name in case.must_run:
        if name not in run_data:
            failed.append(f"must_run {name}: node did not run")
    for name in case.must_not_run:
        if name in run_data:
            failed.append(f"must_not_run {name}: node ran")
    for assertion in case.output_assertions:
        label = f"output {assertion['node']}[{assertion.get('item', 0)}].{assertion['path']} == {assertion['equals']!r}"
        try:
            actual = _path_value(outputs[assertion["node"]][assertion.get("item", 0)], assertion["path"])
            matches = _json_equal(actual, assertion["equals"])
        except (KeyError, IndexError, TypeError, ValueError):
            matches = False
        if not matches:
            failed.append(label)
    if table_ctx:
        failed.extend(_tables.check_table_assertions(case.table_assertions, observed_tables, table_ctx["specs"]))
    included = set(case.must_run) | set(case.must_not_run) | stub_nodes | {a["node"] for a in case.output_assertions}
    read_back = {"source": "n8n execution run data", "execution_id": execution_id,
                 "execution_status": status, "nodes_run": sorted(run_data),
                 "node_outputs": {name: outputs[name] for name in sorted(included) if name in outputs}}
    if table_ctx:
        # Deliberately not keyed like a store read-back: this is a disposable copy this run created and seeded itself.
        read_back["simulated_sandbox_data"] = {
            "source": "disposable test tables created by this run; not client data and not a production read",
            "tables": {logical: {"table_name": table_ctx["names"][logical], "rows_seeded": seeded[logical],
                                 "rows_after": _tables.normalise_rows(observed_tables[logical], table_ctx["specs"][logical])}
                       for logical in table_ctx["specs"]}}
    observed = {"case_id": case.id, "failed_assertions": failed}
    if failed:
        return _case_result(case, "PRODUCT_FAIL", "one or more declared assertions failed", execution_id,
                            failed, observed, read_back)
    return _case_result(case, "CONFORMS", "no declared assertion failed in this simulated run", execution_id,
                        (), observed, read_back)


def _blocked_case(case, detail):
    return _case_result(case, "BLOCKED", detail)


def simulate(cases_path, *, backend, transport, mechanism, out_root, run_id=None, timeout=120, check_ids=None,
             labels=None):
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = Path(out_root) / f"run-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    check_ids = check_ids or {}
    groups = []
    reasons = []
    source_sha256 = ""
    source_digest = ""
    classification = {}
    cases_file = None
    prepared = ()
    try:
        cases_file = _cases.load_cases(cases_path)
        source_sha256 = cases_file.workflow_sha256
        source_digest = canonical_digest(cases_file.definition)
        rebindable = [node for spec in cases_file.tables.values() for node in spec.nodes]
        evaluated = _pf.evaluate(cases_file.definition, rebindable_nodes=rebindable)
        classification = {name: verdict.disposition.value for name, verdict in evaluated.nodes.items()}
        if evaluated.blocked:
            reasons.extend(evaluated.reasons)
            raise _Stop
        first = cases_file.cases[0]
        plan = {"entrypoint": cases_file.entry_node, "synthetic_input": {"payload": first.input},
                "oracle": {"invariant": "the declared case assertions hold"},
                "business_rule_ids": [case.id for case in cases_file.cases],
                "input_boundary": "entry_node", "input_contract": {"boundary": "entry_node", "field_path": cases_file.entry_node},
                "isolated": True, "deadline_seconds": timeout,
                "cleanup_plan": ("delete the disposable clone",) + (("delete the disposable test tables",) if rebindable else ())}
        checked = _pf.preflight(cases_file.definition, plan, rebindable_nodes=rebindable)
        if checked.blocked:
            reasons.extend(checked.reasons)
            raise _Stop
        try:
            prepared = _neutralise.prepare_cases(cases_file, mechanism)
        except (_neutralise.MechanismUnverified, _neutralise.NeutraliseBlocked,
                _neutralise.StubError, _neutralise.TransformError) as exc:
            reasons.extend(getattr(exc, "reasons", getattr(exc, "problems", [str(exc)])))
            raise _Stop
    except _cases.CasesError as exc:
        reasons.extend(exc.problems)
    except _Stop:
        pass

    run_blocked = bool(reasons) or cases_file is None
    if cases_file is not None and not run_blocked:
        source_ids = {node.get("id") for node in cases_file.definition.get("nodes", []) if isinstance(node, Mapping) and "id" in node}
        by_id = {case.id: case for case in cases_file.cases}
        for index, group in enumerate(prepared):
            current_cases = []
            group_reasons = []
            clone_id = None
            cleanup = "NOT_CREATED"
            group_status = "EXECUTED"
            # With tables the prepared definition holds placeholder ids and is never created; only a neutralisation made
            # against the created tables is evidence, so a group that never got that far records no digest or manifest.
            neutralised = None if cases_file.tables else group.neutralised
            table_ctx, table_records, table_ids = None, [], []
            tables_before = set(getattr(backend, "created_tables", {}))
            orphans_before = len(getattr(backend, "possible_orphans", ()))
            try:
                try:
                    neutralised, table_ctx = _provision_tables(cases_file, group, run_id=run_id, index=index, backend=backend,
                                                               mechanism=mechanism, records=table_records)
                    table_ids = list(table_ctx["ids"].values()) if table_ctx else []
                    clone_id = _pf.gate(neutralised.definition, plan, backend.create, neutralised.definition,
                                        isolated_tables=table_ids)
                except _pf.PreflightBlocked as exc:
                    group_status, group_reasons = "BLOCKED", list(exc.reasons)
                    current_cases = [_blocked_case(by_id[cid], "clone creation blocked by preflight") for cid in group.case_ids]
                except _TableSetupError as exc:
                    group_status, group_reasons = "INCONCLUSIVE", [f"test table setup failed: {exc}"]
                    current_cases = [_case_result(by_id[cid], "INCONCLUSIVE", "test table setup failed") for cid in group.case_ids]
                except Exception as exc:
                    group_status, group_reasons = "INCONCLUSIVE", [f"clone creation failed: {type(exc).__name__}"]
                    current_cases = [_case_result(by_id[cid], "INCONCLUSIVE", "clone creation failed") for cid in group.case_ids]
                else:
                    if not isinstance(clone_id, str) or not clone_id or clone_id in source_ids:
                        group_status, group_reasons = "BLOCKED", ["clone id is empty, invalid, or matches a source node id"]
                        current_cases = [_blocked_case(by_id[cid], "clone identity check failed") for cid in group.case_ids]
                    else:
                        try:
                            read = backend.read(clone_id)
                            safety = []
                            if read.get("active") is not False:
                                safety.append("clone is active or active state is missing")
                            safety.extend(_neutralise.verify_transformed(read, manifest=neutralised.manifest,
                                                                         mechanism=mechanism, allow_server_keys=True,
                                                                         isolated_tables=table_ids))
                            if canonical_digest(read) != neutralised.definition_digest:
                                safety.append("clone definition digest does not match transformed definition")
                        except Exception as exc:
                            safety = [f"clone safety read failed: {type(exc).__name__}"]
                        if safety:
                            group_status, group_reasons = "BLOCKED", safety
                            current_cases = [_blocked_case(by_id[cid], "clone safety re-read failed") for cid in group.case_ids]
                        else:
                            current_cases = [_execute_case(by_id[cid], clone_id=clone_id, entry_node=cases_file.entry_node,
                                                           timeout=timeout, transport=transport, definition=read,
                                                           manifest=neutralised.manifest, table_ctx=table_ctx)
                                             for cid in group.case_ids]
            finally:
                if clone_id is not None:
                    try:
                        final_read = backend.read(clone_id)
                        if final_read.get("name") != neutralised.definition["name"] or not str(final_read.get("name", "")).startswith("[BREAKER SIMULATE]"):
                            cleanup = "FAILED: identity mismatch, not deleted"
                        else:
                            backend.delete(clone_id)
                            cleanup = "DELETED"
                    except Exception as exc:
                        cleanup = f"FAILED: {type(exc).__name__}"
                if cases_file.tables:  # after the clone, which references them
                    _delete_group_tables(backend, tables_before, table_records, orphans_before)
            groups.append(GroupResult(group.stub_hash, tuple(group.case_ids), group_status, tuple(group_reasons),
                                      neutralised.definition_digest if neutralised else "",
                                      copy.deepcopy(neutralised.manifest) if neutralised else None,
                                      clone_id if isinstance(clone_id, str) else None, cleanup, tuple(current_cases),
                                      tuple(table_records)))

    status = "BLOCKED" if run_blocked else "COMPLETED"
    result = SimulationResult(run_id, run_dir, status, tuple(reasons), source_sha256, source_digest,
                              copy.deepcopy(getattr(mechanism, "verification", None)), classification, tuple(groups),
                              copy.deepcopy(dict(labels or {})))
    evidence = _load("breaker_sim_evidence_simulate", "breaker_sim_evidence.py")
    evidence.write_run_files(result, check_ids)
    return result


class _Stop(Exception):
    pass


class _TableSetupError(RuntimeError):
    pass


def _provision_tables(cases_file, group, *, run_id, index, backend, mechanism, records):
    """Create this group's disposable test tables and neutralise against their real ids: (neutralised, context)."""
    specs = cases_file.tables
    if not specs:
        return group.neutralised, None
    bindings = {}
    try:
        for logical, spec in specs.items():
            name = _tables.table_name(run_id, index, logical)
            table_id = backend.create_table(name, [{"name": n, "type": t} for n, t in spec.columns])
            records.append({"logical": logical, "table_id": table_id, "table_name": name, "cleanup": "NOT_DELETED"})
            bindings[logical] = {"id": table_id, "name": name}
        neutralised = _neutralise.neutralise(cases_file.definition, group.stubs, mechanism=mechanism,
                                             source_sha256=cases_file.workflow_sha256, tables=specs,
                                             table_bindings=bindings)
    except Exception as exc:
        raise _TableSetupError(type(exc).__name__) from exc
    return neutralised, {"specs": specs, "backend": backend, "ids": {k: v["id"] for k, v in bindings.items()},
                         "names": {k: v["name"] for k, v in bindings.items()}}


def _delete_group_tables(backend, owned_before, records, orphans_before=0):
    """Delete every table the backend owns that this group caused to exist, including one whose creation half-failed.

    Only tables the backend itself created are reachable, and each delete is identity-checked there."""
    by_id = {row["table_id"]: row for row in records}
    for table_id in [t for t in getattr(backend, "created_tables", {}) if t not in owned_before]:
        row = by_id.get(table_id)
        if row is None:
            row = {"logical": None, "table_id": table_id, "table_name": backend.created_tables[table_id],
                   "cleanup": "NOT_DELETED"}
            records.append(row)
        try:
            backend.delete_table(table_id)
            row["cleanup"] = "DELETED"
        except Exception as exc:
            row["cleanup"] = f"FAILED: {type(exc).__name__}"
    for name in list(getattr(backend, "possible_orphans", ()))[orphans_before:]:
        records.append({"logical": None, "table_id": None, "table_name": name,
                        "cleanup": "POSSIBLE_ORPHAN: a create had no usable answer and the table could not be located"})
