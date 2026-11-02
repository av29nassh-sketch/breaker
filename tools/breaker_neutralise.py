"""Build deterministic, offline definitions with verified inert stand-ins."""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
import uuid
from collections.abc import Mapping

_ROOT = pathlib.Path(__file__).resolve().parent

def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, _ROOT / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

_pf = _load("breaker_effect_preflight_neutralise", "breaker_effect_preflight.py")
_cases = _load("breaker_cases_neutralise", "breaker_cases.py")
_lane = _load("breaker_n8n_rest_neutralise", "breaker_n8n_rest.py")
_tables = _cases.tables_mod
evaluate = _pf.evaluate
canonical_digest = _lane.canonical_digest
validate_stub = _cases.validate_stub


@dataclass(frozen=True)
class Mechanism:
    node_type: str
    type_version: float
    parameters_for: object
    verification: Mapping | None


# Set node JSON-output mode and the executeOnce node setting are documented by n8n, but the exact parameter names/typeVersion are NOT verified against a running n8n; verification stays None until the S4 probe records an execution that emitted exactly the declared stub.
SET_RAW_JSON = Mechanism(
    "n8n-nodes-base.set", 3.4,
    lambda stub: {"mode": "raw", "jsonOutput": json.dumps(stub, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                  "includeOtherFields": False, "options": {}},
    None,
)


STUB_MARK = "BREAKER SIMULATE STUB replaces "
_STUB_NODE_KEYS = {"id", "name", "type", "typeVersion", "position", "parameters", "executeOnce", "notesInFlow",
                   "notes", "disabled"}


class MechanismUnverified(RuntimeError):
    pass


class NeutraliseBlocked(RuntimeError):
    def __init__(self, reasons):
        self.reasons = tuple(reasons)
        super().__init__("workflow blocked: " + "; ".join(self.reasons))


class StubError(ValueError):
    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


class TransformError(ValueError):
    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class NeutralisedWorkflow:
    definition: dict
    definition_digest: str
    manifest: dict


@dataclass(frozen=True)
class PreparedGroup:
    stub_hash: str
    case_ids: tuple[str, ...]
    neutralised: NeutralisedWorkflow
    stubs: Mapping | None = None  # the group's stub set, so a table run can neutralise again once real table ids exist


def _json_hash(value):
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _verified(mechanism):
    record = mechanism.verification
    # The record must name the very mechanism it verified, so a record for another node type or version cannot be reused.
    return (isinstance(record, Mapping) and isinstance(record.get("execution_id"), str) and bool(record["execution_id"].strip())
            and record.get("observed_output_equals_declared") is True
            and record.get("node_type") == mechanism.node_type and record.get("type_version") == mechanism.type_version)


def _table_plan(tables, table_bindings):
    """node name -> (table id, table name) for every declared Data Table node, after checking the bindings are complete."""
    tables, table_bindings = tables or {}, table_bindings or {}
    if set(tables) != set(table_bindings):
        raise StubError(["table bindings must exactly match the declared tables"])
    plan, seen = {}, set()
    for logical, spec in tables.items():
        binding = table_bindings[logical]
        table_id, table_name = binding.get("id"), binding.get("name")
        if not isinstance(table_id, str) or not table_id or not isinstance(table_name, str) or not table_name:
            raise StubError([f"table {logical!r} has no created table id and name"])
        if table_id in seen or table_id == spec.source_id:
            raise StubError([f"table {logical!r} is bound to a duplicate or source table id"])
        seen.add(table_id)
        plan.update({node: (table_id, table_name) for node in spec.nodes})
    return plan


def neutralise(definition, stubs, *, mechanism, source_sha256=None, tables=None, table_bindings=None):
    # All refusal checks run before constructing a transformed definition.
    if not _verified(mechanism):
        raise MechanismUnverified("mechanism lacks an execution record proving the declared output")
    rebind = _table_plan(tables, table_bindings)
    result = evaluate(definition, rebindable_nodes=rebind)
    if result.blocked:
        raise NeutraliseBlocked(result.reasons)
    if not isinstance(stubs, Mapping) or set(stubs) != set(result.needs_neutralisation):
        raise StubError(["stub names must exactly match nodes needing neutralisation"])
    errors = []
    for name, stub in stubs.items():
        errors.extend(validate_stub(name, stub))
    if errors:
        raise StubError(errors)

    source_digest = canonical_digest(dict(definition))
    replacement_names = set(result.needs_neutralisation)
    transformed_nodes, stub_rows, removed_rows = [], [], []
    for original in definition["nodes"]:
        node = copy.deepcopy(original)
        name = node["name"]
        node_id = str(uuid.uuid5(uuid.NAMESPACE_URL, source_digest + "\0" + name))
        removed = sorted(k for k in ("credentials", "webhookId") if k in node)
        removed_rows.append({"node": name, "keys": removed})
        if name in replacement_names:
            creds = original.get("credentials")
            cred_types = sorted(creds.keys()) if isinstance(creds, Mapping) else []
            position = original.get("position")
            if not isinstance(position, list) or len(position) != 2 or any(not isinstance(x, (int, float)) or isinstance(x, bool) for x in position):
                position = [0, 0]
            replacement = {
                "id": node_id, "name": name, "type": mechanism.node_type,
                "typeVersion": mechanism.type_version, "position": copy.deepcopy(position),
                "parameters": mechanism.parameters_for(copy.deepcopy(stubs[name])),
                "executeOnce": True, "notesInFlow": True,
                "notes": STUB_MARK + original["type"],
            }
            if original.get("disabled") is True:
                replacement["disabled"] = True
            transformed_nodes.append(replacement)
            stub_rows.append({"name": name, "original_type": original["type"], "had_credentials": "credentials" in original,
                              "credential_types": cred_types, "stub_sha256": _json_hash(stubs[name]), "node_id": node_id})
        else:
            node.pop("credentials", None)
            node.pop("webhookId", None)
            node["id"] = node_id
            if name in rebind:  # the whole reference is replaced, so no cached name or url of the client's table survives
                node.setdefault("parameters", {})["dataTableId"] = _tables.rebind_parameter(*rebind[name])
            transformed_nodes.append(node)
    source_settings = definition.get("settings") if isinstance(definition.get("settings"), Mapping) else {}
    allowed_settings = {"executionOrder", "availableInMCP"}
    # `description` is dropped too: the n8n public API does not accept it on create, so it could never round-trip
    # and the clone's re-read digest would differ from the transformed definition's.
    dropped_definition = sorted(set(definition) - {"name", "nodes", "connections", "settings"})
    dropped_settings = sorted(set(source_settings) - allowed_settings)
    output = {
        "name": "[BREAKER SIMULATE] " + source_digest[:12],
        "nodes": transformed_nodes,
        "connections": copy.deepcopy(definition.get("connections", {})),
        "settings": {"executionOrder": source_settings.get("executionOrder") if source_settings.get("executionOrder") in ("v0", "v1") else "v1",
                     "availableInMCP": True},
    }
    table_rows = [{"logical": logical, "nodes": list(spec.nodes), "table_id": table_bindings[logical]["id"],
                   "table_name": table_bindings[logical]["name"],
                   "source_table_id_sha256": hashlib.sha256(spec.source_id.encode("utf-8")).hexdigest()}
                  for logical, spec in sorted((tables or {}).items())]
    problems = _tables.leak_problems(output, [spec.source_id for spec in (tables or {}).values()])
    problems += verify_transformed(output, manifest={"stub_nodes": stub_rows}, mechanism=mechanism,
                                   isolated_tables=[row["table_id"] for row in table_rows])
    if problems:
        raise TransformError(problems)
    output_digest = canonical_digest(output)
    manifest = {
        "schema_version": 1, "source_sha256": source_sha256, "source_definition_digest": source_digest,
        "transformed_definition_digest": output_digest,
        "mechanism": {"node_type": mechanism.node_type, "type_version": mechanism.type_version,
                      "verification": copy.deepcopy(dict(mechanism.verification))},
        "stub_nodes": stub_rows, "dropped_definition_keys": dropped_definition,
        "dropped_settings_keys": dropped_settings,
        "removed_node_keys": removed_rows,
    }
    if table_rows:  # absent for a workflow without Data Tables, so its manifest is byte-identical to before
        manifest["test_tables"] = table_rows
    manifest["manifest_sha256"] = _json_hash(manifest)
    return NeutralisedWorkflow(output, output_digest, manifest)


_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


def _has_destination(value):
    if isinstance(value, str):
        return bool(_URL.search(value) or value.startswith("mailto:"))
    if isinstance(value, Mapping):
        return any(_has_destination(k) or _has_destination(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_destination(item) for item in value)
    return False


def _stub_node_problems(node, row, mechanism, allow_server_keys):
    """A substituted node is trusted only if it is exactly what the manifest and the mechanism say it must be."""
    name, problems = node.get("name"), []
    if node.get("type") != mechanism.node_type or node.get("typeVersion") != mechanism.type_version:
        problems.append(f"stub node {name!r} has the wrong type or version")
    if not allow_server_keys and set(node) - _STUB_NODE_KEYS:
        problems.append(f"stub node {name!r} has unexpected keys: {sorted(set(node) - _STUB_NODE_KEYS)}")
    if node.get("executeOnce") is not True:
        problems.append(f"stub node {name!r} is not executeOnce")
    if node.get("notes") != STUB_MARK + str(row.get("original_type")) or node.get("id") != row.get("node_id"):
        problems.append(f"stub node {name!r} does not match its manifest entry")
    params = node.get("parameters")
    try:
        stub = json.loads(params["jsonOutput"])
        bound = (_json_hash(stub) == row.get("stub_sha256") and params == mechanism.parameters_for(copy.deepcopy(stub)))
    except (TypeError, KeyError, ValueError):
        bound = False
    if not bound:
        problems.append(f"stub node {name!r} parameters do not reproduce the manifest's stub")
    return problems


def verify_transformed(definition, *, manifest=None, mechanism=None, allow_server_keys=False, isolated_tables=()):
    """Problems that make a transformed definition unacceptable (empty list = acceptable).

    Only a node the manifest names as substituted, and that matches the mechanism's exact output for the recorded
    stub, is exempt from the destination scan of its ``jsonOutput``. Notes are source-controlled text and are never
    trusted: a node that merely carries the stub marker is a problem and is scanned like any other.
    """
    problems = []
    expected = {}
    if manifest is not None and mechanism is not None:
        expected = {row.get("name"): row for row in manifest.get("stub_nodes", ())}
    if not isinstance(definition, Mapping):
        return ["definition must be an object"]
    required = {"name", "nodes", "connections", "settings"}
    extras = set(definition) - required
    if extras and not allow_server_keys:
        problems.append("unexpected top-level keys: " + ", ".join(sorted(extras)))
    if not required <= set(definition):
        problems.append("required top-level keys are missing")
    result = evaluate(definition, isolated_tables=isolated_tables)
    if result.blocked:
        problems.extend(result.reasons)
    if result.needs_neutralisation:
        problems.append("substitutable nodes remain")
    nodes = definition.get("nodes")
    names = set()
    if not isinstance(nodes, list):
        problems.append("nodes must be a list")
        nodes = []
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        name = node.get("name")
        if isinstance(name, str):
            names.add(name)
        if "credentials" in node:
            problems.append(f"node {name!r} contains credentials")
        if "webhookId" in node:
            problems.append(f"node {name!r} contains webhookId")
        params = node.get("parameters", {})
        row = expected.get(name) if isinstance(name, str) else None
        exempt_output = False
        if row is not None:
            stub_problems = _stub_node_problems(node, row, mechanism, allow_server_keys)
            problems.extend(stub_problems)
            exempt_output = not stub_problems
        elif isinstance(node.get("notes"), str) and node["notes"].startswith(STUB_MARK):
            problems.append(f"node {name!r} carries a stub marker but is not a manifest-bound substituted node")
        if isinstance(params, Mapping):
            for key, value in params.items():
                if exempt_output and key == "jsonOutput":
                    continue
                if node.get("type") == _pf.PREFIX + "stickyNote" and key == "content":
                    continue
                if _has_destination(key) or _has_destination(value):
                    problems.append(f"node {name!r} parameters contain an external destination")
                    break
    for name in expected:
        if name not in names:
            problems.append(f"manifest names substituted node {name!r} that is not in the definition")
    settings = definition.get("settings")
    if not isinstance(settings, Mapping) or set(settings) != {"executionOrder", "availableInMCP"}:
        problems.append("settings keys must be exactly executionOrder and availableInMCP")
    if definition.get("active"):
        problems.append("definition is active")
    connections = definition.get("connections")
    if not isinstance(connections, Mapping):
        problems.append("connections must be an object")
    else:
        for source, outputs in connections.items():
            if source not in names:
                problems.append(f"connection source {source!r} does not exist")
            if isinstance(outputs, Mapping):
                for ports in outputs.values():
                    if not isinstance(ports, list):
                        continue
                    for port in ports:
                        if isinstance(port, list):
                            for edge in port:
                                target = edge.get("node") if isinstance(edge, Mapping) else None
                                if target not in names:
                                    problems.append(f"connection target {target!r} does not exist")
    return problems


def prepare_cases(cases_file, mechanism):
    """Static preparation of every group. For a workflow with test tables the real table ids do not exist yet, so this
    neutralises against placeholder ids purely to validate; the runner neutralises again with the created ones."""
    groups = _cases.group_by_stubs(cases_file)
    tables = getattr(cases_file, "tables", None) or {}
    placeholder = {logical: {"id": "placeholder-" + logical, "name": "placeholder_" + logical} for logical in tables}
    prepared = []
    for stub_hash, case_ids in groups.items():
        case = next(case for case in cases_file.cases if case.id == case_ids[0])
        prepared.append(PreparedGroup(stub_hash, case_ids,
                                      neutralise(cases_file.definition, case.stubs, mechanism=mechanism,
                                                 source_sha256=cases_file.workflow_sha256,
                                                 tables=tables, table_bindings=placeholder), case.stubs))
    return prepared
