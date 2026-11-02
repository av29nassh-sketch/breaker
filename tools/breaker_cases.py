"""Load and validate generic, versioned offline simulation cases."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import pathlib
import re
from typing import Any

import importlib.util
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("breaker_effect_preflight_cases", _ROOT / "breaker_effect_preflight.py")
_pf = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _pf
_spec.loader.exec_module(_pf)
_tspec = importlib.util.spec_from_file_location("breaker_tables_cases", _ROOT / "breaker_tables.py")
tables_mod = importlib.util.module_from_spec(_tspec)
sys.modules[_tspec.name] = tables_mod
_tspec.loader.exec_module(tables_mod)


class CasesError(ValueError):
    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class Case:
    id: str
    description: str | None
    input: dict
    stubs: dict
    expected: Any
    output_assertions: tuple
    must_run: tuple[str, ...]
    must_not_run: tuple[str, ...]
    seed: dict = field(default_factory=dict)  # logical test table -> rows; replaces that table's default seed
    table_assertions: tuple = ()


@dataclass(frozen=True)
class CasesFile:
    schema_version: int
    workflow_path: pathlib.Path
    workflow_sha256: str
    definition: dict
    entry_node: str
    cases: tuple[Case, ...]
    tables: dict = field(default_factory=dict)  # logical name -> TableSpec: the disposable tables this run may create


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _bad_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def _depth(value):
    if isinstance(value, dict):
        return 1 + max((_depth(kv) for kv in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(x) for x in value), default=0)
    return 0


def _expression(value):
    if isinstance(value, str):
        return value.startswith("=")
    if isinstance(value, dict):
        return any(k.startswith("=") or _expression(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_expression(v) for v in value)
    return False


def validate_stub(node_name, stub):
    problems = []
    label = f"stub for {node_name!r}"
    if not isinstance(stub, dict):
        return [f"{label} must be a JSON object"]
    try:
        encoded = _canonical(stub).encode("utf-8")
    except (TypeError, ValueError):
        encoded = b""
        problems.append(f"{label} contains a non-finite or non-JSON value")
    if len(encoded) > 65536:
        problems.append(f"{label} exceeds 65536 bytes")
    if _depth(stub) > 20:
        problems.append(f"{label} exceeds depth 20")
    if _expression(stub):
        problems.append(f"{label} contains an expression marker")
    return problems


def stub_set_hash(stubs):
    return hashlib.sha256(_canonical(stubs).encode("utf-8")).hexdigest()


def group_by_stubs(cases_file):
    groups = {}
    for case in cases_file.cases:
        groups.setdefault(stub_set_hash(case.stubs), []).append(case.id)
    return {key: tuple(ids) for key, ids in groups.items()}


def load_cases(path):
    source = pathlib.Path(path).resolve()
    problems = []
    try:
        raw = source.read_text(encoding="utf-8")
        data = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_bad_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CasesError([f"cannot parse cases file: {exc}"]) from exc
    if not isinstance(data, dict):
        raise CasesError(["root must be an object"])
    _keys(data, {"schema_version", "workflow", "entry_node", "stubs", "tables", "cases"}, "root", problems)
    if data.get("schema_version") != 1 or isinstance(data.get("schema_version"), bool):
        problems.append("schema_version must equal 1")
    wf = data.get("workflow")
    definition, workflow_path, actual_hash = {}, source.parent, ""
    if not isinstance(wf, dict):
        problems.append("workflow must be an object")
        wf = {}
    _keys(wf, {"path", "sha256"}, "workflow", problems)
    rel = wf.get("path")
    if not isinstance(rel, str) or not rel:
        problems.append("workflow.path must be a relative path")
    else:
        rp = pathlib.PurePath(rel)
        if rp.is_absolute() or pathlib.PureWindowsPath(rel).is_absolute() or pathlib.PureWindowsPath(rel).drive or ".." in rp.parts or ".." in pathlib.PureWindowsPath(rel).parts:
            problems.append("workflow.path must be relative and contain no '..'")
        else:
            workflow_path = (source.parent / rel).resolve()
            try:
                workflow_path.relative_to(source.parent.resolve())
            except ValueError:
                problems.append("workflow.path resolves outside the cases file directory")
            else:
                if not workflow_path.is_file():
                    problems.append("workflow.path must resolve to a regular file")
                else:
                    raw_wf = workflow_path.read_bytes()
                    actual_hash = hashlib.sha256(raw_wf).hexdigest()
                    expected_hash = wf.get("sha256")
                    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                        problems.append("workflow.sha256 must be 64 lowercase hex characters")
                    elif actual_hash != expected_hash:
                        problems.append("workflow sha256 mismatch")
                    try:
                        definition = json.loads(raw_wf.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_bad_constant)
                    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                        problems.append(f"workflow JSON is invalid: {exc}")
    if not isinstance(definition, dict):
        problems.append("workflow definition must be an object")
        definition = {}
    nodes = definition.get("nodes")
    if not isinstance(nodes, list):
        problems.append("workflow definition nodes must be a list")
        nodes = []
    node_map = {n.get("name"): n for n in nodes if isinstance(n, dict) and isinstance(n.get("name"), str)}
    entry = data.get("entry_node")
    if not isinstance(entry, str) or entry not in node_map:
        problems.append("entry_node must name an existing workflow node")
    elif node_map[entry].get("type") not in _pf.ENTRY:
        problems.append("entry_node must have an entry node type")
    defaults = data.get("stubs", {})
    if not isinstance(defaults, dict):
        problems.append("stubs must be an object")
        defaults = {}
    specs, table_problems = tables_mod.parse_declarations(data.get("tables"), definition)
    problems.extend(table_problems)
    needed = set(_pf.evaluate(definition, rebindable_nodes=[n for s in specs.values() for n in s.nodes]).needs_neutralisation)
    for name, stub in defaults.items():
        _check_stub(name, stub, node_map, needed, problems, "default")
    cases_data = data.get("cases")
    if not isinstance(cases_data, list):
        problems.append("cases must be a list")
        cases_data = []
    if not cases_data:
        problems.append("at least one case is required")
    if len(cases_data) > 1000:
        problems.append("at most 1000 cases are allowed")
    ids, cases = set(), []
    case_keys = {"id", "description", "input", "stubs", "expected", "expected_sha256", "output_assertions", "must_run", "must_not_run",
                 "seed", "table_assertions"}
    for i, row in enumerate(cases_data):
        label = f"case[{i}]"
        if not isinstance(row, dict):
            problems.append(f"{label} must be an object")
            continue
        _keys(row, case_keys, label, problems)
        cid = row.get("id")
        if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", cid):
            problems.append(f"{label} id is invalid")
        elif cid in ids:
            problems.append(f"duplicate case id {cid!r}")
        else:
            ids.add(cid)
        desc = row.get("description")
        if "description" in row and not isinstance(desc, str):
            problems.append(f"{label} description must be a string")
        payload = row.get("input")
        if not isinstance(payload, dict):
            problems.append(f"{label} input must be an object")
            payload = {}
        overrides = row.get("stubs", {})
        if not isinstance(overrides, dict):
            problems.append(f"{label} stubs must be an object")
            overrides = {}
        for name, stub in overrides.items():
            _check_stub(name, stub, node_map, needed, problems, label)
        effective = {name: dict(stub) for name, stub in defaults.items() if isinstance(stub, dict)}
        for name, stub in overrides.items():
            if isinstance(stub, dict):
                effective[name] = dict(stub)  # replaces the node's whole stub: no field is inherited from a default
        for name in sorted(needed - set(effective)):
            problems.append(f"{label} missing effective stub for {name!r}")
        expected = row.get("expected")
        if "expected_sha256" in row:
            digest = row["expected_sha256"]
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                problems.append(f"{label} expected_sha256 must be 64 lowercase hex characters")
            elif "expected" not in row or hashlib.sha256(_canonical(expected).encode("utf-8")).hexdigest() != digest:
                problems.append(f"{label} expected_sha256 mismatch")
        assertions = row.get("output_assertions", [])
        if not isinstance(assertions, list):
            problems.append(f"{label} output_assertions must be a list")
            assertions = []
        clean_assertions = []
        for j, assertion in enumerate(assertions):
            if not isinstance(assertion, dict):
                problems.append(f"{label} output_assertions[{j}] must be an object")
                continue
            _keys(assertion, {"node", "item", "path", "equals"}, f"{label} output_assertions[{j}]", problems)
            if not {"node", "path", "equals"} <= set(assertion):
                problems.append(f"{label} output_assertions[{j}] missing required fields")
                continue
            node = assertion.get("node")
            if not isinstance(node, str) or node not in node_map:
                problems.append(f"{label} output assertion names an unknown node")
            if not isinstance(assertion.get("path"), str) or not assertion["path"]:
                problems.append(f"{label} output assertion path must be a string")
            item = assertion.get("item", 0)
            if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                problems.append(f"{label} output assertion item must be an integer >= 0")
            clean_assertions.append(dict(assertion, item=item))
        mr = _node_list(row.get("must_run", []), f"{label} must_run", node_map, problems)
        mn = _node_list(row.get("must_not_run", []), f"{label} must_not_run", node_map, problems)
        if set(mr) & set(mn):
            problems.append(f"{label} must_run and must_not_run overlap")
        seed = row.get("seed")
        problems.extend(tables_mod.validate_case_seed(seed, specs, f"{label} seed"))
        table_assertions, ta_problems = tables_mod.validate_table_assertions(
            row.get("table_assertions", []), specs, f"{label} table_assertions")
        problems.extend(ta_problems)
        cases.append(Case(cid if isinstance(cid, str) else "", desc, payload, effective, expected,
                          tuple(clean_assertions), tuple(mr), tuple(mn),
                          seed if isinstance(seed, dict) else {}, tuple(table_assertions)))
    if problems:
        raise CasesError(problems)
    return CasesFile(1, workflow_path, actual_hash, definition, entry, tuple(cases), specs)


def _keys(obj, allowed, label, problems):
    for key in obj:
        if key not in allowed:
            problems.append(f"{label} has unknown key {key!r}")


def _check_stub(name, stub, node_map, needed, problems, label):
    if name not in node_map:
        problems.append(f"{label} stub names unknown node {name!r}")
    if name not in needed:
        problems.append(f"{label} stub for non-substitutable node {name!r}")
    problems.extend(validate_stub(name, stub))


def _node_list(value, label, node_map, problems):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        problems.append(f"{label} must be a list of node names")
        return []
    if len(set(value)) != len(value):
        problems.append(f"{label} has duplicate node names")
    for name in value:
        if name not in node_map:
            problems.append(f"{label} names unknown node {name!r}")
    return value
