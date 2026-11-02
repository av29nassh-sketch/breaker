"""Generic, workflow-agnostic handling of n8n Data Tables for disposable test runs (offline; no n8n contact).

A cases file declares the test tables a workflow needs; no workflow name or table id is ever hard-coded here::

    "tables": {"leads": {"nodes": ["Find Lead", "Save Lead"],
                         "columns": [{"name": "email", "type": "string"}, {"name": "status", "type": "string"}],
                         "seed": [{"email": "old@example.invalid", "status": "NEW"}]}},
    "cases": [{"id": "known-lead", "input": {...}, "seed": {"leads": [...]},
               "table_assertions": [{"table": "leads", "count": 1},
                                    {"table": "leads", "contains": [{"email": "old@example.invalid", "status": "CONTACTED"}]}]}]

Every Data Table node must be listed by exactly one declared table, with a static table reference, node version 1.1 and a
row operation the mechanism probe exercises (get, insert, upsert). The runner creates a fresh table per declared table and
stub group, rebinds the listed nodes to it (the client's table id never reaches the clone), resets it to the case's own seed
before every case, reads it back over REST independently of the workflow, and deletes it. Results stay simulation only.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import json
import math
import re

PREFIX = "n8n-nodes-base."
DATA_TABLE = PREFIX + "dataTable"
COLUMN_TYPES = ("string", "number", "boolean", "date")
SYSTEM_COLUMNS = frozenset({"id", "createdAt", "updatedAt"})
#: Row operations the table mechanism probe exercises on a real instance. A node using any other operation (update,
#: delete, existence checks) or another resource is refused rather than assumed to behave the same way.
PROBED_OPERATIONS = ("get", "insert", "upsert")
PROBED_TYPE_VERSION = 1.1
MAX_COLUMNS = 50
MAX_ROWS_PER_TABLE = 1000
MAX_SEED_BYTES = 262144

_LOGICAL = re.compile(r"[a-z][a-z0-9_]{0,23}\Z")
_COLUMN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")


@dataclass(frozen=True)
class TableSpec:
    logical: str
    nodes: tuple[str, ...]
    columns: tuple[tuple[str, str], ...]
    seed: tuple[dict, ...]
    source_id: str


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def data_table_nodes(definition) -> dict[str, dict]:
    if not isinstance(definition, dict) or not isinstance(definition.get("nodes"), list):
        return {}
    return {node["name"]: node for node in definition["nodes"]
            if isinstance(node, dict) and node.get("type") == DATA_TABLE
            and isinstance(node.get("name"), str) and node["name"]}


def static_source_id(node) -> str | None:
    if not isinstance(node, dict):
        return None
    params = node.get("parameters")
    ref = params.get("dataTableId") if isinstance(params, dict) else None
    if not isinstance(ref, dict) or ref.get("mode") not in (None, "id", "list"):
        return None
    value = ref.get("value")
    return value if isinstance(value, str) and value and not value.startswith("=") else None


def unprobed_use(node) -> str | None:
    """Why this node's resource or operation has no probed mechanism, or None when it is one the probe covers."""
    params = node.get("parameters") if isinstance(node, dict) else None
    params = params if isinstance(params, dict) else {}
    if node.get("typeVersion") != PROBED_TYPE_VERSION:
        return f"typeVersion {node.get('typeVersion')!r} was not probed (probed: {PROBED_TYPE_VERSION})"
    resource, operation = params.get("resource", "row"), params.get("operation", "get")
    if resource != "row":
        return f"resource {resource!r} is not a row operation"
    if operation not in PROBED_OPERATIONS:
        return f"operation {operation!r} has no probed mechanism (probed: {', '.join(PROBED_OPERATIONS)})"
    return None


def referenced_columns(node) -> set[str]:
    found = set()
    if not isinstance(node, dict):
        return found
    params = node.get("parameters")
    if not isinstance(params, dict):
        return found
    filters = params.get("filters")
    conditions = filters.get("conditions") if isinstance(filters, dict) else None
    if isinstance(conditions, list):
        found.update(item["keyName"] for item in conditions
                     if isinstance(item, dict) and isinstance(item.get("keyName"), str))
    columns = params.get("columns")
    if isinstance(columns, dict):
        matching = columns.get("matchingColumns")
        if isinstance(matching, list):
            found.update(name for name in matching if isinstance(name, str))
        values = columns.get("value")
        if columns.get("mappingMode") != "autoMapInputData" and isinstance(values, dict):
            found.update(name for name in values if isinstance(name, str))
    return found


def validate_rows(rows, columns, label) -> list[str]:
    problems = []
    if not isinstance(rows, list):
        return [f"{label} must be a list of rows"]
    if len(rows) > MAX_ROWS_PER_TABLE:
        problems.append(f"{label} exceeds {MAX_ROWS_PER_TABLE} rows")
    types = dict(columns) if isinstance(columns, (tuple, list)) else {}
    for index, row in enumerate(rows):
        row_label = f"{label}[{index}]"
        if not isinstance(row, dict):
            problems.append(f"{row_label} must be an object")
            continue
        for key, value in row.items():
            if not isinstance(key, str) or key in SYSTEM_COLUMNS or key not in types:
                problems.append(f"{row_label} has undeclared column {key!r}")
                continue
            if value is None:
                continue
            kind = types[key]
            valid = (isinstance(value, str) if kind in ("string", "date") else
                     isinstance(value, bool) if kind == "boolean" else
                     isinstance(value, (int, float)) and not isinstance(value, bool)
                     and (not isinstance(value, float) or math.isfinite(value)) if kind == "number" else False)
            if not valid:
                problems.append(f"{row_label}.{key} must be a {kind} or null")
    try:
        size = len(_canonical(rows).encode("utf-8"))
    except (TypeError, ValueError, UnicodeError):
        size = None
        problems.append(f"{label} must contain only finite JSON values")
    if size is not None and size > MAX_SEED_BYTES:
        problems.append(f"{label} exceeds {MAX_SEED_BYTES} bytes")
    return problems


def parse_declarations(raw, definition) -> tuple[dict[str, TableSpec], list[str]]:
    specs, problems = {}, []
    if raw is None or raw == {}:
        return specs, problems
    if not isinstance(raw, dict):
        return specs, ["tables must be an object"]
    nodes = data_table_nodes(definition)
    used_nodes, source_owner = {}, {}
    for logical, declaration in raw.items():
        table_problems = []
        if not isinstance(logical, str) or not _LOGICAL.fullmatch(logical):
            table_problems.append(f"table logical name {logical!r} is invalid")
        if not isinstance(declaration, dict):
            problems.extend(table_problems + [f"table {logical!r} must be an object"])
            continue
        for key in declaration:
            if key not in {"nodes", "columns", "seed"}:
                table_problems.append(f"table {logical!r} has unknown key {key!r}")
        node_names = declaration.get("nodes")
        if not isinstance(node_names, list) or not node_names or any(not isinstance(x, str) for x in node_names):
            table_problems.append(f"table {logical!r} nodes must be a non-empty list of strings")
            node_names = []
        elif len(set(node_names)) != len(node_names):
            table_problems.append(f"table {logical!r} nodes must be unique")
        source_ids = []
        for name in node_names:
            if name in used_nodes:
                table_problems.append(f"Data Table node {name!r} appears in more than one declared table")
            else:
                used_nodes[name] = logical
            if name not in nodes:
                table_problems.append(f"table {logical!r} names missing or non-Data Table node {name!r}")
                continue
            reason = unprobed_use(nodes[name])
            if reason:
                table_problems.append(f"Data Table node {name!r}: {reason}")
            source_id = static_source_id(nodes[name])
            if source_id is None:
                table_problems.append(f"Data Table node {name!r} has no static source id")
            else:
                source_ids.append(source_id)
        if len(set(source_ids)) > 1:
            table_problems.append(f"table {logical!r} nodes point at different static source ids")

        raw_columns = declaration.get("columns")
        clean_columns = []
        col_names = set()
        if not isinstance(raw_columns, list) or not raw_columns:
            table_problems.append(f"table {logical!r} columns must be a non-empty list")
            raw_columns = []
        for col in raw_columns:
            if not isinstance(col, dict) or set(col) != {"name", "type"} or not isinstance(col.get("name"), str) or not isinstance(col.get("type"), str):
                table_problems.append(f"table {logical!r} columns must contain exact name/type string objects")
                continue
            name, kind = col["name"], col["type"]
            if not _COLUMN.fullmatch(name):
                table_problems.append(f"table {logical!r} column name {name!r} is invalid")
            if name in SYSTEM_COLUMNS:
                table_problems.append(f"table {logical!r} column {name!r} is a system column")
            if name in col_names:
                table_problems.append(f"table {logical!r} has duplicate column {name!r}")
            col_names.add(name)
            if kind not in COLUMN_TYPES:
                table_problems.append(f"table {logical!r} column {name!r} has invalid type {kind!r}")
            clean_columns.append((name, kind))
        if len(clean_columns) > MAX_COLUMNS:
            table_problems.append(f"table {logical!r} exceeds {MAX_COLUMNS} columns")
        seed = declaration.get("seed", [])
        row_problems = validate_rows(seed, tuple(clean_columns), f"table {logical!r} seed")
        table_problems.extend(row_problems)
        for name in node_names:
            if name in nodes:
                for column in sorted(referenced_columns(nodes[name]) - col_names):
                    table_problems.append(f"Data Table node {name!r} references undeclared column {column!r}")
        source_id = source_ids[0] if source_ids else ""
        if source_id and source_id in source_owner and source_owner[source_id] != logical:
            table_problems.append(f"logical tables {source_owner[source_id]!r} and {logical!r} share one client source id")
        elif source_id:
            source_owner[source_id] = logical
        problems.extend(table_problems)
        if not table_problems and isinstance(logical, str):
            specs[logical] = TableSpec(logical, tuple(node_names), tuple(clean_columns),
                                       tuple(copy.deepcopy(seed)), source_id)
    for name in nodes:
        if name not in used_nodes:
            problems.append(f"Data Table node {name!r} is not covered by any declared test table")
    return specs, problems


def validate_case_seed(case_seed, specs, label) -> list[str]:
    if case_seed is None:
        return []
    if not isinstance(case_seed, dict):
        return [f"{label} must be an object"]
    problems = []
    for logical, rows in case_seed.items():
        if logical not in specs:
            problems.append(f"{label} names undeclared table {logical!r}")
        else:
            problems.extend(validate_rows(rows, specs[logical].columns, f"{label}.{logical}"))
    return problems


def effective_seed(spec, case_seed) -> list[dict]:
    rows = case_seed.get(spec.logical, list(spec.seed)) if isinstance(case_seed, dict) else list(spec.seed)
    return copy.deepcopy(rows)


def validate_table_assertions(assertions, specs, label) -> tuple[list[dict], list[str]]:
    clean, problems = [], []
    if not isinstance(assertions, list):
        return clean, [f"{label} must be a list"]
    for index, assertion in enumerate(assertions):
        alabel = f"{label}[{index}]"
        if not isinstance(assertion, dict):
            problems.append(f"{alabel} must be an object")
            continue
        if set(assertion) - {"table", "count", "equals", "contains"}:
            problems.append(f"{alabel} has unknown keys")
        table = assertion.get("table")
        if not isinstance(table, str) or table not in specs:
            problems.append(f"{alabel} names an undeclared table")
            continue
        kinds = [key for key in ("count", "equals", "contains") if key in assertion]
        if len(kinds) != 1 or set(assertion) != {"table", kinds[0]}:
            problems.append(f"{alabel} must have table and exactly one assertion")
            continue
        kind = kinds[0]
        value = assertion[kind]
        if kind == "count":
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                problems.append(f"{alabel}.count must be an integer >= 0")
                continue
        else:
            if kind == "contains" and (not isinstance(value, list) or not value
                                       or any(isinstance(row, dict) and not row for row in value)):
                problems.append(f"{alabel}.contains must be a non-empty list of non-empty rows")
                continue
            row_problems = validate_rows(value, specs[table].columns, f"{alabel}.{kind}")
            if row_problems:
                problems.extend(row_problems)
                continue
            value = copy.deepcopy(value)
        clean.append({"table": table, kind: value})
    return clean, problems


def _normal_number(value):
    return int(value) if isinstance(value, float) and value.is_integer() else value


def normalise_rows(rows, spec) -> list[dict]:
    result = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        projected = {name: _normal_number(row.get(name)) for name, _ in spec.columns}
        result.append(projected)
    return sorted(result, key=_canonical)


def _short(value):
    rendered = repr(value)
    return rendered if len(rendered) <= 160 else rendered[:157] + "..."


def check_table_assertions(assertions, observed, specs) -> list[str]:
    failures = []
    for assertion in assertions:
        table = assertion["table"]
        kind = next(key for key in ("count", "equals", "contains") if key in assertion)
        if table not in observed:
            expected = assertion[kind]
            label_value = _short(expected)
            failures.append(f"table {table} {kind} == {label_value} (no readback)" if kind == "count"
                            else f"table {table} {kind} {label_value} (no readback)")
            continue
        actual = normalise_rows(observed[table], specs[table])
        expected = assertion[kind]
        if kind == "count":
            if len(actual) != expected:
                failures.append(f"table {table} count == {expected}")
        elif kind == "equals":
            wanted = normalise_rows(expected, specs[table])
            if actual != wanted:
                failures.append(f"table {table} equals {_short(expected)}")
        else:
            for row in _unmatched(expected, actual):
                failures.append(f"table {table} contains {_short(row)}")
    return failures


def _unmatched(expected, stored):
    """Expected rows left without a distinct stored row that agrees on every key they name (maximum matching, so an
    earlier, looser expected row can never steal the only stored row a later, stricter one needs)."""
    fits = [[i for i, row in enumerate(stored)
             if all(_normal_number(row.get(k)) == _normal_number(v) for k, v in want.items())] for want in expected]
    owner = {}

    def place(e, seen):
        for i in fits[e]:
            if i not in seen:
                seen.add(i)
                if i not in owner or place(owner[i], seen):
                    owner[i] = e
                    return True
        return False

    for e in range(len(expected)):
        place(e, set())
    placed = set(owner.values())
    return [want for e, want in enumerate(expected) if e not in placed]


def rebind_parameter(table_id, table_name) -> dict:
    return {"__rl": True, "mode": "id", "value": table_id, "cachedResultName": table_name}


def leak_problems(definition, source_ids) -> list[str]:
    try:
        encoded = _canonical(definition)
    except (TypeError, ValueError):
        encoded = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return [f"client table id {source_id[:4]}... is still referenced in the clone"
            for source_id in sorted(set(source_ids)) if isinstance(source_id, str) and source_id and source_id in encoded]


def table_name(run_id, group_index, logical) -> str:
    if not isinstance(group_index, int) or isinstance(group_index, bool) or group_index < 0:
        raise ValueError("group_index must be a non-negative integer")
    if not isinstance(logical, str) or not _LOGICAL.fullmatch(logical):
        raise ValueError("logical is invalid")
    result = f"breaker_sim_{hashlib.sha256(str(run_id).encode('utf-8')).hexdigest()[:8]}_{group_index}_{logical}"
    if len(result) > 63:
        raise ValueError("table name exceeds 63 characters")
    return result
