from __future__ import annotations

import json
from typing import Any, Mapping

"""Generic deterministic compaction of an n8n workflow document for semantic reasoning.

Rules are generic and apply to any n8n workflow:

- keep graph topology, node identity/type, operation/resource, matching columns,
  conditions, expressions/field mappings, triggers, responses, error relationships,
  and external-boundary facts;
- drop presentation and export noise (UI coordinates, webhook identity strings,
  timestamps, tags, static data, pin data, empty option blocks);
- drop human-authored prose (workflow description, sticky-note content, node notes)
  because such text restates the intended business meaning and would leak
  adjudicated ground truth into a semantic evaluation;
- keep credential *names* only, never credential values or identifiers.
"""

_OMIT_NODE_TYPES = {"stickynote"}

_DENY_PARAM_KEYS = {
    "position", "width", "height", "notes", "notesInFlow", "content", "pinData",
    "credentials", "id", "webhookId", "typeVersion", "alwaysOutputData",
    "executeOnce", "retryOnFail", "maxTries", "waitBetweenTries", "options",
    "saveDataSuccessExecution", "saveDataErrorExecution", "saveManualExecutions",
    # summarized at node level, so not repeated inside params
    "operation", "resource", "matchingColumns", "onError",
}

_DENY_WORKFLOW_KEYS = {
    "description", "staticData", "pinData", "tags", "createdAt", "updatedAt",
    "versionId", "meta", "triggerCount", "shared", "usedCredentials", "views",
    "recentViews", "totalViews", "isArchived", "homeProject", "scopes", "checksum",
}

_MAX_STRING = 300
_MAX_LIST = 40


def semantic_payload_bytes(payload: Mapping[str, Any]) -> int:
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def compact_workflow(workflow: Mapping[str, Any]) -> Mapping[str, Any]:
    raw_nodes = [node for node in workflow.get("nodes", ()) or () if isinstance(node, Mapping)]
    nodes = [_compact_node(node) for node in raw_nodes if not _is_omitted(node)]
    omitted = len(raw_nodes) - len(nodes)
    connections = workflow.get("connections", {}) or {}
    edges = [
        {"from": source, "to": link.get("node"), "branch": output_index}
        for source, outputs in connections.items()
        if isinstance(outputs, Mapping)
        for output_index, links in enumerate(outputs.get("main", ()) or ())
        for link in links
        if isinstance(link, Mapping)
    ]
    settings = workflow.get("settings", {}) or {}
    return {
        "workflow": {
            "id": workflow.get("id") or workflow.get("workflowId"),
            "name": workflow.get("name"),
            "active": bool(workflow.get("active", False)),
            "settings": {k: v for k, v in settings.items() if k not in _DENY_PARAM_KEYS},
        },
        "nodes": nodes,
        "edges": edges,
        "triggers": [node["name"] for node in nodes if node.get("trigger")],
        "error_nodes": [node["name"] for node in nodes if node["type"] == "errorTrigger"],
        "branch_sources": [source for source, outputs in connections.items() if isinstance(outputs, Mapping) and len(outputs.get("main", ()) or ()) > 1],
        "webhook": [
            {k: node.get("params", {}).get(k) for k in ("httpMethod", "path", "responseMode") if node.get("params", {}).get(k) is not None}
            for node in nodes
            if node["type"] == "webhook"
        ],
        "credential_types": sorted({item for node in nodes for item in node.get("credential_types", [])}),
        "omitted_node_count": omitted,
    }


def _is_omitted(node: Mapping[str, Any]) -> bool:
    return _base_type(str(node.get("type", ""))).lower() in _OMIT_NODE_TYPES


def _base_type(node_type: str) -> str:
    return node_type.rsplit(".", 1)[-1]


def _compact_node(node: Mapping[str, Any]) -> Mapping[str, Any]:
    params = node.get("parameters") or {}
    if not isinstance(params, Mapping):
        params = {}
    filtered = _filter_params(params)
    credentials = node.get("credentials") or {}
    compact: dict[str, Any] = {
        "id": str(node.get("id", "")) or None,
        "name": str(node.get("name", "")),
        "type": _base_type(str(node.get("type", ""))),
    }
    for key, value in (
        ("operation", _scalar(params.get("operation"))),
        ("resource", _scalar(params.get("resource"))),
        ("matching_columns", _matching_columns(params)),
        ("fields", _field_refs(filtered)),
        ("on_error", _scalar(params.get("onError") or node.get("onError"))),
        ("trigger", _is_trigger(str(node.get("type", ""))) or None),
        ("external_boundary", (bool(credentials) or _has_endpoint(filtered) or _is_mutating(params.get("operation"))) or None),
        ("disabled", bool(node.get("disabled", False)) or None),
        ("credential_types", sorted(str(key) for key in credentials if isinstance(credentials, Mapping))),
        ("params", filtered),
    ):
        if value not in (None, "", False, {}, []):
            compact[key] = value
    return compact


def _filter_params(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _filter_params(child) for key, child in value.items() if key not in _DENY_PARAM_KEYS and child not in (None, "", {}, [])}
    if isinstance(value, list):
        return [_filter_params(item) for item in value[:_MAX_LIST]]
    if isinstance(value, str):
        return value if len(value) <= _MAX_STRING else value[:_MAX_STRING] + "...[truncated]"
    return value


def _scalar(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool)) else None


def _matching_columns(params: Mapping[str, Any]) -> list[str]:
    columns = params.get("columns")
    source = columns if isinstance(columns, Mapping) else params
    matching = source.get("matchingColumns") or params.get("matchingColumns") or ()
    if not isinstance(matching, (list, tuple)):
        matching = (matching,)
    return [str(item) for item in matching]


def _is_trigger(node_type: str) -> bool:
    base = _base_type(node_type).lower()
    return base == "webhook" or base.endswith("trigger")


def _is_mutating(operation: Any) -> bool:
    return str(operation or "").lower() in {"create", "insert", "update", "upsert", "appendorupdate", "append", "send", "delete", "remove", "execute"}


def _has_endpoint(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_has_endpoint(child) for child in value.values())
    if isinstance(value, list):
        return any(_has_endpoint(child) for child in value)
    return isinstance(value, str) and (value.startswith("http://") or value.startswith("https://"))


def _field_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, Mapping):
        for child in value.values():
            refs.extend(_field_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(_field_refs(child))
    elif isinstance(value, str):
        marker = "$json."
        start = 0
        while True:
            index = value.find(marker, start)
            if index < 0:
                break
            tail = value[index + len(marker):]
            field = ""
            for char in tail:
                if char.isalnum() or char in "_.$[]":
                    field += char
                else:
                    break
            if field:
                refs.append(field.split(".")[0].split("[")[0])
            start = index + len(marker)
    return sorted(set(refs))
