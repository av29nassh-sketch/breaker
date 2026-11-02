from __future__ import annotations

import json
from typing import Any, Mapping

from .compaction import semantic_payload_bytes

SINGLE_CALL = "SINGLE_CALL"
HIERARCHICAL_REQUIRED = "HIERARCHICAL_REQUIRED"

#: Measured single-call payload budget. Compacted workflows below this size are
#: sent as one workflow-level synthesis; larger ones use the hierarchical path.
SINGLE_CALL_LIMIT_BYTES = 20_000

_SYSTEM = (
    "You are the Breaker workflow reasoning model. Return JSON only. "
    "Infer semantics, never execution proof. Every claim must include "
    "supporting_node_ids, supporting_facts, confidence, assumptions, and uncertainty. "
    "Never emit CONFIRMED_FAILURE."
)

_SCHEMA: Mapping[str, Any] = {
    "claims": [{
        "claim": "string",
        "role": "TRIGGER|INPUT_VALIDATION|TRANSFORMATION|NORMALIZATION|ROUTING|STATE_READ|STATE_WRITE|PERSISTENT_WRITE|UPSERT|DEDUPLICATION|EXTERNAL_READ|EXTERNAL_WRITE|NOTIFICATION|RESPONSE|ERROR_HANDLER|UNKNOWN",
        "supporting_node_ids": ["string"],
        "supporting_facts": ["string"],
        "confidence": 0.0,
        "assumptions": ["string"],
        "uncertainty": ["string"],
    }],
    "workflow_purpose": {"statement": "string", "supporting_node_ids": ["string"], "confidence": 0.0, "uncertainty": ["string"]},
}


def synthesis_strategy(compact: Mapping[str, Any], *, single_call_limit_bytes: int = SINGLE_CALL_LIMIT_BYTES) -> str:
    return SINGLE_CALL if semantic_payload_bytes(compact) <= single_call_limit_bytes else HIERARCHICAL_REQUIRED


def build_reasoning_request(compact_facts: Mapping[str, Any], *, instruction: str | None = None) -> Mapping[str, Any]:
    user = "COMPACT_DETERMINISTIC_WORKFLOW_FACTS:\n" + _compact_json(compact_facts)
    user += "\nREQUIRED_OUTPUT_SCHEMA:\n" + _compact_json(_SCHEMA)
    if instruction:
        user += "\nADDITIONAL_REQUIREMENTS:\n" + instruction
    return {
        "model": "deepseek/deepseek-v4-flash",
        "messages": [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }


def split_into_semantic_groups(compact: Mapping[str, Any], *, group_limit_bytes: int) -> tuple[Mapping[str, Any], ...]:
    """Deterministically split a compacted workflow into topology-respecting groups.

    Nodes are grouped by connected component and then by breadth-first layers so a
    group never separates a path from the nodes it feeds. Used only for workflows
    that exceed the single-call budget.
    """
    nodes = [node for node in compact.get("nodes", ()) or () if isinstance(node, Mapping)]
    edges = [edge for edge in compact.get("edges", ()) or () if isinstance(edge, Mapping)]
    by_name = {str(node["name"]): node for node in nodes}
    adjacency: dict[str, set[str]] = {name: set() for name in by_name}
    for edge in edges:
        source, target = str(edge.get("from")), str(edge.get("to"))
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)
    groups: list[list[str]] = []
    unvisited = set(by_name)
    trigger_names = sorted(str(node["name"]) for node in nodes if node.get("trigger"))
    roots = trigger_names + sorted(unvisited)
    for root in roots:
        if root not in unvisited:
            continue
        order: list[str] = []
        queue = [root]
        unvisited.discard(root)
        while queue:
            current = queue.pop(0)
            order.append(current)
            for neighbour in sorted(adjacency.get(current, ())):
                if neighbour in unvisited:
                    unvisited.discard(neighbour)
                    queue.append(neighbour)
        groups.append(order)
    grouped: list[Mapping[str, Any]] = []
    for order in groups:
        current: list[str] = []
        for name in order:
            candidate = current + [name]
            if current and semantic_payload_bytes(_group_payload(candidate, by_name, edges)) > group_limit_bytes:
                grouped.append(_group_payload(current, by_name, edges))
                current = [name]
            else:
                current = candidate
        if current:
            grouped.append(_group_payload(current, by_name, edges))
    return tuple(grouped)


def _group_payload(names: list[str], by_name: Mapping[str, Mapping[str, Any]], edges: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    selected = set(names)
    return {
        "nodes": [by_name[name] for name in names],
        "edges": [edge for edge in edges if str(edge.get("from")) in selected and str(edge.get("to")) in selected],
    }


def _compact_json(value: Any) -> str:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))
