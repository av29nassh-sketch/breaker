from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
import ast
import json
import re

from .model import EvidenceClass
from .rules import BusinessRule


@dataclass(frozen=True)
class NodeFacts:
    node_id: str
    name: str
    node_type: str
    type_version: Any
    operation: str | None
    resource: str | None
    matching_columns: tuple[str, ...]
    expressions: tuple[str, ...]
    referenced_fields: tuple[str, ...]
    external_boundary: bool
    disabled: bool
    credentials: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id, "name": self.name, "node_type": self.node_type,
            "type_version": self.type_version, "operation": self.operation, "resource": self.resource,
            "matching_columns": list(self.matching_columns), "expressions": list(self.expressions),
            "referenced_fields": list(self.referenced_fields), "external_boundary": self.external_boundary,
            "disabled": self.disabled, "credentials": [dict(item) for item in self.credentials],
        }


@dataclass(frozen=True)
class WorkflowFacts:
    workflow_id: str | None
    name: str | None
    trigger_nodes: tuple[dict[str, Any], ...]
    nodes: tuple[NodeFacts, ...]
    edges: tuple[dict[str, Any], ...]
    branch_sources: tuple[str, ...]
    error_nodes: tuple[str, ...]
    webhook_properties: tuple[dict[str, Any], ...]
    workflow_settings: Mapping[str, Any]
    rule_facts: tuple[BusinessRule, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id, "name": self.name,
            "trigger_nodes": [dict(item) for item in self.trigger_nodes],
            "nodes": [item.as_dict() for item in self.nodes],
            "edges": [dict(item) for item in self.edges],
            "branch_sources": list(self.branch_sources), "error_nodes": list(self.error_nodes),
            "webhook_properties": [dict(item) for item in self.webhook_properties],
            "workflow_settings": dict(self.workflow_settings),
            "rule_facts": [rule.as_dict() for rule in self.rule_facts],
        }


class DeterministicFactExtractor:
    """Extract only facts directly present in an n8n workflow document."""

    def extract(self, workflow: Mapping[str, Any]) -> WorkflowFacts:
        raw_nodes = list(workflow.get("nodes", ()))
        trigger_nodes = tuple(node for node in raw_nodes if _is_trigger(node.get("type", "")))
        node_facts = tuple(_node_facts(node) for node in raw_nodes)
        connections = workflow.get("connections", {}) or {}
        edges = tuple(
            {"source": source, "output": output_index, "target": link.get("node"), "target_index": link.get("index", 0), "type": link.get("type", "main")}
            for source, outputs in connections.items()
            for output_index, links in enumerate(outputs.get("main", ()))
            for link in links
        )
        branch_sources = tuple(source for source, outputs in connections.items() if len(outputs.get("main", ())) > 1)
        error_nodes = tuple(node.name for node in node_facts if _is_error_node(node.node_type))
        webhook_properties = tuple(
            {
                "node_id": node.get("id"),
                "name": node.get("name"),
                "method": (node.get("parameters") or {}).get("httpMethod"),
                "path": (node.get("parameters") or {}).get("path"),
                "response_mode": (node.get("parameters") or {}).get("responseMode"),
            }
            for node in raw_nodes
            if _base_type(node.get("type", "")) == "webhook"
        )
        return WorkflowFacts(
            workflow_id=workflow.get("id") or workflow.get("workflowId"),
            name=workflow.get("name"),
            trigger_nodes=trigger_nodes,
            nodes=node_facts,
            edges=edges,
            branch_sources=branch_sources,
            error_nodes=error_nodes,
            webhook_properties=webhook_properties,
            workflow_settings=workflow.get("settings", {}) or {},
            rule_facts=extract_rule_facts(workflow),
        )


def _base_type(node_type: str) -> str:
    return str(node_type).rsplit(".", 1)[-1].lower()


def _is_trigger(node_type: str) -> bool:
    base = _base_type(node_type)
    return base == "webhook" or base.endswith("trigger")


def _is_error_node(node_type: str) -> bool:
    return _base_type(node_type) == "errortrigger"


def _node_facts(node: Mapping[str, Any]) -> NodeFacts:
    params = node.get("parameters") or {}
    operation = params.get("operation")
    columns = params.get("columns") or {}
    matching = columns.get("matchingColumns") or params.get("matchingColumns") or ()
    if not isinstance(matching, (list, tuple)):
        matching = (str(matching),)
    expressions = tuple(_strings(params, expression_only=True))
    refs = tuple(sorted(set(_field_refs(expressions))))
    credentials = tuple(
        {"type": str(kind), "name": str(ref.get("name", "<redacted>"))}
        for kind, ref in (node.get("credentials") or {}).items()
        if isinstance(ref, Mapping)
    )
    external = bool(credentials or _has_endpoint(params) or _is_mutating_operation(operation))
    return NodeFacts(
        node_id=str(node.get("id", "")), name=str(node.get("name", "")), node_type=str(node.get("type", "")),
        type_version=node.get("typeVersion"), operation=str(operation) if operation is not None else None,
        resource=str(params.get("resource")) if params.get("resource") is not None else str(node.get("type", "")),
        matching_columns=tuple(str(item) for item in matching), expressions=expressions,
        referenced_fields=refs, external_boundary=external, disabled=bool(node.get("disabled", False)),
        credentials=credentials,
    )


def _has_endpoint(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_has_endpoint(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_endpoint(v) for v in value)
    return isinstance(value, str) and (value.startswith("http://") or value.startswith("https://"))


def _is_mutating_operation(operation: Any) -> bool:
    return str(operation or "").lower() in {
        "create", "insert", "update", "upsert", "appendorupdate", "append", "send", "delete", "remove", "execute"
    }


def _strings(value: Any, *, expression_only: bool = False) -> list[str]:
    result: list[str] = []
    if isinstance(value, Mapping):
        for child in value.values():
            result.extend(_strings(child, expression_only=expression_only))
    elif isinstance(value, list):
        for child in value:
            result.extend(_strings(child, expression_only=expression_only))
    elif isinstance(value, str) and (not expression_only or "={{" in value or "{{" in value):
        result.append(value)
    return result


def _field_refs(expressions: tuple[str, ...]) -> list[str]:
    refs: list[str] = []
    for expression in expressions:
        marker = "$json."
        start = 0
        while True:
            index = expression.find(marker, start)
            if index < 0:
                break
            tail = expression[index + len(marker):]
            field = ""
            for char in tail:
                if char.isalnum() or char in "_.$[]":
                    field += char
                else:
                    break
            if field:
                refs.append(field)
            start = index + len(marker)
    return refs


def extract_rule_facts(workflow: Mapping[str, Any]) -> tuple[BusinessRule, ...]:
    """Extract bounded, domain-neutral rule facts without executing arbitrary code."""
    rules: list[BusinessRule] = []
    connections = workflow.get("connections", {}) or {}
    for node in workflow.get("nodes", ()) or ():
        node_id = str(node.get("id", ""))
        node_type = _base_type(str(node.get("type", "")))
        params = node.get("parameters") or {}
        if node_type == "if" and params.get("conditions"):
            expression = json.dumps(params["conditions"], sort_keys=True, separators=(",", ":"))
            rules.append(BusinessRule(
                rule_id=f"RULE_{node_id}_CONDITION",
                rule_type="CONDITIONAL_ROUTE",
                source_node_ids=(node_id,),
                deterministic_expression=expression,
                input_fields=tuple(sorted(set(_field_refs((expression,))))),
                condition=params["conditions"],
                evidence_class=EvidenceClass.OBSERVED_STRUCTURE,
                testability="NEEDS_ORACLE",
            ))
        if node_type == "set":
            assignments = ((params.get("assignments") or {}).get("assignments") or [])
            for index, assignment in enumerate(assignments):
                if not isinstance(assignment, Mapping) or not assignment.get("name"):
                    continue
                value = assignment.get("value")
                expression = json.dumps({"field": assignment["name"], "value": value}, sort_keys=True, separators=(",", ":"))
                rules.append(BusinessRule(
                    rule_id=f"RULE_{node_id}_MAP_{index}",
                    rule_type="VALUE_MAPPING" if not (isinstance(value, str) and ("={{" in value or "{{" in value)) else "FIELD_TRANSFORMATION",
                    source_node_ids=(node_id,),
                    deterministic_expression=expression,
                    input_fields=tuple(sorted(set(_field_refs((str(value),))))),
                    expected_outcome=str(value), output_field=str(assignment["name"]),
                    evidence_class=EvidenceClass.OBSERVED_STRUCTURE,
                    testability="NEEDS_ORACLE",
                ))
        if node_type == "code" and isinstance(params.get("jsCode"), str):
            rules.extend(_extract_code_rules(node_id, params["jsCode"]))
    return tuple(rules)


def _extract_code_rules(node_id: str, code: str) -> list[BusinessRule]:
    found: list[BusinessRule] = []
    index = 0
    for name, opening in re.findall(r"const\s+([A-Za-z_$][\w$]*)\s*=\s*([\[\{])", code):
        closing = "]" if opening == "[" else "}"
        start = code.find(opening, code.find(name))
        literal = _balanced_literal(code, start, opening, closing)
        if literal is None:
            continue
        try:
            value = _parse_js_literal(literal)
        except (SyntaxError, ValueError):
            continue
        lowered = name.lower()
        if isinstance(value, list) and value and all(isinstance(item, (list, tuple)) for item in value):
            pairs = tuple(str(item[0]) for item in value if item)
            keywords = tuple(str(term) for item in value for term in (item[1] if len(item) > 1 and isinstance(item[1], (list, tuple)) else ()) )
            rule_type = "KEYWORD_CLASSIFICATION" if keywords else "VALUE_MAPPING"
            found.append(BusinessRule(rule_id=f"RULE_{node_id}_{index}", rule_type=rule_type, source_node_ids=(node_id,), deterministic_expression=literal, mapping={str(item[0]): list(item[1]) if len(item) > 1 and isinstance(item[1], (list, tuple)) else None for item in value}, keyword_set=keywords, expected_outcome="computed output", evidence_class=EvidenceClass.OBSERVED_STRUCTURE, assumptions=(f"constant {name} is used by deterministic code",), testability="NEEDS_ORACLE")); index += 1
        elif isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            found.append(BusinessRule(rule_id=f"RULE_{node_id}_{index}", rule_type="KEYWORD_CLASSIFICATION", source_node_ids=(node_id,), deterministic_expression=literal, keyword_set=tuple(value), expected_outcome="computed output", evidence_class=EvidenceClass.OBSERVED_STRUCTURE, assumptions=(f"constant {name} is used by deterministic code",), testability="NEEDS_ORACLE")); index += 1
        elif isinstance(value, dict):
            found.append(BusinessRule(rule_id=f"RULE_{node_id}_{index}", rule_type="VALUE_MAPPING", source_node_ids=(node_id,), deterministic_expression=literal, mapping={str(k): v for k, v in value.items()}, expected_outcome="computed output", evidence_class=EvidenceClass.OBSERVED_STRUCTURE, assumptions=(f"constant {name} is used by deterministic code",), testability="NEEDS_ORACLE")); index += 1
    if found:
        return found
    return [BusinessRule(rule_id=f"RULE_{node_id}_UNSUPPORTED_CODE", rule_type="UNSUPPORTED_CODE_LOGIC", source_node_ids=(node_id,), deterministic_expression=code[:2000], evidence_class=EvidenceClass.OBSERVED_STRUCTURE, testability="NEEDS_ORACLE")]


def _parse_js_literal(literal: str) -> Any:
    try:
        return ast.literal_eval(literal)
    except (SyntaxError, ValueError):
        normalized = re.sub(r"(?<!['\"])([A-Za-z_$][\w$]*)\s*:", r"'\1':", literal)
        return ast.literal_eval(normalized)


def _balanced_literal(text: str, start: int, opening: str, closing: str) -> str | None:
    if start < 0:
        return None
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"', "`"):
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return None
