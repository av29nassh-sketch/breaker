from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Mapping

from .model import EvidenceClass, WorkflowSemanticModel


@dataclass(frozen=True)
class BusinessRule:
    rule_id: str
    rule_type: str
    source_node_ids: tuple[str, ...] = ()
    source_path: tuple[tuple[str, str], ...] = ()
    deterministic_expression: str = ""
    semantic_interpretation: str = ""
    input_fields: tuple[str, ...] = ()
    condition: Mapping[str, Any] = field(default_factory=dict)
    threshold: Any = None
    mapping: Mapping[str, Any] = field(default_factory=dict)
    keyword_set: tuple[str, ...] = ()
    expected_outcome: str = ""
    output_field: str | None = None
    confidence: float | None = None
    evidence_class: EvidenceClass = EvidenceClass.OBSERVED_STRUCTURE
    assumptions: tuple[str, ...] = ()
    oracle_type: str | None = None
    testability: str = "NEEDS_ORACLE"
    status: str = "UNASSESSED"
    grounding_reasons: tuple[str, ...] = ()
    lineage: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "rule_type": self.rule_type,
            "source_node_ids": list(self.source_node_ids), "source_path": [list(item) for item in self.source_path],
            "deterministic_expression": self.deterministic_expression,
            "semantic_interpretation": self.semantic_interpretation, "input_fields": list(self.input_fields),
            "condition": dict(self.condition), "threshold": self.threshold, "mapping": dict(self.mapping),
            "keyword_set": list(self.keyword_set), "expected_outcome": self.expected_outcome,
            "output_field": self.output_field, "confidence": self.confidence,
            "evidence_class": self.evidence_class.value, "assumptions": list(self.assumptions),
            "oracle_type": self.oracle_type, "testability": self.testability,
            "status": self.status, "grounding_reasons": list(self.grounding_reasons), "lineage": list(self.lineage),
        }


def ground_business_rules(model: WorkflowSemanticModel, rules: tuple[BusinessRule, ...]) -> tuple[BusinessRule, ...]:
    facts = model.workflow.get("deterministic_facts", {})
    nodes = facts.get("nodes", ()) if isinstance(facts, Mapping) else ()
    node_ids = {str(node.get("node_id")) for node in nodes}
    edges = facts.get("edges", ()) if isinstance(facts, Mapping) else ()
    edge_pairs = {(str(edge.get("source")), str(edge.get("target"))) for edge in edges}
    grounded: list[BusinessRule] = []
    for rule in rules:
        reasons: list[str] = []
        missing = sorted(set(rule.source_node_ids) - node_ids)
        if missing:
            reasons.append(f"unknown source nodes: {missing}")
        if not rule.deterministic_expression:
            reasons.append("deterministic expression is missing")
        if not rule.expected_outcome:
            reasons.append("expected outcome is missing")
        for source, target in rule.source_path:
            if (source, target) not in edge_pairs and source != target:
                reasons.append(f"source path is not grounded: {source}->{target}")
        invalid_path = any("source path is not grounded" in reason for reason in reasons)
        if missing or not rule.deterministic_expression or invalid_path:
            status = "REJECTED_UNSUPPORTED"
        elif not rule.expected_outcome or not rule.oracle_type or rule.testability != "READY":
            status = "NEEDS_ORACLE"
        elif reasons:
            status = "PARTIALLY_GROUNDED"
        else:
            status = "GROUNDED"
        grounded.append(replace(rule, status=status, grounding_reasons=tuple(reasons)))
    return tuple(grounded)
