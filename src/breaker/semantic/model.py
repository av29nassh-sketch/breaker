from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping


class EvidenceClass(str, Enum):
    OBSERVED_STRUCTURE = "OBSERVED_STRUCTURE"
    AI_INFERRED_SEMANTIC = "AI_INFERRED_SEMANTIC"
    GROUNDED_SEMANTIC = "GROUNDED_SEMANTIC"
    STATIC_RISK = "STATIC_RISK"
    NEEDS_VERIFICATION = "NEEDS_VERIFICATION"
    DYNAMICALLY_REPRODUCED = "DYNAMICALLY_REPRODUCED"
    VERIFIED_FIX = "VERIFIED_FIX"
    INCONCLUSIVE = "INCONCLUSIVE"


class SemanticRole(str, Enum):
    TRIGGER = "TRIGGER"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    TRANSFORMATION = "TRANSFORMATION"
    NORMALIZATION = "NORMALIZATION"
    ROUTING = "ROUTING"
    STATE_READ = "STATE_READ"
    STATE_WRITE = "STATE_WRITE"
    PERSISTENT_WRITE = "PERSISTENT_WRITE"
    UPSERT = "UPSERT"
    DEDUPLICATION = "DEDUPLICATION"
    EXTERNAL_READ = "EXTERNAL_READ"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    NOTIFICATION = "NOTIFICATION"
    RESPONSE = "RESPONSE"
    ERROR_HANDLER = "ERROR_HANDLER"
    AI_INFERENCE = "AI_INFERENCE"
    AGGREGATION = "AGGREGATION"
    LOOP = "LOOP"
    WAIT = "WAIT"
    SUBWORKFLOW = "SUBWORKFLOW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SemanticClaim:
    claim: str
    role: SemanticRole
    evidence: EvidenceClass
    supporting_node_ids: tuple[str, ...]
    supporting_facts: tuple[str, ...] = ()
    confidence: float | None = None
    uncertainty: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if self.evidence in {EvidenceClass.DYNAMICALLY_REPRODUCED, EvidenceClass.VERIFIED_FIX}:
            raise ValueError("semantic claims cannot assert dynamic or verified-fix evidence")


@dataclass(frozen=True)
class WorkflowSemanticModel:
    workflow: Mapping[str, Any]
    claims: tuple[SemanticClaim, ...] = ()
    nodes: tuple[Mapping[str, Any], ...] = ()
    paths: tuple[Mapping[str, Any], ...] = ()
    unknowns: tuple[str, ...] = ()
    provenance: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_facts(cls, *, workflow_id: str | None, name: str | None, facts: Mapping[str, Any]) -> "WorkflowSemanticModel":
        return cls(workflow={"id": workflow_id, "name": name, "deterministic_facts": dict(facts)}, provenance={"source": "deterministic"})

    def with_claim(self, *, claim: str, role: SemanticRole, evidence: EvidenceClass, supporting_node_ids: tuple[str, ...], supporting_facts: tuple[str, ...] = (), confidence: float | None = None, uncertainty: tuple[str, ...] = (), assumptions: tuple[str, ...] = ()) -> "WorkflowSemanticModel":
        item = SemanticClaim(claim, role, evidence, supporting_node_ids, supporting_facts, confidence, uncertainty, assumptions)
        return replace(self, claims=self.claims + (item,))

    def can_claim_dynamic_reproduction(self) -> bool:
        return False

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "workflow": dict(self.workflow),
            "claims": [{"claim": c.claim, "role": c.role.value, "evidence": c.evidence.value, "supporting_node_ids": list(c.supporting_node_ids), "supporting_facts": list(c.supporting_facts), "confidence": c.confidence, "uncertainty": list(c.uncertainty), "assumptions": list(c.assumptions)} for c in self.claims],
            "nodes": [dict(node) for node in self.nodes],
            "paths": [dict(path) for path in self.paths],
            "unknowns": list(self.unknowns),
            "provenance": dict(self.provenance),
        }
