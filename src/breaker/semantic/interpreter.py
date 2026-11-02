from __future__ import annotations

from typing import Any, Mapping

from .model import EvidenceClass, SemanticRole, WorkflowSemanticModel


def apply_jev_answers(model: WorkflowSemanticModel, response: Mapping[str, Any], *, supporting_node_ids: tuple[str, ...]) -> WorkflowSemanticModel:
    if response.get("model") != "typesafe/jev":
        raise ValueError("unexpected decision model")
    answers = response.get("answers")
    if not isinstance(answers, Mapping):
        raise ValueError("decision response has no answers object")
    result = model
    semantic = answers.get("semantic_role")
    if isinstance(semantic, Mapping) and semantic.get("choice"):
        role = _role_for_choice(str(semantic["choice"]))
        result = result.with_claim(
            claim=f"semantic role is {semantic['choice']}", role=role,
            evidence=EvidenceClass.AI_INFERRED_SEMANTIC, supporting_node_ids=supporting_node_ids,
            supporting_facts=("decision model answer",), confidence=_confidence(semantic.get("confidence")),
        )
    persistent = answers.get("persistent_write")
    if isinstance(persistent, Mapping) and persistent.get("noul") is not None:
        result = result.with_claim(
            claim="persistent write likelihood returned by decision model", role=SemanticRole.PERSISTENT_WRITE,
            evidence=EvidenceClass.AI_INFERRED_SEMANTIC, supporting_node_ids=supporting_node_ids,
            supporting_facts=("decision model noul probability",), confidence=_confidence(persistent.get("noul")),
        )
    return result


def apply_v4_claims(model: WorkflowSemanticModel, response: Mapping[str, Any]) -> WorkflowSemanticModel:
    if response.get("model") != "deepseek/deepseek-v4-flash":
        raise ValueError("unexpected reasoning model")
    claims = response.get("claims")
    if not isinstance(claims, list):
        raise ValueError("reasoning response must contain a claims list")
    result = model
    for item in claims:
        if not isinstance(item, Mapping) or not item.get("claim") or not item.get("role"):
            raise ValueError("reasoning claim missing required fields")
        node_ids = item.get("supporting_node_ids")
        if not isinstance(node_ids, list) or not node_ids:
            raise ValueError("reasoning claim requires supporting node IDs")
        result = result.with_claim(
            claim=str(item["claim"]), role=SemanticRole(str(item["role"])),
            evidence=EvidenceClass.AI_INFERRED_SEMANTIC, supporting_node_ids=tuple(str(value) for value in node_ids),
            supporting_facts=tuple(str(value) for value in item.get("supporting_facts", ())),
            confidence=_confidence(item.get("confidence")), uncertainty=tuple(str(value) for value in item.get("uncertainty", ())),
            assumptions=tuple(str(value) for value in item.get("assumptions", ())),
        )
    return result


def _confidence(value: Any) -> float | None:
    if value is None:
        return None
    result = float(value)
    if not 0 <= result <= 1:
        raise ValueError("confidence must be between 0 and 1")
    return result


def _role_for_choice(choice: str) -> SemanticRole:
    normalized = choice.upper()
    aliases = {"STATE_WRITE": SemanticRole.STATE_WRITE, "PERSISTENT_WRITE": SemanticRole.PERSISTENT_WRITE, "NOTIFICATION": SemanticRole.NOTIFICATION, "TRANSFORMATION": SemanticRole.TRANSFORMATION, "ROUTING": SemanticRole.ROUTING}
    return aliases.get(normalized, SemanticRole.UNKNOWN)
