from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .model import SemanticRole, WorkflowSemanticModel
from .safety import EffectDisposition


@dataclass(frozen=True)
class SemanticEffect:
    node_id: str
    effect_class: str
    disposition: EffectDisposition
    confidence: float | None
    evidence_claims: tuple[str, ...]


_ROLE_EFFECTS = {
    SemanticRole.NOTIFICATION: "NOTIFICATION",
    SemanticRole.PERSISTENT_WRITE: "PERSISTENT_WRITE",
    SemanticRole.STATE_WRITE: "EXTERNAL_MUTATION",
    SemanticRole.EXTERNAL_WRITE: "EXTERNAL_MUTATION",
    SemanticRole.UPSERT: "PERSISTENT_WRITE",
    SemanticRole.EXTERNAL_READ: "EXTERNAL_READ",
}

_EFFECT_PRIORITY = {
    "PAYMENT": 100,
    "DESTRUCTIVE_OPERATION": 90,
    "PERSISTENT_WRITE": 80,
    "EXTERNAL_MUTATION": 75,
    "ACCOUNT_CREATE": 78,
    "NOTIFICATION": 60,
    "EXTERNAL_READ": 40,
}
_LOCAL_NODE_TYPES = {"webhook", "code", "if", "switch", "set", "stickynote", "respondtowebhook", "function", "merge", "noop"}


def _is_externalish(node: Mapping[str, object]) -> bool:
    if bool(node.get("external_boundary")):
        return True
    node_type = str(node.get("node_type", "")).rsplit(".", 1)[-1].lower()
    return node_type not in _LOCAL_NODE_TYPES


def _compatible(effect_class: str, node: Mapping[str, object]) -> bool:
    base = str(node.get("node_type", "")).rsplit(".", 1)[-1].lower()
    operation = str(node.get("operation") or "").lower()
    message_like = any(token in base for token in ("mail", "slack", "message", "notification", "sms", "chat")) or operation in {"send", "notify"}
    storage_like = any(token in base for token in ("sheet", "table", "database", "airtable", "notion", "storage", "record"))
    if effect_class == "NOTIFICATION":
        return message_like
    if effect_class == "PERSISTENT_WRITE":
        return storage_like or operation in {"create", "insert", "update", "upsert", "append", "delete", "remove"}
    if effect_class == "EXTERNAL_READ":
        return storage_like or operation in {"read", "lookup", "get", "search", "list"}
    return True


def classify_semantic_effects(model: WorkflowSemanticModel) -> Mapping[str, SemanticEffect]:
    """Bridge grounded roles into generic effect classes without overriding safety."""
    facts = model.workflow.get("deterministic_facts", {})
    nodes = facts.get("nodes", ()) if isinstance(facts, dict) else ()
    claims_by_node: dict[str, list] = {}
    for claim in model.claims:
        for node_id in claim.supporting_node_ids:
            claims_by_node.setdefault(str(node_id), []).append(claim)

    result: dict[str, SemanticEffect] = {}
    for node in nodes:
        node_id = str(node.get("node_id", ""))
        claims = claims_by_node.get(node_id, [])
        candidates = [(_ROLE_EFFECTS[c.role], c) for c in claims if c.role in _ROLE_EFFECTS and _is_externalish(node) and _compatible(_ROLE_EFFECTS[c.role], node)]
        if not candidates and _is_externalish(node):
            operation = str(node.get("operation") or "").lower()
            if operation in {"account_create", "provision", "create_account"}:
                candidates = [("ACCOUNT_CREATE", None)]
            elif operation in {"invite"}:
                candidates = [("EXTERNAL_MUTATION", None)]
            elif operation in {"append", "create", "insert", "update", "upsert", "delete", "remove"}:
                candidates = [("PERSISTENT_WRITE", None)]
            elif operation in {"send", "notify"}:
                candidates = [("NOTIFICATION", None)]
            elif operation in {"read", "lookup", "get", "search", "list"}:
                candidates = [("EXTERNAL_READ", None)]
        if candidates:
            effect_class, _ = max(candidates, key=lambda item: _EFFECT_PRIORITY[item[0]])
            confidence = min((c.confidence for _, c in candidates if c is not None and c.confidence is not None), default=None)
            result[node_id] = SemanticEffect(
                node_id=node_id,
                effect_class=effect_class,
                disposition=EffectDisposition.SUBSTITUTE,
                confidence=confidence,
                evidence_claims=tuple(c.claim for _, c in candidates if c is not None),
            )
        elif bool(node.get("external_boundary")):
            result[node_id] = SemanticEffect(
                node_id=node_id,
                effect_class="UNKNOWN_EXTERNAL_EFFECT",
                disposition=EffectDisposition.BLOCK,
                confidence=None,
                evidence_claims=(),
            )
    return result
