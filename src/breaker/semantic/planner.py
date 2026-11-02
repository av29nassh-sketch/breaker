from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import EvidenceClass, SemanticClaim, SemanticRole, WorkflowSemanticModel
from .rules import BusinessRule, ground_business_rules


@dataclass(frozen=True)
class CandidateInvariant:
    invariant_id: str
    description: str
    scope: str
    supporting_semantics: tuple[str, ...]
    supporting_nodes: tuple[str, ...]
    oracle_type: str
    confidence: float | None
    required_input: dict[str, Any]
    expected_observation: str
    consequential_side_effects: tuple[str, ...]
    uncertainty: tuple[str, ...]
    supporting_semantic_claims: tuple[str, ...] = ()
    conflicting_semantic_claims: tuple[str, ...] = ()
    consistency_status: str = "SUPPORTED"
    business_rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class TestHypothesis:
    hypothesis_id: str
    description: str
    invariant_id: str
    required_input: dict[str, Any]
    oracle_type: str
    expected_observation: str
    safety: tuple[str, ...]
    status: str
    consistency_status: str = "SUPPORTED"
    business_rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class SemanticPlan:
    invariants: tuple[CandidateInvariant, ...]
    hypotheses: tuple[TestHypothesis, ...]


_ROLE_RULES = {
    SemanticRole.INPUT_VALIDATION: ("INVALID_INPUT_NO_SIDE_EFFECT", "Invalid input should not reach a consequential boundary.", "validation", "EXTERNAL_CONTRACT_SUPPORTED"),
    SemanticRole.TRANSFORMATION: ("TRANSFORMATION_PRESERVED", "The declared transformation preserves required fields and meaning.", "transformation", "CUSTOMER_ORACLE_REQUIRED"),
    SemanticRole.NORMALIZATION: ("TRANSFORMATION_PRESERVED", "Normalization is deterministic and preserves the declared canonical meaning.", "normalization", "CUSTOMER_ORACLE_REQUIRED"),
    SemanticRole.ROUTING: ("ROUTING_CONDITION_SELECTS_PATH", "The routing condition selects the path implied by the input.", "routing", "WORKFLOW_SUPPORTED"),
    SemanticRole.PERSISTENT_WRITE: ("REPEATED_IDENTITY_NO_DUPLICATE_STATE", "Repeated stable identity does not create duplicate persistent state.", "persistence", "CUSTOMER_ORACLE_REQUIRED"),
    SemanticRole.UPSERT: ("REPEATED_IDENTITY_NO_DUPLICATE_STATE", "Repeated stable identity updates one state record rather than creating a duplicate.", "persistence", "CUSTOMER_ORACLE_REQUIRED"),
    SemanticRole.RESPONSE: ("VALID_INPUT_REACHES_EXPECTED_BOUNDARY", "Valid input reaches the declared response boundary.", "response", "WORKFLOW_SUPPORTED"),
    SemanticRole.ERROR_HANDLER: ("FAILURE_DOES_NOT_REPEAT_COMPLETED_SIDE_EFFECT", "Failure handling does not repeat a completed consequential effect.", "failure", "CUSTOMER_ORACLE_REQUIRED"),
}

_CONFLICTING_ROLES = {
    SemanticRole.NOTIFICATION, SemanticRole.PERSISTENT_WRITE, SemanticRole.STATE_WRITE,
    SemanticRole.EXTERNAL_WRITE, SemanticRole.UPSERT,
}


_LOCAL_NODE_TYPES = {"webhook", "code", "if", "switch", "set", "stickynote", "respondtowebhook", "function", "merge", "noop"}


def _effect_nodes(model: WorkflowSemanticModel, claim) -> set[str]:
    facts = model.workflow.get("deterministic_facts", {})
    nodes = facts.get("nodes", ()) if isinstance(facts, dict) else ()
    by_id = {str(node.get("node_id")): node for node in nodes}
    return {
        node_id for node_id in claim.supporting_node_ids
        if str(by_id.get(str(node_id), {}).get("node_type", "")).rsplit(".", 1)[-1].lower() not in _LOCAL_NODE_TYPES
    }


class SemanticPlanner:
    def plan(self, model: WorkflowSemanticModel, business_rules: tuple[BusinessRule, ...] | None = None) -> SemanticPlan:
        node_ids = {str(node.get("node_id")) for node in self._nodes(model)}
        grounded_rules = ground_business_rules(model, business_rules or ()) if business_rules is not None else ()
        rules_by_id = {rule.rule_id: rule for rule in grounded_rules}
        invariants: list[CandidateInvariant] = []
        seen: set[str] = set()
        claims = model.claims or self._claims_from_rules(grounded_rules)
        for claim in claims:
            unknown = set(claim.supporting_node_ids) - node_ids
            if unknown:
                raise ValueError(f"supporting node references are unknown: {sorted(unknown)}")
            rule = _ROLE_RULES.get(claim.role)
            if rule is None or rule[0] in seen:
                continue
            invariant_id, description, scope, oracle = rule
            seen.add(invariant_id)
            supporting = tuple(item.claim for item in claims if set(item.supporting_node_ids) & set(claim.supporting_node_ids))
            conflicts = tuple(item.claim for item in claims if item.role in _CONFLICTING_ROLES and _effect_nodes(model, item) & set(claim.supporting_node_ids)) if invariant_id == "INVALID_INPUT_NO_SIDE_EFFECT" else ()
            consistency = "REJECTED_CONTRADICTION" if invariant_id == "INVALID_INPUT_NO_SIDE_EFFECT" and conflicts else "SUPPORTED"
            rule_ids = tuple(rule_item.rule_id for rule_item in grounded_rules if rule_item.status == "GROUNDED" and set(rule_item.source_node_ids) & set(claim.supporting_node_ids))
            if business_rules is not None and not rule_ids and consistency == "SUPPORTED":
                consistency = "NEEDS_ORACLE"
            invariants.append(CandidateInvariant(
                invariant_id=invariant_id,
                description=description,
                scope=scope,
                supporting_semantics=(claim.claim,),
                supporting_nodes=claim.supporting_node_ids,
                oracle_type=oracle,
                confidence=claim.confidence,
                required_input={"strategy": self._strategy_for(invariant_id)},
                expected_observation=description,
                consequential_side_effects=("external_write",) if scope == "persistence" else (),
                uncertainty=claim.uncertainty + claim.assumptions,
                supporting_semantic_claims=supporting,
                conflicting_semantic_claims=conflicts,
                consistency_status=consistency,
                business_rule_ids=rule_ids,
            ))
        hypotheses = tuple(self._hypothesis(item) for item in invariants)
        return SemanticPlan(tuple(invariants), hypotheses)

    @staticmethod
    def _claims_from_rules(rules: tuple[BusinessRule, ...]) -> tuple[SemanticClaim, ...]:
        claims: list[SemanticClaim] = []
        role_by_rule = {
            "CONDITIONAL_ROUTE": SemanticRole.ROUTING,
            "FIELD_VALUE_ROUTE": SemanticRole.ROUTING,
            "DEFAULT_ROUTE": SemanticRole.ROUTING,
            "THRESHOLD_RULE": SemanticRole.ROUTING,
            "KEYWORD_CLASSIFICATION": SemanticRole.ROUTING,
            "VALUE_MAPPING": SemanticRole.TRANSFORMATION,
            "FIELD_TRANSFORMATION": SemanticRole.TRANSFORMATION,
            "VALIDATION_RULE": SemanticRole.INPUT_VALIDATION,
            "DEFAULT_RULE": SemanticRole.ROUTING,
        }
        for rule in rules:
            role = role_by_rule.get(rule.rule_type)
            if role is None or rule.status != "GROUNDED":
                continue
            claims.append(SemanticClaim(
                claim=rule.semantic_interpretation or f"{rule.rule_type} produces {rule.expected_outcome}",
                role=role,
                evidence=rule.evidence_class,
                supporting_node_ids=rule.source_node_ids,
                supporting_facts=(rule.deterministic_expression,),
                confidence=rule.confidence,
                assumptions=rule.assumptions,
            ))
        return tuple(claims)

    @staticmethod
    def _nodes(model: WorkflowSemanticModel):
        facts = model.workflow.get("deterministic_facts", {})
        return facts.get("nodes", ()) if isinstance(facts, dict) else ()

    @staticmethod
    def _strategy_for(invariant_id: str) -> str:
        return {
            "INVALID_INPUT_NO_SIDE_EFFECT": "invalid_input",
            "TRANSFORMATION_PRESERVED": "transformation_probe",
            "ROUTING_CONDITION_SELECTS_PATH": "branch_boundary_pair",
            "REPEATED_IDENTITY_NO_DUPLICATE_STATE": "identity_replay",
            "FAILURE_DOES_NOT_REPEAT_COMPLETED_SIDE_EFFECT": "failure_after_effect",
            "VALID_INPUT_REACHES_EXPECTED_BOUNDARY": "valid_input",
        }[invariant_id]

    @staticmethod
    def _hypothesis(item: CandidateInvariant) -> TestHypothesis:
        if item.consistency_status == "REJECTED_CONTRADICTION":
            status = "REJECTED_CONTRADICTION"
        elif item.consistency_status == "NEEDS_ORACLE" or not item.business_rule_ids:
            status = "NEEDS_ORACLE"
        elif item.oracle_type in {"EXTERNAL_CONTRACT_SUPPORTED", "WORKFLOW_SUPPORTED"}:
            status = "APPLICABLE"
        else:
            status = "NEEDS_ORACLE"
        if item.consequential_side_effects:
            safety = ("persistent external write must be substituted", "read-back is unproven unless an external contract is supplied")
        else:
            safety = ("unknown consequential effects default to BLOCK",)
        return TestHypothesis(
            hypothesis_id=f"HYPOTHESIS_{item.invariant_id}",
            description=item.description,
            invariant_id=item.invariant_id,
            required_input=item.required_input,
            oracle_type=item.oracle_type,
            expected_observation=item.expected_observation,
            safety=safety,
            status=status,
            consistency_status=item.consistency_status,
            business_rule_ids=item.business_rule_ids,
        )
