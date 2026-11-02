from __future__ import annotations

from dataclasses import replace
from typing import Any

from .effect_bridge import classify_semantic_effects
from .model import WorkflowSemanticModel
from .planner import SemanticPlan
from .safety import SafeExecutionPlan, validate_safe_execution_plan


def generate_safe_execution_plans(model: WorkflowSemanticModel, semantic_plan: SemanticPlan) -> tuple[SafeExecutionPlan, ...]:
    """Materialize only hypotheses with grounded support and controllable effects."""
    facts = model.workflow.get("deterministic_facts", {})
    triggers = facts.get("trigger_nodes", ()) if isinstance(facts, dict) else ()
    entrypoint = str((triggers[0] if triggers else {}).get("name", "")) if triggers else ""
    contract = facts.get("test_contract") if isinstance(facts, dict) else None
    if not isinstance(contract, dict) or not contract.get("synthetic_input") or not contract.get("expected_observable"):
        return ()
    input_boundary = str(contract.get("execution_boundary", ""))
    input_contract = contract.get("input_contract")
    if not input_boundary or not isinstance(input_contract, dict):
        return ()
    effects = classify_semantic_effects(model)
    plans: list[SafeExecutionPlan] = []
    for hypothesis in semantic_plan.hypotheses:
        if hypothesis.status != "APPLICABLE" or hypothesis.consistency_status != "SUPPORTED" or not hypothesis.business_rule_ids:
            continue
        invariant = next(item for item in semantic_plan.invariants if item.invariant_id == hypothesis.invariant_id)
        if not entrypoint or hypothesis.oracle_type not in {"WORKFLOW_SUPPORTED", "EXTERNAL_CONTRACT_SUPPORTED"}:
            continue
        if any(effect.disposition.value not in {"SUBSTITUTE", "BLOCK", "REQUIRE_HUMAN", "ALLOW"} for effect in effects.values()):
            continue
        boundaries = tuple(sorted(effects))
        substitutions = tuple(
            {
                "boundary": node_id,
                "disposition": effect.disposition.value,
                "what_this_proves": "the source path reaches a generic controlled effect boundary",
                "does_not_prove": "real external service success or durable external state",
            }
            for node_id, effect in sorted(effects.items())
            if effect.disposition.value == "SUBSTITUTE"
        )
        plan = SafeExecutionPlan(
            plan_id=f"PLAN_{hypothesis.hypothesis_id}",
            invariant_id=invariant.invariant_id,
            hypothesis_id=hypothesis.hypothesis_id,
            business_rule_ids=hypothesis.business_rule_ids,
            entrypoint=entrypoint,
            input_boundary=input_boundary,
            input_contract=dict(input_contract),
            synthetic_input=dict(contract["synthetic_input"]),
            oracle={
                "invariant": invariant.invariant_id,
                "expected_observation": invariant.expected_observation,
                "expected_observable": str(contract["expected_observable"]),
                "support": hypothesis.oracle_type,
            },
            consequential_nodes=boundaries,
            side_effect_classes=tuple(sorted({effect.effect_class for effect in effects.values()})),
            blocked_boundaries=boundaries,
            substitutions=substitutions,
            effect_policies={node_id: effect.disposition for node_id, effect in effects.items()},
            cleanup_plan=("persist evidence before cleanup", "archive disposable clone", "verify no live clone remains"),
            unsupported_areas=(),
            target_active=False,
            isolated=True,
            deadline_seconds=120,
        )
        validation = validate_safe_execution_plan(plan)
        if validation.status == "READY":
            plans.append(replace(plan, validation=validation))
    return tuple(plans)


def _synthetic_input(model: WorkflowSemanticModel) -> dict[str, Any]:
    """Construct a credential-free generic webhook envelope, never real customer data."""
    facts = model.workflow.get("deterministic_facts", {})
    fields: set[str] = set()
    for node in facts.get("nodes", ()) if isinstance(facts, dict) else ():
        fields.update(str(value).split(".")[0] for value in node.get("referenced_fields", ()))
    values: dict[str, Any] = {}
    samples = {
        "amount": 100,
        "vendor": "synthetic-vendor",
        "requesterEmail": "synthetic@example.invalid",
        "requester_email": "synthetic@example.invalid",
        "urgency": "normal",
        "route": "through",
    }
    for field in sorted(fields):
        values[field] = samples.get(field, "synthetic")
    return {"body": values}
