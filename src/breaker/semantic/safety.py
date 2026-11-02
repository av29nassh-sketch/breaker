from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class EffectDisposition(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SUBSTITUTE = "SUBSTITUTE"
    REQUIRE_HUMAN = "REQUIRE_HUMAN"
    UNSUPPORTED = "UNSUPPORTED"


def classify_effects(effects: Mapping[str, str]) -> dict[str, EffectDisposition]:
    result = {}
    for node_id, requested in effects.items():
        try:
            result[node_id] = EffectDisposition(str(requested).upper())
        except ValueError:
            result[node_id] = EffectDisposition.BLOCK
    return result


@dataclass(frozen=True)
class SafeExecutionPlan:
    entrypoint: str
    synthetic_input: Mapping[str, Any]
    oracle: Mapping[str, Any]
    consequential_nodes: tuple[str, ...]
    side_effect_classes: tuple[str, ...]
    blocked_boundaries: tuple[str, ...]
    substitutions: tuple[Mapping[str, Any], ...]
    cleanup_plan: tuple[str, ...]
    unsupported_areas: tuple[str, ...]
    target_active: bool
    isolated: bool
    deadline_seconds: int
    plan_id: str = ""
    invariant_id: str = ""
    hypothesis_id: str = ""
    business_rule_ids: tuple[str, ...] = ()
    input_boundary: str = ""
    input_contract: Mapping[str, Any] = field(default_factory=dict)
    effect_policies: Mapping[str, EffectDisposition] = field(default_factory=dict)
    validation: SafetyValidation | None = None


@dataclass(frozen=True)
class SafetyValidation:
    status: str
    reasons: tuple[str, ...] = ()


def validate_safe_execution_plan(plan: SafeExecutionPlan) -> SafetyValidation:
    reasons: list[str] = []
    if not plan.entrypoint:
        reasons.append("entrypoint is missing")
    if not plan.synthetic_input:
        reasons.append("synthetic input is missing")
    if not plan.oracle or not plan.oracle.get("invariant"):
        reasons.append("oracle invariant is missing")
    if not plan.business_rule_ids:
        reasons.append("grounded business rule identity is missing")
    if not plan.input_boundary:
        reasons.append("execution input boundary is missing")
    if not isinstance(plan.input_contract, Mapping) or plan.input_contract.get("boundary") != plan.input_boundary:
        reasons.append("input contract must identify the execution boundary")
    if not isinstance(plan.input_contract, Mapping) or not plan.input_contract.get("field_path"):
        reasons.append("input contract field path is missing")
    if plan.target_active:
        reasons.append("target must be inactive")
    if not plan.isolated:
        reasons.append("isolated execution is required")
    if not isinstance(plan.deadline_seconds, int) or plan.deadline_seconds <= 0:
        reasons.append("positive deadline is required")
    if not plan.cleanup_plan:
        reasons.append("cleanup plan is missing")
    for effect in plan.side_effect_classes:
        if effect in {"UNKNOWN_EXTERNAL_EFFECT", "DESTRUCTIVE_OPERATION", "PAYMENT"}:
            reasons.append(f"unknown consequential effect: {effect}")
    blocked = set(plan.blocked_boundaries)
    for substitution in plan.substitutions:
        boundary = substitution.get("boundary")
        if not boundary or boundary not in blocked:
            reasons.append("every substitution must correspond to a blocked boundary")
        if not substitution.get("what_this_proves") or not substitution.get("does_not_prove"):
            reasons.append("substitutions require proof and non-proof statements")
    for effect in plan.side_effect_classes:
        if effect not in {"UNKNOWN_EXTERNAL_EFFECT", "DESTRUCTIVE_OPERATION", "PAYMENT"} and plan.consequential_nodes and not blocked:
            reasons.append("consequential boundaries must be blocked or explicitly safe")
            break
    return SafetyValidation("BLOCK" if reasons else "READY", tuple(reasons))
