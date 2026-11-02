from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from .safety import EffectDisposition, SafeExecutionPlan, validate_safe_execution_plan


class EffectState(str, Enum):
    NOT_REACHED_BY_WORKFLOW_LOGIC = "NOT_REACHED_BY_WORKFLOW_LOGIC"
    REACHED_AND_SUBSTITUTED = "REACHED_AND_SUBSTITUTED"
    REACHED_AND_BLOCKED = "REACHED_AND_BLOCKED"


_SECRET_PARTS = ("authorization", "password", "secret", "token", "api_key", "apikey", "credential")


def redact_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: "[REDACTED]" if any(part in str(key).lower() for part in _SECRET_PARTS) else redact_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_payload(item) for item in value)
    return value


def classify_effect_path(
    node_name: str,
    disposition: EffectDisposition,
    executed_nodes: Sequence[str],
) -> EffectState:
    """Classify only from the observed execution path, never from the plan."""
    if node_name not in executed_nodes:
        return EffectState.NOT_REACHED_BY_WORKFLOW_LOGIC
    if disposition == EffectDisposition.SUBSTITUTE:
        return EffectState.REACHED_AND_SUBSTITUTED
    if disposition in {EffectDisposition.BLOCK, EffectDisposition.REQUIRE_HUMAN, EffectDisposition.UNSUPPORTED}:
        return EffectState.REACHED_AND_BLOCKED
    raise ValueError(f"consequential node has unsafe disposition: {disposition}")


def substitute_workflow_effects(
    workflow: Mapping[str, Any],
    policies: Mapping[str, EffectDisposition],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Transform a clone into inert generic boundaries without mutating source."""
    clone = deepcopy(dict(workflow))
    records: list[dict[str, Any]] = []
    for node in clone.get("nodes", []):
        name = str(node.get("name", ""))
        disposition = policies.get(name)
        if disposition is None:
            continue
        original_type = node.get("type")
        original_parameters = deepcopy(node.get("parameters", {}))
        if disposition == EffectDisposition.SUBSTITUTE:
            node["type"] = "n8n-nodes-base.set"
            node["typeVersion"] = 3.5
            node["parameters"] = {
                "mode": "manual",
                "assignments": {"assignments": [
                    {"id": "breaker-original-node", "name": "breaker_original_node", "value": name, "type": "string"},
                    {"id": "breaker-original-type", "name": "breaker_original_type", "value": str(original_type), "type": "string"},
                    {"id": "breaker-effect-class", "name": "breaker_effect_class", "value": "CONSEQUENTIAL", "type": "string"},
                    {"id": "breaker-real-effect", "name": "real_effect_executed", "value": False, "type": "boolean"},
                    {"id": "breaker-payload", "name": "breaker_incoming_payload", "value": "={{ $json }}", "type": "object"},
                ]},
                "includeOtherFields": True,
            }
        elif disposition in {EffectDisposition.BLOCK, EffectDisposition.REQUIRE_HUMAN, EffectDisposition.UNSUPPORTED}:
            node["type"] = "n8n-nodes-base.stopAndError"
            node["typeVersion"] = 1
            node["parameters"] = {"message": f"Breaker blocked consequential boundary: {name}"}
        elif disposition == EffectDisposition.ALLOW:
            raise ValueError("ALLOW is not permitted for a generic consequential effect transformation")
        else:
            disposition = EffectDisposition.BLOCK
        records.append({
            "original_node_id": node.get("id"),
            "original_node_name": name,
            "original_node_type": original_type,
            "original_parameters": redact_payload(original_parameters),
            "disposition": disposition.value,
            "real_effect_executed": False,
        })
    return clone, records


@dataclass(frozen=True)
class RuntimeBinding:
    plan_id: str
    source_hash: str
    clone_workflow_id: str
    entrypoint: str
    input_boundary: str
    input_contract: Mapping[str, Any]
    synthetic_input: Mapping[str, Any]
    oracle: Mapping[str, Any]
    policies: Mapping[str, EffectDisposition]
    cleanup_plan: tuple[str, ...]


def bind_safe_execution_plan(
    plan: SafeExecutionPlan,
    *,
    source_hash: str,
    clone_workflow_id: str,
) -> RuntimeBinding:
    validation = validate_safe_execution_plan(plan)
    if validation.status != "READY":
        raise ValueError("SafeExecutionPlan rejected: " + "; ".join(validation.reasons))
    policies = {node: EffectDisposition.SUBSTITUTE for node in plan.consequential_nodes}
    policies.update({node: EffectDisposition.BLOCK for node in plan.blocked_boundaries if node not in policies})
    plan_id = str(plan.oracle.get("plan_id", "INVALID_INPUT_NO_SIDE_EFFECT"))
    return RuntimeBinding(
        plan_id=plan_id,
        source_hash=source_hash,
        clone_workflow_id=clone_workflow_id,
        entrypoint=plan.entrypoint,
        input_boundary=plan.input_boundary,
        input_contract=redact_payload(plan.input_contract),
        synthetic_input=redact_payload(plan.synthetic_input),
        oracle=redact_payload(plan.oracle),
        policies=policies,
        cleanup_plan=plan.cleanup_plan,
    )


@dataclass(frozen=True)
class ExecutionEvidence:
    plan_id: str
    source_hash: str
    clone_workflow_id: str
    execution_id: str
    input_payload: Mapping[str, Any]
    executed_nodes: tuple[str, ...]
    effect_states: Mapping[str, EffectState]
    outputs: Mapping[str, Any]
    oracle_result: str
    cleanup_result: str
    verdict: str

    @classmethod
    def from_runtime(
        cls,
        *,
        plan_id: str,
        source_hash: str,
        clone_workflow_id: str,
        execution_id: str,
        input_payload: Mapping[str, Any],
        executed_nodes: Sequence[str],
        effect_states: Mapping[str, EffectState],
        outputs: Mapping[str, Any],
        oracle_result: str,
        cleanup_result: str,
    ) -> "ExecutionEvidence":
        if cleanup_result != "PASS":
            verdict = "INCONCLUSIVE_RUNTIME_CLEANUP_FAILURE"
        elif any(state == EffectState.REACHED_AND_BLOCKED for state in effect_states.values()):
            verdict = "INCONCLUSIVE"
        else:
            verdict = oracle_result
        return cls(
            plan_id=plan_id,
            source_hash=source_hash,
            clone_workflow_id=clone_workflow_id,
            execution_id=execution_id,
            input_payload=redact_payload(input_payload),
            executed_nodes=tuple(executed_nodes),
            effect_states=dict(effect_states),
            outputs=redact_payload(outputs),
            oracle_result=oracle_result,
            cleanup_result=cleanup_result,
            verdict=verdict,
        )
