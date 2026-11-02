"""Generic effect classification and fail-closed preflight for an n8n workflow definition.

Every node is classified by its *type* alone (never by workflow or node name) into one of Core's dispositions:
ALLOW (pure logic or an entry point), SUBSTITUTE (an external call that may run only after a later stage
neutralises it) or BLOCK. Anything this table does not positively know is BLOCK with a reason. Core's
``classify_effects`` and ``validate_safe_execution_plan`` do the disposition normalisation and plan validation.

Nothing here contacts n8n. ``gate`` is the only way an action (an import, a run) should be reached: it evaluates
first and calls the action only when the definition and the plan are both safe, so a refusal makes zero calls.

A Code node is always BLOCK. Neither a token scan nor a hash attestation shows that code cannot reach the network;
only an independently verified isolation or offline replay mechanism could, and none exists yet.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from breaker.semantic.safety import (
    EffectDisposition,
    SafeExecutionPlan,
    SafetyValidation,
    classify_effects,
    validate_safe_execution_plan,
)

PREFIX = "n8n-nodes-base."

ENTRY = frozenset(PREFIX + name for name in (
    "manualTrigger", "webhook", "executeWorkflowTrigger", "scheduleTrigger"))
PURE = frozenset(PREFIX + name for name in (
    "set", "if", "switch", "merge", "filter", "noOp", "stickyNote", "splitOut", "aggregate", "sort", "limit",
    "removeDuplicates", "splitInBatches", "respondToWebhook"))
#: External calls with a safe inert stand-in (built in a later slice). Never runnable as they are.
SUBSTITUTABLE = frozenset(PREFIX + name for name in ("httpRequest", "emailSend"))
DATA_TABLE = PREFIX + "dataTable"
#: Types with a known reason to refuse, so the report says why rather than only "unknown".
KNOWN_UNSAFE = {
    PREFIX + "code": "Code node: execution safety is unproven (no verified isolation or offline replay)",
    PREFIX + "function": "legacy Code node: execution safety is unproven",
    PREFIX + "functionItem": "legacy Code node: execution safety is unproven",
    PREFIX + "executeCommand": "runs shell commands on the host",
    PREFIX + "ssh": "reaches a remote host",
    PREFIX + "ftp": "reaches a remote host",
    PREFIX + "readWriteFile": "reads or writes host files",
    PREFIX + "readBinaryFile": "reads host files",
    PREFIX + "writeBinaryFile": "writes host files",
    PREFIX + "executeWorkflow": "calls another workflow that is not classified",
}


@dataclass(frozen=True)
class NodeVerdict:
    name: str
    node_type: str
    disposition: EffectDisposition
    reason: str


@dataclass(frozen=True)
class PreflightResult:
    nodes: Mapping[str, NodeVerdict]
    workflow_reasons: tuple[str, ...]
    plan_validation: SafetyValidation | None = None
    reasons: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        found = list(self.workflow_reasons)
        found += [f"{v.name} ({v.node_type}): {v.reason}" for v in self.nodes.values()
                  if v.disposition not in (EffectDisposition.ALLOW, EffectDisposition.SUBSTITUTE)]
        if self.plan_validation is not None:
            found += list(self.plan_validation.reasons)
        object.__setattr__(self, "reasons", tuple(found))

    @property
    def blocked(self) -> bool:
        return bool(self.reasons)

    @property
    def needs_neutralisation(self) -> tuple[str, ...]:
        return tuple(n for n, v in self.nodes.items() if v.disposition == EffectDisposition.SUBSTITUTE)


class PreflightBlocked(RuntimeError):
    def __init__(self, reasons: Iterable[str]):
        self.reasons = tuple(reasons)
        super().__init__("blocked before any n8n call: " + "; ".join(self.reasons))


def _classify_node(node: Any, isolated_tables: frozenset[str],
                   rebindable: frozenset[str] = frozenset()) -> tuple[str, str, str, str]:
    """(name, type, requested disposition, reason); never raises on a malformed node."""
    if not isinstance(node, dict):
        return "<malformed>", "", "BLOCK", "node is not an object"
    name, node_type = node.get("name"), node.get("type")
    if not isinstance(name, str) or not name or not isinstance(node_type, str) or not node_type:
        return str(name or "<unnamed>"), str(node_type or ""), "BLOCK", "node has no name or type"
    if node_type in KNOWN_UNSAFE:
        return name, node_type, "BLOCK", KNOWN_UNSAFE[node_type]
    if node_type == DATA_TABLE:
        ref = (node.get("parameters") or {}).get("dataTableId")
        value = ref.get("value") if isinstance(ref, dict) else None
        if isinstance(value, str) and value in isolated_tables:
            return name, node_type, "ALLOW", "bound to a table this run created"
        # A declared node of a *source* definition is acceptable only because the neutralise stage rebinds it to a
        # table this run creates; a static reference is required, so a dynamic (expression) table is never rebound.
        if name in rebindable and isinstance(value, str) and value and not value.startswith("="):
            return name, node_type, "ALLOW", "declared test table: rebound to a table this run creates"
        return name, node_type, "BLOCK", "Data Table not bound to a table this run created"
    if node_type in SUBSTITUTABLE:
        return name, node_type, "SUBSTITUTE", "external call: runnable only after neutralisation"
    if node.get("credentials"):
        return name, node_type, "BLOCK", "holds credentials and has no safe stand-in"
    if node_type in ENTRY or node_type in PURE:
        return name, node_type, "ALLOW", "entry point" if node_type in ENTRY else "pure logic"
    return name, node_type, "BLOCK", "unknown node type: effects not established"


def evaluate(definition: Mapping[str, Any], *, isolated_tables: Iterable[str] = (),
             rebindable_nodes: Iterable[str] = ()) -> PreflightResult:
    """Classify every node (connected or not) and the workflow-level settings. Touches nothing.

    ``rebindable_nodes`` names Data Table nodes of a *source* definition that the caller will rebind to tables it
    creates. It is for classifying a source only: ``gate`` and the clone checks never receive it.
    """
    workflow_reasons: list[str] = []
    nodes = definition.get("nodes") if isinstance(definition, Mapping) else None
    if not isinstance(nodes, list) or not nodes:
        return PreflightResult({}, ("definition has no nodes",))
    if definition.get("active"):
        workflow_reasons.append("workflow is active")
    settings = definition.get("settings") or {}
    if isinstance(settings, Mapping) and settings.get("errorWorkflow"):
        workflow_reasons.append("an error workflow is set: it could cause unclassified effects")
    tables, rebindable = frozenset(isolated_tables), frozenset(rebindable_nodes)
    requested: dict[str, str] = {}
    meta: dict[str, tuple[str, str]] = {}
    for node in nodes:
        name, node_type, disposition, reason = _classify_node(node, tables, rebindable)
        if name in requested:
            workflow_reasons.append(f"duplicate node name {name!r}")
            continue
        requested[name], meta[name] = disposition, (node_type, reason)
    dispositions = classify_effects(requested)
    verdicts = {n: NodeVerdict(n, meta[n][0], dispositions[n], meta[n][1]) for n in requested}
    return PreflightResult(verdicts, tuple(workflow_reasons))


def build_plan(result: PreflightResult, definition: Mapping[str, Any], plan: Mapping[str, Any]) -> SafeExecutionPlan:
    """Core's plan for this definition. ``plan`` supplies what only the caller knows (entrypoint, oracle, ...)."""
    external = tuple(n for n, v in result.nodes.items() if v.disposition != EffectDisposition.ALLOW)
    unknown = any(v.disposition == EffectDisposition.BLOCK for v in result.nodes.values())
    return SafeExecutionPlan(
        entrypoint=plan.get("entrypoint", ""),
        synthetic_input=plan.get("synthetic_input") or {},
        oracle=plan.get("oracle") or {},
        consequential_nodes=external,
        side_effect_classes=("UNKNOWN_EXTERNAL_EFFECT",) if unknown else (("EXTERNAL_CALL",) if external else ()),
        blocked_boundaries=external,
        substitutions=tuple({"boundary": n, "what_this_proves": "the workflow's own logic around this call",
                             "does_not_prove": "the behaviour of the real external service"}
                            for n in result.needs_neutralisation),
        cleanup_plan=tuple(plan.get("cleanup_plan") or ()),
        unsupported_areas=tuple(plan.get("unsupported_areas") or ()),
        target_active=bool(definition.get("active")),
        isolated=bool(plan.get("isolated")),
        deadline_seconds=plan.get("deadline_seconds", 0),
        business_rule_ids=tuple(plan.get("business_rule_ids") or ()),
        input_boundary=plan.get("input_boundary", ""),
        input_contract=plan.get("input_contract") or {},
        effect_policies={n: v.disposition for n, v in result.nodes.items()},
    )


def preflight(definition: Mapping[str, Any], plan: Mapping[str, Any], *,
              isolated_tables: Iterable[str] = (), rebindable_nodes: Iterable[str] = ()) -> PreflightResult:
    """Static classification plus Core's plan validation, merged into one result."""
    static = evaluate(definition, isolated_tables=isolated_tables, rebindable_nodes=rebindable_nodes)
    if not static.nodes:
        return static
    validation = validate_safe_execution_plan(build_plan(static, definition, plan))
    return PreflightResult(static.nodes, static.workflow_reasons, validation)


def gate(definition: Mapping[str, Any], plan: Mapping[str, Any], action: Callable[..., Any], *args: Any,
         isolated_tables: Iterable[str] = (), **kwargs: Any) -> Any:
    """Call ``action`` (an import, a run) only if the preflight finds nothing to refuse.

    A definition that still contains an external-call node is refused too: ``gate`` is for the neutralised
    definition, in which those nodes no longer exist.
    """
    result = preflight(definition, plan, isolated_tables=isolated_tables)
    pending = [f"{n}: external call not yet neutralised" for n in result.needs_neutralisation]
    if result.blocked or pending:
        raise PreflightBlocked(result.reasons + tuple(pending))
    return action(*args, **kwargs)
