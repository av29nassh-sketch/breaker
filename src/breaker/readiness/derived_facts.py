"""Facts safely derivable from a frozen workflow definition, each with the evidence that produced it.

WHY THIS MODULE EXISTS
----------------------
A large NOT_TESTED set exists because a fact an applicability rule needs was never observed. Some of those
facts *are* structurally present in the frozen export and were simply not being read. This module reads the
ones that can be read honestly, and records the evidence source for each — so a derived fact is always
traceable to a node and a parameter, never an inference.

It also states the other half explicitly: the facts that are **operator-owned** and must never be derived.
``production_environment``, the manual fallback policy, a capacity/volume threshold, the restore target,
credential ownership/rotation policy, a business SLA and live deployment authorization are decisions about the
business, not properties of a graph. Deriving them from node types would be exactly the false confidence the
framework exists to prevent.

Nothing here writes to a frozen artifact or executes anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from breaker.readiness.profile import classify_node_type

#: Facts that remain operator-owned. Listed so a report can quote them rather than paraphrase, and so a future
#: change that tries to derive one is a visible edit to this set.
OPERATOR_OWNED_FACTS: tuple[str, ...] = (
    "production_environment",
    "manual_fallback_policy",
    "capacity_volume_threshold",
    "restore_target",
    "credential_ownership_and_rotation_policy",
    "business_sla",
    "live_deployment_authorization",
)

#: Node types that write a persistence surface (their parameters/operations are the proof, not this list).
_PERSISTENCE_TYPES: tuple[str, ...] = ("supabase", "postgres", "mysql", "mongoDb", "redis", "dataTable",
                                       "googleSheets", "airtable", "microsoftSql")
_NOTIFICATION_TYPES: tuple[str, ...] = ("emailSend", "gmail", "slack", "telegram", "twilio", "microsoftTeams",
                                        "whatsApp")
_SUBWORKFLOW_TYPES: tuple[str, ...] = ("executeWorkflowTrigger", "executeWorkflow", "toolWorkflow")
_AI_NODE_TYPES: tuple[str, ...] = ("openAi", "langchain", "lmChatOllama", "ollama", "anthropic", "cohere",
                                   "mistral")


@dataclass(frozen=True)
class DerivedFact:
    """One fact read from the frozen definition, with the evidence that produced it."""

    name: str
    value: Any
    evidence: str
    source: str

    def as_record(self) -> dict[str, Any]:
        return {"name": self.name, "value": self.value, "evidence": self.evidence, "source": self.source}


def _nodes(workflow: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    return [item for item in ((workflow or {}).get("nodes") or ()) if isinstance(item, Mapping)]


def _names_of(nodes: list[Mapping[str, Any]], predicate) -> list[str]:
    return [str(node.get("name") or node.get("id") or "") for node in nodes if predicate(node)]


def _type_matches(node_type: str, needles: tuple[str, ...]) -> bool:
    lowered = (node_type or "").lower()
    return any(needle.lower() in lowered for needle in needles)


def _parameters_text(node: Mapping[str, Any]) -> str:
    parameters = node.get("parameters")
    if not isinstance(parameters, Mapping):
        return ""
    try:
        import json

        return json.dumps(parameters, ensure_ascii=False, default=str)
    except Exception:  # pragma: no cover - parameters are JSON from an export
        return str(parameters)


def derive_workflow_facts(workflow: Mapping[str, Any] | None,
                          *, ai_surfaces: tuple[str, ...] = ()) -> tuple[DerivedFact, ...]:
    """Read the safely-derivable facts from a frozen n8n export, each with its evidence.

    ``ai_surfaces`` is the claimed AI surface list (native nodes plus the HTTP-request detector's claims), so
    the AI fact is not re-derived here from a second, weaker reader.
    """
    nodes = _nodes(workflow)
    facts: list[DerivedFact] = []
    source = f"frozen definition ({len(nodes)} node(s))"

    # -- has AI component ---------------------------------------------------------------------------------
    native_ai = _names_of(nodes, lambda node: _type_matches(str(node.get("type") or ""), _AI_NODE_TYPES))
    ai_names = sorted(dict.fromkeys([*native_ai, *[str(name) for name in ai_surfaces if str(name)]]))
    facts.append(DerivedFact(
        "has_ai_component", bool(ai_names),
        f"node types/evidence matching a model call: {ai_names}" if ai_names
        else "no native AI node type and no grounded HTTP-request AI surface", source))

    # -- intake triggers ----------------------------------------------------------------------------------
    webhook = _names_of(nodes, lambda node: str(node.get("type") or "").endswith("webhook"))
    form = _names_of(nodes, lambda node: str(node.get("type") or "").endswith("formTrigger"))
    facts.append(DerivedFact("has_webhook_trigger", bool(webhook),
                             f"webhook node(s): {webhook}" if webhook else "no webhook node", source))
    facts.append(DerivedFact("has_form_trigger", bool(form),
                             f"form trigger node(s): {form}" if form else "no form trigger node", source))

    # -- persistence preparation surface ------------------------------------------------------------------
    persistence_nodes = _names_of(
        nodes, lambda node: _type_matches(str(node.get("type") or ""), _PERSISTENCE_TYPES)
        or (str(node.get("type") or "") == "n8n-nodes-base.httpRequest"
            and "rest/v1" in _parameters_text(node)))
    if not persistence_nodes:
        # an HTTP request that declares an RPC/CRUD body is a persistence surface too
        persistence_nodes = _names_of(
            nodes, lambda node: str(node.get("type") or "") == "n8n-nodes-base.httpRequest"
            and any(token in _parameters_text(node).lower()
                    for token in ("upsert", "rpc", "insert", "conflict")))
    preparation = _names_of(nodes, lambda node: str(node.get("type") or "") in
                           ("n8n-nodes-base.code", "n8n-nodes-base.set")
                           and any(token in _parameters_text(node).lower()
                                   for token in ("_payload", "payload", "p_")))
    facts.append(DerivedFact(
        "has_persistence_preparation_surface", bool(persistence_nodes or preparation),
        f"persistence node(s): {persistence_nodes or preparation}"
        if (persistence_nodes or preparation) else "no persistence write surface", source))

    # -- notification surface -----------------------------------------------------------------------------
    notification = _names_of(nodes, lambda node: _type_matches(str(node.get("type") or ""),
                                                               _NOTIFICATION_TYPES))
    facts.append(DerivedFact("has_email_or_notification_surface", bool(notification),
                             f"notification node(s): {notification}" if notification
                             else "no email/notification node", source))

    # -- simulation boundary ------------------------------------------------------------------------------
    simulation = _names_of(nodes, lambda node: "effects_mode" in _parameters_text(node))
    facts.append(DerivedFact(
        "has_simulation_boundary", bool(simulation),
        f"node(s) whose parameters reference a simulation/effects-mode barrier: {simulation}" if simulation
        else "no node references a simulation/effects-mode barrier", source))

    # -- sub-workflow / test entry surface -----------------------------------------------------------------
    subworkflow = _names_of(nodes, lambda node: _type_matches(str(node.get("type") or ""),
                                                              _SUBWORKFLOW_TYPES))
    facts.append(DerivedFact("has_sub_workflow_or_test_entry_surface", bool(subworkflow),
                             f"sub-workflow/test entry node(s): {subworkflow}" if subworkflow
                             else "no sub-workflow or test entry node", source))
    return tuple(facts)


def derived_facts_record(workflow: Mapping[str, Any] | None, *,
                         ai_surfaces: tuple[str, ...] = ()) -> dict[str, Any]:
    """The derived facts as a machine-readable record, with the operator-owned facts stated beside them."""
    facts = derive_workflow_facts(workflow, ai_surfaces=ai_surfaces)
    return {"derived": [item.as_record() for item in facts],
            "operator_owned": list(OPERATOR_OWNED_FACTS),
            "note": ("derived facts are read from the frozen definition and carry their evidence; "
                     "operator-owned facts are decisions and are never derived")}


__all__ = ["DerivedFact", "OPERATOR_OWNED_FACTS", "derive_workflow_facts", "derived_facts_record"]
