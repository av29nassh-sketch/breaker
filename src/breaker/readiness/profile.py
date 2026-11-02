"""The workflow profile: what Breaker knows about the thing under verification.

The applicability engine needs facts, and a fact Breaker cannot ground must stay *unknown* rather than become
a false negative. So the profile separates three kinds of knowledge:

* **observed structure** — node kinds, triggers, effects, credentials and AI surfaces read from a workflow
  graph (via :mod:`breaker.workflow_ir` or an n8n workflow JSON);
* **declared facts** — properties a graph cannot show, such as "the destination can be read back
  independently" or "concurrency of five is safe for this target", which a caller declares with a source;
* **contract facts** — read from the :class:`~breaker.readiness.contract.ProductionContract`.

Every value carries where it came from, and anything not covered stays ``None``: that is what turns a check
into ``NOT_TESTED / WORKFLOW_PROFILE_INCOMPLETE`` instead of a quiet ``N/A``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence


class TriggerKind(StrEnum):
    WEBHOOK = "WEBHOOK"
    HTTP = "HTTP"
    SCHEDULE = "SCHEDULE"
    EVENT = "EVENT"
    MANUAL = "MANUAL"
    SUBWORKFLOW = "SUBWORKFLOW"
    UNKNOWN = "UNKNOWN"


class EffectKind(StrEnum):
    PERSISTENCE = "PERSISTENCE"
    NOTIFICATION = "NOTIFICATION"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    PAYMENT = "PAYMENT"
    CALENDAR = "CALENDAR"
    FILE = "FILE"
    READ = "READ"
    LOOKUP = "LOOKUP"
    AI_ACTION = "AI_ACTION"


#: n8n Data Table operations that change stored rows. A *read* proves the table exists — the table is a state
#: surface either way — but only a write is an effect on that state, so the operation decides which one a node
#: is. Without this the export's own persistence nodes classify as nothing, and "state is persisted" resolves
#: false for a workflow whose graph is nothing but state writes.
DATA_TABLE_WRITE_OPERATIONS = frozenset({"insert", "append", "upsert", "update", "delete", "clear"})


#: n8n node type -> the surfaces Breaker derives from it. Only the two properties that matter to the
#: checklist are mapped: what the node does, and whether it brings an AI surface with it.
N8N_NODE_RULES: tuple[tuple[str, Mapping[str, Any]], ...] = (
    ("webhook", {"trigger": TriggerKind.WEBHOOK}),
    ("scheduleTrigger", {"trigger": TriggerKind.SCHEDULE}),
    ("cron", {"trigger": TriggerKind.SCHEDULE}),
    ("interval", {"trigger": TriggerKind.SCHEDULE}),
    ("executeWorkflowTrigger", {"trigger": TriggerKind.SUBWORKFLOW}),
    ("manualTrigger", {"trigger": TriggerKind.MANUAL}),
    ("formTrigger", {"trigger": TriggerKind.WEBHOOK}),
    ("if", {"router": True}),
    ("switch", {"router": True}),
    ("merge", {"merge": True}),
    ("splitInBatches", {"batch": True, "pagination": True}),
    ("httpRequest", {"dependency": True}),
    ("graphql", {"dependency": True}),
    ("postgres", {"dependency": True, "persistence": True}),
    ("mysql", {"dependency": True, "persistence": True}),
    ("mongoDb", {"dependency": True, "persistence": True}),
    ("redis", {"dependency": True, "persistence": True}),
    ("googleSheets", {"dependency": True, "persistence": True}),
    ("airtable", {"dependency": True, "persistence": True}),
    ("supabase", {"dependency": True, "persistence": True}),
    ("microsoftSql", {"dependency": True, "persistence": True}),
    ("gmail", {"notification": True, "dependency": True}),
    ("emailSend", {"notification": True, "dependency": True}),
    ("slack", {"notification": True, "dependency": True}),
    ("telegram", {"notification": True, "dependency": True}),
    ("twilio", {"notification": True, "dependency": True}),
    ("microsoftTeams", {"notification": True, "dependency": True}),
    ("whatsApp", {"notification": True, "dependency": True}),
    ("quickbooks", {"externalWrite": True, "dependency": True, "payment": True}),
    ("stripe", {"externalWrite": True, "dependency": True, "payment": True}),
    ("xero", {"externalWrite": True, "dependency": True}),
    ("hubspot", {"externalWrite": True, "dependency": True, "readBack": True}),
    ("salesforce", {"externalWrite": True, "dependency": True, "readBack": True}),
    ("googlesheets", {"persistence": True, "dependency": True}),
    # n8n's own Data Table node: whether it writes or reads is decided by its operation, so the type alone
    # only says "there is a table here" (see ``data_table_reference`` / ``data_table_writes``).
    ("dataTable", {"dataStore": True}),
    ("googleCalendar", {"calendar": True, "externalWrite": True, "dependency": True}),
    ("code", {"code": True}),
    ("set", {"transformation": True}),
    ("function", {"code": True}),
    ("noOp", {}),
    ("wait", {"longRunning": True}),
    ("executeWorkflow", {"dependency": True}),
    ("errorTrigger", {"errorWorkflow": True}),
    ("stopAndError", {"errorWorkflow": True}),
    ("langchain.agent", {"ai": True, "agent": True, "tools": True}),
    ("langchain.chainLlm", {"ai": True}),
    ("langchain.lmChat", {"ai": True}),
    ("openAi", {"ai": True, "dependency": True}),
    ("lmChatOllama", {"ai": True}),
    ("toolVectorStore", {"ai": True, "retrieval": True}),
    ("vectorStore", {"retrieval": True, "dependency": True}),
    ("documentDefaultDataLoader", {"retrieval": True}),
    ("toolHttpRequest", {"ai": True, "tools": True, "dependency": True}),
    ("toolCode", {"ai": True, "tools": True, "code": True}),
    ("toolWorkflow", {"ai": True, "tools": True}),
    ("memoryBufferWindow", {"ai": True}),
)


@dataclass(frozen=True)
class EffectDeclaration:
    kind: EffectKind
    destination: str = ""
    system: str = ""
    reversible: bool | None = None
    critical: bool | None = None
    acknowledged: bool | None = None
    unique_key_enforced: bool | None = None
    multi_field: bool | None = None
    source: str = ""

    def as_record(self) -> dict[str, Any]:
        return {"kind": str(self.kind), "destination": self.destination, "system": self.system,
                "reversible": self.reversible, "critical": self.critical, "acknowledged": self.acknowledged,
                "unique_key_enforced": self.unique_key_enforced, "multi_field": self.multi_field,
                "source": self.source}


@dataclass(frozen=True)
class DependencyDeclaration:
    system: str
    credential_owner: str = ""
    failure_impact: str = ""
    manual_fallback: str = ""
    source: str = ""

    def as_record(self) -> dict[str, Any]:
        return {"system": self.system, "credential_owner": self.credential_owner,
                "failure_impact": self.failure_impact, "manual_fallback": self.manual_fallback,
                "source": self.source}


@dataclass(frozen=True)
class WorkflowProfile:
    """Everything Breaker knows, with the source of each fact kept alongside it."""

    workflow_id: str = ""
    name: str = ""
    platform: str = "unknown"
    version: str | None = None
    environment: str | None = None
    entrypoints: tuple[str, ...] = ()
    trigger_kinds: tuple[TriggerKind, ...] = ()
    node_kinds: tuple[str, ...] = ()
    routers: tuple[str, ...] = ()
    batch_or_pagination: tuple[str, ...] = ()
    code_nodes: tuple[str, ...] = ()
    effects: tuple[EffectDeclaration, ...] = ()
    state_surfaces: tuple[str, ...] = ()
    lookup_operations: tuple[str, ...] = ()
    dependencies: tuple[DependencyDeclaration, ...] = ()
    credential_references: tuple[str, ...] = ()
    downstream_systems: tuple[str, ...] = ()
    ai_surfaces: tuple[str, ...] = ()
    ai_tools: tuple[str, ...] = ()
    retrieval_surfaces: tuple[str, ...] = ()
    untrusted_content_sources: tuple[str, ...] = ()
    human_approval_gates: tuple[str, ...] = ()
    error_workflows: tuple[str, ...] = ()
    self_trigger_surface: tuple[str, ...] = ()
    declarations: Mapping[str, Any] = field(default_factory=dict)
    declared_sources: Mapping[str, str] = field(default_factory=dict)
    unknowns: tuple[str, ...] = ()
    source: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)

    # -- derived structure ---------------------------------------------------------------------------
    @property
    def has_effects(self) -> bool:
        return bool(self.effects)

    @property
    def write_effects(self) -> tuple[EffectDeclaration, ...]:
        return tuple(item for item in self.effects if item.kind != EffectKind.READ)

    @property
    def notification_effects(self) -> tuple[EffectDeclaration, ...]:
        return tuple(item for item in self.effects if item.kind == EffectKind.NOTIFICATION)

    @property
    def persistence_effects(self) -> tuple[EffectDeclaration, ...]:
        return tuple(item for item in self.effects
                     if item.kind in {EffectKind.PERSISTENCE, EffectKind.EXTERNAL_WRITE, EffectKind.PAYMENT,
                                      EffectKind.CALENDAR, EffectKind.FILE})

    @property
    def has_ai(self) -> bool:
        return bool(self.ai_surfaces)

    @property
    def has_tools(self) -> bool:
        return bool(self.ai_tools)

    @property
    def has_retrieval(self) -> bool:
        return bool(self.retrieval_surfaces)

    def declaration(self, name: str) -> Any:
        return self.declarations.get(name)

    def declaration_source(self, name: str) -> str:
        return self.declared_sources.get(name, "")

    @property
    def declared(self) -> tuple[str, ...]:
        return tuple(sorted(self.declarations))

    def unknown(self, name: str) -> None:
        if name not in self.unknowns:
            object.__setattr__(self, "unknowns", tuple(sorted((*self.unknowns, name))))

    def merged(self, overlay: "WorkflowProfile") -> "WorkflowProfile":
        """Additive merge: the overlay fills gaps, it never erases an observed surface."""
        def union(first: Sequence[Any], second: Sequence[Any]) -> tuple[Any, ...]:
            seen: list[Any] = list(first)
            for item in second:
                if item not in seen:
                    seen.append(item)
            return tuple(seen)

        declarations = dict(self.declarations)
        sources = dict(self.declared_sources)
        for key, value in overlay.declarations.items():
            if key not in declarations or declarations[key] in (None, "", (), []):
                declarations[key] = value
                sources[key] = overlay.declared_sources.get(key, overlay.source)
        return WorkflowProfile(
            workflow_id=self.workflow_id or overlay.workflow_id, name=self.name or overlay.name,
            platform=overlay.platform if self.platform == "unknown" else self.platform,
            version=self.version or overlay.version, environment=self.environment or overlay.environment,
            entrypoints=union(self.entrypoints, overlay.entrypoints),
            trigger_kinds=union(self.trigger_kinds, overlay.trigger_kinds),
            node_kinds=union(self.node_kinds, overlay.node_kinds), routers=union(self.routers, overlay.routers),
            batch_or_pagination=union(self.batch_or_pagination, overlay.batch_or_pagination),
            code_nodes=union(self.code_nodes, overlay.code_nodes), effects=union(self.effects, overlay.effects),
            state_surfaces=union(self.state_surfaces, overlay.state_surfaces),
            lookup_operations=union(self.lookup_operations, overlay.lookup_operations),
            dependencies=union(self.dependencies, overlay.dependencies),
            credential_references=union(self.credential_references, overlay.credential_references),
            downstream_systems=union(self.downstream_systems, overlay.downstream_systems),
            ai_surfaces=union(self.ai_surfaces, overlay.ai_surfaces),
            ai_tools=union(self.ai_tools, overlay.ai_tools),
            retrieval_surfaces=union(self.retrieval_surfaces, overlay.retrieval_surfaces),
            untrusted_content_sources=union(self.untrusted_content_sources, overlay.untrusted_content_sources),
            human_approval_gates=union(self.human_approval_gates, overlay.human_approval_gates),
            error_workflows=union(self.error_workflows, overlay.error_workflows),
            declarations=declarations, declared_sources=sources,
            unknowns=union(self.unknowns, overlay.unknowns),
            source=f"{self.source}+{overlay.source}" if self.source and overlay.source else self.source or overlay.source,
            raw={**dict(self.raw), **dict(overlay.raw)},
        )

    def as_record(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id, "name": self.name, "platform": self.platform,
            "version": self.version, "environment": self.environment,
            "entrypoints": list(self.entrypoints),
            "trigger_kinds": [str(item) for item in self.trigger_kinds],
            "node_kinds": list(self.node_kinds), "routers": list(self.routers),
            "batch_or_pagination": list(self.batch_or_pagination), "code_nodes": list(self.code_nodes),
            "self_trigger_surface": list(self.self_trigger_surface),
            "effects": [item.as_record() for item in self.effects], "state_surfaces": list(self.state_surfaces),
            "lookup_operations": list(self.lookup_operations),
            "dependencies": [item.as_record() for item in self.dependencies],
            "credential_references": list(self.credential_references),
            "downstream_systems": list(self.downstream_systems),
            "ai_surfaces": list(self.ai_surfaces), "ai_tools": list(self.ai_tools),
            "retrieval_surfaces": list(self.retrieval_surfaces),
            "untrusted_content_sources": list(self.untrusted_content_sources),
            "human_approval_gates": list(self.human_approval_gates),
            "error_workflows": list(self.error_workflows),
            "declarations": {key: (value if isinstance(value, (str, int, float, bool, type(None))) else str(value))
                             for key, value in sorted(self.declarations.items())},
            "declared_sources": dict(sorted(self.declared_sources.items())),
            "unknowns": list(self.unknowns), "source": self.source,
            "raw_summary": {key: self.raw[key] for key in ("definition_integrity", "subject_id", "recorded_tag",
                                                           "contract_path", "node_count") if key in self.raw},
        }


def classify_node_type(node_type: str) -> dict[str, Any]:
    """Map one n8n node type to the surfaces it implies. Unknown types change nothing."""
    lowered = (node_type or "").lower()
    surfaces: dict[str, Any] = {}
    for needle, rules in N8N_NODE_RULES:
        if needle.lower() in lowered:
            for key, value in rules.items():
                surfaces.setdefault(key, value)
    return surfaces


def data_table_reference(node: Mapping[str, Any]) -> str:
    """The Data Table a node points at: its cached name where the export carries one, else its id."""
    parameters = node.get("parameters") if isinstance(node.get("parameters"), Mapping) else {}
    reference = parameters.get("dataTableId")
    if isinstance(reference, Mapping):
        return str(reference.get("cachedResultName") or reference.get("value") or "").strip()
    return str(reference or "").strip()


def data_table_writes(node: Mapping[str, Any]) -> bool:
    """Whether a Data Table node changes stored rows, rather than only reading them."""
    parameters = node.get("parameters") if isinstance(node.get("parameters"), Mapping) else {}
    return str(parameters.get("operation") or "").strip().lower() in DATA_TABLE_WRITE_OPERATIONS


def profile_from_n8n_workflow(workflow: Mapping[str, Any], *, source: str = "",
                              declared: Mapping[str, Any] | None = None) -> WorkflowProfile:
    """Read an n8n workflow export into a profile.

    This is structure only: it can see which systems a node talks to and whether an AI node exists, but it
    cannot see whether a destination is readable afterwards. Those stay declared facts.
    """
    nodes = [dict(item) for item in (workflow.get("nodes") or []) if isinstance(item, Mapping)]
    trigger_kinds: list[TriggerKind] = []
    routers: list[str] = []
    batch: list[str] = []
    code_nodes: list[str] = []
    effects: list[EffectDeclaration] = []
    dependencies: list[DependencyDeclaration] = []
    credentials: list[str] = []
    systems: list[str] = []
    state_surfaces: list[str] = []
    ai_surfaces: list[str] = []
    tools: list[str] = []
    retrieval: list[str] = []
    approval: list[str] = []
    errors: list[str] = []
    entrypoints: list[str] = []
    intake_nodes: list[str] = []
    node_kinds: list[str] = []
    for node in nodes:
        node_type = str(node.get("type", ""))
        name = str(node.get("name", node.get("id", "")))
        node_kinds.append(node_type)
        surfaces = classify_node_type(node_type)
        if "trigger" in surfaces and surfaces["trigger"] not in trigger_kinds:
            trigger_kinds.append(surfaces["trigger"])
        if surfaces.get("trigger") in {TriggerKind.WEBHOOK, TriggerKind.HTTP, TriggerKind.SCHEDULE}:
            entrypoints.append(name)
        if surfaces.get("trigger") in {TriggerKind.WEBHOOK, TriggerKind.HTTP}:
            # an external intake (a webhook or a form): a caller-supplied payload enters here
            intake_nodes.append(name)
        if surfaces.get("router"):
            routers.append(name)
        if surfaces.get("batch") or surfaces.get("pagination"):
            batch.append(name)
        if surfaces.get("code"):
            code_nodes.append(name)
        if surfaces.get("ai"):
            ai_surfaces.append(name)
        if surfaces.get("tools"):
            tools.append(name)
        if surfaces.get("retrieval"):
            retrieval.append(name)
        if surfaces.get("errorWorkflow"):
            errors.append(name)
        if surfaces.get("dataStore"):
            table = data_table_reference(node) or name
            if table not in state_surfaces:
                state_surfaces.append(table)
            if data_table_writes(node):
                effects.append(EffectDeclaration(kind=EffectKind.PERSISTENCE, system=node_type,
                                                 destination=table, source=f"node:{name}"))
        if surfaces.get("dependency"):
            dependencies.append(DependencyDeclaration(system=node_type, source=f"node:{name}"))
            systems.append(node_type)
        if surfaces.get("notification"):
            effects.append(EffectDeclaration(kind=EffectKind.NOTIFICATION, system=node_type,
                                             destination=name, source=f"node:{name}"))
        elif surfaces.get("payment"):
            effects.append(EffectDeclaration(kind=EffectKind.PAYMENT, system=node_type, destination=name,
                                             source=f"node:{name}"))
        elif surfaces.get("externalWrite"):
            effects.append(EffectDeclaration(kind=EffectKind.EXTERNAL_WRITE, system=node_type, destination=name,
                                             source=f"node:{name}"))
        elif surfaces.get("persistence"):
            effects.append(EffectDeclaration(kind=EffectKind.PERSISTENCE, system=node_type, destination=name,
                                             source=f"node:{name}"))
        elif surfaces.get("calendar"):
            effects.append(EffectDeclaration(kind=EffectKind.CALENDAR, system=node_type, destination=name,
                                             source=f"node:{name}"))
        node_credentials = node.get("credentials") or {}
        if isinstance(node_credentials, Mapping):
            credentials.extend(f"{name}:{key}" for key in node_credentials)
    # self-trigger surface: TRUE only when a real graph edge targets a trigger node. A missing or
    # malformed connections block is recorded as an unknown, never as "no self-trigger surface".
    self_trigger: list[str] = []
    extra_unknowns: list[str] = []
    connections = workflow.get("connections")
    trigger_names = {str(n.get("name", n.get("id", ""))) for n in nodes
                     if "trigger" in classify_node_type(str(n.get("type", "")))}
    if isinstance(connections, Mapping):
        for src, outputs in connections.items():
            if not isinstance(outputs, Mapping):
                extra_unknowns.append("self_trigger_surface:topology_unreadable")
                continue
            for branches in (outputs.get("main") or []):
                if not isinstance(branches, list):
                    extra_unknowns.append("self_trigger_surface:topology_unreadable")
                    continue
                for edge in branches:
                    if isinstance(edge, Mapping) and str(edge.get("node")) in trigger_names:
                        self_trigger.append(str(src))
    else:
        extra_unknowns.append("self_trigger_surface:topology_unreadable")
    environment = None
    if isinstance(workflow.get("meta"), Mapping):
        environment = workflow["meta"].get("environment")
    # Generic AI-surface detection: an AI call implemented as an HTTP Request node (not a native AI node) is
    # invisible to the node-type reader above, so its grounded evidence is read here and the claimed node names
    # are added to the AI surfaces. Unknown/ambiguous calls are recorded as unknowns, never guessed.
    ai_surface = _http_ai_surface_evidence(workflow)
    for surface_name in ai_surface["surfaces"]:
        if surface_name and surface_name not in ai_surfaces:
            ai_surfaces.append(surface_name)
    # Untrusted content reaching the model: a claimed AI surface whose request body references the workflow item
    # is fed data the workflow received. With an external intake (webhook/form) declared in the same graph, that
    # is a structural fact — recorded with its evidence — not an assumption.
    untrusted: list[str] = []
    if intake_nodes and ai_surface["consumes_item_data"]:
        for intake in intake_nodes:
            for ai_node in ai_surface["consumes_item_data"]:
                untrusted.append(f"{intake} -> {ai_node} (item data referenced by the model request)")
    return WorkflowProfile(
        workflow_id=str(workflow.get("id") or workflow.get("workflow_id") or ""),
        name=str(workflow.get("name") or ""), platform="n8n",
        version=str(workflow.get("version") or workflow.get("versionId") or "") or None,
        environment=environment, entrypoints=tuple(entrypoints), trigger_kinds=tuple(trigger_kinds),
        node_kinds=tuple(sorted(set(node_kinds))), routers=tuple(routers), batch_or_pagination=tuple(batch),
        code_nodes=tuple(code_nodes), effects=tuple(effects),
        state_surfaces=tuple(state_surfaces),
        lookup_operations=tuple(name for name in batch), dependencies=tuple(dependencies),
        credential_references=tuple(credentials), downstream_systems=tuple(sorted(set(systems))),
        ai_surfaces=tuple(ai_surfaces), ai_tools=tuple(tools), retrieval_surfaces=tuple(retrieval),
        untrusted_content_sources=tuple(untrusted),
        human_approval_gates=tuple(approval), error_workflows=tuple(errors),
        declarations=dict(declared or {}),
        self_trigger_surface=tuple(sorted(set(self_trigger))),
        unknowns=tuple(sorted(set(extra_unknowns))),
        declared_sources={key: source for key in (declared or {})},
        source=source or f"n8n-workflow:{workflow.get('id') or workflow.get('name')}",
        raw={"node_count": len(nodes), "ai_surface": ai_surface,
             "derived_facts": _derived_facts(workflow, tuple(ai_surfaces))},
    )


def _derived_facts(workflow: Mapping[str, Any], ai_surfaces: tuple[str, ...]) -> dict[str, Any]:
    """The safely-derivable facts for this graph, each with its evidence source.

    Deferred import: the derived-facts reader imports :func:`classify_node_type` from this module, so it must be
    loaded after this module is defined.
    """
    from breaker.readiness.derived_facts import derived_facts_record

    return derived_facts_record(workflow, ai_surfaces=ai_surfaces)


def _http_ai_surface_evidence(workflow: Mapping[str, Any]) -> dict[str, Any]:
    """The HTTP-Request AI-surface evidence for a workflow, as a record the profile can carry.

    Deferred import so the profile module stays importable without the detector (and so there is no cycle: the
    detector imports nothing from this module).
    """
    from breaker.readiness.ai_surfaces import classify_http_surfaces

    return classify_http_surfaces(workflow)


def profile_from_declaration(declared: Mapping[str, Any], *, source: str, workflow_id: str = "",
                             name: str = "", platform: str = "declared") -> WorkflowProfile:
    """Build a profile from an explicit declaration: the only way to state facts a graph cannot show."""
    if not source:
        raise ValueError("a declared profile must name its source")
    return WorkflowProfile(workflow_id=workflow_id, name=name, platform=platform,
                           declarations=dict(declared), declared_sources={key: source for key in declared},
                           source=source)


def profile_from_ir(ir: Any, *, source: str = "workflow_ir", declared: Mapping[str, Any] | None = None,
                    raw_workflow: Mapping[str, Any] | None = None) -> WorkflowProfile:
    """Read Breaker's own :class:`~breaker.workflow_ir.WorkflowIR` into a profile."""
    nodes = tuple(getattr(ir, "nodes", ()) or ())
    node_kinds: list[str] = []
    trigger_kinds: list[TriggerKind] = []
    routers: list[str] = []
    effects: list[EffectDeclaration] = []
    systems: list[str] = []
    ai_surfaces: list[str] = []
    tools: list[str] = []
    retrieval: list[str] = []
    credentials: list[str] = []
    code_nodes: list[str] = []
    for node in nodes:
        kind = str(getattr(node, "kind", ""))
        node_kinds.append(kind)
        surfaces = classify_node_type(kind)
        if surfaces.get("trigger") and surfaces["trigger"] not in trigger_kinds:
            trigger_kinds.append(surfaces["trigger"])
        if surfaces.get("router"):
            routers.append(str(getattr(node, "id", "")))
        if surfaces.get("code"):
            code_nodes.append(str(getattr(node, "id", "")))
        if surfaces.get("ai"):
            ai_surfaces.append(str(getattr(node, "id", "")))
        if surfaces.get("tools"):
            tools.append(str(getattr(node, "id", "")))
        if surfaces.get("retrieval"):
            retrieval.append(str(getattr(node, "id", "")))
        if surfaces.get("dependency"):
            systems.append(kind)
        if getattr(node, "credential_reference_present", False):
            credentials.append(str(getattr(node, "id", "")))
    for effect in tuple(getattr(ir, "effects", ()) or ()):
        kind = str(effect.get("kind", effect.get("type", "EXTERNAL_WRITE"))).upper()
        mapped = EffectKind.EXTERNAL_WRITE
        for candidate in EffectKind:
            if candidate.value in kind:
                mapped = candidate
                break
        effects.append(EffectDeclaration(kind=mapped, destination=str(effect.get("destination", "")),
                                         system=str(effect.get("system", "")), source=source,
                                         reversible=effect.get("reversible"),
                                         critical=effect.get("critical"),
                                         unique_key_enforced=effect.get("unique_key_enforced"),
                                         multi_field=effect.get("multi_field")))
    state_surfaces = tuple(str(item.get("name", item)) if isinstance(item, Mapping) else str(item)
                           for item in (getattr(ir, "state_surfaces", ()) or ()))
    return WorkflowProfile(
        workflow_id=str(getattr(ir, "workflow_id", "") or ""), name=str(getattr(ir, "name", "") or ""),
        platform=str(getattr(ir, "platform", "unknown")), entrypoints=tuple(getattr(ir, "entrypoints", ()) or ()),
        trigger_kinds=tuple(trigger_kinds), node_kinds=tuple(sorted(set(node_kinds))), routers=tuple(routers),
        code_nodes=tuple(code_nodes), effects=tuple(effects),
        state_surfaces=state_surfaces, dependencies=tuple(DependencyDeclaration(system=item, source=source)
                                                          for item in sorted(set(systems))),
        credential_references=tuple(credentials), downstream_systems=tuple(sorted(set(systems))),
        ai_surfaces=tuple(ai_surfaces), ai_tools=tuple(tools), retrieval_surfaces=tuple(retrieval),
        declarations=dict(declared or {}), declared_sources={key: source for key in (declared or {})},
        unknowns=tuple(getattr(ir, "unknowns", ()) or ()), source=source,
        raw={"raw_workflow": dict(raw_workflow or {})},
    )
