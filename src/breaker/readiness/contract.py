"""The production contract: the criteria source's WORKFLOW CONTRACT criteria record, as a validated object.

Section 3 of the upgrade brief asks Breaker's target contract to line up with the contract schema
concepts, and section 14 forbids inventing a threshold the contract does not contain: if load.check_wf057 needs a
realistic burst and the contract has no peak volume, the answer is
``NOT_TESTED / REQUIRED_CONTRACT_VALUE_MISSING / missing = volume_capacity.peak_volume`` — not a guess.

So the contract is a *lookup*, not a story. Engines ask it for exact dotted paths and get either a value or a
:class:`ContractGap`. Values are never defaulted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

#: Every labelled concept the contract schema defines, mapped to the field this module reads.
#: Used by tests to prove nothing in the criteria record is silently unmodelled.
CONTRACT_CONCEPTS: dict[str, str] = {
    "Workflow name": "identity.workflow_name",
    "Version": "identity.version",
    "Business owner": "identity.business_owner",
    "Technical owner": "identity.technical_owner",
    "Environment": "identity.environment",
    "Problem being solved": "problem_solved",
    "Intended business outcome": "intended_business_outcome",
    "Trigger": "trigger",
    "Successful end state": "successful_end_state",
    "Manual fallback": "manual_fallback",
    "Inputs": "inputs",
    "Outputs / Side Effects": "outputs",
    "Business Paths": "business_paths",
    "External Dependencies": "dependencies",
    "Business key / deduplication": "business_key_dedup",
    "Must-not-happen rules": "must_not_happen",
    "Volume and capacity": "volume_capacity",
    "Timeout and retry policy": "timeout_retry_policy",
    "Ordering and freshness": "ordering_freshness",
    "Detection and response": "detection_response",
    "Recovery objectives": "recovery_objectives",
    "Data handling": "data_handling",
    "AI evaluation, if used": "ai_evaluation",
    "AI limits, if used": "ai_limits",
    "Fixture / path evidence": "fixture_evidence_location",
    "Release / runbook location": "release_runbook_location",
}

#: Fields whose absence stops a check rather than triggering a fallback. Named here so the gap reason is
#: always the same string regardless of which engine asked.
GAP_REASON = "REQUIRED_CONTRACT_VALUE_MISSING"

_MISSING = object()


class ContractError(ValueError):
    """The contract is structurally wrong (as opposed to incomplete)."""


class ContractGap(LookupError):
    """A required contract value is absent. Carries the exact path so the gap report can name it."""

    def __init__(self, path: str, *, check_id: str | None = None, scope: str | None = None) -> None:
        self.path = path
        self.check_id = check_id
        self.scope = scope
        super().__init__(f"REQUIRED_CONTRACT_VALUE_MISSING: {path}")

    @property
    def fact(self) -> str:
        return self.path

    def as_record(self) -> dict[str, Any]:
        record = {"reason_code": GAP_REASON, "missing": self.path}
        if self.check_id:
            record["check_id"] = self.check_id
        if self.scope:
            record["scope"] = self.scope
        return record


@dataclass(frozen=True)
class ProductionContract:
    """A contract as declared, plus the paths it is missing.

    ``declared_paths`` is the set of dotted paths that hold a usable value. Everything else is a gap, and the
    engine reports it instead of choosing a number.
    """

    data: Mapping[str, Any] = field(default_factory=dict)
    source: str = ""
    contract_id: str = ""
    contract_version: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None, *, source: str = "", contract_id: str = "",
                     contract_version: str = "") -> "ProductionContract":
        payload = dict(data or {})
        contract = cls(data=payload, source=source,
                       contract_id=str(contract_id or payload.get("contract_id", "")),
                       contract_version=str(contract_version or payload.get("contract_version", "")))
        contract.validate()
        return contract

    def validate(self) -> None:
        for name, value in self.data.items():
            if name in {"identity", "trigger", "business_key_dedup", "volume_capacity",
                        "timeout_retry_policy", "ordering_freshness", "detection_response",
                        "recovery_objectives", "data_handling", "ai_evaluation", "ai_limits",
                        "release_runbook_location"}:
                if value is None or value == "":
                    continue
                if not isinstance(value, Mapping):
                    raise ContractError(f"contract field {name!r} must be an object, not {type(value).__name__}")
        for name in ("inputs", "outputs", "business_paths", "dependencies", "must_not_happen"):
            value = self.data.get(name)
            if value is None or value == "":
                continue
            if not isinstance(value, (list, tuple, Mapping)) and not isinstance(value, str):
                raise ContractError(f"contract field {name!r} must be a list, object or text")

    # -- lookup ---------------------------------------------------------------------------------------
    def raw(self, path: str) -> Any:
        """The raw value at a dotted path, or :data:`_MISSING`."""
        if not path:
            raise ContractError("contract lookup needs a path")
        current: Any = self.data
        for part in path.split("."):
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            elif isinstance(current, (list, tuple)):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return _MISSING
            else:
                return _MISSING
        return current

    def has(self, path: str) -> bool:
        """True only when the path holds a usable value.

        Empty strings, empty collections, ``None`` and the literal ``'N/A'`` are all gaps: the criteria source's
        amber cells are blank, and an unfilled cell must not read as a decision.
        """
        value = self.raw(path)
        if value is _MISSING or value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip()) and value.strip().upper() not in {"N/A", "NA", "TBD", "SAMPLE"}
        if isinstance(value, (Mapping, list, tuple, set)):
            return len(value) > 0
        return True

    def value(self, path: str, *, check_id: str | None = None, scope: str | None = None) -> Any:
        if not self.has(path):
            raise ContractGap(path, check_id=check_id, scope=scope)
        return self.raw(path)

    def optional(self, path: str, default: Any = None) -> Any:
        return self.raw(path) if self.has(path) else default

    def is_production(self) -> bool:
        """True when the contract itself declares a production/live environment.

        A declaration pack scoped to the local/disposable TEST environment supplies test operating bounds; the
        contract-loading path refuses to let one fill a production contract, so a test value never silently
        satisfies a production requirement.
        """
        environment = self.optional("identity.environment", "")
        return str(environment).strip().upper() in {"PRODUCTION", "PROD", "LIVE"}

    def text(self, path: str, *, check_id: str | None = None) -> str:
        return str(self.value(path, check_id=check_id)).strip()

    def entries(self, path: str, *, check_id: str | None = None) -> tuple[Mapping[str, Any], ...]:
        """Rows of a contract table (inputs, outputs, paths, dependencies) as mappings."""
        value = self.value(path, check_id=check_id)
        if isinstance(value, str):
            return ({"text": value},)
        if isinstance(value, Mapping):
            return tuple(dict(value) if isinstance(value, Mapping) else {"value": value} for value in value.values())
        return tuple(dict(item) if isinstance(item, Mapping) else {"value": item} for item in value)

    def require(self, paths: Sequence[str], *, check_id: str, scope: str | None = None) -> dict[str, Any]:
        """Resolve several paths at once, raising the *first* gap with the exact missing path.

        The named gap is what the readiness report shows, so an engine never has to describe a missing value
        in its own words.
        """
        resolved: dict[str, Any] = {}
        for path in paths:
            if not self.has(path):
                raise ContractGap(path, check_id=check_id, scope=scope)
            resolved[path] = self.raw(path)
        return resolved

    def missing(self, paths: Iterable[str]) -> tuple[str, ...]:
        return tuple(path for path in paths if not self.has(path))

    def declared_paths(self) -> tuple[str, ...]:
        """Every dotted path that holds a value, depth-first and sorted."""
        found: list[str] = []

        def walk(prefix: str, value: Any) -> None:
            if isinstance(value, Mapping):
                for key in sorted(value, key=str):
                    walk(f"{prefix}.{key}" if prefix else str(key), value[key])
                return
            if isinstance(value, (list, tuple)):
                if value:
                    found.append(prefix)
                return
            found.append(prefix)

        for key in sorted(self.data, key=str):
            walk(str(key), self.data[key])
        return tuple(sorted({path for path in found if self.has(path)}))

    def sub_contract(self, prefix: str, *, check_id: str) -> "ProductionContract":
        """A view rooted at ``prefix`` — for engines that only read one contract section."""
        value = self.raw(prefix)
        if value is _MISSING:
            raise ContractGap(prefix, check_id=check_id)
        if isinstance(value, Mapping):
            return ProductionContract(data=dict(value), source=self.source, contract_id=self.contract_id,
                                      contract_version=self.contract_version)
        raise ContractError(f"contract field {prefix!r} is not an object")

    def as_record(self) -> dict[str, Any]:
        return {"contract_id": self.contract_id, "contract_version": self.contract_version,
                "source": self.source, "declared_paths": list(self.declared_paths())}


#: Sub-paths each readiness engine may need. Kept together so the gap report and the tests agree on names.
REQUIRED_PATHS: dict[str, tuple[str, ...]] = {
    "dedup_retention": ("business_key_dedup.retention",),
    "dedup_key": ("business_key_dedup.event_id", "business_key_dedup.business_object_key"),
    "uniqueness_scope": ("business_key_dedup.uniqueness_scope",),
    "normal_volume": ("volume_capacity.normal_volume",),
    "peak_volume": ("volume_capacity.peak_volume",),
    "burst_shape": ("volume_capacity.burst_shape",),
    "backlog_limit": ("volume_capacity.backlog_limit",),
    "batch_size": ("volume_capacity.batch_size",),
    "retry_attempts": ("timeout_retry_policy.retry_attempts",),
    "retryable_faults": ("timeout_retry_policy.retryable_faults",),
    "unknown_write": ("timeout_retry_policy.unknown_write_handling",),
    "freshness_window": ("ordering_freshness.latest_useful_arrival",),
    "version_rule": ("ordering_freshness.version_rule",),
    "run_window": ("detection_response.run_window",),
    "volume_threshold": ("detection_response.volume_threshold",),
    "escalation_time": ("detection_response.escalation_time",),
    "alert_destination": ("detection_response.alert_destination",),
    "heartbeat": ("detection_response.heartbeat_expectation",),
    "correlation_id": ("detection_response.correlation_id",),
    "recovery_time": ("recovery_objectives.recovery_time",),
    "allowed_data_loss": ("recovery_objectives.allowed_data_loss",),
    "retention": ("data_handling.retention",),
    "allowed_destinations": ("data_handling.allowed_destinations",),
    "sensitive_fields": ("data_handling.sensitive_fields",),
    "ai_rubric": ("ai_evaluation.correctness_rubric",),
    "ai_labeled_set": ("ai_evaluation.labeled_fixtures",),
    "ai_repetitions": ("ai_evaluation.repeated_run_sample",),
    "ai_approval_criteria": ("ai_evaluation.approval_criteria",),
    "ai_versions": ("ai_limits.model_versions",),
    "ai_cost_budget": ("ai_limits.cost_budget",),
    "ai_step_budget": ("ai_limits.step_budget",),
    "ai_allowed_tools": ("ai_limits.allowed_tools",),
    "ai_fallback_model": ("ai_limits.fallback_model",),
    "trigger_kind": ("trigger.kind",),
    "trigger_source": ("trigger.source",),
    "trigger_timezone": ("trigger.timezone",),
    "trigger_event_id": ("trigger.event_identifier",),
    "environment": ("identity.environment",),
    "version": ("identity.version",),
    "release_runbook": ("release_runbook_location",),
}
