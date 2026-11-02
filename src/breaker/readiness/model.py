"""Breaker v2 check model.

One criterion from a criteria pack becomes one :class:`CheckSpec`. One run of the readiness engine produces one
:class:`CheckOutcome` per applicable spec. The model's job is to make the dishonest states
*unrepresentable* rather than merely discouraged:

* a PASS needs evidence, and the evidence has to be the kind the check's execution class can produce;
* a check that can only be inspected statically can never report a dynamic PASS;
* ``FAIL`` means a real product defect (``PRODUCT_FAIL``) — a harness or provider problem is reported as
  ``NOT_TESTED`` carrying that classification, never as a product failure;
* ``N/A`` and ``NOT_TESTED`` must carry a reason from a closed set, so "we did not run it" always says why.

Because these rules live in constructors and ``__post_init__`` validation, an engine cannot quietly produce a
PASS it did not earn: building the object raises.
"""
from __future__ import annotations

import hashlib
import json

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence

from breaker.verification.taxonomy import (
    BLOCKING_VERDICTS,
    VERDICT_DEFINITIONS,
    Verdict,
    counts_as_dynamic_proof,
)

REGISTRY_SCHEMA_VERSION = "2.0.0"
WORKFLOW_CHECK_COUNT = 83
AI_CHECK_COUNT = 18
TOTAL_CHECK_COUNT = 101


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


class CheckStatus(StrEnum):
    """The criterion source's vocabulary. Kept separate from Breaker's failure classification."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_TESTED = "NOT_TESTED"
    NA = "N/A"


class EvidenceClass(StrEnum):
    """How a check was actually satisfied (section 21 splits its counts this way)."""

    DYNAMIC = "DYNAMIC"
    STATIC = "STATIC"
    CONTROLLED_ENVIRONMENT = "CONTROLLED_ENVIRONMENT"
    EVIDENCE_ONLY = "EVIDENCE_ONLY"


class OriginKind(StrEnum):
    """How an evidence record came to exist — the fact a provenance claim may never exceed.

    The distinction that matters is whether the observation was *produced by something that ran the
    subject* (``LIVE_RUN``), produced against a stand-in for the subject (``SYNTHETIC_RUN``), read out of a
    stored artifact (``STATIC_READING``), or invented from repository metadata (``REPOSITORY_DERIVATION``).
    A record's provenance is **derived** from this, never chosen freely, so a claim can never be stronger
    than the thing that produced it.
    """

    LIVE_RUN = "LIVE_RUN"
    CONTROLLED_RUN = "CONTROLLED_RUN"
    FAULT_INJECTION_RUN = "FAULT_INJECTION_RUN"
    LOAD_RUN = "LOAD_RUN"
    SYNTHETIC_RUN = "SYNTHETIC_RUN"
    OPERATOR_RECORD = "OPERATOR_RECORD"
    RECORDED_ARTIFACT = "RECORDED_ARTIFACT"
    STATIC_READING = "STATIC_READING"
    REPOSITORY_DERIVATION = "REPOSITORY_DERIVATION"


class EvidenceProvenance(StrEnum):
    """The closed vocabulary of provenance types an evidence claim may carry.

    This is a *model* vocabulary on purpose: every booked verdict that can make a checklist row pass names
    exactly one of these, and an unknown value is a bug rather than a new category. The set is closed so no
    engine, campaign or operator record can invent a stronger-sounding type ad hoc.
    """

    LIVE_EXECUTION = "LIVE_EXECUTION"
    PROVIDER_READBACK = "PROVIDER_READBACK"
    DATABASE_READBACK = "DATABASE_READBACK"
    FILESYSTEM_READBACK = "FILESYSTEM_READBACK"
    FAULT_INJECTION = "FAULT_INJECTION"
    LOAD_OBSERVATION = "LOAD_OBSERVATION"
    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"
    OPERATOR_EVIDENCE = "OPERATOR_EVIDENCE"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DERIVED_METADATA = "DERIVED_METADATA"


#: What each origin kind can support at most. A claim stronger than its origin's ceiling is refused by
#: :mod:`breaker.readiness.provenance` — e.g. a campaign run against a pinned test double can never be a
#: ``PROVIDER_READBACK``, and a record synthesised from a repository file can only ever be
#: ``DERIVED_METADATA``.
ORIGIN_PROVENANCE_CEILING: Mapping[OriginKind, EvidenceProvenance] = {
    OriginKind.LIVE_RUN: EvidenceProvenance.LIVE_EXECUTION,
    OriginKind.CONTROLLED_RUN: EvidenceProvenance.LIVE_EXECUTION,
    OriginKind.FAULT_INJECTION_RUN: EvidenceProvenance.FAULT_INJECTION,
    OriginKind.LOAD_RUN: EvidenceProvenance.LOAD_OBSERVATION,
    OriginKind.SYNTHETIC_RUN: EvidenceProvenance.SYNTHETIC_FIXTURE,
    OriginKind.OPERATOR_RECORD: EvidenceProvenance.OPERATOR_EVIDENCE,
    OriginKind.RECORDED_ARTIFACT: EvidenceProvenance.OPERATOR_EVIDENCE,
    OriginKind.STATIC_READING: EvidenceProvenance.STATIC_ANALYSIS,
    OriginKind.REPOSITORY_DERIVATION: EvidenceProvenance.DERIVED_METADATA,
}

#: Read-back provenance is *about what was read*, not about how the run happened, so it is ordered alongside
#: the execution types rather than under one of them. These are the types that can only be claimed when the
#: record's read-back actually came from that surface (see
#: :func:`breaker.readiness.provenance.readback_surfaces`).
READBACK_PROVENANCE: frozenset[EvidenceProvenance] = frozenset({
    EvidenceProvenance.PROVIDER_READBACK,
    EvidenceProvenance.DATABASE_READBACK,
    EvidenceProvenance.FILESYSTEM_READBACK,
})

#: Ordered weakest -> strongest for the "cannot claim more than its origin" rule. Read-back types sit above a
#: bare execution because they assert an *independent* read of external state, and above synthetic or derived
#: origins by a wide margin.
PROVENANCE_STRENGTH: Mapping[EvidenceProvenance, int] = {
    EvidenceProvenance.DERIVED_METADATA: 0,
    EvidenceProvenance.OPERATOR_EVIDENCE: 1,
    EvidenceProvenance.STATIC_ANALYSIS: 2,
    EvidenceProvenance.SYNTHETIC_FIXTURE: 3,
    EvidenceProvenance.LOAD_OBSERVATION: 4,
    EvidenceProvenance.FAULT_INJECTION: 4,
    EvidenceProvenance.LIVE_EXECUTION: 4,
    EvidenceProvenance.FILESYSTEM_READBACK: 5,
    EvidenceProvenance.DATABASE_READBACK: 5,
    EvidenceProvenance.PROVIDER_READBACK: 5,
}

#: The default sufficiency rule: a check passes from any provenance except a repository derivation or a run
#: against a stand-in. Individual checks narrow this (see
#: :data:`breaker.readiness.provenance.SUFFICIENT_PROVENANCE_BY_CHECK`).
DEFAULT_SUFFICIENT_PROVENANCE: tuple[EvidenceProvenance, ...] = tuple(
    item for item in EvidenceProvenance
    if item not in {EvidenceProvenance.DERIVED_METADATA, EvidenceProvenance.SYNTHETIC_FIXTURE})

#: Provenance types that can never on their own carry a PASS, whatever a check declares.
NEVER_SUFFICIENT_FOR_PASS: frozenset[EvidenceProvenance] = frozenset({
    EvidenceProvenance.DERIVED_METADATA, EvidenceProvenance.SYNTHETIC_FIXTURE})


class ExecutionClass(StrEnum):
    """How a check *can* be executed. An implementation concept, not a status."""

    DYNAMIC_FIXTURE = "DYNAMIC_FIXTURE"
    STATIC_SCAN = "STATIC_SCAN"
    FAULT_INJECTION = "FAULT_INJECTION"
    CONCURRENCY = "CONCURRENCY"
    TRIGGER_SIMULATION = "TRIGGER_SIMULATION"
    RECOVERY_CAMPAIGN = "RECOVERY_CAMPAIGN"
    OBSERVABILITY_CAMPAIGN = "OBSERVABILITY_CAMPAIGN"
    LOAD_CAMPAIGN = "LOAD_CAMPAIGN"
    SECURITY_TEST = "SECURITY_TEST"
    DEPLOYMENT_CHECK = "DEPLOYMENT_CHECK"
    BACKUP_RESTORE_TEST = "BACKUP_RESTORE_TEST"
    AI_EVALUATION = "AI_EVALUATION"
    CONTROLLED_ENV_REQUIRED = "CONTROLLED_ENV_REQUIRED"
    EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"

    @property
    def dynamic_capable(self) -> bool:
        """False for classes that can never produce a dynamic PASS on their own terms."""
        return self not in {ExecutionClass.CONTROLLED_ENV_REQUIRED, ExecutionClass.EVIDENCE_REQUIRED,
                            ExecutionClass.STATIC_SCAN}


#: Classes whose evidence is a reading rather than an execution.
STATIC_EVIDENCE_CLASSES = frozenset({EvidenceClass.STATIC, EvidenceClass.EVIDENCE_ONLY})
DYNAMIC_EVIDENCE_CLASSES = frozenset({EvidenceClass.DYNAMIC, EvidenceClass.CONTROLLED_ENVIRONMENT})

# Reason codes are closed sets. An unknown code is a bug, not a free-text excuse.
NA_REASON_CODES = frozenset({
    "WORKFLOW_HAS_NO_AI_COMPONENT",
    "WORKFLOW_HAS_NO_WEBHOOK_TRIGGER",
    "WORKFLOW_HAS_NO_SCHEDULE_TRIGGER",
    "WORKFLOW_HAS_NO_HTTP_TRIGGER",
    "WORKFLOW_HAS_NO_EXTERNAL_DEPENDENCY",
    "WORKFLOW_HAS_NO_PERSISTENCE_SURFACE",
    "WORKFLOW_HAS_NO_NOTIFICATION_EFFECT",
    "WORKFLOW_HAS_NO_DOWNSTREAM_SYSTEM",
    "WORKFLOW_HAS_NO_BATCH_OR_PAGINATION_PATH",
    "WORKFLOW_HAS_NO_LONG_RUNNING_PATH",
    "WORKFLOW_HAS_NO_LOAD_SURFACE",
    "WORKFLOW_HAS_NO_DEPLOYMENT_SURFACE",
    "WORKFLOW_HAS_NO_BACKUP_SURFACE",
    "WORKFLOW_HAS_NO_CONFIGURABLE_STATE",
    "WORKFLOW_HAS_NO_TOOL_USE",
    "WORKFLOW_HAS_NO_RETRIEVAL_SURFACE",
    "WORKFLOW_HAS_NO_MULTI_TENANT_RETRIEVAL_INDEX",
    "WORKFLOW_HAS_NO_HUMAN_APPROVAL_GATE",
    "WORKFLOW_HAS_NO_EXTERNAL_IDENTIFIER",
    "WORKFLOW_HAS_NO_DESTINATION_LOOKUP",
    "WORKFLOW_HAS_NO_LOGGING_SURFACE",
    "WORKFLOW_HAS_NO_HEARTBEAT_EXPECTATION",
    "WORKFLOW_HAS_NO_VOLUME_EXPECTATION",
    "WORKFLOW_HAS_NO_ALERT_SINK",
    "WORKFLOW_HAS_NO_MULTI_SYSTEM_TRACE",
    "WORKFLOW_HAS_NO_KILL_SWITCH",
    "WORKFLOW_HAS_NO_ROLLBACK_PATH",
    "CHECK_IS_OUT_OF_WORKFLOW_TOPOLOGY_SCOPE",
    "CONTRACT_DECLARES_CHECK_NOT_APPLICABLE",
    "SUBCASE_SUPERSEDED_BY_ANOTHER_CHECK",
})

NOT_TESTED_REASON_CODES = frozenset({
    "REQUIRED_CONTRACT_VALUE_MISSING",
    "WORKFLOW_PROFILE_INCOMPLETE",
    "NO_EVIDENCE_RECORDED",
    "EVIDENCE_COVERS_ONLY_PART_OF_THE_CHECK",
    "CONTROLLED_ENVIRONMENT_REQUIRED",
    "CONTROLLED_PRODUCTION_TEST_REQUIRED",
    "EVIDENCE_REQUIRED_NOT_SUPPLIED",
    "OPERATOR_EVIDENCE_REQUIRED",
    "HARNESS_CAPABILITY_MISSING",
    "SAFETY_LIMIT_BLOCKS_EXECUTION",
    # A run-scoped permit is in force for this check and the call after the one it authorized was refused.
    # The bound the scenario named was reached; the call was reported, not silently dropped.
    "RUN_SCOPED_AI_PERMIT_EXHAUSTED",
    # A run-scoped load/concurrency permit is in force for this check and a probe asked for more concurrency
    # than the permit authorizes. The bound the contract named was exceeded; the probe was refused, not trimmed.
    "RUN_SCOPED_LOAD_PERMIT_EXHAUSTED",
    "DEPENDENCY_CANNOT_BE_FAULTED",
    "PROPOSED_TEST_NEEDS_ORACLE",
    "NO_SUBJECT_TO_TEST",
    "NO_APPLICABLE_SUBCASE",
    # -- Evidence Claim Integrity (capability C2). A booked verdict that cannot honestly carry a PASS lands
    # on one of these instead, so the reason is always machine-readable and never free text.
    "CLAIM_BINDING_INCOMPLETE",
    "CLAIM_BINDING_MISMATCH",
    "CLAIM_SUBCASE_SCOPE_UNDECLARED",
    "CLAIM_EVIDENCE_PROVENANCE_INSUFFICIENT",
    "CLAIM_EXPECTED_USED_AS_OBSERVED",
    "CLAIM_RESTORATION_NOT_OBSERVED",
    "CLAIM_PROVENANCE_INFLATED",
    "CLAIM_SUPERSEDED_BY_CORRECTION_REGISTRY",
    "DECLARATION_REQUIRED",
    # -- Operator evidence (the owner-evidence controls a pack marks ``owner_evidence``). A control whose
    # evidence is the owner's/operator's is refused with the exact requirement that was not met, never booked as
    # a PASS for a record that is absent, malformed, stale, bound to another candidate or a recorded rejection.
    "OPERATOR_EVIDENCE_SCHEMA_INVALID",
    "OPERATOR_EVIDENCE_STALE",
    "OPERATOR_EVIDENCE_MISBOUND",
    "OPERATOR_EVIDENCE_REJECTED",
    "OPERATOR_EVIDENCE_PENDING",
})


class CheckModelError(ValueError):
    """Raised when a check outcome would misstate what was actually proven."""


@dataclass(frozen=True)
class EvidenceContract:
    """What a PASS for this check has to be able to point at.

    ``allowed_evidence_classes`` is the honesty gate: a check allowed only ``DYNAMIC`` evidence cannot be
    passed by reading a file, no matter who read it.
    """

    allowed_evidence_classes: tuple[EvidenceClass, ...]
    required_fields: tuple[str, ...] = ()
    environment: str = "LOCAL"
    description: str = ""

    def __post_init__(self) -> None:
        if not self.allowed_evidence_classes:
            raise CheckModelError("an evidence contract must allow at least one evidence class")
        for item in self.allowed_evidence_classes:
            EvidenceClass(item)

    @property
    def static_capable(self) -> bool:
        return any(item in STATIC_EVIDENCE_CLASSES for item in self.allowed_evidence_classes)

    @property
    def dynamic_capable(self) -> bool:
        return any(item in DYNAMIC_EVIDENCE_CLASSES for item in self.allowed_evidence_classes)

    def as_record(self) -> dict[str, Any]:
        return {
            "allowed_evidence_classes": [str(item) for item in self.allowed_evidence_classes],
            "required_fields": list(self.required_fields),
            "environment": self.environment,
            "description": self.description,
        }


@dataclass(frozen=True)
class CheckSpec:
    """One checklist row, plus the authored execution metadata that turns it into a capability."""

    id: str
    category: str
    title: str
    why_it_matters: str
    how_to_test: str
    expected_result: str
    severity: Severity
    execution_class: ExecutionClass
    engine: str
    evidence_contract: EvidenceContract
    prerequisites: tuple[str, ...] = ()
    applicability_rules: tuple[str, ...] = ()
    required_contract_fields: tuple[str, ...] = ()
    safe_environments: tuple[str, ...] = ("LOCAL",)
    dependencies: tuple[str, ...] = ()
    source: Mapping[str, Any] = field(default_factory=dict)
    #: The provenance types a PASS for this row may rest on. Every check declares this explicitly (the
    #: registry fills it from :mod:`breaker.readiness.provenance`), because "which evidence is good enough" is a
    #: property of the criterion requirement, not a per-campaign decision. A row whose verdict cites only
    #: provenance outside this tuple cannot be PASS.
    sufficient_provenance: tuple[EvidenceProvenance, ...] = DEFAULT_SUFFICIENT_PROVENANCE
    #: The engine capability that executes this criterion (see :mod:`breaker.readiness.capabilities`). A criterion
    #: id belongs to the criteria pack; a capability name belongs to the engine, so a pack can be renamed or
    #: re-namespaced without touching an implementation, and the engine never needs to know a criterion id.
    capability: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise CheckModelError("a check needs an id")
        if self.engine and not self.capability:
            # The engine names what it can execute; a criterion that names an engine but no capability has no
            # implementation to reach, so it fails here rather than producing a silent miss later.
            raise CheckModelError(
                f"{self.id}: names engine {self.engine!r} but declares no capability "
                f"(see src/readiness/capabilities.py)")
        if self.severity not in tuple(Severity):
            raise CheckModelError(f"{self.id}: unknown severity {self.severity!r}")
        if not self.safe_environments:
            raise CheckModelError(f"{self.id}: a check must declare at least one safe environment")
        if not self.sufficient_provenance:
            raise CheckModelError(f"{self.id}: a check must declare which provenance types can carry a PASS")
        for item in self.sufficient_provenance:
            EvidenceProvenance(item)
        if len(set(self.sufficient_provenance)) != len(self.sufficient_provenance):
            raise CheckModelError(f"{self.id}: duplicate provenance types in sufficient_provenance")
        if NEVER_SUFFICIENT_FOR_PASS.issubset(set(self.sufficient_provenance)):
            # The default already excludes them; a check may never re-admit both as its whole basis.
            raise CheckModelError(
                f"{self.id}: {sorted(str(item) for item in NEVER_SUFFICIENT_FOR_PASS)} can never carry a PASS")

    def provenance_is_sufficient(self, provenance: EvidenceProvenance) -> bool:
        """True when a PASS may rest on ``provenance`` for this check."""
        if provenance in NEVER_SUFFICIENT_FOR_PASS and provenance not in self.sufficient_provenance:
            return False
        return provenance in self.sufficient_provenance

    @property
    def prefix(self) -> str:
        """The id's namespace: the text before a trailing numeric segment, else the whole id.

        A criteria pack owns its ids, so the shape is the pack's business: ``business.wf_001`` has the namespace
        ``WF``, ``SYN-W-001`` has ``SYN-W``, and ``acme.retention`` has no numeric segment and is its own
        namespace. Nothing in the engine's behaviour depends on the shape — only stable ordering does.
        """
        head, separator, tail = self.id.rpartition("-")
        return head if separator and head and tail.isdigit() else self.id

    @property
    def number(self) -> int:
        """The id's numeric segment when it has one, else 0 (ordering only, never semantics)."""
        _head, separator, tail = self.id.rpartition("-")
        return int(tail) if separator and tail.isdigit() else 0

    @property
    def static_capable(self) -> bool:
        return self.evidence_contract.static_capable

    def as_record(self) -> dict[str, Any]:
        return {
            "id": self.id, "category": self.category, "title": self.title,
            "why_it_matters": self.why_it_matters, "how_to_test": self.how_to_test,
            "expected_result": self.expected_result, "severity": str(self.severity),
            "execution_class": str(self.execution_class), "engine": self.engine,
            "prerequisites": list(self.prerequisites),
            "applicability_rules": list(self.applicability_rules),
            "required_contract_fields": list(self.required_contract_fields),
            "evidence_contract": self.evidence_contract.as_record(),
            "safe_environments": list(self.safe_environments),
            "dependencies": list(self.dependencies),
            "sufficient_provenance": [str(item) for item in self.sufficient_provenance],
            "source": dict(self.source),
        }


@dataclass(frozen=True)
class SubcaseResult:
    """One independently observed subcase of a check row.

    Rows such as business.wf_002 explicitly require every branch to be exercised: this is how "all subcases pass" is
    enforced instead of assumed.
    """

    subcase_id: str
    status: CheckStatus
    classification: Verdict | None = None
    reason_code: str | None = None
    detail: str = ""
    evidence_ids: tuple[str, ...] = ()
    applicable: bool = True
    #: How this subcase's evidence declared its own coverage, set by
    #: :func:`breaker.readiness.engines.base.from_evidence` and read by the claim layer:
    #: ``EXPLICIT_SET`` (the record names the subcases it covers), ``SUBCASE`` (the record was recorded
    #: against exactly this subcase), ``CHECK`` (the engine explicitly declared the record answers the whole
    #: check) or ``UNDECLARED``. See :data:`breaker.readiness.claim.SCOPE_MODES`.
    scope_mode: str = ""

    def __post_init__(self) -> None:
        if not self.subcase_id:
            raise CheckModelError("a subcase needs an id")
        if self.status == CheckStatus.PASS:
            if self.classification not in (Verdict.PASS, Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED):
                raise CheckModelError(f"{self.subcase_id}: a PASS needs a PASS classification, not {self.classification}")
        elif self.classification == Verdict.PASS:
            raise CheckModelError(f"{self.subcase_id}: classification PASS requires status PASS")
        if (not self.applicable) and self.status != CheckStatus.NA:
            raise CheckModelError(f"{self.subcase_id}: an inapplicable subcase reports N/A, not {self.status}")
        if self.status == CheckStatus.NA:
            if self.reason_code not in NA_REASON_CODES:
                raise CheckModelError(f"{self.subcase_id}: N/A needs a grounded reason from NA_REASON_CODES, not {self.reason_code!r}")
        if self.status == CheckStatus.NOT_TESTED and self.reason_code not in NOT_TESTED_REASON_CODES:
            raise CheckModelError(f"{self.subcase_id}: NOT_TESTED needs a reason from NOT_TESTED_REASON_CODES, not {self.reason_code!r}")
        if self.status == CheckStatus.FAIL and self.classification != Verdict.PRODUCT_FAIL:
            raise CheckModelError(f"{self.subcase_id}: FAIL is reserved for PRODUCT_FAIL evidence, not {self.classification}")
        if self.status == CheckStatus.PASS and not self.evidence_ids:
            raise CheckModelError(f"{self.subcase_id}: a PASS without evidence is not a PASS")

    @property
    def dynamic(self) -> bool:
        return self.status == CheckStatus.PASS and self.classification == Verdict.PASS

    def as_record(self) -> dict[str, Any]:
        record = {"subcase_id": self.subcase_id, "status": str(self.status), "applicable": bool(self.applicable),
                  "detail": self.detail}
        if self.classification is not None:
            record["classification"] = str(self.classification)
        if self.reason_code:
            record["reason_code"] = self.reason_code
        if self.evidence_ids:
            record["evidence_ids"] = list(self.evidence_ids)
        if self.scope_mode:
            record["scope_mode"] = self.scope_mode
        return record


def derive_status(subcases: Sequence[SubcaseResult]) -> tuple[CheckStatus, Verdict | None, str | None]:
    """Resolve a criterion's status from its subcases, with the source's "all subcases pass" rule.

    Precedence, and why:

    1. a trustworthy ``PRODUCT_FAIL`` in any subcase makes the row ``FAIL``. A confirmed defect is a fact about
       the workflow and must not hide behind a sibling subcase that could not be observed; the unobserved
       subcases stay visible on the row (see :attr:`CheckOutcome.unobserved_subcases`) and in the detail.
    2. otherwise, if every applicable subcase passed, the row passes — dynamically only if every subcase was
       dynamically observed, otherwise as a disclosed static result.
    3. otherwise the row is ``NOT_TESTED`` carrying the strongest blocker classification, because an
       observation Breaker could not trust is never a verdict about the workflow.
    """
    if not subcases:
        return CheckStatus.NOT_TESTED, None, "NO_APPLICABLE_SUBCASE"
    applicable = [item for item in subcases if item.applicable and item.status != CheckStatus.NA]
    if not applicable:
        reason = next((item.reason_code for item in subcases if item.reason_code), None)
        return CheckStatus.NA, None, reason
    if any(item.status == CheckStatus.FAIL for item in applicable):
        return CheckStatus.FAIL, Verdict.PRODUCT_FAIL, None
    if all(item.status == CheckStatus.PASS for item in applicable):
        if all(item.classification == Verdict.PASS for item in applicable):
            return CheckStatus.PASS, Verdict.PASS, None
        return CheckStatus.PASS, Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED, None
    blockers = [item.classification for item in applicable
                if item.status != CheckStatus.PASS and item.classification in BLOCKING_VERDICTS]
    for verdict in (Verdict.PROVIDER_FAIL, Verdict.HARNESS_FAIL, Verdict.INCONCLUSIVE):
        if verdict in blockers:
            return CheckStatus.NOT_TESTED, verdict, _blocker_reason(applicable, verdict)
    static = next((item for item in applicable
                   if item.classification == Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED), None)
    if static is not None:
        return CheckStatus.NOT_TESTED, Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED, static.reason_code
    reason = next((item.reason_code for item in applicable if item.reason_code), "NO_EVIDENCE_RECORDED")
    return CheckStatus.NOT_TESTED, None, reason


def _blocker_reason(subcases: Sequence[SubcaseResult], verdict: Verdict) -> str | None:
    for item in subcases:
        if item.classification == verdict and item.reason_code:
            return item.reason_code
    return None


@dataclass(frozen=True)
class CheckOutcome:
    """The verdict for one check, derived from its subcases and validated at construction."""

    check_id: str
    status: CheckStatus
    classification: Verdict | None
    reason_code: str | None
    detail: str
    subcases: tuple[SubcaseResult, ...]
    evidence_ids: tuple[str, ...]
    evidence_classes: tuple[EvidenceClass, ...] = ()
    environment: str = "LOCAL"
    candidate_version: str | None = None
    candidate_hash: str | None = None
    runner: str = "breaker-readiness-engine"
    observed_at: str = ""
    #: The provenance the cited evidence actually carried, resolved by :mod:`breaker.readiness.claim`. Reported
    #: so an operator can see *what kind of proof* a PASS rests on without opening the evidence records.
    provenance: tuple[EvidenceProvenance, ...] = ()

    def __post_init__(self) -> None:
        if self.status == CheckStatus.PASS:
            if self.classification not in (Verdict.PASS, Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED):
                raise CheckModelError(f"{self.check_id}: PASS requires a PASS classification")
            if not self.evidence_ids:
                raise CheckModelError(f"{self.check_id}: PASS requires evidence ids")
            if self.classification == Verdict.PASS and not any(item in DYNAMIC_EVIDENCE_CLASSES for item in self.evidence_classes):
                raise CheckModelError(f"{self.check_id}: a dynamic PASS requires dynamic evidence")
            if not self.evidence_classes:
                raise CheckModelError(f"{self.check_id}: PASS must declare how it was evidenced")
            # Structural, not merely discouraged: a PASS that rests only on a repository derivation or a run
            # against a stand-in is unrepresentable, whatever an engine wishes to report.
            if self.provenance and all(item in NEVER_SUFFICIENT_FOR_PASS for item in self.provenance):
                raise CheckModelError(
                    f"{self.check_id}: a PASS cannot rest on {sorted(str(item) for item in self.provenance)} alone")
        if self.classification == Verdict.PASS and self.status != CheckStatus.PASS:
            raise CheckModelError(f"{self.check_id}: classification PASS requires status PASS")
        if self.status == CheckStatus.FAIL and self.classification != Verdict.PRODUCT_FAIL:
            raise CheckModelError(f"{self.check_id}: FAIL requires PRODUCT_FAIL evidence")
        if self.status == CheckStatus.NA and self.reason_code not in NA_REASON_CODES:
            raise CheckModelError(f"{self.check_id}: N/A needs a grounded reason, not {self.reason_code!r}")
        if self.status == CheckStatus.NOT_TESTED and self.reason_code not in NOT_TESTED_REASON_CODES:
            raise CheckModelError(f"{self.check_id}: NOT_TESTED needs a reason, not {self.reason_code!r}")
        if self.classification == Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED:
            if any(item in DYNAMIC_EVIDENCE_CLASSES for item in self.evidence_classes):
                raise CheckModelError(f"{self.check_id}: a static PASS cannot cite dynamic evidence")

    @classmethod
    def from_subcases(cls, check_id: str, subcases: Sequence[SubcaseResult], *, detail: str = "",
                      evidence_classes: Sequence[EvidenceClass] = (), environment: str = "LOCAL",
                      candidate_version: str | None = None, candidate_hash: str | None = None,
                      observed_at: str = "", provenance: Sequence[EvidenceProvenance] = ()) -> "CheckOutcome":
        status, classification, reason = derive_status(subcases)
        evidence_ids: list[str] = []
        for item in subcases:
            for evidence_id in item.evidence_ids:
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
        if status == CheckStatus.PASS and not evidence_classes:
            # the class is inferred from the subcases so a caller cannot forget to declare it
            evidence_classes = (EvidenceClass.DYNAMIC,) if classification == Verdict.PASS else (EvidenceClass.STATIC,)
        resolved_detail = detail or _first_subcase_detail(subcases) \
            or _default_detail(status, classification, reason)
        if status == CheckStatus.PASS and len(subcases) > 1 and len(evidence_ids) == 1:
            # A campaign observation is recorded against the check, not against one subcase of it. Say so on the
            # row: otherwise "all 7 subcases passed" reads as if seven runs happened, when one observation
            # answered the check and the record's own detail names exactly what was exercised.
            resolved_detail = (f"{resolved_detail} - all {len(subcases)} subcases are answered by the single booked "
                               f"observation {evidence_ids[0]}, whose detail records what was exercised")
        return cls(
            check_id=check_id, status=status, classification=classification, reason_code=reason,
            detail=resolved_detail,
            subcases=tuple(subcases),
            evidence_ids=tuple(evidence_ids), evidence_classes=tuple(evidence_classes), environment=environment,
            candidate_version=candidate_version, candidate_hash=candidate_hash, observed_at=observed_at,
            provenance=tuple(provenance),
        )

    @property
    def dynamic(self) -> bool:
        return self.status == CheckStatus.PASS and self.classification == Verdict.PASS

    @property
    def static_pass(self) -> bool:
        return self.status == CheckStatus.PASS and self.classification == Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED

    @property
    def failed_subcases(self) -> tuple[str, ...]:
        """Subcases that produced a trustworthy product contradiction."""
        return tuple(item.subcase_id for item in self.subcases if item.status == CheckStatus.FAIL)

    @property
    def unobserved_subcases(self) -> tuple[str, ...]:
        """Subcases that never produced a usable observation — kept visible beside any confirmed defect."""
        return tuple(item.subcase_id for item in self.subcases if item.status == CheckStatus.NOT_TESTED)

    @property
    def verdicts(self) -> tuple[Verdict, ...]:
        found: list[Verdict] = []
        for item in self.subcases:
            if item.classification is not None and item.classification not in found:
                found.append(item.classification)
        return tuple(found)

    @property
    def counts_as_dynamic_proof(self) -> bool:
        return bool(self.classification) and counts_as_dynamic_proof(self.classification)

    def as_record(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": str(self.status),
            "classification": str(self.classification) if self.classification else None,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "evidence_classes": [str(item) for item in self.evidence_classes],
            "evidence_ids": list(self.evidence_ids),
            "environment": self.environment,
            "candidate_version": self.candidate_version,
            "candidate_hash": self.candidate_hash,
            "runner": self.runner,
            "observed_at": self.observed_at,
            "provenance": [str(item) for item in self.provenance],
            "dynamic": self.dynamic,
            "static_pass": self.static_pass,
            "subcases": [item.as_record() for item in self.subcases],
        }


def _first_subcase_detail(subcases: Sequence["SubcaseResult"]) -> str:
    """The engine's own words for the first subcase that explains itself.

    A row-level "not tested" is only useful if it names what was missing, and the subcase already computed
    that. Falling back to a generic sentence would throw the reason away at the last step.
    """
    for item in subcases:
        if item.status in {CheckStatus.NOT_TESTED, CheckStatus.FAIL} and item.detail.strip():
            return item.detail.strip()
    for item in subcases:
        if item.detail.strip():
            return item.detail.strip()
    return ""


def _default_detail(status: CheckStatus, classification: Verdict | None, reason: str | None) -> str:
    if status == CheckStatus.PASS:
        text = "expected result observed"
        if classification == Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED:
            text += " by static inspection only"
        return text
    if status == CheckStatus.FAIL:
        return "observed behaviour contradicts the expected result"
    if status == CheckStatus.NA:
        return f"not applicable: {reason}"
    return f"not tested because {reason}" if reason else "not tested"


def summarize_outcomes(outcomes: Iterable[CheckOutcome]) -> dict[str, Any]:
    """The counts the criterion source's own status vocabulary produces, plus the technique split."""
    items = list(outcomes)
    status_counts = {str(status): 0 for status in CheckStatus}
    for item in items:
        status_counts[str(item.status)] += 1
    dynamic = [item.check_id for item in items if item.dynamic]
    static = [item.check_id for item in items if item.static_pass]
    untouched = [item.check_id for item in items if item.status == CheckStatus.NOT_TESTED]
    return {
        "total": len(items),
        "status_counts": status_counts,
        "dynamic_passed": len(dynamic),
        "statically_verified": len(static),
        "dynamic_ids": dynamic,
        "static_ids": static,
        "not_tested_ids": untouched,
        "failed_ids": [item.check_id for item in items if item.status == CheckStatus.FAIL],
        "na_ids": [item.check_id for item in items if item.status == CheckStatus.NA],
    }


def criteria_pack_digest(checks: Sequence[Any]) -> str:
    """A stable digest of a set of criteria — the public identity of a run's criteria source.

    Derived from the normalised criteria themselves, so it identifies what the engine will run rather than the
    file the criteria happened to be loaded from.
    """
    rows = [{
        "id": spec.id,
        "engine": spec.engine,
        "capability": spec.capability,
        "severity": str(spec.severity),
        "execution_class": str(spec.execution_class),
        "category": spec.category,
        "required_contract_fields": list(spec.required_contract_fields),
    } for spec in checks]
    payload = json.dumps(sorted(rows, key=lambda row: row["id"]), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
