"""Evidence provenance: how an observation came to exist, and which provenance a check may pass from.

Capability **C2 — Evidence Claim Integrity**. This module is deliberately import-light (it depends only on
:mod:`breaker.readiness.model` and the standard library) so both :mod:`breaker.readiness.evidence` and
:mod:`breaker.readiness.claim` can use it without a cycle.

Two ideas do the work:

1. **Provenance is derived, never chosen.** :func:`derive_provenance` maps the origin facts that already
   exist on an evidence record — evidence class, environment, runner, the campaign that produced it and what
   its read-back actually read — onto the closed :class:`~breaker.readiness.model.EvidenceProvenance` vocabulary.
   A record that *declares* a provenance stronger than its origin supports is refused
   (:func:`provenance_exceeds_origin`), so a campaign run against a pinned test double cannot be presented as
   a provider read-back, and a record synthesised from a repository file is degraded to
   ``DERIVED_METADATA`` rather than being allowed to look like a backup record.
2. **Sufficiency is a property of the checklist row.** :func:`sufficient_provenance_for` gives every check a
   declared set of provenance types that can carry its PASS: by default everything except a repository
   derivation and a run against a stand-in, narrowed where the criteria source says so (a backup/restore row may
   never pass from ``DERIVED_METADATA``; a persistence row needs an independent read of the store, not the
   node's own success status; a recovery row needs an actually observed restoration).

Nothing here writes to a frozen artifact, a recorded campaign or the criteria source: it reads them and reports.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from breaker.readiness.model import (
    DEFAULT_SUFFICIENT_PROVENANCE,
    DYNAMIC_EVIDENCE_CLASSES,
    NEVER_SUFFICIENT_FOR_PASS,
    ORIGIN_PROVENANCE_CEILING,
    PROVENANCE_STRENGTH,
    READBACK_PROVENANCE,
    EvidenceClass,
    EvidenceProvenance,
    OriginKind,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Where the machine-readable correction registry lives. It names verdicts that were booked against the wrong
#: criteria source row and must be honoured (never edited): the registry is additive, the artifacts stay as recorded.
MIS_MAPPED_VERDICTS_PATH = REPO_ROOT / "artifacts" / "readiness" / "mis_mapped_verdicts.json"
ENV_MIS_MAPPED = "BREAKER_MIS_MAPPED_VERDICTS"

#: Environments that mean "a stand-in for the subject, not the subject". An observation produced there can be
#: a SYNTHETIC_FIXTURE and nothing more.
SYNTHETIC_ENVIRONMENTS: frozenset[str] = frozenset({
    "LOCAL_FIXTURE", "FIXTURE", "SIMULATED", "TEST_DOUBLE", "PINNED_DOUBLE", "STUB", "MOCK",
})

#: Runners that are fixtures by construction.
SYNTHETIC_RUNNERS: frozenset[str] = frozenset({"simulated-harness", "fixture-harness", "test-double"})

#: A campaign's own declared scenario, mapped onto the provenance it can support. Anything not named here
#: gets the weakest execution provenance (``LIVE_EXECUTION``) rather than a flattering guess.
CAMPAIGN_PROVENANCE: Mapping[str, EvidenceProvenance] = {
    "send_failure": EvidenceProvenance.FAULT_INJECTION,
    "provider_fault": EvidenceProvenance.FAULT_INJECTION,
    "unknown_write": EvidenceProvenance.FAULT_INJECTION,
    # Capability C1's fault-injection execution harness books its observations under one campaign name, so the
    # provenance a harness declares and the provenance its origin supports are the same thing.
    "fault_injection": EvidenceProvenance.FAULT_INJECTION,
    # A fault the candidate *declares* through its own test-only hook is a fixture, never a fault injection: the
    # environment did not fail, so nothing about a real dependency's behaviour was observed.
    "declared_fault_fixture": EvidenceProvenance.SYNTHETIC_FIXTURE,
    "coherence": EvidenceProvenance.LIVE_EXECUTION,
    # Capability C6's observability harness books its observations under one campaign name. The *surface* the
    # read-back came from is what raises a destination receipt to a provider read-back; the campaign only
    # records that the observation came from an execution-shaped run.
    "observability_detection": EvidenceProvenance.LIVE_EXECUTION,
    # An observation produced against a declared stand-in is a fixture, whatever its read-back looks like.
    "observability_fixture": EvidenceProvenance.SYNTHETIC_FIXTURE,
    "concurrency": EvidenceProvenance.LOAD_OBSERVATION,
    "distinct": EvidenceProvenance.LOAD_OBSERVATION,
    "volume": EvidenceProvenance.LOAD_OBSERVATION,
    "duplicates": EvidenceProvenance.LIVE_EXECUTION,
    "dedup_retention": EvidenceProvenance.LIVE_EXECUTION,
    "update_targeting": EvidenceProvenance.LIVE_EXECUTION,
    "input_edges": EvidenceProvenance.LIVE_EXECUTION,
    "business_invariants": EvidenceProvenance.LIVE_EXECUTION,
    "smoke": EvidenceProvenance.LIVE_EXECUTION,
    "egress_scan": EvidenceProvenance.STATIC_ANALYSIS,
    "authorization_boundary_and_effect_gate": EvidenceProvenance.STATIC_ANALYSIS,
    "ai_input_safety_probe": EvidenceProvenance.LIVE_EXECUTION,
    "model_answer_safety": EvidenceProvenance.LIVE_EXECUTION,
    "live_model_ai010_ai013": EvidenceProvenance.LIVE_EXECUTION,
    "gate_and_isolation_probe": EvidenceProvenance.LIVE_EXECUTION,
    # Capability C3's deployment harness does NOT register a campaign mapping, deliberately. Its observations
    # are read-backs of a disposable target's own stored state, so the honest provenance is the surface the probe
    # actually read (LIVE_EXECUTION, or DATABASE_/PROVIDER_/FILESYSTEM_READBACK when the read-back carries that
    # surface's keys) - never a scenario label. Its campaign name is 'deployment_verification'; registering it here
    # would flatten a kill-switch read-back of the destination sink and a rollback read-back of the release store
    # into one invented provenance and would let the label, not the observation, decide.
    # Capability C8's backup/restore harness books its observations under one campaign name: the drill reads a
    # real store and a disposable target, so the campaign is a live observation and not a scenario label.
    "backup_restore_drill": EvidenceProvenance.LIVE_EXECUTION,
}

#: Campaign *families*: a driver may label its campaign documents per subject/row (the live fault-rows driver
#: writes ``fault_rows:dependencies.wf_030`` / ``fault_rows-partial_failure.wf_048``) while the observations inside were produced by one
#: registered harness scenario (``fault_injection``). A family entry maps the driver's label *root* to the
#: registered scenario the observations actually came from, so provenance is derived from the producing
#: scenario and never from a filename — and so a new row added to the family resolves without a code change.
CAMPAIGN_FAMILIES: Mapping[str, str] = {
    # tools/readiness_cs_fault_rows.py labels its per-row artifacts ``fault_rows:<row>``; the observations
    # inside are produced by the C1 fault-injection harness, whose scenario is registered as FAULT_INJECTION.
    "fault_rows": "fault_injection",
}


def registered_campaign(campaign: str) -> str:
    """The registered scenario name a campaign label resolves to (family labels included).

    Returns ``""`` when the label names no registered scenario, so a caller derives provenance from the origin
    rather than from an unregistered label. Exact names win; otherwise the label's root is looked up in
    :data:`CAMPAIGN_FAMILIES`. A label such as ``unknown_write:campaign`` does *not* resolve, because only an
    explicitly registered family root maps.
    """
    name = str(campaign or "").strip()
    if not name:
        return ""
    if name in CAMPAIGN_PROVENANCE:
        return name
    root = re.split(r"[:\-]", name, 1)[0].strip()
    family = CAMPAIGN_FAMILIES.get(root)
    if family and family in CAMPAIGN_PROVENANCE:
        return family
    return ""


#: Campaigns whose scenario is an injected dependency fault, and whose runs are therefore fault-injection
#: observations rather than ordinary executions.
FAULT_CAMPAIGNS: frozenset[str] = frozenset({"send_failure", "provider_fault", "unknown_write",
                                             "fault_injection"})

#: Campaigns whose scenario is a load/concurrency shape.
LOAD_CAMPAIGNS: frozenset[str] = frozenset({"concurrency", "distinct", "volume"})

#: Read-back key families -> the surface the read-back came from. The keys are the vocabulary the campaign
#: verdicts and the engines already use; nothing is invented here.
_STORE_KEYS = re.compile(
    r"(ledger|table|record|rows?|row_count|store|escalations?|conversation_status|destination_rows|"
    r"identity_keys|objects|persisted|persistence|state_after|reconcil)", re.IGNORECASE)
_PROVIDER_KEYS = re.compile(r"(provider|sink|smtp|delivery|notification|mail|inbox|delivered)", re.IGNORECASE)
_FILESYSTEM_KEYS = re.compile(r"(file|path|directory|artifact|backup_file|fs_)", re.IGNORECASE)

#: Repository metadata: a path that points at a file *in the repository* rather than at a place a recovery
#: artifact is kept. A record whose only "owner" or "change record" is one of these is a derivation from the
#: repository, not a stored backup.
METADATA_SUFFIXES: tuple[str, ...] = (".json", ".yaml", ".yml", ".md", ".py", ".toml", ".criteria pack", ".csv", ".txt")
_PATH_SHAPE = re.compile(r"([A-Za-z]:[\\/]|\\\\|/)")
_EMAIL_SHAPE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_repository_path(value: Any) -> bool:
    """True when ``value`` names a file in a filesystem tree rather than a person, service or location.

    An entry such as ``recovery@example.test`` is an owner; ``…/frozen/example-subject-v1.0.1/…/workflow.json``
    is a repository file. Only the second one is repository metadata.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip()
    if _EMAIL_SHAPE.match(text):
        return False
    if not _PATH_SHAPE.search(text):
        return False
    return text.lower().endswith(METADATA_SUFFIXES)


def record_is_repository_derivation(record: Mapping[str, Any] | None) -> bool:
    """True when an operator record's only anchor is a repository file.

    The synthesised backup/release records are recognisable without trusting their own labels: their
    ``owner``/``change_record`` is a path into the repository and they carry a hash of a repository file.
    A genuine operator record names a person, a service or a storage location instead.
    """
    if not isinstance(record, Mapping):
        return False
    for key in ("owner", "change_record", "location", "path", "backup_location", "stored_at"):
        if key in record and is_repository_path(record.get(key)):
            return True
    hash_keys = [key for key in record if "sha256" in str(key).lower() or "hash" in str(key).lower()]
    return bool(hash_keys) and any(is_repository_path(value) for value in record.values())


def readback_surfaces(read_back: Mapping[str, Any] | None, observed: Mapping[str, Any] | None = None
                      ) -> frozenset[EvidenceProvenance]:
    """Which read-back surfaces a record's own read-back demonstrates.

    Only reported when a read-back exists at all: a record that read nothing back cannot claim a read-back
    provenance, which is what stops a node's own success status from being dressed up as a store read.
    """
    keys: list[str] = []
    for source in (read_back, observed):
        if isinstance(source, Mapping):
            keys.extend(str(key) for key in source)
    if not keys:
        return frozenset()
    found: set[EvidenceProvenance] = set()
    joined = " ".join(keys)
    if _STORE_KEYS.search(joined):
        found.add(EvidenceProvenance.DATABASE_READBACK)
    if _PROVIDER_KEYS.search(joined):
        found.add(EvidenceProvenance.PROVIDER_READBACK)
    if _FILESYSTEM_KEYS.search(joined):
        found.add(EvidenceProvenance.FILESYSTEM_READBACK)
    return frozenset(found)


def derive_provenance(*, evidence_class: EvidenceClass | str, environment: str = "LOCAL", runner: str = "",
                      method: str = "", campaign: str = "", origin: OriginKind | str | None = None,
                      read_back: Mapping[str, Any] | None = None,
                      observed: Mapping[str, Any] | None = None,
                      repository_derivation: bool = False) -> EvidenceProvenance:
    """The provenance an observation of this origin can honestly carry.

    Order matters and is fail-closed: a synthetic or repository origin is decided first, and only then is a
    read-back surface considered. So a record produced against a pinned double is a
    ``SYNTHETIC_FIXTURE`` even if its read-back mentions a provider.
    """
    resolved_class = EvidenceClass(str(evidence_class))
    if origin is not None:
        kind = OriginKind(str(origin))
        if kind is OriginKind.REPOSITORY_DERIVATION:
            return EvidenceProvenance.DERIVED_METADATA
        if kind is OriginKind.SYNTHETIC_RUN:
            return EvidenceProvenance.SYNTHETIC_FIXTURE
    if repository_derivation:
        return EvidenceProvenance.DERIVED_METADATA
    environment_token = (environment or "").strip().upper()
    runner_token = (runner or "").strip().lower()
    if environment_token in SYNTHETIC_ENVIRONMENTS or runner_token in SYNTHETIC_RUNNERS:
        return EvidenceProvenance.SYNTHETIC_FIXTURE

    if resolved_class in DYNAMIC_EVIDENCE_CLASSES:
        # A family label (``fault_rows:dependencies.wf_030``) resolves to the registered scenario that produced the
        # observations; provenance comes from the producing scenario, never from the document's filename.
        base = CAMPAIGN_PROVENANCE.get(registered_campaign(campaign) or (campaign or "").strip())
        execution = base if base is not None else (
            EvidenceProvenance.LIVE_EXECUTION if origin is None else
            EvidenceProvenance(ORIGIN_PROVENANCE_CEILING[OriginKind(str(origin))]))
        if execution in READBACK_PROVENANCE:
            return execution
        if PROVENANCE_STRENGTH[execution] < PROVENANCE_STRENGTH[EvidenceProvenance.LIVE_EXECUTION]:
            # A record that carries execution ids and an observed state cannot be described as a reading or a
            # derivation: the execution happened, whatever the campaign's subject matter was.
            execution = EvidenceProvenance.LIVE_EXECUTION
        # An execution whose read-back independently touched the store/provider/filesystem is reported as that
        # read-back, because that is the strongest true thing the record demonstrates. Otherwise the
        # execution provenance stands on its own.
        surfaces = readback_surfaces(read_back, observed)
        if environment_token in {"CONTROLLED_ENVIRONMENT", "DISPOSABLE", "CLONE"}:
            execution = EvidenceProvenance.LIVE_EXECUTION
        for candidate in (EvidenceProvenance.DATABASE_READBACK, EvidenceProvenance.PROVIDER_READBACK,
                          EvidenceProvenance.FILESYSTEM_READBACK):
            if candidate in surfaces:
                return candidate
        return execution

    # A reading, not an execution.
    if repository_derivation:
        return EvidenceProvenance.DERIVED_METADATA
    if origin is not None:
        kind = OriginKind(str(origin))
        if kind in {OriginKind.REPOSITORY_DERIVATION}:
            return EvidenceProvenance.DERIVED_METADATA
        if kind in {OriginKind.OPERATOR_RECORD, OriginKind.RECORDED_ARTIFACT}:
            return EvidenceProvenance.OPERATOR_EVIDENCE
        if kind in {OriginKind.STATIC_READING, OriginKind.LIVE_RUN, OriginKind.CONTROLLED_RUN,
                    OriginKind.FAULT_INJECTION_RUN, OriginKind.LOAD_RUN}:
            return EvidenceProvenance.STATIC_ANALYSIS
    if environment_token in {"OPERATOR", "RECORDED_EVIDENCE", "DECLARATION"} or runner_token.startswith(
            "operator-evidence"):
        return EvidenceProvenance.OPERATOR_EVIDENCE
    if environment_token in {"DERIVED", "REPOSITORY"} or "derived" in (method or "").lower():
        return EvidenceProvenance.DERIVED_METADATA
    return EvidenceProvenance.STATIC_ANALYSIS


def provenance_exceeds_origin(claimed: EvidenceProvenance, derived: EvidenceProvenance) -> bool:
    """True when a claim is stronger than the origin that produced it.

    Read-back types are checked by *family* as well: a record whose derived provenance is an execution may
    only claim a read-back type when its read-back actually demonstrates that surface.
    """
    if claimed == derived:
        return False
    if PROVENANCE_STRENGTH[claimed] > PROVENANCE_STRENGTH[derived]:
        return True
    if claimed in READBACK_PROVENANCE and derived not in READBACK_PROVENANCE:
        return True
    return False


# -- sufficiency per checklist item ----------------------------------------------------------------------

#: Rows the criteria source requires an independent read of persisted state for: the node's own "I succeeded" status
#: is not the observation. These need a store/filesystem read-back (or provider read-back for delivery state).
PERSISTENCE_PROVENANCE: tuple[EvidenceProvenance, ...] = (
    EvidenceProvenance.DATABASE_READBACK, EvidenceProvenance.FILESYSTEM_READBACK,
    EvidenceProvenance.PROVIDER_READBACK)

#: Rows that assert a stored backup or a restore. A repository derivation can never carry one of these: the
#: artifact being inspected *is* the thing under test, so metadata about it proves nothing. Neither can a
#: static reading of the repository - that is the same defect wearing a different hat; these rows need an
#: operator's declaration, a real read of the store/provider, or an executed restore drill.
RESTORE_PROVENANCE: tuple[EvidenceProvenance, ...] = (
    EvidenceProvenance.OPERATOR_EVIDENCE, EvidenceProvenance.LIVE_EXECUTION,
    EvidenceProvenance.FAULT_INJECTION, EvidenceProvenance.LOAD_OBSERVATION,
    EvidenceProvenance.DATABASE_READBACK, EvidenceProvenance.FILESYSTEM_READBACK,
    EvidenceProvenance.PROVIDER_READBACK)

#: Rows where "the record was reused, only the missing step performed and the uncertainty reconciled" is the
#: requirement, so the claim has to be able to show state that was read back from the systems involved.
PARTIAL_FAILURE_PROVENANCE: tuple[EvidenceProvenance, ...] = (
    EvidenceProvenance.DATABASE_READBACK, EvidenceProvenance.PROVIDER_READBACK,
    EvidenceProvenance.FILESYSTEM_READBACK, EvidenceProvenance.FAULT_INJECTION,
    EvidenceProvenance.LIVE_EXECUTION)

#: The backup/restore category and the deployment rows that read a stored release record.
BACKUP_RESTORE_CHECKS: frozenset[str] = frozenset({"backup_restore.check_wf080", "backup_restore.check_wf081", "backup_restore.check_wf082", "backup_restore.check_wf083"})
STORED_RELEASE_CHECKS: frozenset[str] = frozenset({"deployment.check_wf073"})
#: Partial-failure rows (category G): persistence and delivery have to be observed, not inferred.
PARTIAL_FAILURE_CHECKS: frozenset[str] = frozenset({"partial_failure.wf_047", "partial_failure.wf_048", "partial_failure.wf_049"})
#: Data-integrity rows whose requirement is what the destination holds (category J).
STATE_READBACK_CHECKS: frozenset[str] = frozenset({"data_integrity.check_wf062", "data_integrity.check_wf063", "data_integrity.check_wf064", "data_integrity.check_wf065", "data_integrity.check_wf066"})

#: Data-integrity rows: the destination state is the evidence, so a store read-back (or an executed probe)
#: is required rather than a static reading of the definition.
STATE_READBACK_PROVENANCE: tuple[EvidenceProvenance, ...] = (
    EvidenceProvenance.DATABASE_READBACK, EvidenceProvenance.FILESYSTEM_READBACK,
    EvidenceProvenance.PROVIDER_READBACK, EvidenceProvenance.LIVE_EXECUTION,
    EvidenceProvenance.FAULT_INJECTION, EvidenceProvenance.LOAD_OBSERVATION)

#: Per-check sufficiency overrides. Every entry *narrows* the default; none widens it.
SUFFICIENT_PROVENANCE_BY_CHECK: Mapping[str, tuple[EvidenceProvenance, ...]] = {
    **{check_id: RESTORE_PROVENANCE for check_id in BACKUP_RESTORE_CHECKS},
    **{check_id: RESTORE_PROVENANCE for check_id in STORED_RELEASE_CHECKS},
    **{check_id: PARTIAL_FAILURE_PROVENANCE for check_id in PARTIAL_FAILURE_CHECKS},
    **{check_id: STATE_READBACK_PROVENANCE for check_id in STATE_READBACK_CHECKS},
}


def sufficient_provenance_for(capability: str, *, category: str = "", execution_class: str = "") -> tuple[
        EvidenceProvenance, ...]:
    """Which provenance types a PASS for ``check_id`` may rest on.

    The default (everything except a repository derivation and a run against a stand-in) is narrowed by the
    per-check table above and by two category rules the criteria source states outright:

    * a backup/restore row may never pass from ``DERIVED_METADATA`` (already excluded by the default, and
      asserted explicitly here so a future widening of the default cannot re-admit it);
    * a row whose requirement is the state a store ends up holding needs a read-back of that store.
    """
    declared = SUFFICIENT_PROVENANCE_BY_CHECK.get(capability)
    if declared is not None:
        allowed = tuple(item for item in declared if item not in NEVER_SUFFICIENT_FOR_PASS or
                        item in DEFAULT_SUFFICIENT_PROVENANCE)
    else:
        allowed = tuple(item for item in DEFAULT_SUFFICIENT_PROVENANCE)
    if capability in BACKUP_RESTORE_CHECKS or capability in STORED_RELEASE_CHECKS:
        allowed = tuple(item for item in allowed if item is not EvidenceProvenance.DERIVED_METADATA)
    if not allowed:
        raise ValueError(f"{capability}: no provenance type can carry a PASS; that is not a check")
    return tuple(dict.fromkeys(allowed))


# -- recovery/restoration ---------------------------------------------------------------------------------

#: Rows whose requirement is that something was actually *restored* (or recovered) and observed afterwards.
#: A claim for one of these that records a failure without a restored state is refused.
REQUIRES_RESTORATION_OBSERVATION: frozenset[str] = frozenset({
    "recovery.check_wf041", "recovery.check_wf042", "recovery.check_wf043", "recovery.check_wf044", "recovery.check_wf045", "recovery.check_wf046", "deployment.check_wf077", "backup_restore.check_wf083",
})

_RESTORATION_KEYS = re.compile(r"(restor|recover|replay|reuse|resumed|resend_after_reconcile|converge)",
                               re.IGNORECASE)
#: A key that merely names an *intent* is not an observation of a restoration having happened.
_RESTORATION_NEGATIVE_KEYS = re.compile(r"(attempt|request|initiat|plan|schedul|tried|try|expect)",
                                         re.IGNORECASE)


def restoration_observed(read_back: Mapping[str, Any] | None, observed: Mapping[str, Any] | None = None,
                         detail: str = "") -> bool:
    """True when the claim shows a restoration/recovery was actually observed, not merely attempted.

    A read-back key naming a restored/recovered/reused state *with a truthy value* is required; a key that only
    records the attempt ("restore_attempted": True) does not count, because the attempt is the failure the row
    is about. A detail sentence is accepted only as corroboration of such a key, never on its own — a narrative
    is not an observation.
    """
    for source in (read_back, observed):
        if not isinstance(source, Mapping):
            continue
        for key, value in source.items():
            text = str(key)
            if not _RESTORATION_KEYS.search(text) or _RESTORATION_NEGATIVE_KEYS.search(text):
                continue
            if value not in (None, "", False, 0, "NO", "NONE"):
                return True
    return False


# -- behaviour requirements (the criteria source's own subject matter) --------------------------------------------

#: Per-check behaviour tokens, taken from the criteria source's own wording. When a check appears here, a booked
#: verdict for it must *declare* the behaviours it measured — an artifact that never says what it exercised
#: cannot claim the row. This is what makes "the wrong campaign attached to an id" machine-checkable.
REQUIRED_BEHAVIOUR: Mapping[str, frozenset[str]] = {
    "input_adversary.wf_015": frozenset({"LENGTH_BOUNDARY_PROBED", "OVERSIZE_TEXT_VISIBLY_HANDLED", "NO_SILENT_TRUNCATION"}),
    "input_adversary.wf_017": frozenset({"LARGE_PAYLOAD_OR_FILE_PROBED", "OVERSIZE_INPUT_REJECTED_VISIBLY",
                         "OTHER_WORK_NOT_LOST"}),
    "partial_failure.wf_047": frozenset({"NOTIFICATION_SUCCEEDED", "PERSISTENCE_FAILED", "INCONSISTENCY_DETECTED",
                         "REPAIR_ASSIGNED", "SENT_EVIDENCE_PRESERVED", "NO_SECOND_MESSAGE"}),
    "partial_failure.wf_048": frozenset({"PERSISTENCE_COMMITTED", "NOTIFICATION_FAILED", "EXISTING_RECORD_REUSED",
                         "ONLY_MISSING_NOTIFICATION_SENT", "DELIVERY_UNCERTAINTY_RECONCILED",
                         "NO_DUPLICATE_PERSISTENCE"}),
    "partial_failure.wf_049": frozenset({"TWO_DOWNSTREAM_SYSTEMS_DISAGREE", "AUTHORITATIVE_STATE_VISIBLE",
                         "PENDING_REPAIR_VISIBLE", "CONVERGED_OR_EXPLICITLY_UNDER_REVIEW"}),
    "deployment.check_wf073": frozenset({"IMMUTABLE_VERSION_IDENTIFIES_RELEASE", "LAST_KNOWN_GOOD_IDENTIFIED",
                         "CHANGE_RECORD_NAMED"}),
    "backup_restore.check_wf080": frozenset({"BACKUP_READABLE", "BACKUP_CURRENT", "RECOVERY_OWNER_NAMED"}),
    "backup_restore.check_wf083": frozenset({"RESTORE_DRILL_PERFORMED", "RECOVERED_STATE_MATCHES_BACKUP",
                         "NO_REPEATED_COMPLETED_EFFECTS"}),
}

#: Tokens that describe *this workflow's* behaviour rather than the criteria source requirement. Declaring one of
#: these while leaving the requirement's own tokens out is the "workflow-specific proxy" defect: the proxy may
#: be real and valuable and still not be evidence for the row.
PROXY_BEHAVIOUR_TOKENS: frozenset[str] = frozenset({
    "SEND_FAILED_RECORDED", "HUMAN_QUEUE_ROW_WRITTEN", "FAILED_SEND_NOT_RECORDED_AS_SUCCESS",
    "RETRY_WAS_DUPLICATE", "ESCALATION_ROW_PRESENT", "FIELD_LENGTH_PROBED", "SINK_DELTA_ZERO",
})


def behaviour_missing(capability: str, declared: Iterable[str]) -> tuple[str, ...]:
    """The criteria source behaviours a claim for ``check_id`` declares but does not cover."""
    required = REQUIRED_BEHAVIOUR.get(capability)
    if not required:
        return ()
    present = {str(item).strip().upper() for item in declared}
    return tuple(sorted(required - present))


def behaviour_is_proxy_only(capability: str, declared: Iterable[str]) -> bool:
    """True when a claim offers only workflow-specific proxy tokens for a check that names requirements."""
    required = REQUIRED_BEHAVIOUR.get(capability)
    if not required:
        return False
    present = {str(item).strip().upper() for item in declared}
    return bool(present & PROXY_BEHAVIOUR_TOKENS) and not (present & required)


# -- the correction registry ------------------------------------------------------------------------------

DISPOSITIONS = frozenset({"mis-mapped", "superseded", "provenance-insufficient"})
#: How a correction entry is matched against a booked record.
MATCH_ARTIFACT_GLOB = "ARTIFACT_GLOB"
MATCH_SYNTHESISED_OPERATOR_RECORD = "SYNTHESISED_OPERATOR_RECORD"
#: The standing statement about history, repeated on every entry.
PRESERVED_HISTORY = ("the original artifact is preserved exactly as recorded and is not edited; the "
                     "correction is an additive record the integrity layer honours")


@dataclass(frozen=True)
class CorrectionEntry:
    """One verdict the audit proved was booked against the wrong row, or from evidence that cannot carry it."""

    verdict_id: str
    check_id: str
    artifact: str
    disposition: str
    reason_code: str
    criterion_wording: str
    failed_requirement: str
    match: str = MATCH_ARTIFACT_GLOB
    artifact_globs: tuple[str, ...] = ()
    recorded_verdict: str = "PASS"
    history: str = PRESERVED_HISTORY

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise ValueError(f"{self.verdict_id}: unknown disposition {self.disposition!r}")
        if self.match not in {MATCH_ARTIFACT_GLOB, MATCH_SYNTHESISED_OPERATOR_RECORD}:
            raise ValueError(f"{self.verdict_id}: unknown match kind {self.match!r}")

    def as_record(self) -> dict[str, Any]:
        return {
            "verdict_id": self.verdict_id, "check_id": self.check_id, "artifact": self.artifact,
            "disposition": self.disposition, "reason_code": self.reason_code,
            "criterion_wording": self.criterion_wording, "failed_requirement": self.failed_requirement,
            "match": self.match, "artifact_globs": list(self.artifact_globs),
            "recorded_verdict": self.recorded_verdict, "history": self.history,
        }


@dataclass(frozen=True)
class CorrectionRegistry:
    """The correction registry, honoured rather than reported beside the verdict path."""

    entries: tuple[CorrectionEntry, ...] = ()
    source: str = ""
    note: str = ""

    def for_check(self, check_id: str) -> tuple[CorrectionEntry, ...]:
        return tuple(entry for entry in self.entries if entry.check_id == check_id)

    def blocks(self, check_id: str, *, artifact: str = "", provenance: EvidenceProvenance | None = None,
               runner: str = "") -> CorrectionEntry | None:
        """The correction entry that forbids a PASS for this booked record, if any.

        Matching is deliberately precise (the check id **and** the artifact, or the check id **and** the
        synthesis site). A correction must never suppress an unrelated, honest verdict for the same row.
        """
        for entry in self.for_check(check_id):
            if entry.match == MATCH_ARTIFACT_GLOB:
                if not entry.artifact_globs:
                    if artifact and entry.artifact == artifact:
                        return entry
                    continue
                if any(_glob_matches(pattern, artifact) for pattern in entry.artifact_globs):
                    return entry
                continue
            if entry.match == MATCH_SYNTHESISED_OPERATOR_RECORD:
                if provenance is EvidenceProvenance.DERIVED_METADATA and (
                        not runner or runner.startswith("operator-evidence")):
                    return entry
                continue
        return None

    @property
    def check_ids(self) -> tuple[str, ...]:
        return tuple(sorted({entry.check_id for entry in self.entries}))

    def as_record(self) -> dict[str, Any]:
        return {"artifact": "breaker-mis-mapped-verdict-corrections", "source": self.source,
                "note": self.note, "check_ids": list(self.check_ids),
                "corrections": [entry.as_record() for entry in self.entries]}


def _glob_matches(pattern: str, value: str) -> bool:
    import fnmatch
    if not value:
        return False
    normalised = value.replace("\\", "/")
    return fnmatch.fnmatch(normalised, pattern) or fnmatch.fnmatch(normalised, pattern.replace("\\", "/"))


_EMPTY_REGISTRY = CorrectionRegistry()


def load_corrections(path: str | Path | None = None) -> CorrectionRegistry:
    """Read the correction registry. A missing registry is an empty one, never an error.

    The registry is *additive*: it names a verdict and a disposition and the integrity layer honours it. No
    recorded campaign JSON, frozen workflow artifact, audit file or criteria source is read for writing or modified.
    """
    target = Path(os.environ.get(ENV_MIS_MAPPED, path or MIS_MAPPED_VERDICTS_PATH))
    if not target.exists():
        return _EMPTY_REGISTRY
    payload = json.loads(target.read_text(encoding="utf-8"))
    entries = tuple(
        CorrectionEntry(
            verdict_id=str(item["verdict_id"]), check_id=str(item["check_id"]),
            artifact=str(item.get("artifact", "")), disposition=str(item["disposition"]),
            reason_code=str(item.get("reason_code", "CLAIM_SUPERSEDED_BY_CORRECTION_REGISTRY")),
            criterion_wording=str(item.get("criterion_wording", "")),
            failed_requirement=str(item.get("failed_requirement", "")),
            match=str(item.get("match", MATCH_ARTIFACT_GLOB)),
            artifact_globs=tuple(str(glob) for glob in item.get("artifact_globs") or ()),
            recorded_verdict=str(item.get("recorded_verdict", "PASS")),
            history=str(item.get("history", PRESERVED_HISTORY)),
        )
        for item in payload.get("corrections") or ()
    )
    return CorrectionRegistry(entries=entries, source=str(target), note=str(payload.get("note", "")))


# -- the "expected used as observed" rule ------------------------------------------------------------------

#: Keys that are bookkeeping rather than an observation: they legitimately appear on both sides.
_BOOKKEEPING_KEYS = frozenset({
    "expected_count", "observed_count", "action", "status", "parameters", "forbidden_actions",
})

#: Phrases with which a producer states, in its own observation, that the probe did not happen. A booked
#: verdict resting on such an observation has observed nothing.
NON_OBSERVATION_MARKERS: tuple[str, ...] = (
    "NOT PERFORMED", "NOT_EXECUTED", "NOT EXECUTED", "WAS NOT RUN", "NOT RUN", "NOT OBSERVED",
    "NOT OBSERVABLE", "VACUOUS", "NOT TESTED", "PROBE WAS NOT", "COULD NOT BE PERFORMED",
    "SKIPPED - ", "SKIPPED:",
)


def restates_expectation(observed: Mapping[str, Any] | None, expected: Mapping[str, Any] | None) -> bool:
    """True when the observation is nothing but a restatement of the values the probe asked for.

    A harness that echoes ``request.expected`` as its read-back has observed nothing: it repeated the request.
    Only applied where a claim declares both sides (booked/recorded evidence and declaration records) — a
    fresh probe is decided by the engine's own authored oracle over the read-back it obtained.
    """
    if not isinstance(observed, Mapping) or not observed or not isinstance(expected, Mapping) or not expected:
        return False
    substantive = {str(key): value for key, value in observed.items() if str(key) not in _BOOKKEEPING_KEYS}
    if not substantive:
        return False
    for key, value in substantive.items():
        if key not in expected:
            return False
        if expected[key] != value:
            return False
    return True


def declared_non_observation(observed: Mapping[str, Any] | None) -> str:
    """A short description of the first value in an observation that declares the probe did not happen.

    Returns ``""`` when the observation does not disclaim itself. Only the observation's own values are read —
    a narrative in ``detail`` is not enough to refuse a claim, but a read-back field that says the probe was
    never performed is a statement by the producer that there is nothing to book.
    """
    if not isinstance(observed, Mapping):
        return ""
    for key, value in observed.items():
        if not isinstance(value, str):
            continue
        upper = value.upper()
        for marker in NON_OBSERVATION_MARKERS:
            if marker in upper:
                return f"{key}: {value.strip()[:160]}"
    return ""


def map_evidence_class(evidence_class: EvidenceClass | str, environment: str = "") -> OriginKind:
    """Map the pre-existing EvidenceClass/environment vocabulary onto an origin kind, losing nothing.

    This is the documented bridge required by C2 point 2: every existing record keeps a home in the new
    vocabulary, and the environment decides which home inside a class.
    """
    resolved = EvidenceClass(str(evidence_class))
    token = (environment or "").strip().upper()
    if resolved in DYNAMIC_EVIDENCE_CLASSES:
        if token in SYNTHETIC_ENVIRONMENTS:
            return OriginKind.SYNTHETIC_RUN
        if token in {"CONTROLLED_ENVIRONMENT", "DISPOSABLE", "CLONE"}:
            return OriginKind.CONTROLLED_RUN
        return OriginKind.LIVE_RUN
    if token in {"OPERATOR", "DECLARATION", "RECORDED_EVIDENCE"}:
        return OriginKind.OPERATOR_RECORD if token == "OPERATOR" else OriginKind.RECORDED_ARTIFACT
    if token in {"DERIVED", "REPOSITORY"}:
        return OriginKind.REPOSITORY_DERIVATION
    return OriginKind.STATIC_READING


#: Which operator record a check's authored `method` reads. Used to recover the record's declared origin from
#: ``profile.raw['evidence_provenance']`` without the engines having to pass anything new.
OPERATOR_RECORD_FOR_METHOD: Mapping[str, str] = {
    "version-record-review": "release_record",
    "clean-import-review": "clean_import_record",
    "inventory-review": "approved_inventory",
    "backup-record-review": "workflow_backup",
    "backup-schedule-review": "database_backup",
    "recovery-prerequisite-review": "recovery_prerequisites",
}


def operator_record_origin(profile_raw: Mapping[str, Any] | None, method: str
                           ) -> tuple[bool, Mapping[str, Any] | None, str]:
    """Recognise a declaration record that was synthesised from repository metadata.

    Returns ``(repository_derivation, record, origin_detail)``. Two independent signals are used, either of
    which is enough: the profile's own ``evidence_provenance`` map naming a repository path for the record, and
    the record's content pointing at a repository file. A record whose owner is a person or a service, or a
    location outside the repository, stays an operator record.
    """
    raw = profile_raw if isinstance(profile_raw, Mapping) else {}
    name = OPERATOR_RECORD_FOR_METHOD.get(method, "")
    provenance_map = raw.get("evidence_provenance")
    hints = provenance_map if isinstance(provenance_map, Mapping) else {}
    hint = str(hints.get(name, "")) if name else ""
    supplied = raw.get("evidence")
    record = dict(supplied.get(name)) if isinstance(supplied, Mapping) and name and isinstance(
        supplied.get(name), Mapping) else None
    if hint and is_repository_path(hint):
        return True, record, hint
    if record is not None and record_is_repository_derivation(record):
        return True, record, hint or "the record's own fields point at a repository file"
    return False, record, hint


def vocabulary() -> dict[str, Any]:
    """The closed vocabularies, as a machine-readable record (used by the report and the regression suite)."""
    return {
        "provenance_types": [str(item) for item in EvidenceProvenance],
        "origin_kinds": [str(item) for item in OriginKind],
        "default_sufficient": [str(item) for item in DEFAULT_SUFFICIENT_PROVENANCE],
        "never_sufficient": sorted(str(item) for item in NEVER_SUFFICIENT_FOR_PASS),
        "strength": {str(key): value for key, value in PROVENANCE_STRENGTH.items()},
        "origin_ceiling": {str(key): str(value) for key, value in ORIGIN_PROVENANCE_CEILING.items()},
        "campaign_provenance": {key: str(value) for key, value in sorted(CAMPAIGN_PROVENANCE.items())},
        "campaign_families": dict(sorted(CAMPAIGN_FAMILIES.items())),
        "sufficiency_overrides": {check: [str(item) for item in value]
                                  for check, value in sorted(SUFFICIENT_PROVENANCE_BY_CHECK.items())},
        "required_behaviour": {check: sorted(value) for check, value in sorted(REQUIRED_BEHAVIOUR.items())},
        "requires_restoration": sorted(REQUIRES_RESTORATION_OBSERVATION),
        "dispositions": sorted(DISPOSITIONS),
    }
