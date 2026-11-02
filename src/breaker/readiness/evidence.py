"""Evidence records, and the gate that decides whether they can carry a PASS.

Section 23 of the upgrade brief asks every PASS to carry: check ID, fixture/case IDs, execution IDs, observed
state, external/state read-back, evidence artifact, tester/runner, timestamp and candidate version/hash. A
green execution alone is not evidence.

So an :class:`EvidenceRecord` will not construct without those values, and :class:`EvidenceBook` refuses a
dynamic PASS that cites evidence of a lower class. Records are always serialized through
:func:`redact_secrets`, which replaces anything that looks like a credential with a redacted fingerprint —
the secret value itself is never stored, printed or reported.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from breaker.readiness.model import (
    DYNAMIC_EVIDENCE_CLASSES,
    STATIC_EVIDENCE_CLASSES,
    CheckModelError,
    CheckSpec,
    EvidenceClass,
    EvidenceContract,
    EvidenceProvenance,
    OriginKind,
)
from breaker.readiness.provenance import derive_provenance, provenance_exceeds_origin, record_is_repository_derivation
from breaker.verification.taxonomy import Verdict

REDACTED = "[REDACTED]"

#: Values that look like credentials. Deliberately conservative: a false positive costs a redaction, a false
#: negative costs a leaked secret in an evidence file.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("basic_auth", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{12,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("assignment", re.compile(r"(?i)\b(?:api[_-]?key|apikey|secret|password|passwd|token|client[_-]?secret|access[_-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9._\-/+]{8,})")),
    ("n8n_credential_ref", re.compile(r"(?i)\bcredential(?:s)?\b\s*[:=]\s*[\"']?([A-Za-z0-9._\-]{6,})")),
)

_SECRET_KEY_WORDS = ("api_key", "apikey", "token", "password", "passwd", "secret", "authorization", "cookie",
                     "credential", "private_key", "client_secret", "access_key", "refresh_token")


def secret_fingerprint(value: str) -> str:
    """A stable, non-reversible fingerprint for a secret-like value."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def find_secret_like(value: Any, *, path: str = "") -> list[dict[str, Any]]:
    """Locate secret-like values without returning them. Only type, location and fingerprint are reported."""
    found: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            found.extend(find_secret_like(item, path=f"{path}.{key}" if path else str(key)))
        return found
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(find_secret_like(item, path=f"{path}[{index}]"))
        return found
    if not isinstance(value, str):
        return found
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(value):
            token = match.group(1) if match.groups() else match.group(0)
            if token.lower() in {"true", "false", "null", "none"}:
                continue
            found.append({"kind": kind, "location": path or "value",
                          "fingerprint": secret_fingerprint(token), "redacted": REDACTED})
    return found


def redact_secrets(value: Any, *, key: str | None = None) -> Any:
    """Replace secret-like values anywhere in a structure. Used before anything is written to disk."""
    if isinstance(value, Mapping):
        return {str(item_key): redact_secrets(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        if key and any(word in key.lower() for word in _SECRET_KEY_WORDS):
            return REDACTED
        redacted = value
        for _, pattern in SECRET_PATTERNS:
            redacted = pattern.sub(REDACTED, redacted)
        return redacted
    if key and any(word in key.lower() for word in _SECRET_KEY_WORDS) and value is not None:
        return REDACTED
    return value


def assert_redacted(payload: Any, *, where: str) -> None:
    """Last line of defence: nothing secret-shaped may reach a report."""
    leaks = find_secret_like(payload)
    if leaks:
        locations = sorted({item["location"] for item in leaks})
        raise CheckModelError(f"{where}: secret-like value would be written at {locations}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class EvidenceRecord:
    """One observation Breaker is prepared to defend."""

    evidence_id: str
    check_id: str
    evidence_class: EvidenceClass
    source: str
    artifact: str
    runner: str
    observed_at: str
    observed_state: Mapping[str, Any] = field(default_factory=dict)
    read_back: Mapping[str, Any] = field(default_factory=dict)
    fixture_ids: tuple[str, ...] = ()
    execution_ids: tuple[str, ...] = ()
    candidate_version: str | None = None
    candidate_hash: str | None = None
    environment: str = "LOCAL"
    detail: str = ""
    method: str = ""
    subcase_id: str = ""
    recorded_verdict: "Verdict | None" = None
    #: A campaign observation can answer part of a check rather than all of it. When this is set, the record may
    #: only satisfy the subcase ids it names; without a scope it is treated as covering the whole check, which is
    #: what every record written before this field existed actually did.
    covers_subcases: tuple[str, ...] = ()
    #: -- Evidence Claim Integrity (capability C2) ---------------------------------------------------------
    #: The provenance the producer *declares*. It is checked against — never trusted over — the origin.
    provenance: EvidenceProvenance | None = None
    #: The origin kind this record came from (see :class:`~breaker.readiness.model.OriginKind`).
    origin: str = ""
    #: The campaign/probe that produced it, used to derive provenance from a declared scenario.
    campaign: str = ""
    #: What the producing probe expected. Present only when the record declares it; it is what makes the
    #: "expected used as observed" rule decidable.
    expected: Mapping[str, Any] = field(default_factory=dict)
    #: The behaviours the observation measured, from the criteria source's own behaviour vocabulary.
    declared_behaviour: tuple[str, ...] = ()
    #: Set by a producer that knows the record was synthesised from repository metadata (never inferred from
    #: the record's own labels, which are what the claim layer is supposed to distrust).
    repository_derivation: bool = False
    #: The raw operator/source record an evidence record was built from, when there is one. It is inspected to
    #: recognise a record whose only anchor is a repository file; it is never reported.
    origin_record: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.check_id:
            raise CheckModelError("evidence needs an id and the check it belongs to")
        EvidenceClass(self.evidence_class)
        for name, value in (("source", self.source), ("artifact", self.artifact), ("runner", self.runner),
                            ("observed_at", self.observed_at)):
            if not value:
                raise CheckModelError(f"{self.evidence_id}: evidence requires {name}")
        if self.evidence_class in DYNAMIC_EVIDENCE_CLASSES:
            if not self.execution_ids:
                raise CheckModelError(f"{self.evidence_id}: dynamic evidence requires execution ids")
            if not self.observed_state:
                raise CheckModelError(f"{self.evidence_id}: dynamic evidence requires an observed state")
            if not self.read_back:
                raise CheckModelError(f"{self.evidence_id}: dynamic evidence requires an independent read-back")
        if not (self.candidate_version or self.candidate_hash):
            raise CheckModelError(f"{self.evidence_id}: evidence requires a candidate version or hash")
        if self.provenance is not None:
            declared = EvidenceProvenance(str(self.provenance))
            derived = derive_provenance(
                evidence_class=self.evidence_class, environment=self.environment, runner=self.runner,
                method=self.method, campaign=self.campaign,
                origin=OriginKind(self.origin) if self.origin else None,
                read_back=self.read_back, observed=self.observed_state,
                repository_derivation=self.repository_derivation
                or record_is_repository_derivation(self.origin_record))
            if provenance_exceeds_origin(declared, derived):
                # Fail closed at construction: a record may never be labelled with a provenance stronger than
                # the thing that produced it. This is what stops a pinned-double run being booked as a real
                # provider read-back.
                raise CheckModelError(
                    f"{self.evidence_id}: declared provenance {declared} exceeds what its origin supports "
                    f"({derived})")
        for token in self.declared_behaviour:
            if not str(token).strip():
                raise CheckModelError(f"{self.evidence_id}: empty behaviour token")

    @property
    def dynamic(self) -> bool:
        return self.evidence_class in DYNAMIC_EVIDENCE_CLASSES

    @property
    def static(self) -> bool:
        return self.evidence_class in STATIC_EVIDENCE_CLASSES

    def as_record(self) -> dict[str, Any]:
        record = {
            "evidence_id": self.evidence_id,
            "check_id": self.check_id,
            "evidence_class": str(self.evidence_class),
            "source": self.source,
            "artifact": self.artifact,
            "runner": self.runner,
            "observed_at": self.observed_at,
            "environment": self.environment,
            "dynamic": self.dynamic,
        }
        if self.fixture_ids:
            record["fixture_ids"] = list(self.fixture_ids)
        if self.execution_ids:
            record["execution_ids"] = list(self.execution_ids)
        if self.observed_state:
            record["observed_state"] = redact_secrets(dict(self.observed_state))
        if self.read_back:
            record["read_back"] = redact_secrets(dict(self.read_back))
        if self.candidate_version:
            record["candidate_version"] = self.candidate_version
        if self.candidate_hash:
            record["candidate_hash"] = self.candidate_hash
        if self.detail:
            record["detail"] = redact_secrets(self.detail)
        if self.method:
            record["method"] = self.method
        if self.subcase_id:
            record["subcase_id"] = self.subcase_id
        if self.recorded_verdict is not None:
            record["recorded_verdict"] = str(self.recorded_verdict)
        if self.covers_subcases:
            record["covers_subcases"] = list(self.covers_subcases)
        if self.provenance is not None:
            record["provenance"] = str(self.provenance)
        if self.origin:
            record["origin"] = self.origin
        if self.campaign:
            record["campaign"] = self.campaign
        if self.declared_behaviour:
            record["declared_behaviour"] = list(self.declared_behaviour)
        if self.repository_derivation:
            record["repository_derivation"] = True
        return record


def dynamic_evidence(check_id: str, *, execution_ids: Sequence[str], observed_state: Mapping[str, Any],
                     read_back: Mapping[str, Any], source: str, artifact: str, runner: str,
                     fixture_ids: Sequence[str] = (), candidate_version: str | None = None,
                     candidate_hash: str | None = None, environment: str = "LOCAL", detail: str = "",
                     observed_at: str | None = None, suffix: str = "",
                     evidence_class: EvidenceClass | None = None, subcase_id: str = "",
                     recorded_verdict: "Verdict | None" = None,
                     covers_subcases: Sequence[str] = (), provenance: EvidenceProvenance | None = None,
                     origin: OriginKind | str | None = None, campaign: str = "",
                     expected: Mapping[str, Any] | None = None,
                     declared_behaviour: Sequence[str] = (),
                     repository_derivation: bool = False,
                     origin_record: Mapping[str, Any] | None = None) -> EvidenceRecord:
    """Build dynamic evidence with the ids the record validator demands."""
    identifier = _evidence_id(check_id, "DYNAMIC", suffix or ",".join(execution_ids), runner, "independent-read-back")
    if evidence_class is None:
        evidence_class = (EvidenceClass.CONTROLLED_ENVIRONMENT
                          if environment in {"CONTROLLED_ENVIRONMENT", "DISPOSABLE", "CLONE"} else EvidenceClass.DYNAMIC)
    return EvidenceRecord(
        evidence_id=identifier, check_id=check_id, evidence_class=evidence_class,
        source=source, artifact=artifact, runner=runner, observed_at=observed_at or now_iso(),
        observed_state=dict(observed_state), read_back=dict(read_back), fixture_ids=tuple(fixture_ids),
        execution_ids=tuple(execution_ids), candidate_version=candidate_version, candidate_hash=candidate_hash,
        environment=environment, detail=detail, method="independent-read-back", subcase_id=subcase_id,
        recorded_verdict=recorded_verdict, covers_subcases=tuple(covers_subcases),
        provenance=EvidenceProvenance(str(provenance)) if provenance else None,
        origin=str(origin) if origin else "", campaign=campaign,
        expected=dict(expected or {}), declared_behaviour=tuple(declared_behaviour),
        repository_derivation=repository_derivation, origin_record=origin_record,
    )


def static_evidence(check_id: str, *, source: str, artifact: str, runner: str, method: str,
                    detail: str = "", candidate_version: str | None = None, candidate_hash: str | None = None,
                    environment: str = "LOCAL", observed_at: str | None = None, suffix: str = "",
                    evidence_class: EvidenceClass = EvidenceClass.STATIC, subcase_id: str = "",
                    recorded_verdict: "Verdict | None" = None,
                    provenance: EvidenceProvenance | None = None, origin: OriginKind | str | None = None,
                    campaign: str = "", declared_behaviour: Sequence[str] = (),
                    repository_derivation: bool = False,
                    origin_record: Mapping[str, Any] | None = None,
                    expected: Mapping[str, Any] | None = None) -> EvidenceRecord:
    """Build a reading: an inspection, a scan or an operator-supplied record."""
    identifier = _evidence_id(check_id, str(evidence_class), suffix or artifact, runner, method)
    return EvidenceRecord(
        evidence_id=identifier, check_id=check_id, evidence_class=evidence_class, source=source,
        artifact=artifact, runner=runner, observed_at=observed_at or now_iso(), candidate_version=candidate_version,
        candidate_hash=candidate_hash, environment=environment, detail=detail, method=method,
        subcase_id=subcase_id, recorded_verdict=recorded_verdict,
        provenance=EvidenceProvenance(str(provenance)) if provenance else None,
        origin=str(origin) if origin else "", campaign=campaign,
        declared_behaviour=tuple(declared_behaviour), repository_derivation=repository_derivation,
        origin_record=origin_record, expected=dict(expected or {}),
    )


def _evidence_id(check_id: str, kind: str, *parts: str) -> str:
    """A deterministic id for one observation.

    The parts include the runner and the method, because two *different* observations can legitimately exist
    for the same check and subcase — a recorded campaign result and a supplied operator record, for instance.
    Keying only on the check would make the second one look like a contradiction of the first.
    """
    payload = "|".join([check_id, kind, *(part for part in parts if part)])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"{check_id}:{kind.lower()}:{digest}"


class EvidenceBook:
    """The evidence a run accumulated, indexed by check, with conflict detection."""

    def __init__(self, records: Iterable[EvidenceRecord] = ()) -> None:
        self._records: dict[str, EvidenceRecord] = {}
        for record in records:
            self.add(record)

    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        existing = self._records.get(record.evidence_id)
        if existing is not None and existing != record:
            raise CheckModelError(f"conflicting evidence for {record.evidence_id}")
        self._records[record.evidence_id] = record
        return record

    def extend(self, records: Iterable[EvidenceRecord]) -> None:
        for record in records:
            self.add(record)

    def get(self, evidence_id: str) -> EvidenceRecord:
        try:
            return self._records[evidence_id]
        except KeyError as error:
            raise CheckModelError(f"unknown evidence id {evidence_id}") from error

    def for_check(self, check_id: str) -> tuple[EvidenceRecord, ...]:
        return tuple(sorted((record for record in self._records.values() if record.check_id == check_id),
                            key=lambda item: item.evidence_id))

    def dynamic_for_capability(self, capability: str) -> tuple[EvidenceRecord, ...]:
        return tuple(record for record in self.for_check(check_id) if record.dynamic)

    def extend_with(self, other: "EvidenceBook") -> None:
        self.extend(other.records)

    @property
    def records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    def __len__(self) -> int:
        return len(self._records)

    def as_records(self) -> list[dict[str, Any]]:
        return [record.as_record() for record in self.records]

    def gate(self, spec: CheckSpec, evidence_ids: Sequence[str]) -> Verdict:
        """Decide which PASS classification the cited evidence can support, or refuse.

        Raises :class:`CheckModelError` when the cited evidence cannot support a PASS at all. This is the
        single place the "static inspection is not dynamic proof" rule is enforced for every engine.
        """
        if not evidence_ids:
            raise CheckModelError(f"{spec.id}: a PASS must cite evidence")
        records = [self.get(evidence_id) for evidence_id in evidence_ids]
        contract: EvidenceContract = spec.evidence_contract
        for record in records:
            if record.evidence_class not in contract.allowed_evidence_classes:
                raise CheckModelError(
                    f"{spec.id}: {record.evidence_class} evidence is not acceptable for "
                    f"{spec.execution_class} (allowed: "
                    f"{', '.join(str(item) for item in contract.allowed_evidence_classes)})")
            for required in contract.required_fields:
                if required not in record.as_record():
                    raise CheckModelError(f"{spec.id}: evidence {record.evidence_id} lacks required field {required!r}")
        if all(record.static for record in records) and not contract.static_capable:
            raise CheckModelError(f"{spec.id}: static evidence cannot satisfy this check")
        if all(record.dynamic for record in records):
            return Verdict.PASS
        if all(record.static for record in records):
            return Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED
        return Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED
