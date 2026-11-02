"""Evidence ingestion: turning *recorded* observations into rows Breaker is willing to report.

Section 26 of the brief says to prefer saved evidence over new external writes, and section 25 says never to
retrofit evidence that does not exist. Those two sentences pull in opposite directions unless the ingestion
is strict, so it is:

* every claim comes from an entry in ``fixtures/readiness/evidence-mappings.json`` that names the artifact,
  the locator inside it, and why the recorded outcome *is* the checklist statement;
* the claim is re-verified against the artifact at ingest time — a case that did not record a PASS, a
  criterion that is not ``true``, or a pack whose field assertions did not all match produces no PASS;
* everything ingested is ``EVIDENCE_ONLY``: these observations carry no execution id Breaker can attribute to
  a run it performed, so they can never be reported as dynamic proof. They are counted separately, which is
  exactly the distinction the public summary exists to preserve.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from breaker.readiness.evidence import EvidenceBook, dynamic_evidence, static_evidence
from breaker.readiness.model import CheckModelError, EvidenceClass, EvidenceProvenance, OriginKind
from breaker.readiness.provenance import (
    CAMPAIGN_PROVENANCE,
    FAULT_CAMPAIGNS,
    LOAD_CAMPAIGNS,
    derive_provenance,
    registered_campaign,
)
from breaker.verification.taxonomy import Verdict

#: Recorded-evidence mappings are deployment data: the file that maps saved campaign artifacts to checks
#: belongs to the deployment, not to the engine. Point BREAKER_EVIDENCE_MAPPINGS at it. When no file is
#: configured the engine ingests nothing, which leaves rows NOT_TESTED and invents no evidence: only a
#: recorded PASS observation can ever be ingested (see EvidenceMapping.__post_init__).
ENV_MAPPINGS = "BREAKER_EVIDENCE_MAPPINGS"
MAPPINGS_PATH = Path(__file__).resolve().parents[3] / "fixtures" / "readiness" / "evidence-mappings.json"

KIND_DYNAMIC_CAMPAIGN = "CAMPAIGN_VERDICT"
KIND_CASE_RESULT = "CASE_RESULT"
KIND_VERIFIED_CRITERION = "VERIFIED_CRITERION"
KIND_PACK_CASE = "PACK_CASE"
KIND_FROZEN_MANIFEST = "FROZEN_MANIFEST"
KINDS = (KIND_CASE_RESULT, KIND_VERIFIED_CRITERION, KIND_PACK_CASE, KIND_FROZEN_MANIFEST)


class IngestionError(RuntimeError):
    """A mapping is wrong, or an artifact no longer says what the mapping claims."""


@dataclass(frozen=True)
class EvidenceMapping:
    subject: str
    check_id: str
    kind: str
    artifact: str
    locator: str
    verdict: Verdict
    evidence_class: EvidenceClass
    rationale: str
    does_not_establish: str = ""
    subcase_id: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise IngestionError(f"{self.check_id}: unknown mapping kind {self.kind!r}")
        if self.verdict != Verdict.PASS:
            raise IngestionError(f"{self.check_id}: only recorded PASS observations may be ingested")
        if self.evidence_class != EvidenceClass.EVIDENCE_ONLY:
            raise IngestionError(
                f"{self.check_id}: a recorded observation must be ingested as EVIDENCE_ONLY; "
                "dynamic proof requires an execution Breaker performed itself")


@dataclass(frozen=True)
class IngestionResult:
    book: EvidenceBook
    accepted: tuple[str, ...]
    rejected: tuple[dict[str, Any], ...]

    @property
    def summary(self) -> dict[str, Any]:
        return {"accepted": len(self.accepted), "rejected": len(self.rejected),
                "accepted_checks": list(self.accepted), "rejections": [dict(item) for item in self.rejected]}


def mappings_path(explicit: str | Path | None = None) -> Path:
    import os
    if explicit is not None:
        return Path(explicit)
    override = os.environ.get(ENV_MAPPINGS)
    return Path(override) if override else MAPPINGS_PATH


def load_mappings(path: str | Path | None = None) -> dict[str, tuple[EvidenceMapping, ...]]:
    target = mappings_path(path)
    if not target.exists():
        return {}
    payload = json.loads(target.read_text(encoding="utf-8"))
    subjects: dict[str, tuple[EvidenceMapping, ...]] = {}
    for subject, entries in (payload.get("subjects") or {}).items():
        subjects[subject] = tuple(
            EvidenceMapping(
                subject=subject, check_id=entry["check_id"], kind=entry["kind"], artifact=entry["artifact"],
                locator=entry["locator"], verdict=Verdict(entry["verdict"]),
                evidence_class=EvidenceClass(entry["evidence_class"]), rationale=entry["rationale"],
                does_not_establish=entry.get("does_not_establish", ""), subcase_id=entry.get("subcase_id", ""),
            )
            for entry in entries
        )
    return subjects


def _read_json(root: Path, relative: str) -> Any:
    path = root / relative
    if not path.exists():
        raise IngestionError(f"artifact not found: {relative}")
    return json.loads(path.read_text(encoding="utf-8"))


#: The pin values a campaign document may record to mean "the frozen definition was the installed one".
_PASSING_PIN = {"PASSED", "PASS", "TRUE", "OK"}


def _pin_passed(pin: Any) -> bool:
    """Whether a recorded campaign pin authorises booking.

    Compared against the passing vocabulary rather than tested for truthiness: ``"FAILED"`` is a non-empty
    string, so a truthiness check would book a campaign that ran against a definition that is not the
    frozen one.
    """
    if isinstance(pin, bool):
        return pin
    return str(pin).strip().upper() in _PASSING_PIN


def ingest_campaigns(campaign_dir: str | Path, *, root: str | Path, candidate_version: str | None = None,
                     candidate_hash: str | None = None, runner: str = "readiness-campaign"
                     ) -> IngestionResult:
    """Turn live campaign results into dynamic evidence Breaker can cite.

    Unlike the recorded-evidence path, these observations carry execution ids Breaker obtained itself, so the
    records are dynamic: a PASS here is dynamic proof, and a FAIL is a product defect that stays visible.

    Re-verification is still enforced. Every ingested verdict must cite execution ids that the same campaign
    document records, and a NOT_TESTED verdict is not ingested at all — there is nothing to prove, and
    converting "we could not run it" into a booked observation is how a gap report starts lying.
    """
    directory = Path(campaign_dir)
    if not directory.exists():
        return IngestionResult(book=EvidenceBook(), accepted=(), rejected=())
    if not (candidate_version or candidate_hash):
        raise IngestionError("campaign ingestion needs the candidate identity the runs belong to")
    base_path = Path(root)
    book = EvidenceBook()
    accepted: list[str] = []
    rejected: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if path.name in {"dynamic-evidence.json", "aggregate-summary.json"}:
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            rejected.append({"artifact": path.name, "reason": f"unreadable: {error}"})
            continue
        # A campaign may only be booked on the *identity* verdict: definition equality, node hash, inactive
        # state. The aggregate status cannot carry this, because some of its checks can never pass after a
        # legitimate re-install. An affirmative identity verdict therefore governs even when the aggregate
        # preflight fails. A document that records *only* a failed aggregate preflight is refused, and a
        # document that records neither an identity verdict nor a preflight pin — whether the fields are
        # absent or explicitly ``null`` — is ambiguous about which candidate its executions belong to and is
        # refused too: ``.get()`` cannot tell an absent key from a JSON null, and booking a document that
        # asserts nothing about identity is how a legacy artifact silently becomes evidence.
        candidate = document.get("candidate") or {}
        identity = candidate.get("preflight_identity_pass")
        pin = candidate.get("preflight_pass")
        if identity is not None:
            if not identity:
                rejected.append({"artifact": path.name,
                                 "reason": "the document records that candidate identity was not established "
                                           "by its preflight; its executions are not evidence about this "
                                           "candidate"})
                continue
        elif pin is not None:
            if not _pin_passed(pin):
                rejected.append({"artifact": path.name,
                                 "reason": f"the document records a preflight that did not pass ({pin!r}) and no "
                                           f"identity verdict; its executions are not evidence about this candidate"})
                continue
        else:
            # Neither an identity verdict nor a preflight pin establishes the candidate. Name which fields
            # were absent versus explicitly null so the refusal is diagnosable, but refuse both.
            fields = []
            for name in ("preflight_identity_pass", "preflight_pass"):
                fields.append(f"{name} is " + ("null" if name in candidate else "absent"))
            rejected.append({"artifact": path.name,
                             "reason": "the document records no identity verdict and no preflight pin ("
                                       + "; ".join(fields)
                                       + "); nothing establishes that its executions are about this candidate, "
                                         "so it is not evidence"})
            continue
        executions = {str(item.get("execution_id")) for item in
                      [run for campaign in (document.get("campaigns") or {}).values()
                       for run in (campaign.get("executions") or [])]}
        for index, verdict in enumerate(document.get("verdicts") or []):
            check_id = str(verdict.get("check_id") or "")
            status = str(verdict.get("status") or "")
            cited = [str(item) for item in (verdict.get("execution_ids") or [])]
            if status == "NOT_TESTED":
                continue
            if not check_id or status not in {"PASS", "FAIL"}:
                rejected.append({"check_id": check_id, "artifact": path.name,
                                 "reason": f"unsupported verdict status {status!r}"})
                continue
            unknown = [item for item in cited if item not in executions]
            if unknown or not cited:
                rejected.append({"check_id": check_id, "artifact": path.name,
                                 "reason": f"cited execution ids are not in the campaign document: {unknown}"})
                continue
            verdict_kind = Verdict.PASS if status == "PASS" else Verdict.PRODUCT_FAIL
            try:
                relative = str(path.relative_to(base_path))
            except ValueError:
                relative = str(path)
            observed = dict(verdict.get("observed") or {})
            read_back = dict(verdict.get("read_back") or {})
            environment = str(document.get("environment") or "LOCAL").strip() or "LOCAL"
            # The *scenario* is the verdict's own declaration when it makes one: a driver labels its documents
            # per row ("fault_rows:dependencies.wf_030") while the observations inside were produced by one registered
            # scenario ("fault_injection"). Provenance is derived from the producing scenario, never from the
            # document's filename, so the label a tool chooses cannot change what the evidence is.
            document_campaign = str(document.get("campaign_requested") or path.stem)
            declared_scenario = str(observed.get("campaign") or "").strip()
            scenario = registered_campaign(declared_scenario or document_campaign)
            campaign_name = scenario or declared_scenario or document_campaign
            origin = (OriginKind.FAULT_INJECTION_RUN if campaign_name in FAULT_CAMPAIGNS
                      else OriginKind.LOAD_RUN if campaign_name in LOAD_CAMPAIGNS
                      else OriginKind.LIVE_RUN)
            # The provenance is *derived* from the campaign's own declared scenario and from what its read-back
            # actually read. It is stored on the record so the claim layer can check the record's origin
            # against what it asserts — never so a producer can assert a stronger one.
            derived = derive_provenance(
                evidence_class=EvidenceClass.DYNAMIC, environment=environment,
                runner=f"{runner}:example-subject", campaign=campaign_name, origin=origin,
                read_back=read_back, observed=observed)
            # A verdict's *declared* provenance is honoured only when the scenario that made the declaration
            # is registered for it: a fault scenario may claim FAULT_INJECTION, a fixture scenario may claim
            # SYNTHETIC_FIXTURE, and an unregistered scenario name may claim nothing. A declared provenance the
            # registration does not authorise is refused here rather than being silently booked as the derived
            # one — that is how a declared FAULT_INJECTION artifact is kept from booking under a class its own
            # declaration contradicts.
            provenance = derived
            declared_provenance = observed.get("provenance")
            if declared_provenance:
                try:
                    declared = EvidenceProvenance(str(declared_provenance))
                except ValueError:
                    rejected.append({"check_id": check_id, "artifact": path.name,
                                     "reason": f"the verdict declares an unknown provenance "
                                               f"{declared_provenance!r}; the vocabulary is closed"})
                    continue
                if not scenario or CAMPAIGN_PROVENANCE.get(scenario) != declared:
                    registered = CAMPAIGN_PROVENANCE.get(scenario) if scenario else None
                    rejected.append({
                        "check_id": check_id, "artifact": path.name,
                        "reason": (f"the verdict declares provenance {declared}, but the scenario "
                                   f"{declared_scenario or document_campaign!r} is "
                                   + (f"registered as {registered}" if scenario else "not a registered campaign")
                                   + ", so the declaration is not authorised")})
                    continue
                provenance = declared
            try:
                record = dynamic_evidence(
                    check_id, execution_ids=tuple(cited), observed_state=observed,
                    read_back=read_back, source=relative,
                    artifact=relative, runner=f"{runner}:example-subject",
                    candidate_version=candidate_version, candidate_hash=candidate_hash,
                    environment=environment, detail=str(verdict.get("detail") or ""),
                    # One campaign document may hold several observations of the *same* check — the
                    # concurrency campaign reports one per level. The record's own position in the document is
                    # therefore part of its identity: keying only on the file made the second observation look
                    # like a contradiction of the first, which is what the id scheme exists to prevent.
                    suffix=f"campaign:{relative}:{index}", recorded_verdict=verdict_kind,
                    covers_subcases=tuple(str(item) for item in (verdict.get("covers_subcases") or ())),
                    provenance=provenance, campaign=campaign_name,
                    declared_behaviour=tuple(str(item) for item in (verdict.get("declared_behaviour") or ())),
                    expected=dict(verdict.get("expected") or {}))
            except CheckModelError as error:
                # A declared provenance that exceeds what its origin supports (a fixture environment, a
                # repository derivation, a static reading) is refused, not downgraded to the derived one.
                rejected.append({"check_id": check_id, "artifact": path.name,
                                 "reason": f"the declared provenance cannot be carried by its origin: {error}"})
                continue
            book.add(record)
            accepted.append(check_id)
    return IngestionResult(book=book, accepted=tuple(sorted(set(accepted))), rejected=tuple(rejected))


def ingest_subject(subject: str, *, root: str | Path, mappings: Mapping[str, Sequence[EvidenceMapping]] | None = None,
                   candidate_version: str | None = None, candidate_hash: str | None = None) -> IngestionResult:
    """Re-verify every mapping for one subject and return the evidence Breaker may cite."""
    base = Path(root)
    if not (candidate_version or candidate_hash):
        # Section 23 wants every PASS to name the candidate it was observed on. An artifact that does not
        # carry that identity cannot be turned into evidence, so the caller must supply it (the freeze record
        # usually has it) rather than Breaker inventing one.
        raise IngestionError(
            "ingestion needs the candidate identity the evidence belongs to: pass candidate_version and/or "
            "candidate_hash")
    table = dict(mappings) if mappings is not None else load_mappings()
    book = EvidenceBook()
    accepted: list[str] = []
    rejected: list[dict[str, Any]] = []
    for mapping in table.get(subject, ()):
        try:
            record = _verify(mapping, base, candidate_version=candidate_version, candidate_hash=candidate_hash)
        except IngestionError as error:
            rejected.append({"check_id": mapping.check_id, "artifact": mapping.artifact,
                             "reason": str(error)})
            continue
        book.add(record)
        accepted.append(mapping.check_id)
    return IngestionResult(book=book, accepted=tuple(sorted(set(accepted))), rejected=tuple(rejected))


def _verify(mapping: EvidenceMapping, root: Path, *, candidate_version: str | None,
            candidate_hash: str | None):
    payload = _read_json(root, mapping.artifact)
    if mapping.kind == KIND_CASE_RESULT:
        observed = _case_result(payload, mapping)
    elif mapping.kind == KIND_VERIFIED_CRITERION:
        observed = _verified_criterion(payload, mapping)
    elif mapping.kind == KIND_PACK_CASE:
        observed = _pack_case(payload, mapping)
    else:
        observed = _frozen_manifest(payload, mapping)
    detail = (f"{mapping.rationale} [re-verified against {mapping.artifact}; "
              f"this does not establish: {mapping.does_not_establish or 'anything beyond the recorded case'}]")
    return static_evidence(
        mapping.check_id, source=mapping.artifact, artifact=mapping.artifact,
        runner="readiness-evidence-ingestion", method=f"recorded-{mapping.kind.lower()}",
        detail=detail, candidate_version=candidate_version or observed.get("candidate_version"),
        candidate_hash=candidate_hash or observed.get("candidate_hash"),
        environment="RECORDED_EVIDENCE", suffix=mapping.subcase_id or mapping.locator,
        evidence_class=EvidenceClass.EVIDENCE_ONLY, subcase_id=mapping.subcase_id,
        recorded_verdict=Verdict.PASS, origin=OriginKind.RECORDED_ARTIFACT,
    )


def _case_result(payload: Any, mapping: EvidenceMapping) -> dict[str, Any]:
    cases = payload if isinstance(payload, list) else payload.get("case_results", [])
    match = next((item for item in cases if item.get("case_id") == mapping.locator), None)
    if match is None:
        raise IngestionError(f"case {mapping.locator!r} is not in the artifact")
    if match.get("status") != "PASS":
        raise IngestionError(f"case {mapping.locator!r} status is {match.get('status')!r}, not PASS")
    state = (match.get("state_verification") or {}).get("status")
    if state != "PASS":
        raise IngestionError(f"case {mapping.locator!r} has no passing persisted-state assertion "
                             f"(state_verification={state!r})")
    assertions = match.get("assertions") or {}
    if assertions and not all(value == "MATCH" for value in assertions.values()):
        raise IngestionError(f"case {mapping.locator!r} assertions did not all match: {assertions}")
    return {"case_id": mapping.locator, "status": match.get("status"),
            "state_verification": state, "evidence_ref": match.get("evidence_ref"),
            "expected": match.get("expected"), "actual": match.get("actual")}


def _verified_criterion(payload: Any, mapping: EvidenceMapping) -> dict[str, Any]:
    criteria = payload.get("verified_criteria") or {}
    if mapping.locator not in criteria:
        raise IngestionError(f"criterion {mapping.locator!r} is not recorded in the campaign")
    if criteria[mapping.locator] is not True:
        raise IngestionError(f"criterion {mapping.locator!r} is {criteria[mapping.locator]!r}, not true")
    verdict = payload.get("final_verdict")
    if verdict not in {"VERIFIED", "PASS"}:
        raise IngestionError(f"the campaign's final verdict is {verdict!r}")
    inspection = payload.get("inspection") or {}
    return {"criterion": mapping.locator, "final_verdict": verdict, "run_id": payload.get("run_id"),
            "definition_sha256": inspection.get("definition_sha256"),
            "candidate_hash": inspection.get("definition_sha256")}


def _pack_case(payload: Any, mapping: EvidenceMapping) -> dict[str, Any]:
    if payload.get("pack_id") != mapping.locator:
        raise IngestionError(f"pack id is {payload.get('pack_id')!r}, mapping expects {mapping.locator!r}")
    cases = payload.get("cases") or []
    if not cases:
        raise IngestionError("the pack records no cases")
    mismatched = [case.get("case_id") for case in cases
                  if case.get("observed_state") != case.get("expected_state")]
    if mismatched:
        raise IngestionError(f"cases disagree with their expected state: {mismatched}")
    unmatched_fields = [case.get("case_id") for case in cases
                        if any(value is not True for value in (case.get("asserted_field_matches") or {}).values())]
    if unmatched_fields:
        raise IngestionError(f"field assertions did not all match for {unmatched_fields}")
    candidate = payload.get("candidate") or {}
    return {"pack_id": mapping.locator, "cases": len(cases),
            "candidate_hash": candidate.get("expected_definition_sha256"), "tag": candidate.get("tag"),
            "execution_ids": sorted({str(case.get("execution_id")) for case in cases if case.get("execution_id")})}


def _frozen_manifest(payload: Any, mapping: EvidenceMapping) -> dict[str, Any]:
    candidate = payload.get("candidate") or {}
    field = mapping.locator.split(".")[-1]
    value = candidate.get(field)
    if not value:
        raise IngestionError(f"the artifact records no {field!r} for the candidate")
    return {"candidate_hash": value, "tag": candidate.get("tag"),
            "frozen_manifest_status": payload.get("frozen_manifest_status")}
