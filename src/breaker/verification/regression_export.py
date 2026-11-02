"""Turn a verified product defect into an artifact the workflow builder can adopt.

When Breaker finds a real defect, the useful thing it can hand over is not a paragraph in a report but a
self-contained artifact: the exact input, the authored expectation, what was observed instead, the state and
effect evidence, the candidate's identity, and the failure classification. That is what
``regression_candidate.json`` is.

Two boundaries are deliberate:

* It is an **export**. It never edits the product's test pack, never writes into the candidate's directory,
  and never changes an expectation. Adoption is the builder's decision, so the artifact carries the
  instructions and the exact assertions to adopt rather than performing the edit.
* It only exports **product defects**. A harness or provider failure is not a regression the product can
  adopt; exporting one would create a test that fails for a reason that is not the product's behaviour.
  Passing ``allow_non_product=True`` records the classification honestly but marks the artifact as not
  adoptable, which is what a diagnosis needs.

Historical fixture: Customer Support v1.0.0's live-send persistence defect — the terminal payload reported
``RESPONDED``/``AUTOMATION`` while the persisted conversation row held ``OPEN``/``HUMAN``, with
``knowledge_refs`` double-encoded.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Mapping, Sequence

from breaker.verification.taxonomy import VERDICT_DEFINITIONS, Verdict, is_product_defect

REGRESSION_CANDIDATE_SCHEMA_VERSION = "1.0.0"

#: Where an adopted regression is expected to land. Recorded so the builder knows the target, never written.
DEFAULT_ADOPTION_TARGET = "the candidate's own case pack (authored expectations), then Breaker's replay"


def build_regression_candidate(*, target_id: str, case_id: str, candidate: Mapping[str, Any],
                               failing_input: Mapping[str, Any], authored_expectation: Mapping[str, Any],
                               observed_result: Mapping[str, Any], classification: Verdict | str,
                               evidence: Mapping[str, Any] | None = None,
                               surfaces: Mapping[str, Any] | None = None,
                               contract: Mapping[str, Any] | None = None,
                               provider: str | None = None, run_id: str | None = None,
                               extra_assertions: Sequence[Mapping[str, Any]] = (),
                               allow_non_product: bool = False) -> dict[str, Any]:
    """Build the regression candidate document.

    Raises ``ValueError`` when the classification is not a product defect, unless ``allow_non_product`` is
    set — in which case the artifact is produced with ``adoptable: false`` and the reason recorded.
    """
    verdict = Verdict(classification)
    adoptable = is_product_defect(verdict)
    if not adoptable and not allow_non_product:
        raise ValueError(
            f"refusing to export {verdict}: only PRODUCT_FAIL is a regression the product can adopt "
            f"({VERDICT_DEFINITIONS[verdict]['meaning']}). Pass allow_non_product=True to record it as "
            f"a diagnosis instead."
        )

    document: dict[str, Any] = {
        "schema_version": REGRESSION_CANDIDATE_SCHEMA_VERSION,
        "artifact": "regression_candidate",
        "target_id": target_id,
        "case_id": case_id,
        "failure_classification": str(verdict),
        "failure_classification_definition": VERDICT_DEFINITIONS[verdict]["meaning"],
        "adoptable": adoptable,
        "candidate": {
            "tag": candidate.get("tag"),
            "version_id": candidate.get("version_id"),
            "definition_sha256": candidate.get("definition_sha256"),
            "nodes_sha256": candidate.get("nodes_sha256"),
            "status": candidate.get("status"),
            **{key: value for key, value in candidate.items()
               if key not in {"tag", "version_id", "definition_sha256", "nodes_sha256", "status"}},
        },
        "failing_input": dict(failing_input),
        "authored_expectation": dict(authored_expectation),
        "observed_result": dict(observed_result),
        "evidence": dict(evidence or {}),
        "provider": provider,
        "run_id": run_id,
        "adoption": {
            "adopt": adoptable,
            "action": "add this case to the candidate's authored case pack, then replay it in Breaker",
            "target": DEFAULT_ADOPTION_TARGET,
            "does_not_edit": [
                "the candidate's case pack",
                "the candidate's frozen definition",
                "Breaker's existing verification artifacts",
            ],
            "reason": None if adoptable else
                      f"{verdict} is not the product's behaviour; record it as a diagnosis instead",
        },
        "provenance": {
            "produced_by": "breaker.verification.regression_export",
            "classification_source": "breaker.verification.taxonomy",
            "case_id": case_id,
            "run_id": run_id,
        },
    }
    if surfaces:
        document["surfaces"] = {name: dict(values) for name, values in surfaces.items()}
    if contract:
        document["contract"] = dict(contract)
    assertions = _assertions_from(observed_result, authored_expectation)
    if assertions:
        document["assertions_to_adopt"] = assertions
    if extra_assertions:
        document["assertions_to_adopt"] = list(document.get("assertions_to_adopt") or []) + [
            dict(assertion) for assertion in extra_assertions]
    return document


def _assertions_from(observed: Mapping[str, Any], expected: Mapping[str, Any]
                     ) -> list[dict[str, Any]]:
    """The per-field assertions worth adopting: where the observation differed from the authored value."""
    assertions: list[dict[str, Any]] = []
    for key, authored in expected.items():
        if key not in observed:
            continue
        seen = observed.get(key)
        if seen == authored:
            continue
        assertions.append({"assert": key, "authored": authored, "observed_at_defect_time": seen})
    return assertions


def from_case_report(case_report: Mapping[str, Any], *, target_id: str, candidate: Mapping[str, Any],
                     classification: Verdict | str | None = None, failing_input: Mapping[str, Any] | None = None,
                     extra_assertions: Sequence[Mapping[str, Any]] = (),
                     allow_non_product: bool = False) -> dict[str, Any]:
    """Build a candidate from a harness case report (``case_id``, ``checks``, ``observed``, ``verdict``)."""
    observed = dict(case_report.get("observed") or {})
    expected = dict(case_report.get("expected") or case_report.get("authored") or {})
    for check in case_report.get("checks") or []:
        if isinstance(check, Mapping) and not check.get("ok") and check.get("check") in expected:
            expected.setdefault(check["check"], expected.get(check["check"]))
    failures = [check for check in case_report.get("checks") or []
                if isinstance(check, Mapping) and not check.get("ok")]
    if classification is None:
        classification = Verdict.PRODUCT_FAIL if any(
            str(check.get("verdict")) == str(Verdict.PRODUCT_FAIL) or check.get("verdict") is None
            for check in failures) else Verdict.HARNESS_FAIL
    return build_regression_candidate(
        target_id=target_id, case_id=str(case_report.get("case_id")), candidate=candidate,
        failing_input=dict(failing_input or case_report.get("payload") or {}),
        authored_expectation=expected, observed_result=observed, classification=classification,
        evidence={"checks": list(case_report.get("checks") or []),
                  "execution_id": case_report.get("execution_id"),
                  "verdict": case_report.get("verdict")},
        extra_assertions=extra_assertions, allow_non_product=allow_non_product)


def write_regression_candidate(out_dir: str | pathlib.Path, candidate: Mapping[str, Any], *,
                               file_name: str = "regression_candidate.json") -> pathlib.Path:
    """Write the artifact. It is an export for review; nothing downstream is edited."""
    directory = pathlib.Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / file_name
    path.write_text(json.dumps(candidate, indent=2, ensure_ascii=False, default=str) + "\n",
                    encoding="utf-8")
    return path
