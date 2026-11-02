"""The public evidence layer: what a downstream consumer may consume, derived from the formal evidence.

Breaker's internal artifacts are built for a verifier: layer reports, per-case checks, captured payloads,
attempt ledgers. A consumer should not have to read that layout, and it must never be handed a claim that
Breaker cannot point at evidence for. So this module produces one additive file — ``public-summary.json`` —
with a versioned, self-describing schema.

Three distinctions the summary is required to carry, because collapsing them is how a verification gets
oversold:

* **deterministic verification vs model benchmark** — a 47-case deterministic pack and a 30-case semantic
  benchmark of a model layer are different kinds of evidence, and the benchmark's rate is not a pass rate;
* **simulated effect vs real controlled effect** — a case that ran with effects disabled proves the decision,
  not the delivery;
* **sandbox/local vs production** — a capture sink is a local fixture; a QuickBooks sandbox is not production.

Every item also carries a **source** reference into the formal evidence. An item without one cannot be
built: that is the guard against invented marketing copy, enforced rather than documented.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

PUBLIC_SUMMARY_SCHEMA_VERSION = "1.0.0"

#: Statuses a consumer may act on.
PUBLIC_STATUSES = ("VERIFIED", "NOT_VERIFIED", "INCONCLUSIVE", "BLOCKED")
#: How an effect was produced. A simulated effect is never presented as a delivery.
EFFECT_MODES = ("SIMULATED", "LIVE_CONTROLLED")
#: Where the evidence came from.
ENVIRONMENTS = ("LOCAL", "SANDBOX", "PRODUCTION")
#: What kind of evidence an entry is.
EVALUATION_TYPES = ("DETERMINISTIC_PACK", "MODEL_BENCHMARK", "LIVE_EFFECT", "STATIC_INSPECTION",
                    "PERSISTENCE_READBACK", "COHERENCE", "GROUNDING", "ARCHITECTURE")
#: Disclaimers the summary attaches by itself, so a consumer cannot miss a limitation.
DISCLAIMERS = {
    "SIMULATED": "these cases ran with external effects disabled: they prove the decision, not the delivery",
    "LOCAL": "the effect was captured by a local test fixture, not delivered to a real recipient mailbox",
    "SANDBOX": "the provider was a sandbox, not a production account",
    "MODEL_BENCHMARK": "a model-layer benchmark rate is not a pass rate for the workflow",
}


@dataclass(frozen=True)
class EffectDisclosure:
    """One effect the verification really exercised, with how and where."""

    kind: str
    mode: str
    environment: str
    count: int
    source: str
    adapter: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        # validated at construction, so a caller cannot build an undisclosed effect and only find out when
        # it happens to be serialized
        if self.mode not in EFFECT_MODES:
            raise ValueError(f"effect mode must be one of {EFFECT_MODES}, not {self.mode!r}")
        if self.environment not in ENVIRONMENTS:
            raise ValueError(f"environment must be one of {ENVIRONMENTS}, not {self.environment!r}")
        if not self.source:
            raise ValueError("an effect must cite the formal evidence it was observed in")

    def as_record(self) -> dict[str, Any]:
        record = {"kind": self.kind, "mode": self.mode, "environment": self.environment,
                  "count": int(self.count), "source": self.source,
                  "disclaimer": DISCLAIMERS.get(self.mode.rsplit("_", 1)[-1]) or DISCLAIMERS.get(self.mode)}
        if self.adapter:
            record["adapter"] = self.adapter
        if self.description:
            record["description"] = self.description
        if self.environment in DISCLAIMERS:
            record["environment_disclaimer"] = DISCLAIMERS[self.environment]
        return record


@dataclass(frozen=True)
class EvaluationDisclosure:
    """One separately reported evaluation, kept distinct from the deterministic pack."""

    name: str
    evaluation_type: str
    source: str
    passed: int | None = None
    total: int | None = None
    notes: str = ""
    metrics: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if self.evaluation_type not in EVALUATION_TYPES:
            raise ValueError(f"unknown evaluation type {self.evaluation_type!r}")
        if not self.source:
            raise ValueError("an evaluation must cite the formal evidence it was reported in")
        if self.evaluation_type == "MODEL_BENCHMARK" and self.passed is not None:
            raise ValueError("a model benchmark carries metrics, not a pass count: "
                             "report it under metrics so it cannot be read as a pass rate")

    def as_record(self) -> dict[str, Any]:
        self._validate()
        record: dict[str, Any] = {"name": self.name, "evaluation_type": self.evaluation_type,
                                  "source": self.source}
        if self.passed is not None:
            record["passed"] = int(self.passed)
        if self.total is not None:
            record["total"] = int(self.total)
        if self.notes:
            record["notes"] = self.notes
        if self.metrics:
            record["metrics"] = dict(self.metrics)
        if self.evaluation_type == "MODEL_BENCHMARK":
            record["disclaimer"] = DISCLAIMERS["MODEL_BENCHMARK"]
        return record


def critical_from_checks(check_summary: Mapping[str, Any]) -> dict[str, int]:
    """The critical counts, taken from a :class:`~breaker.verification.checks.CheckSet` summary or a verdict roll-up."""
    if "passed" in check_summary and "total" in check_summary:
        return {"passed": int(check_summary["passed"]), "total": int(check_summary["total"])}
    counts = check_summary.get("counts") or {}
    total = int(check_summary.get("total") or 0)
    passed = int(counts.get("PASS", check_summary.get("passed", 0)))
    return {"passed": passed, "total": total}


def _require_source(item: Mapping[str, Any], kind: str) -> None:
    if not item.get("source"):
        raise ValueError(f"every {kind} entry needs a source reference into the formal evidence; "
                         f"this one has none: {dict(item)!r}")


def _as_records(items: Iterable[Any], kind: str) -> list[dict[str, Any]]:
    """Normalize entries to records, running dicts through their dataclass.

    A caller that passes a plain dict must not be able to skip the disclosure rules (disclaimers, the ban on
    a model benchmark carrying a pass count), so dicts are validated by construction rather than trusted.
    """
    records: list[dict[str, Any]] = []
    for item in items:
        if kind == "effect" and isinstance(item, Mapping) and not hasattr(item, "as_record"):
            item = EffectDisclosure(**dict(item))
        elif kind == "separate evaluation" and isinstance(item, Mapping) and not hasattr(item, "as_record"):
            item = EvaluationDisclosure(**dict(item))
        record = item.as_record() if hasattr(item, "as_record") else dict(item)
        _require_source(record, kind)
        records.append(record)
    return records


def build_public_summary(*, workflow: Mapping[str, Any], status: str, critical: Mapping[str, Any],
                         effects: Sequence[Any] = (), example_cases: Sequence[Any] = (),
                         separate_evaluations: Sequence[Any] = (), tested: Sequence[Any] = (),
                         not_tested: Sequence[Any] = (), known_limitations: Sequence[Any] = (),
                         provenance: Mapping[str, Any] | None = None,
                         generated_from: Sequence[str] = ()) -> dict[str, Any]:
    """Assemble and validate the public summary. Nothing enters without a source."""
    if status not in PUBLIC_STATUSES:
        raise ValueError(f"status must be one of {PUBLIC_STATUSES}, not {status!r}")
    if "passed" not in critical or "total" not in critical:
        raise ValueError("critical requires integer passed and total")
    passed, total = int(critical["passed"]), int(critical["total"])
    if passed > total:
        raise ValueError(f"critical.passed ({passed}) cannot exceed critical.total ({total})")
    if not workflow.get("workflow_id") and not workflow.get("name"):
        raise ValueError("workflow needs at least an id or a name")
    if status == "VERIFIED" and passed != total:
        raise ValueError("a VERIFIED summary cannot carry a failed critical check")

    summary: dict[str, Any] = {
        "schema_version": PUBLIC_SUMMARY_SCHEMA_VERSION,
        "artifact": "public-summary",
        "workflow": dict(workflow),
        "status": status,
        "critical": {"passed": passed, "total": total},
        "effects": _as_records(effects, "effect"),
        "example_cases": _as_records(example_cases, "example case"),
        "separate_evaluations": _as_records(separate_evaluations, "separate evaluation"),
        "tested": _as_records(tested, "tested entry"),
        "not_tested": _as_records(not_tested, "not-tested entry"),
        "known_limitations": _as_records(known_limitations, "limitation"),
        "provenance": {
            "produced_by": "breaker.verification.public_summary",
            "derived_from_formal_evidence": list(generated_from),
            "note": "every entry cites the formal evidence it was derived from; nothing here is written "
                    "for presentation",
            **dict(provenance or {}),
        },
    }
    summary["disclaimers"] = _collected_disclaimers(summary)
    return summary


def _collected_disclaimers(summary: Mapping[str, Any]) -> list[str]:
    found: list[str] = []
    for effect in summary.get("effects") or []:
        for key in ("disclaimer", "environment_disclaimer"):
            text = effect.get(key)
            if text and text not in found:
                found.append(text)
    for entry in summary.get("separate_evaluations") or []:
        text = entry.get("disclaimer")
        if text and text not in found:
            found.append(text)
    return found


def write_public_summary(out_dir: str | pathlib.Path, summary: Mapping[str, Any], *,
                         file_name: str = "public-summary.json") -> pathlib.Path:
    """Write the consumer-facing summary next to the technical artifacts, leaving those untouched."""
    if summary.get("schema_version") != PUBLIC_SUMMARY_SCHEMA_VERSION:
        raise ValueError(f"public summary must carry schema_version {PUBLIC_SUMMARY_SCHEMA_VERSION}")
    directory = pathlib.Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / file_name
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str) + "\n",
                    encoding="utf-8")
    return path


def validate_public_summary(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Re-validate a written summary, so a consumer can trust the file on its own terms."""
    problems: list[str] = []
    if summary.get("schema_version") != PUBLIC_SUMMARY_SCHEMA_VERSION:
        problems.append(f"schema_version is {summary.get('schema_version')!r}")
    if summary.get("status") not in PUBLIC_STATUSES:
        problems.append(f"status is {summary.get('status')!r}")
    critical = summary.get("critical") or {}
    if int(critical.get("passed", -1)) > int(critical.get("total", -1)):
        problems.append("critical.passed exceeds critical.total")
    for key in ("effects", "example_cases", "separate_evaluations", "tested", "not_tested",
                "known_limitations"):
        for item in summary.get(key) or []:
            if not item.get("source"):
                problems.append(f"{key}: an entry has no source reference")
    for effect in summary.get("effects") or []:
        if effect.get("mode") not in EFFECT_MODES:
            problems.append(f"effects: unknown mode {effect.get('mode')!r}")
        if effect.get("environment") not in ENVIRONMENTS:
            problems.append(f"effects: unknown environment {effect.get('environment')!r}")
    return {"ok": not problems, "problems": problems,
            "schema_version": summary.get("schema_version"),
            "status": summary.get("status")}
