"""Effect and state coherence: do the authoritative surfaces agree with each other?

A workflow reports its own outcome in at least three places, and each one is authoritative for something:

* the **terminal payload** — what the workflow says it decided and did;
* its **internal persistence** — what the ledger and state rows now hold;
* the **external evidence** — what a capture sink, provider object or table can independently be read for.

Verifying each surface against the authored expectation is necessary but not sufficient: a workflow can pass
both and still contradict itself. Customer Support v1.0.0 did exactly that — the same run reported
``state.after=RESPONDED`` / ``handled_by=AUTOMATION`` in its terminal payload while the conversation row it
wrote said ``OPEN`` / ``HUMAN``. The case's own assertions passed because the two surfaces were checked
against different things and never against each other.

This module compares them, and a contradiction between authoritative surfaces is a product defect: the
subject is internally inconsistent about a fact it declares. A surface that is *missing* the field is
``INCONCLUSIVE`` instead, because then there is nothing to contradict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from breaker.verification.taxonomy import Verdict

#: Per-surface default authority. Used only for reporting; the comparison is symmetric.
AUTHORITY = {"terminal": "authoritative", "persistence": "authoritative", "external": "authoritative",
             "provider": "authoritative"}


@dataclass(frozen=True)
class Surface:
    """One authoritative account of the run, as a flat field map."""

    name: str
    values: Mapping[str, Any] = field(default_factory=dict)
    source: str = ""

    def get(self, path: str) -> tuple[bool, Any]:
        """Read a dotted path. Returns (present, value)."""
        current: Any = self.values
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                return False, None
            current = current[part]
        return True, current

    def flatten(self, prefix: str = "") -> dict[str, Any]:
        """Every leaf value, keyed by its dotted path."""
        return _flatten(self.values, prefix)


def _flatten(values: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Descend into nested mappings, accumulating dotted paths."""
    out: dict[str, Any] = {}
    for key, value in values.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out


@dataclass(frozen=True)
class CoherenceRule:
    """Two surfaces must agree about the same fact."""

    left: tuple[str, str]
    right: tuple[str, str]
    exempt: Mapping[str, Sequence[Any]] = field(default_factory=dict)
    note: str = ""

    @property
    def name(self) -> str:
        return f"{self.left[0]}.{self.left[1]} agrees with {self.right[0]}.{self.right[1]}"


@dataclass(frozen=True)
class CoherenceFinding:
    rule: str
    ok: bool
    verdict: str
    detail: str
    left_value: Any = None
    right_value: Any = None
    exempt_reason: str = ""

    def as_record(self) -> dict[str, Any]:
        return {"rule": self.rule, "ok": self.ok, "verdict": self.verdict, "detail": self.detail,
                "left": self.left_value, "right": self.right_value,
                **({"exempt_reason": self.exempt_reason} if self.exempt_reason else {})}


def _normalize(value: Any) -> Any:
    """Compare like a human reading a table: strings strip and case-fold, booleans fold to strings."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value.strip().casefold()
    if isinstance(value, (list, tuple)):
        return "|".join(sorted(str(_normalize(item)) for item in value))
    return value


def _exempt(rule: CoherenceRule, left: Any, right: Any) -> str:
    """A pair that is allowed to differ, with the reason recorded."""
    for key, pairs in rule.exempt.items():
        for pair in pairs:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                if _normalize(left) == _normalize(pair[0]) and _normalize(right) == _normalize(pair[1]):
                    return str(key)
    return ""


def check_coherence(surfaces: Iterable[Surface], rules: Sequence[CoherenceRule]) -> list[CoherenceFinding]:
    """Apply every rule to the surfaces. Contradictions are product defects; absences are inconclusive."""
    index = {surface.name: surface for surface in surfaces}
    findings: list[CoherenceFinding] = []
    for rule in rules:
        left_surface = index.get(rule.left[0])
        right_surface = index.get(rule.right[0])
        if left_surface is None or right_surface is None:
            missing_surface = rule.left[0] if left_surface is None else rule.right[0]
            findings.append(CoherenceFinding(
                rule.name, False, str(Verdict.INCONCLUSIVE),
                f"the {missing_surface!r} surface was not observed, so the rule cannot be applied"))
            continue
        left_present, left = left_surface.get(rule.left[1])
        right_present, right = right_surface.get(rule.right[1])
        if not left_present or not right_present:
            absent = f"{rule.left[0]}.{rule.left[1]}" if not left_present else \
                     f"{rule.right[0]}.{rule.right[1]}"
            findings.append(CoherenceFinding(
                rule.name, False, str(Verdict.INCONCLUSIVE),
                f"{absent} is absent, so there is nothing to contradict",
                left_value=left, right_value=right))
            continue
        reason = _exempt(rule, left, right)
        if reason:
            findings.append(CoherenceFinding(rule.name, True, str(Verdict.PASS),
                                             f"allowed difference: {reason}",
                                             left, right, reason))
            continue
        ok = _normalize(left) == _normalize(right)
        detail = (f"{rule.left[0]}.{rule.left[1]}={left!r} vs {rule.right[0]}.{rule.right[1]}={right!r}"
                  + (f" — {rule.note}" if rule.note else ""))
        findings.append(CoherenceFinding(rule.name, ok, str(Verdict.PASS if ok else Verdict.PRODUCT_FAIL),
                                         detail if not ok else "the surfaces agree", left, right))
    return findings


def terminal_vs_persistence(terminal: Mapping[str, Any], persistence: Mapping[str, Any],
                            mapping: Mapping[str, str], *,
                            exempt: Mapping[str, Sequence[Any]] | None = None,
                            terminal_name: str = "terminal",
                            persistence_name: str = "persistence") -> list[CoherenceFinding]:
    """Check a workflow's terminal payload against the state it persisted.

    ``mapping`` is authored with the case: terminal field path → persistence field name.
    """
    rules = [CoherenceRule((terminal_name, terminal_path), (persistence_name, persistence_field),
                           dict(exempt or {}))
             for terminal_path, persistence_field in mapping.items()]
    surfaces = [Surface(terminal_name, dict(terminal), source="terminal payload"),
                Surface(persistence_name, dict(persistence), source="persisted rows")]
    return check_coherence(surfaces, rules)


def declared_success_vs_effect_ledger(terminal: Mapping[str, Any], ledger: Mapping[str, Any], *,
                                      terminal_path: str = "effect_status",
                                      ledger_field: str = "effect_status",
                                      success: Sequence[str] = ("SENT", "SUCCESS", "OK"),
                                      failure: Sequence[str] = ("FAILED", "ERROR", "NOT_SENT"),
                                      ) -> list[CoherenceFinding]:
    """A success claim must not sit next to a failed effect ledger entry, or the reverse."""
    rule = CoherenceRule(("terminal", terminal_path), ("persistence", ledger_field),
                         {"a declared failure agrees with a failed ledger entry": [
                             (value, value) for value in list(failure)]})
    findings = check_coherence([Surface("terminal", dict(terminal), "terminal payload"),
                                Surface("persistence", dict(ledger), "effect ledger")], [rule])
    out: list[CoherenceFinding] = []
    for finding in findings:
        if finding.ok:
            out.append(finding)
            continue
        left = str(finding.left_value or "").upper()
        right = str(finding.right_value or "").upper()
        if left in success and right in failure or left in failure and right in success:
            out.append(CoherenceFinding(finding.rule, False, str(Verdict.PRODUCT_FAIL),
                                        f"the workflow declares {finding.left_value!r} while its ledger "
                                        f"holds {finding.right_value!r}",
                                        finding.left_value, finding.right_value))
        else:
            out.append(finding)
    return out


def object_claim_vs_provider_readback(*, claimed_created: Any, object_found: bool,
                                      object_identity: str | None = None,
                                      name: str = "the provider object agrees with the claim") -> CoherenceFinding:
    """The workflow says whether it created an object; the provider read-back says whether one exists."""
    if claimed_created is None:
        return CoherenceFinding(name, False, str(Verdict.INCONCLUSIVE),
                                "the workflow does not declare whether it created the object")
    claimed = bool(claimed_created)
    if claimed == bool(object_found):
        return CoherenceFinding(name, True, str(Verdict.PASS),
                                f"claimed={claimed} and read-back={object_found}",
                                claimed, object_found)
    return CoherenceFinding(
        name, False, str(Verdict.PRODUCT_FAIL),
        f"the workflow declares created={claimed} but the provider read-back "
        f"{'found' if object_found else 'found no'} object"
        + (f" {object_identity!r}" if object_identity else ""),
        claimed, object_found)


def coherence_summary(findings: Sequence[CoherenceFinding]) -> dict[str, Any]:
    """Roll the findings up, keeping contradictions and absences distinct."""
    contradictions = [finding for finding in findings
                      if finding.verdict == str(Verdict.PRODUCT_FAIL)]
    unresolved = [finding for finding in findings if finding.verdict == str(Verdict.INCONCLUSIVE)]
    return {
        "rules_applied": len(findings),
        "agreed": len([finding for finding in findings if finding.verdict == str(Verdict.PASS)]),
        "contradictions": [finding.as_record() for finding in contradictions],
        "unresolved": [finding.as_record() for finding in unresolved],
        "verdict": str(Verdict.PRODUCT_FAIL if contradictions else
                       Verdict.INCONCLUSIVE if unresolved else Verdict.PASS),
        "findings": [finding.as_record() for finding in findings],
    }
