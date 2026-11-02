"""One check shape for every layer, so a verdict can be traced to the values behind it.

A :class:`Check` always carries the detail that produced it. A check that cannot be evaluated is not
silently dropped: it is recorded with an explicit :class:`~breaker.verification.taxonomy.Verdict`, which is how
an absent observation becomes ``INCONCLUSIVE`` instead of an accidental pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from breaker.verification.taxonomy import Signal, Verdict, classify_signals, summarize_verdicts


@dataclass(frozen=True)
class Check:
    """One authored assertion, and what the observation did to it."""

    name: str
    ok: bool
    detail: str = ""
    verdict: Verdict | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    @property
    def resolved_verdict(self) -> Verdict:
        if self.verdict is not None:
            return Verdict(self.verdict)
        return Verdict.PASS if self.ok else Verdict.PRODUCT_FAIL

    def as_record(self) -> dict[str, Any]:
        return {"check": self.name, "ok": bool(self.ok), "detail": self.detail,
                "verdict": str(self.resolved_verdict),
                **({"evidence": dict(self.evidence)} if self.evidence else {})}


def passed(name: str, detail: str = "", **evidence: Any) -> Check:
    return Check(name, True, detail, evidence=evidence)


def failed(name: str, detail: str = "", verdict: Verdict = Verdict.PRODUCT_FAIL,
           **evidence: Any) -> Check:
    return Check(name, False, detail, verdict=verdict, evidence=evidence)


def inconclusive(name: str, detail: str = "", **evidence: Any) -> Check:
    return Check(name, False, detail, verdict=Verdict.INCONCLUSIVE, evidence=evidence)


def statically_inspected(name: str, detail: str = "", **evidence: Any) -> Check:
    return Check(name, True, detail, verdict=Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED,
                 evidence=evidence)


class CheckSet:
    """A collector for checks about one case, one layer or one run."""

    def __init__(self, *, label: str = "", checks: Iterable[Check] = ()) -> None:
        self.label = label
        self._checks: list[Check] = list(checks)

    def add(self, check: Check) -> Check:
        self._checks.append(check)
        return check

    def extend(self, checks: Iterable[Check]) -> None:
        for check in checks:
            self.add(check)

    def expect_equal(self, name: str, expected: Any, actual: Any) -> Check:
        return self.add(Check(name, expected == actual, f"{actual!r} vs authored {expected!r}"))

    def expect_true(self, name: str, actual: Any, detail: str = "") -> Check:
        return self.add(Check(name, bool(actual), detail or f"{actual!r}"))

    def expect_in(self, name: str, needle: Any, haystack: Sequence[Any]) -> Check:
        return self.add(Check(name, needle in haystack, f"{needle!r} in {list(haystack)!r}"))

    @property
    def checks(self) -> list[Check]:
        return list(self._checks)

    @property
    def failures(self) -> list[Check]:
        return [check for check in self._checks if not check.ok]

    @property
    def product_failures(self) -> list[Check]:
        return [check for check in self.failures if check.resolved_verdict == Verdict.PRODUCT_FAIL]

    def all_ok(self) -> bool:
        return not self.failures

    def signals(self) -> list[Signal]:
        return [Signal(check.resolved_verdict, check.name, check.detail, source=self.label)
                for check in self._checks]

    def verdict(self) -> Verdict:
        """The case verdict, resolved through the shared precedence rules."""
        return classify_signals(self.signals()).verdict

    def summary(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "checks": [check.as_record() for check in self._checks],
            "passed": len([check for check in self._checks if check.ok]),
            "total": len(self._checks),
            "failures": [check.as_record() for check in self.failures],
            **summarize_verdicts([check.resolved_verdict for check in self._checks]),
        }
