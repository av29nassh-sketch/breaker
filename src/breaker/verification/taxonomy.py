"""Breaker's failure taxonomy.

Six classes, and only six. The point of the taxonomy is that a failure which says nothing about the
subject's behaviour can never be reported as if it did.

===================  ==========================================================  ==================
verdict              meaning                                                      blocks a verdict
===================  ==========================================================  ==================
PASS                 the authored expectation was met by an independent            no
                     observation
PRODUCT_FAIL         the observation is complete and trustworthy, and it           yes (real defect)
                     contradicts the authored expectation
HARNESS_FAIL         Breaker could not obtain a trustworthy observation because    yes (unknown)
                     its own machinery failed: n8n MCP rate window (429), a
                     transport 404/timeout/empty body, a stale session,
                     missing fixture wiring
PROVIDER_FAIL        a dependency the subject relies on failed: model provider    yes (unknown)
                     outage, provider sandbox unavailable, transient provider
                     read errors
INCONCLUSIVE         an observation exists but cannot distinguish expected from    yes (unknown)
                     unexpected: a key is absent, the state is ambiguous, two
                     readings are compatible
STATICALLY_...       the claim was checked by reading the definition/contract      no
                     only and was never executed
===================  ==========================================================  ==================

Only :attr:`Verdict.PRODUCT_FAIL` is a statement about the subject. Everything else is a statement about
the observation. :func:`summarize_verdicts` therefore applies the precedence rules once, in one place,
instead of leaving each harness to invent its own.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence


class Verdict(StrEnum):
    PASS = "PASS"
    PRODUCT_FAIL = "PRODUCT_FAIL"
    HARNESS_FAIL = "HARNESS_FAIL"
    PROVIDER_FAIL = "PROVIDER_FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED = "STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED"


VERDICT_DEFINITIONS: dict[str, dict[str, Any]] = {
    Verdict.PASS: {
        "meaning": "the authored expectation was met by an independent observation",
        "blocks_verdict": False,
        "about_the_subject": False,
        "counts_as_dynamic_proof": True,
    },
    Verdict.PRODUCT_FAIL: {
        "meaning": "a complete, trustworthy observation contradicts the authored expectation",
        "blocks_verdict": True,
        "about_the_subject": True,
        "counts_as_dynamic_proof": True,
    },
    Verdict.HARNESS_FAIL: {
        "meaning": "Breaker could not obtain a trustworthy observation because its own machinery failed",
        "blocks_verdict": True,
        "about_the_subject": False,
        "counts_as_dynamic_proof": False,
        "examples": ["n8n test endpoint returned HTTP 429", "execution 404 or not yet visible",
                     "transport returned an empty body", "stale session", "fixture wiring missing"],
    },
    Verdict.PROVIDER_FAIL: {
        "meaning": "a dependency the subject relies on failed, so behaviour could not be judged",
        "blocks_verdict": True,
        "about_the_subject": False,
        "counts_as_dynamic_proof": False,
        "examples": ["model provider outage", "provider sandbox unavailable", "transient provider read error"],
    },
    Verdict.INCONCLUSIVE: {
        "meaning": "evidence exists but cannot distinguish expected from unexpected",
        "blocks_verdict": True,
        "about_the_subject": False,
        "counts_as_dynamic_proof": False,
        "examples": ["the field is absent from the observation", "two readings are compatible",
                     "state is ambiguous"],
    },
    Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED: {
        "meaning": "checked by reading the definition or contract; never executed",
        "blocks_verdict": False,
        "about_the_subject": False,
        "counts_as_dynamic_proof": False,
    },
}

#: Verdicts that are statements about the subject rather than about the observation.
SUBJECT_VERDICTS = frozenset({Verdict.PRODUCT_FAIL})
#: Verdicts that end a run without a conclusion.
BLOCKING_VERDICTS = frozenset({Verdict.PRODUCT_FAIL, Verdict.HARNESS_FAIL, Verdict.PROVIDER_FAIL,
                               Verdict.INCONCLUSIVE})

# Marker tables. They are explicit so that a classification can be argued with, not guessed at.
_RATE_WINDOW_MARKERS = ("429", "rate limit", "rate window", "retry-after", "too many requests")
_VISIBILITY_MARKERS = ("404", "not found", "not yet visible", "no execution", "execution_not_visible")
_TRANSPORT_MARKERS = ("empty response", "empty body", "timed out", "timeout", "connection reset",
                      "connection refused", "connection aborted", "remote end closed", "broken pipe",
                      "transport", "temporarily unavailable", "502", "503", "504",
                      "websocket", "handshake")
_SESSION_MARKERS = ("stale session", "session expired", "unauthorized", "401", "forbidden", "403")
_PROVIDER_MARKERS = ("provider outage", "sandbox unavailable", "model provider", "provider returned",
                     "provider error", "overloaded", "service unavailable", "upstream")
_AMBIGUITY_MARKERS = ("ambiguous", "cannot distinguish", "unreadable", "absent", "missing key",
                      "no observation", "undetermined", "unknown state")


@dataclass(frozen=True)
class Signal:
    """One reason to hold one verdict, with the evidence that produced it."""

    verdict: Verdict
    reason: str
    detail: str = ""
    source: str = ""
    about_the_subject: bool | None = None

    def __post_init__(self) -> None:
        if self.about_the_subject is None:
            object.__setattr__(self, "about_the_subject", self.verdict in SUBJECT_VERDICTS)

    def as_record(self) -> dict[str, Any]:
        return {"verdict": str(self.verdict), "reason": self.reason, "detail": self.detail,
                "source": self.source, "about_the_subject": bool(self.about_the_subject)}


def _contains(message: str, markers: Sequence[str]) -> str | None:
    normalized = (message or "").lower()
    return next((marker for marker in markers if marker in normalized), None)


def classify_exception(error: BaseException | str) -> Signal:
    """Classify a raised error or an error message.

    Ordered deliberately: rate windows and visibility problems are harness facts that *look* like generic
    transport failures, and a provider outage must not be reported as a product defect. The default for an
    unclassifiable error is :attr:`Verdict.HARNESS_FAIL`, because an error Breaker cannot explain is a fact
    about Breaker, not about the subject.
    """
    if isinstance(error, BaseException):
        name = type(error).__name__
        message = str(error)
    else:
        name = ""
        message = str(error)
    haystack = f"{name}: {message}"

    for verdict, markers, reason in (
        (Verdict.HARNESS_FAIL, _RATE_WINDOW_MARKERS, "MCP_RATE_WINDOW"),
        (Verdict.HARNESS_FAIL, _VISIBILITY_MARKERS, "EXECUTION_NOT_VISIBLE"),
        (Verdict.HARNESS_FAIL, _SESSION_MARKERS, "SESSION_OR_AUTH"),
        (Verdict.PROVIDER_FAIL, _PROVIDER_MARKERS, "PROVIDER_UNAVAILABLE"),
        (Verdict.HARNESS_FAIL, _TRANSPORT_MARKERS, "TRANSPORT"),
        (Verdict.INCONCLUSIVE, _AMBIGUITY_MARKERS, "AMBIGUOUS_EVIDENCE"),
    ):
        marker = _contains(haystack, markers)
        if marker:
            return Signal(verdict, reason, f"matched {marker!r} in {haystack[:200]!r}", source="exception")
    return Signal(Verdict.HARNESS_FAIL, "UNCLASSIFIED_HARNESS_ERROR", f"{haystack[:200]}",
                  source="exception")


def classify_signals(signals: Iterable[Signal]) -> Signal:
    """Combine signals about one case into the verdict that must be reported.

    Precedence, applied once here so every harness agrees:

    1. **A product defect needs trustworthy evidence.** If every signal that is not a PASS is harness-,
       provider- or ambiguity-attributable, the case is reported as that class — never as PRODUCT_FAIL.
       This is the rule that stops a retry from silently becoming a product verdict.
    2. Among the non-subject classes, an unknown observation outranks a PASS but not a real product defect.
    3. Otherwise the first subject signal wins; failing that, the first signal wins.
    """
    ordered = list(signals)
    if not ordered:
        return Signal(Verdict.INCONCLUSIVE, "NO_SIGNALS", "no signal was recorded for this case")

    subject = [signal for signal in ordered if signal.verdict in SUBJECT_VERDICTS]
    others = [signal for signal in ordered if signal.verdict not in SUBJECT_VERDICTS
              and signal.verdict != Verdict.PASS]
    if subject:
        # a subject signal is only trustworthy if nothing else made the observation unusable
        blockers = [signal for signal in others if signal.verdict in BLOCKING_VERDICTS]
        if not blockers:
            return subject[0]
        return Signal(
            blockers[0].verdict,
            f"{blockers[0].reason}_WHILE_PRODUCT_SIGNAL_PRESENT",
            f"{blockers[0].detail} (a product signal was also present: {subject[0].as_record()})",
            source=blockers[0].source,
        )
    if others:
        for verdict in (Verdict.PROVIDER_FAIL, Verdict.HARNESS_FAIL, Verdict.INCONCLUSIVE):
            match = next((signal for signal in others if signal.verdict == verdict), None)
            if match:
                return match
    static = next((signal for signal in ordered
                   if signal.verdict == Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED), None)
    if static:
        return static
    return ordered[0]


def is_product_defect(verdict: Verdict | str) -> bool:
    return Verdict(verdict) in SUBJECT_VERDICTS


def is_blocking(verdict: Verdict | str) -> bool:
    return Verdict(verdict) in BLOCKING_VERDICTS


def counts_as_dynamic_proof(verdict: Verdict | str) -> bool:
    return bool(VERDICT_DEFINITIONS[Verdict(verdict)]["counts_as_dynamic_proof"])


def summarize_verdicts(verdicts: Iterable[Verdict | str | Mapping[str, Any]]) -> dict[str, Any]:
    """Count a set of verdicts and resolve the run verdict with the same precedence rules."""
    normalized: list[Verdict] = []
    for verdict in verdicts:
        if isinstance(verdict, Mapping):
            normalized.append(Verdict(verdict.get("verdict") or verdict.get("status")))
        else:
            normalized.append(Verdict(verdict))
    counts = {str(verdict): 0 for verdict in Verdict}
    for verdict in normalized:
        counts[str(verdict)] += 1
    blockers = [verdict for verdict in normalized if verdict in BLOCKING_VERDICTS]
    if any(verdict == Verdict.PRODUCT_FAIL for verdict in blockers):
        overall = Verdict.PRODUCT_FAIL
    elif any(verdict == Verdict.PROVIDER_FAIL for verdict in blockers):
        overall = Verdict.PROVIDER_FAIL
    elif any(verdict == Verdict.HARNESS_FAIL for verdict in blockers):
        overall = Verdict.HARNESS_FAIL
    elif blockers:
        overall = Verdict.INCONCLUSIVE
    elif normalized and all(verdict == Verdict.PASS for verdict in normalized):
        overall = Verdict.PASS
    elif normalized:
        overall = Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED
    else:
        overall = Verdict.INCONCLUSIVE
    return {
        "total": len(normalized),
        "counts": counts,
        "passed": counts[str(Verdict.PASS)],
        "blocking": counts[str(Verdict.PRODUCT_FAIL)] + counts[str(Verdict.HARNESS_FAIL)]
        + counts[str(Verdict.PROVIDER_FAIL)] + counts[str(Verdict.INCONCLUSIVE)],
        "product_failures": counts[str(Verdict.PRODUCT_FAIL)],
        "harness_failures": counts[str(Verdict.HARNESS_FAIL)],
        "provider_failures": counts[str(Verdict.PROVIDER_FAIL)],
        "inconclusive": counts[str(Verdict.INCONCLUSIVE)],
        "statically_inspected": counts[str(Verdict.STATICALLY_INSPECTED_NOT_DYNAMICALLY_EXECUTED)],
        "verdict": str(overall),
        "definition": VERDICT_DEFINITIONS[overall]["meaning"],
    }
