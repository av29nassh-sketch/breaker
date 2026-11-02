"""Retry and replay, with provenance that cannot be hidden.

Retrying is how Breaker gets past things that are not the product's fault: an n8n MCP rate window, an
execution that is not visible yet, a stale session, a transient provider read. The danger is the opposite
of retrying — a retry that quietly *replaces* the thing it retried, so a failure disappears from the record,
or a harness problem gets retried until it looks like a product verdict.

So two rules are enforced here:

1. **Every attempt is kept.** A replay never deletes or rewrites an earlier attempt; it marks it
   superseded and records why, and the original stays in the ledger with its own verdict.
2. **Only the retryable classes are retried**, and a case whose only failure evidence is retryable is
   reported as that class — never as a product defect. That resolution lives in
   :mod:`breaker.verification.taxonomy` and is applied here through :func:`classify_exception`.

Each attempt records: the original attempt it replays, the reason for the replay, whether state was reset
(and what that means for the evidence), any dependency ordering it relied on, and its own result.
"""
from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from breaker.verification.taxonomy import Signal, Verdict, classify_exception, is_blocking

#: Verdicts worth another attempt. A product defect never is: it is the answer, not a hiccup.
RETRYABLE_VERDICTS = frozenset({Verdict.HARNESS_FAIL, Verdict.PROVIDER_FAIL, Verdict.INCONCLUSIVE})


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Attempt:
    """One attempt at one case, kept forever."""

    index: int
    label: str
    verdict: str
    reason: str = ""
    detail: str = ""
    started_at: str = ""
    finished_at: str = ""
    state_reset: bool = False
    state_reset_detail: str = ""
    dependency_order: tuple[str, ...] = ()
    error_type: str | None = None
    is_replay: bool = False
    replay_reason: str = ""
    original_attempt: int | None = None
    superseded: bool = False
    superseded_by: int | None = None
    superseded_reason: str = ""
    rate_window_wait_s: float = 0.0
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def retryable(self) -> bool:
        return Verdict(self.verdict) in RETRYABLE_VERDICTS

    def as_record(self) -> dict[str, Any]:
        return {
            "attempt": self.index, "label": self.label, "verdict": self.verdict,
            "reason": self.reason, "detail": self.detail, "started_at": self.started_at,
            "finished_at": self.finished_at, "state_reset": self.state_reset,
            "state_reset_detail": self.state_reset_detail, "dependency_order": list(self.dependency_order),
            "error_type": self.error_type, "is_replay": self.is_replay,
            "replay_reason": self.replay_reason, "original_attempt": self.original_attempt,
            "superseded": self.superseded, "superseded_by": self.superseded_by,
            "superseded_reason": self.superseded_reason, "rate_window_wait_s": self.rate_window_wait_s,
            **({"extra": dict(self.extra)} if self.extra else {}),
        }


class ReplayLedger:
    """The attempts of one case (or one run), oldest first, superseded attempts included."""

    def __init__(self, *, label: str = "") -> None:
        self.label = label
        self._attempts: list[Attempt] = []

    @property
    def attempts(self) -> list[Attempt]:
        return list(self._attempts)

    def record(self, attempt: Attempt) -> Attempt:
        self._attempts.append(attempt)
        return attempt

    def supersede(self, index: int, *, reason: str, by_index: int | None = None) -> None:
        """Mark an attempt superseded. The attempt itself is never removed or edited in place."""
        for position, attempt in enumerate(self._attempts):
            if attempt.index == index:
                self._attempts[position] = _replace(attempt, superseded=True, superseded_by=by_index,
                                                    superseded_reason=reason)
                return
        raise KeyError(f"no attempt {index} in this ledger")

    def last(self) -> Attempt | None:
        return self._attempts[-1] if self._attempts else None

    def final(self) -> Attempt | None:
        """The newest attempt that was not superseded — the one the verdict comes from."""
        for attempt in reversed(self._attempts):
            if not attempt.superseded:
                return attempt
        return None

    def replays(self) -> list[Attempt]:
        return [attempt for attempt in self._attempts if attempt.is_replay]

    def to_document(self) -> dict[str, Any]:
        final = self.final()
        return {
            "label": self.label,
            "attempts": [attempt.as_record() for attempt in self._attempts],
            "attempt_count": len(self._attempts),
            "replay_count": len(self.replays()),
            "superseded": [attempt.as_record() for attempt in self._attempts if attempt.superseded],
            "final_verdict": final.verdict if final else None,
            "final_attempt": final.index if final else None,
            "note": "every attempt is retained; a replay marks the attempt it replaces as superseded and "
                    "records why",
        }


def _replace(attempt: Attempt, **changes: Any) -> Attempt:
    """Copy an attempt with changes applied. Uses the dataclass itself, so field names cannot drift."""
    return dataclasses.replace(attempt, **changes)


@dataclass
class RetryPolicy:
    """How many times, how far apart, and for which verdicts."""

    max_attempts: int = 3
    pause_s: float = 1.0
    backoff: float = 1.5
    retry_verdicts: frozenset[str] = frozenset(str(verdict) for verdict in RETRYABLE_VERDICTS)
    max_pause_s: float = 150.0

    def pause_for(self, attempt_index: int) -> float:
        return min(self.pause_s * (self.backoff ** max(0, attempt_index - 1)), self.max_pause_s)

    def retryable(self, verdict: Verdict | str) -> bool:
        return str(verdict) in self.retry_verdicts

    def as_record(self) -> dict[str, Any]:
        return {"max_attempts": self.max_attempts, "pause_s": self.pause_s, "backoff": self.backoff,
                "retry_verdicts": sorted(self.retry_verdicts), "max_pause_s": self.max_pause_s}


@dataclass
class ReplayOutcome:
    verdict: Verdict
    result: Any = None
    attempts: tuple[Attempt, ...] = ()
    ledger: Mapping[str, Any] = field(default_factory=dict)

    @property
    def attempts_used(self) -> int:
        return len(self.attempts)


def run_with_replay(call: Callable[[int], Any], *, label: str, ledger: ReplayLedger | None = None,
                    policy: RetryPolicy | None = None,
                    classify: Callable[[Any], Verdict | Signal | str] | None = None,
                    state_reset: Callable[[int], tuple[bool, str]] | None = None,
                    rate_window: Callable[[str], Mapping[str, Any]] | None = None,
                    dependency_order: Sequence[str] = (),
                    sleep: Callable[[float], None] = time.sleep) -> ReplayOutcome:
    """Attempt ``call`` until it either concludes or stops being retryable.

    ``call`` receives the attempt index (1-based) and returns whatever the caller then classifies.
    ``classify`` maps that result to a verdict; if it is not supplied the result is passed through if it is
    already a verdict, otherwise an exception-free result is treated as a PASS.
    """
    ledger = ledger or ReplayLedger(label=label)
    policy = policy or RetryPolicy()
    outcome: Any = None
    verdict = Verdict.INCONCLUSIVE
    signal = Signal(Verdict.INCONCLUSIVE, "NOT_ATTEMPTED")

    for attempt_index in range(1, policy.max_attempts + 1):
        waited = 0.0
        if rate_window is not None:
            window = dict(rate_window(label) or {})
            waited = float(window.get("waited") or window.get("waited_s") or 0.0)
        reset_flag, reset_detail = (state_reset(attempt_index) if state_reset else (False, ""))
        started = _now()
        error_type: str | None = None
        try:
            outcome = call(attempt_index)
            signal = _classify_result(outcome, classify)
            verdict = signal.verdict
        except Exception as error:  # noqa: BLE001 - classified, never swallowed
            signal = classify_exception(error)
            verdict = signal.verdict
            error_type = type(error).__name__
            outcome = None
        finished = _now()

        previous = ledger.last()
        attempt = Attempt(
            index=attempt_index, label=label, verdict=str(verdict), reason=signal.reason,
            detail=signal.detail, started_at=started, finished_at=finished, state_reset=reset_flag,
            state_reset_detail=reset_detail, dependency_order=tuple(dependency_order),
            error_type=error_type, is_replay=attempt_index > 1,
            replay_reason=(f"attempt {attempt_index - 1} concluded {previous.verdict} "
                           f"({previous.reason}), which is retryable") if attempt_index > 1 else "",
            original_attempt=1 if attempt_index > 1 else None,
            rate_window_wait_s=waited)
        ledger.record(attempt)

        if not policy.retryable(verdict) or attempt_index == policy.max_attempts:
            break
        # the decision to replay is what supersedes this attempt: record it now, so an attempt that was
        # retried never looks like a final result just because the retry happened to succeed
        ledger.supersede(attempt.index,
                         reason=f"replayed after {verdict} ({signal.reason})",
                         by_index=attempt_index + 1)
        sleep(policy.pause_for(attempt_index + 1))

    return ReplayOutcome(verdict, outcome, tuple(ledger.attempts), ledger.to_document())


def _classify_result(result: Any, classify: Callable[[Any], Verdict | Signal | str] | None) -> Signal:
    if isinstance(result, Signal):
        return result
    if isinstance(result, Verdict):
        return Signal(result, "CLASSIFIED")
    if isinstance(result, str):
        try:
            return Signal(Verdict(result), "CLASSIFIED")
        except ValueError as error:
            raise ValueError(f"not a verdict: {result!r}") from error
    if classify is not None:
        classified = classify(result)
        if isinstance(classified, Signal):
            return classified
        return Signal(Verdict(classified), "CLASSIFIED")
    if isinstance(result, Mapping) and "verdict" in result:
        return Signal(Verdict(result["verdict"]), str(result.get("reason") or "REPORTED"))
    return Signal(Verdict.PASS, "NO_CLASSIFIER_SUPPLIED")


@dataclass
class RateWindowPacer:
    """Pace against a rate-limited endpoint, treating an exhausted window as a harness fact.

    ``probe`` should raise an error carrying the HTTP status (Breaker's own transport does) or return
    normally when the window is open. Sleep and clock are injected so the pacing is testable without waiting.
    """

    probe: Callable[[], Any]
    timeout_s: float = 900.0
    default_wait_s: float = 30.0
    max_wait_s: float = 150.0
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], float] = time.monotonic

    def wait(self, label: str = "") -> dict[str, Any]:
        deadline = self.now() + self.timeout_s
        waited = 0.0
        while True:
            try:
                self.probe()
                return {"waited": waited, "label": label, "window": "open"}
            except Exception as error:  # noqa: BLE001 - only a rate window is waited on
                signal = classify_exception(error)
                if signal.reason != "MCP_RATE_WINDOW":
                    return {"waited": waited, "label": label, "window": "closed",
                            "reason": signal.reason, "detail": signal.detail}
                if self.now() >= deadline:
                    return {"waited": waited, "label": label, "window": "timeout"}
                pause = min(getattr(error, "retry_after", None) or self.default_wait_s, self.max_wait_s)
                pause = min(pause, max(0.0, deadline - self.now()))
                self.sleep(pause)
                waited += pause


def wait_for_execution_visibility(fetch: Callable[[str], Any], execution_id: str, *,
                                  timeout_s: float = 120.0, interval_s: float = 1.5,
                                  sleep: Callable[[float], None] = time.sleep,
                                  now: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    """Wait for a delayed execution record to become readable.

    Returns a record with ``visible``. A timeout is reported as an unreadable observation, so a case whose
    execution simply had not appeared yet is never scored as if the execution had produced no effect.
    """
    deadline = now() + timeout_s
    attempts = 0
    last: Any = None
    while True:
        attempts += 1
        try:
            last = fetch(execution_id)
            if last:
                return {"visible": True, "execution_id": execution_id, "attempts": attempts,
                        "execution": last}
        except Exception as error:  # noqa: BLE001 - visibility is the question, not the error
            last = {"error": f"{type(error).__name__}: {error}"}
        if now() >= deadline:
            return {"visible": False, "execution_id": execution_id, "attempts": attempts,
                    "reason": "the execution was not readable before the timeout", "last": last}
        sleep(interval_s)


def blocking_attempts(ledger: ReplayLedger) -> list[Attempt]:
    """Attempts whose verdict blocks a conclusion — the ones a report must show."""
    return [attempt for attempt in ledger.attempts if is_blocking(attempt.verdict)]
