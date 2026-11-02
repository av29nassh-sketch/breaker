"""Generic effect verification: did a real, controlled external effect happen — and exactly how often?

An *effect* is a change outside the subject: a message that arrived in a capture sink, an HTTP object that
now exists, a row a store now holds, a provider object that can be read back. Verification always has the
same shape:

1. take a snapshot *before* the action,
2. let the action run,
3. take a snapshot *after*,
4. compare, and attribute what changed to the action.

The adapters below only know how to **read**. None of them writes to a provider, and none invents a provider
API: every adapter is either a protocol Breaker has actually exercised (a MailHog capture sink, an n8n REST
read, a DataTable read through that same REST API, a provider object read through a reader the target
supplies) or a caller-supplied callable. Providers Breaker has never touched get no abstraction here.

Effect failure modes are explicit rather than inferred, because "nothing happened" and "I could not read"
must never look the same. A snapshot that cannot be read raises :class:`EffectReadFailure`, which the
taxonomy classifies as a harness problem, so an unreachable sink can never be reported as a missing effect.
"""
from __future__ import annotations

import json
import pathlib
import quopri
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence, runtime_checkable

from breaker.verification.checks import Check, failed, inconclusive, passed

#: Values a workflow uses to declare an effect succeeded. Kept explicit so a contradiction can be named.
SUCCESS_EFFECT_VALUES = ("SENT", "SUCCESS", "OK", "CREATED", "DELIVERED", "ACCEPTED", "SYNCED")
#: Values a workflow uses to declare an effect failed.
FAILED_EFFECT_VALUES = ("FAILED", "ERROR", "NOT_SENT", "REJECTED", "TIMEOUT")
#: Values that mean "no effect was attempted" — legitimate, and never evidence of success on their own.
NOT_ATTEMPTED_EFFECT_VALUES = ("NOT_ATTEMPTED", "SKIPPED", "BLOCKED", "SIMULATED", "")


class EffectReadFailure(RuntimeError):
    """A snapshot could not be read. A harness fact, never a statement about the subject."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class EffectKind(StrEnum):
    SMTP_SINK = "SMTP_SINK"
    HTTP_API = "HTTP_API"
    DATA_STORE = "DATA_STORE"
    PROVIDER_OBJECT = "PROVIDER_OBJECT"


@runtime_checkable
class EffectAdapter(Protocol):
    """What every effect adapter must be able to do: name itself, read, and identify."""

    name: str
    kind: str

    def snapshot(self) -> Sequence[Any]:
        ...

    def identity(self, item: Any) -> str | None:
        ...

    def view(self, item: Any) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class EffectWindow:
    """A before/after pair for one adapter, with the attribution already computed."""

    kind: str
    adapter: str
    before: tuple[Any, ...] = ()
    after: tuple[Any, ...] = ()
    matches: tuple[Mapping[str, Any], ...] = ()
    notes: tuple[str, ...] = ()
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def count_before(self) -> int:
        return len(self.before)

    @property
    def count_after(self) -> int:
        return len(self.after)

    @property
    def count_delta(self) -> int:
        return self.count_after - self.count_before

    def as_record(self) -> dict[str, Any]:
        return {"kind": self.kind, "adapter": self.adapter, "count_before": self.count_before,
                "count_after": self.count_after, "count_delta": self.count_delta,
                "matches": [dict(match) for match in self.matches], "notes": list(self.notes),
                **({"detail": dict(self.detail)} if self.detail else {})}


def _identities(items: Iterable[Any], adapter: EffectAdapter) -> list[str]:
    out: list[str] = []
    for item in items:
        identity = adapter.identity(item)
        out.append(str(identity) if identity is not None else f"<unidentified:{id(item)}>")
    return out


# ── adapters ─────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class CallableEffectAdapter:
    """The generic escape hatch: read through a callable the caller already has.

    Used where Breaker reads through a surface the target already owns, so no new coupling is introduced.
    """

    name: str
    kind: str
    read: Callable[[], Sequence[Any]]
    identify: Callable[[Any], str | None]
    describe: Callable[[Any], Mapping[str, Any]] | None = None
    unreachable: Callable[[BaseException], bool] | None = None

    def snapshot(self) -> Sequence[Any]:
        try:
            items = self.read()
        except Exception as error:  # noqa: BLE001 - re-raised as an explicit harness failure
            if self.unreachable and not self.unreachable(error):
                raise
            raise EffectReadFailure(f"{self.name.upper().replace(' ', '_')}_UNREADABLE",
                                    f"{type(error).__name__}: {error}") from error
        return list(items or [])

    def identity(self, item: Any) -> str | None:
        return self.identify(item)

    def view(self, item: Any) -> Mapping[str, Any]:
        return dict(self.describe(item)) if self.describe else {"item": item}


@dataclass
class SmtpSinkAdapter:
    """A MailHog-style capture sink, read over its v2 messages API.

    This is the SMTP effect Breaker has really exercised (Invoice Automation's reminder email and Customer
    Support's support reply). The sink is a *test fixture*, so a capture proves delivery as far as the sink,
    not into a customer mailbox — the distinction is carried in the observations, not left to the reader.
    """

    api_base: str = "http://127.0.0.1:8025"
    container: str | None = None
    limit: int = 100
    timeout: int = 20
    name: str = "capture sink"
    kind: str = str(EffectKind.SMTP_SINK)

    def _fetch(self) -> list[dict]:
        request = urllib.request.Request(f"{self.api_base.rstrip('/')}/api/v2/messages?limit={self.limit}")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        return list(body.get("items") or [])

    def snapshot(self) -> Sequence[Any]:
        try:
            return self._fetch()
        except Exception as error:  # noqa: BLE001
            raise EffectReadFailure("SINK_UNREACHABLE", f"{type(error).__name__}: {error}") from error

    def identity(self, item: Any) -> str | None:
        identifier = (item or {}).get("ID")
        return str(identifier) if identifier is not None else None

    def view(self, item: Any) -> Mapping[str, Any]:
        message = item or {}
        headers = (message.get("Content") or {}).get("Headers") or {}
        first_to = (message.get("To") or [{}])[0] or {}
        subject = headers.get("Subject") or [None]
        raw_body = str((message.get("Content") or {}).get("Body") or "")
        # the sink stores what the SMTP node produced, which is quoted-printable: the observation is what
        # the recipient would read, so it is decoded before anything is compared against it
        try:
            decoded = quopri.decodestring(raw_body.encode("utf-8", "replace")).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - a broken encoding is reported as the raw text
            decoded = raw_body
        from_box = message.get("From") or {}
        return {
            "capture_id": message.get("ID"),
            "from": f"{from_box.get('Mailbox') or ''}@{from_box.get('Domain') or ''}",
            "to": f"{first_to.get('Mailbox') or ''}@{first_to.get('Domain') or ''}",
            "to_header": (headers.get("To") or [None])[0],
            "subject": subject[0] if isinstance(subject, list) else subject,
            "body": decoded,
            "body_raw": raw_body,
            "body_raw_encoding": str((message.get("MIME") or {}).get("ContentTransferEncoding")
                                     or (headers.get("Content-Transfer-Encoding") or [None])[0]),
            "created": (message.get("Created") or ""),
            "size": message.get("Size"),
        }

    def match(self, messages: Sequence[Any], *, to: str | None = None,
              subject: str | None = None, subject_contains: str | None = None,
              body_contains: Sequence[str] = (), from_address: str | None = None) -> Any | None:
        """Find the capture that satisfies the authored *envelope* expectations.

        The body is deliberately not used as a filter here: "no message arrived" and "a message arrived with
        the wrong body" are different findings, and a matcher that filters on the body collapses them into
        one. :func:`message_read_back` checks the body against the capture this returns, so the difference
        survives into the verdict. ``body_contains`` is honoured when a caller passes it directly.
        """
        for message in messages:
            view = self.view(message)
            if to and to not in {view.get("to"), view.get("to_header")}:
                continue
            if from_address and from_address != view.get("from"):
                continue
            if subject is not None and view.get("subject") != subject:
                continue
            if subject_contains and subject_contains not in str(view.get("subject") or ""):
                continue
            if body_contains and not all(str(needle) in str(view.get("body") or "")
                                         for needle in body_contains):
                continue
            return message
        return None


@dataclass
class HttpApiAdapter:
    """A read-only JSON HTTP surface, for HTTP/API effects.

    The caller supplies the URL and the identity key. Nothing about a specific API is assumed: a non-200
    response is a harness read failure, and a payload that is not the expected shape is reported as an
    unreadable snapshot rather than as an empty effect.
    """

    base_url: str
    path: str
    identity_key: str
    headers: Mapping[str, str] = field(default_factory=dict)
    items_key: str | None = None
    timeout: int = 30
    name: str = "http api"
    kind: str = str(EffectKind.HTTP_API)

    def _url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.path.lstrip('/')}"

    def snapshot(self) -> Sequence[Any]:
        request = urllib.request.Request(self._url(), method="GET")
        for key, value in self.headers.items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise EffectReadFailure("HTTP_EFFECT_UNREADABLE",
                                    f"HTTP {error.code} from {self._url()}") from error
        except Exception as error:  # noqa: BLE001
            raise EffectReadFailure("HTTP_EFFECT_UNREADABLE", f"{type(error).__name__}: {error}") from error
        if isinstance(payload, dict) and self.items_key:
            items = payload.get(self.items_key)
            if not isinstance(items, list):
                raise EffectReadFailure("HTTP_EFFECT_UNREADABLE",
                                        f"{self.items_key!r} was not a list")
            return items
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            return [payload]
        raise EffectReadFailure("HTTP_EFFECT_UNREADABLE", f"payload was {type(payload).__name__}")

    def identity(self, item: Any) -> str | None:
        if isinstance(item, Mapping):
            value = item.get(self.identity_key)
            return str(value) if value is not None else None
        return None

    def view(self, item: Any) -> Mapping[str, Any]:
        return dict(item) if isinstance(item, Mapping) else {"item": item}


@dataclass
class ProviderObjectAdapter:
    """Read a provider object back through a reader the target already owns.

    Breaker has not exercised a provider SDK directly: it reads provider state through the workflow's own
    read-back paths (the n8n execution, the candidate's own API reads). This adapter therefore takes the
    reader as a parameter and assumes nothing about the provider. ``fields`` names the object fields the
    authored expectation talks about, so the read-back is comparable.
    """

    name: str
    read: Callable[[], Sequence[Any]]
    identify: Callable[[Any], str | None]
    fields: Sequence[str] = ()
    describe: Callable[[Any], Mapping[str, Any]] | None = None
    kind: str = str(EffectKind.PROVIDER_OBJECT)

    def snapshot(self) -> Sequence[Any]:
        try:
            items = self.read()
        except Exception as error:  # noqa: BLE001
            raise EffectReadFailure("PROVIDER_OBJECT_UNREADABLE",
                                    f"{type(error).__name__}: {error}") from error
        return list(items or [])

    def identity(self, item: Any) -> str | None:
        return self.identify(item)

    def view(self, item: Any) -> Mapping[str, Any]:
        described = dict(self.describe(item)) if self.describe else dict(item or {})
        if self.fields:
            described = {key: described.get(key) for key in self.fields} | {
                key: value for key, value in described.items() if key not in self.fields}
        return described


@dataclass
class DataTableEffectAdapter:
    """A row store read through a reader (n8n DataTable REST, in practice)."""

    name: str
    read: Callable[[], Sequence[Any]]
    identity_field: str = "id"
    kind: str = str(EffectKind.DATA_STORE)

    def snapshot(self) -> Sequence[Any]:
        try:
            return list(self.read() or [])
        except Exception as error:  # noqa: BLE001
            raise EffectReadFailure("DATA_STORE_UNREADABLE",
                                    f"{type(error).__name__}: {error}") from error

    def identity(self, item: Any) -> str | None:
        if isinstance(item, Mapping):
            value = item.get(self.identity_field)
            return str(value) if value is not None else None
        return None

    def view(self, item: Any) -> Mapping[str, Any]:
        return dict(item) if isinstance(item, Mapping) else {"item": item}


# ── primitives ───────────────────────────────────────────────────────────────────────────────────────
def observe(adapter: EffectAdapter) -> tuple[Any, ...]:
    """Take a snapshot. Raises :class:`EffectReadFailure` when the surface cannot be read."""
    return tuple(adapter.snapshot())


def _added(before: Sequence[Any], after: Sequence[Any], adapter: EffectAdapter) -> list[Any]:
    known = set(_identities(before, adapter))
    return [item for item in after if str(adapter.identity(item)) not in known]


def _removed(before: Sequence[Any], after: Sequence[Any], adapter: EffectAdapter) -> list[Any]:
    known = set(_identities(after, adapter))
    return [item for item in before if str(adapter.identity(item)) not in known]


def delta(before: Sequence[Any], after: Sequence[Any], adapter: EffectAdapter, *,
          notes: Iterable[str] = (), detail: Mapping[str, Any] | None = None) -> EffectWindow:
    """The window between two snapshots, with every added item identified."""
    added = _added(before, after, adapter)
    removed = _removed(before, after, adapter)
    matches = tuple({"identity": adapter.identity(item), "view": dict(adapter.view(item))}
                    for item in added)
    return EffectWindow(
        kind=str(adapter.kind), adapter=str(adapter.name), before=tuple(before), after=tuple(after),
        matches=matches, notes=tuple(notes),
        detail={
            "added": [adapter.identity(item) for item in added],
            "removed": [adapter.identity(item) for item in removed],
            "unchanged": sorted(set(_identities(after, adapter)) & set(_identities(before, adapter))),
            **(dict(detail) if detail else {}),
        },
    )


def before_after_counts(window: EffectWindow) -> dict[str, Any]:
    return {"adapter": window.adapter, "kind": window.kind, "before": window.count_before,
            "after": window.count_after, "delta": window.count_delta}


def happened_exactly_once(before: Sequence[Any], after: Sequence[Any], adapter: EffectAdapter, *,
                          name: str = "the effect happened exactly once",
                          match: Callable[[Any], bool] | None = None,
                          expected_delta: int = 1) -> tuple[Check, EffectWindow]:
    """The effect happened, and it happened once.

    ``match`` narrows the observation to the objects the authored case is about. When several objects were
    added, the check still passes only if the authored number is ``expected_delta`` — a workflow that sends
    two emails where the case expected one is a defect, not a rounding error.
    """
    window = delta(before, after, adapter)
    added = list(_added(before, after, adapter))
    counted = [item for item in added if (match(item) if match else True)]
    ok = len(counted) == expected_delta and window.count_delta == expected_delta
    detail = (f"{len(counted)} matching of {len(added)} added "
              f"(count {window.count_before}->{window.count_after})")
    if ok:
        return passed(name, detail, window=window.as_record()), window
    reason = ("the effect did not happen" if not counted else
              f"{len(counted)} effects happened, expected {expected_delta}")
    return failed(name, f"{reason}; {detail}", window=window.as_record()), window


def did_not_happen(before: Sequence[Any], after: Sequence[Any], adapter: EffectAdapter, *,
                   name: str = "no effect happened",
                   match: Callable[[Any], bool] | None = None) -> tuple[Check, EffectWindow]:
    """No effect happened. An unreadable surface raises instead of passing silently."""
    window = delta(before, after, adapter)
    unexpected = [item for item in _added(before, after, adapter)
                  if (match(item) if match else True)]
    ok = not unexpected and window.count_delta == 0
    detail = f"count {window.count_before}->{window.count_after}"
    if ok:
        return passed(name, detail, window=window.as_record()), window
    return failed(name, f"{len(unexpected)} unexpected effect(s); {detail}",
                  window=window.as_record()), window


def object_read_back(after: Sequence[Any], adapter: EffectAdapter, *, identity: str,
                     fields: Sequence[str] = ()) -> dict[str, Any]:
    """Read one provider object back by identity, and return the fields the case cares about."""
    for item in after:
        if str(adapter.identity(item)) == str(identity):
            view = dict(adapter.view(item))
            return {"found": True, "identity": identity, "object": view,
                    "fields": {field: view.get(field) for field in fields}}
    return {"found": False, "identity": identity, "object": None, "fields": {}}


def message_read_back(messages: Sequence[Any], adapter: EffectAdapter, *, to: str | None = None,
                      subject: str | None = None, subject_contains: str | None = None,
                      body_contains: Sequence[str] = (), from_address: str | None = None,
                      name: str = "the message was captured with the authored headers and body"
                      ) -> tuple[Check, Mapping[str, Any]]:
    """Sink/message read-back: find the capture and check the authored expectations against it."""
    matcher = getattr(adapter, "match", None)
    # the envelope identifies the capture; the body is then checked against it, so a wrong body is reported
    # as a wrong body instead of as a missing message
    found = matcher(messages, to=to, subject=subject, subject_contains=subject_contains,
                    from_address=from_address) if matcher else None
    if found is None:
        return failed(name, f"no capture matched to={to!r} subject={subject!r} "
                            f"contains={list(body_contains)!r}"), {}
    view = dict(adapter.view(found))
    missing = [needle for needle in body_contains if str(needle) not in str(view.get("body") or "")]
    if missing:
        return failed(name, f"capture found but the body is missing {missing!r}"), view
    return passed(name, f"capture {view.get('capture_id')} to {view.get('to')!r}",
                  **{"view": view}), view


def duplicate_rerun_produced_no_second_effect(first: EffectWindow, rerun: EffectWindow, *,
                                              name: str = "the duplicate rerun produced no second effect"
                                              ) -> Check:
    """A redelivered input must not produce a second effect.

    Both windows are required: the first must have produced an effect, otherwise "no second effect" is
    vacuously true and proves nothing.
    """
    if first.count_delta < 1:
        # "no second effect" is vacuously true if the first run never produced one, so this is an
        # unusable observation rather than a product defect
        return inconclusive(name, "the first run produced no effect, so the rerun proves nothing",
                            first=first.as_record(), rerun=rerun.as_record())
    ok = rerun.count_delta == 0
    detail = f"first delta {first.count_delta}, rerun delta {rerun.count_delta}"
    if ok:
        return passed(name, detail, first=first.as_record(), rerun=rerun.as_record())
    return failed(name, f"the rerun added {rerun.count_delta} effect(s); {detail}",
                  first=first.as_record(), rerun=rerun.as_record())


def failure_did_not_record_false_success(*, effect_status: Any, effect_observed: bool,
                                         ledger_status: Any = None, transport_ok: bool = True,
                                         name: str = "a failed effect was not recorded as success"
                                         ) -> Check:
    """A failed send must not be recorded as a success.

    Guards the specific shape where the send node errors, the workflow takes the failure branch, and the
    ledger still ends up carrying a success value (or the reverse: a real capture with a FAILED status).
    """
    status = str(effect_status or "").strip().upper()
    ledger = str(ledger_status or "").strip().upper()
    declared_success = status in SUCCESS_EFFECT_VALUES or ledger in SUCCESS_EFFECT_VALUES
    declared_failure = status in FAILED_EFFECT_VALUES or ledger in FAILED_EFFECT_VALUES
    if not transport_ok and declared_success:
        return failed(name, f"the transport failed but the status says {status or ledger!r}")
    if declared_success and not effect_observed:
        return failed(name, f"status {status or ledger!r} claims success with no observed effect")
    if declared_failure and effect_observed:
        return failed(name, f"status {status or ledger!r} claims failure but the effect was observed")
    return passed(name, f"status {status or ledger or '--'!r}, observed={effect_observed}")
