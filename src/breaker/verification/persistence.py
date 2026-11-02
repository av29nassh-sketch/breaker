"""Generic persistence read-back, attributed to one run.

The question this layer answers is not "is there a row?" but **"is this row evidence about *this* run?"**
Customer Support's verification got that wrong in a way worth remembering: a check with a one-second
tolerance matched a row written 0.4 s earlier by the previous case, because the transport stamps whole
seconds. The row was real, the identity was right, and the attribution was still wrong.

So attribution is explicit, ordered strongest-first, and the strategy that matched is always reported:

1. ``run_id`` — the workflow's own run identifier, when the store carries it.
2. ``execution_id`` — the platform's execution identifier.
3. **stable identity** — the authored key that identifies the subject (a message key, a conversation key,
   an invoice id). Strong, but only unique within a run if the subject is genuinely per-run.
4. **precise updated_at window** — weakest. Used only when nothing stronger exists, default tolerance is
   zero, and every row it matches is marked ``weak`` so a caller can refuse it.

Broad time-window matching is never the primary evidence here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence, runtime_checkable

from breaker.verification.checks import Check, failed, inconclusive, passed

#: Preference order for attribution strategies.
ATTRIBUTION_ORDER = ("RUN_ID", "EXECUTION_ID", "STABLE_IDENTITY", "UPDATED_AT_WINDOW")

RUN_ID_FIELDS = ("run_id", "run", "breaker_run_id")
EXECUTION_ID_FIELDS = ("execution_id", "executionId", "execution")
TIME_FIELDS = ("updated_at", "updatedAt", "last_updated", "created_at", "createdAt", "written_at")


class AttributionStrategy(StrEnum):
    RUN_ID = "RUN_ID"
    EXECUTION_ID = "EXECUTION_ID"
    STABLE_IDENTITY = "STABLE_IDENTITY"
    UPDATED_AT_WINDOW = "UPDATED_AT_WINDOW"
    NONE = "NONE"


def _parse_time(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    for candidate in (text, text[:19], text.replace(" ", "T")[:19]):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _first_present(row: Mapping[str, Any], names: Sequence[str]) -> tuple[str | None, Any]:
    for name in names:
        if name in row and row.get(name) not in (None, ""):
            return name, row.get(name)
    return None, None


@dataclass(frozen=True)
class AttributionMatch:
    """Whether one row is evidence about the attributed run, and which rule decided it."""

    matched: bool
    matched_by: str = str(AttributionStrategy.NONE)
    detail: str = ""
    weak: bool = False
    conflicts: tuple[str, ...] = ()

    def as_record(self) -> dict[str, Any]:
        return {"matched": self.matched, "matched_by": self.matched_by, "detail": self.detail,
                "weak": self.weak, "conflicts": list(self.conflicts)}


@dataclass(frozen=True)
class RunAttribution:
    """Everything known about the run a set of rows must be attributed to."""

    run_id: str | None = None
    execution_id: str | None = None
    identity: Mapping[str, Any] = field(default_factory=dict)
    started_at: Any = None
    stopped_at: Any = None
    tolerance_s: float = 0.0
    identity_fields: tuple[str, ...] = ()

    def strength(self) -> str:
        for name, value in (("RUN_ID", self.run_id), ("EXECUTION_ID", self.execution_id)):
            if value not in (None, ""):
                return name
        if self.identity:
            return "STABLE_IDENTITY"
        if self.started_at and self.stopped_at:
            return "UPDATED_AT_WINDOW"
        return str(AttributionStrategy.NONE)

    def available(self) -> tuple[str, ...]:
        present: list[str] = []
        if self.run_id not in (None, ""):
            present.append("RUN_ID")
        if self.execution_id not in (None, ""):
            present.append("EXECUTION_ID")
        if self.identity:
            present.append("STABLE_IDENTITY")
        if self.started_at and self.stopped_at:
            present.append("UPDATED_AT_WINDOW")
        return tuple(present)

    def attribute(self, row: Mapping[str, Any]) -> AttributionMatch:
        conflicts: list[str] = []

        if self.run_id not in (None, ""):
            column, value = _first_present(row, RUN_ID_FIELDS)
            if column is not None:
                if str(value) == str(self.run_id):
                    return AttributionMatch(True, "RUN_ID", f"{column}={value!r}")
                if self._identity_matches(row):
                    conflicts.append(f"{column}={value!r} does not equal this run's {self.run_id!r}")
                return AttributionMatch(False, str(AttributionStrategy.NONE),
                                        f"{column}={value!r} != run {self.run_id!r}",
                                        conflicts=tuple(conflicts))

        if self.execution_id not in (None, ""):
            column, value = _first_present(row, EXECUTION_ID_FIELDS)
            if column is not None:
                if str(value) == str(self.execution_id):
                    return AttributionMatch(True, "EXECUTION_ID", f"{column}={value!r}")
                if self._identity_matches(row):
                    conflicts.append(f"{column}={value!r} does not equal execution {self.execution_id!r}")
                return AttributionMatch(False, str(AttributionStrategy.NONE),
                                        f"{column}={value!r} != execution {self.execution_id!r}",
                                        conflicts=tuple(conflicts))

        if self.identity and self._identity_matches(row):
            if any(name in row for name in RUN_ID_FIELDS + EXECUTION_ID_FIELDS):
                # the store carries run markers and this row has none of them: identity alone is not enough
                return AttributionMatch(False, str(AttributionStrategy.NONE),
                                        "the row carries a stable identity but no run marker",
                                        weak=True)
            return AttributionMatch(True, "STABLE_IDENTITY",
                                    f"identity {dict(self.identity)!r}")

        window = self._window_match(row)
        if window is not None:
            return window
        return AttributionMatch(False, str(AttributionStrategy.NONE),
                                "no run marker, identity or time column matched", conflicts=tuple(conflicts))

    def _identity_matches(self, row: Mapping[str, Any]) -> bool:
        if not self.identity:
            return False
        return all(str(row.get(key)) == str(value) for key, value in self.identity.items())

    def _window_match(self, row: Mapping[str, Any]) -> AttributionMatch | None:
        if not (self.started_at and self.stopped_at):
            return None
        start, stop = _parse_time(self.started_at), _parse_time(self.stopped_at)
        if start is None or stop is None:
            return None
        column, value = _first_present(row, TIME_FIELDS)
        stamped = _parse_time(value)
        if column is None or stamped is None:
            return None
        tolerance = timedelta(seconds=float(self.tolerance_s))
        inside = (start - tolerance) <= stamped <= (stop + tolerance)
        if inside:
            return AttributionMatch(
                True, "UPDATED_AT_WINDOW",
                f"{column}={value!r} inside [{self.started_at}, {self.stopped_at}] "
                f"(tolerance {self.tolerance_s}s)", weak=True)
        return None


@dataclass(frozen=True)
class AttributedRows:
    """Rows split by whether they are evidence about this run."""

    mine: tuple[Mapping[str, Any], ...] = ()
    other: tuple[Mapping[str, Any], ...] = ()
    stale: tuple[Mapping[str, Any], ...] = ()
    matches: tuple[Mapping[str, Any], ...] = ()
    attribution: Mapping[str, Any] = field(default_factory=dict)
    weak: bool = False
    unreadable: str | None = None

    @property
    def count(self) -> int:
        return len(self.mine)

    def as_record(self) -> dict[str, Any]:
        return {
            "attributed_rows": [dict(row) for row in self.mine],
            "other_rows": len(self.other),
            "stale_rows": [dict(row) for row in self.stale],
            "matched_by": sorted({match.get("matched_by") for match in self.matches}),
            "weak": self.weak,
            "attribution": dict(self.attribution),
            **({"unreadable": self.unreadable} if self.unreadable else {}),
        }


def rows_written_by_this_run(rows: Sequence[Mapping[str, Any]], attribution: RunAttribution,
                             *, identity_keys: Sequence[str] = ()) -> AttributedRows:
    """Split rows into this run's rows, other rows, and *stale* rows about the same subject.

    Stale rows are the interesting ones: they share the authored identity (same message key, same invoice)
    but are not attributable to this run, which is exactly the contamination shape that made a previous
    case's row look like this case's evidence.
    """
    mine: list[Mapping[str, Any]] = []
    other: list[Mapping[str, Any]] = []
    stale: list[Mapping[str, Any]] = []
    matches: list[dict[str, Any]] = []
    for row in rows:
        match = attribution.attribute(row)
        record = {"row": dict(row), **match.as_record()}
        matches.append(record)
        if match.matched:
            mine.append(row)
            continue
        other.append(row)
        keys = identity_keys or tuple(attribution.identity)
        if keys and all(key in row for key in keys) and all(
                str(row.get(key)) == str(attribution.identity.get(key)) for key in keys):
            stale.append(row)
    weak = any(match.get("weak") for match in matches if match.get("matched"))
    keys = tuple(identity_keys) or tuple(attribution.identity)
    identity_supplied = all(key in attribution.identity for key in keys) if keys else False
    return AttributedRows(
        mine=tuple(mine), other=tuple(other), stale=tuple(stale), matches=tuple(matches),
        attribution={"run_id": attribution.run_id, "execution_id": attribution.execution_id,
                     "identity": dict(attribution.identity),
                     "started_at": str(attribution.started_at), "stopped_at": str(attribution.stopped_at),
                     "tolerance_s": attribution.tolerance_s, "available": list(attribution.available()),
                     "strength": attribution.strength(),
                     # a caller must be able to see that stale detection was unavailable, rather than
                     # reading "no stale rows" as a clean result
                     "stale_detection": "APPLIED" if identity_supplied else
                                        "UNAVAILABLE_NO_IDENTITY_IN_ATTRIBUTION"},
        weak=weak)


# ── assertions ───────────────────────────────────────────────────────────────────────────────────────
def exact_row_count(rows: AttributedRows | Sequence[Mapping[str, Any]], expected: int, *,
                    name: str | None = None) -> Check:
    attributed = isinstance(rows, AttributedRows)
    label = name or "the run wrote exactly the authored number of rows"
    if attributed and rows.unreadable:
        # a store that could not be read is not a store with zero rows
        return inconclusive(label, f"the store could not be read: {rows.unreadable}")
    actual = rows.count if attributed else len(rows)
    detail = f"{actual} attributed row(s), authored {expected}"
    return passed(label, detail) if actual == expected else failed(label, detail)


def required_fields(rows: Iterable[Mapping[str, Any]], fields: Sequence[str], *,
                    name: str | None = None) -> Check:
    """Every named field must be present and non-empty."""
    rows = list(rows)
    label = name or f"the rows carry {list(fields)!r}"
    if not rows:
        return failed(label, "there are no rows to check")
    missing: list[str] = []
    for index, row in enumerate(rows):
        for field_name in fields:
            value = row.get(field_name)
            if value in (None, "", []):
                missing.append(f"row {index}: {field_name}={value!r}")
    return passed(label, f"{len(rows)} row(s) complete") if not missing else failed(
        label, "; ".join(missing[:6]))


def forbidden_values(rows: Iterable[Mapping[str, Any]], forbidden: Mapping[str, Any], *,
                     name: str | None = None) -> Check:
    """No row may carry a forbidden value (a state a case must never leave behind)."""
    rows = list(rows)
    label = name or "no forbidden values were stored"
    offences: list[str] = []
    for index, row in enumerate(rows):
        for field_name, unwanted in forbidden.items():
            allowed = unwanted if isinstance(unwanted, (list, tuple, set)) else [unwanted]
            if field_name in row and row.get(field_name) in allowed:
                offences.append(f"row {index}: {field_name}={row.get(field_name)!r}")
    return passed(label, f"{len(rows)} row(s) clean") if not offences else failed(
        label, "; ".join(offences[:6]))


def no_duplicate_row(rows: Sequence[Mapping[str, Any]], *, identity_keys: Sequence[str],
                     name: str | None = None) -> Check:
    """One row per identity, not two."""
    label = name or f"no duplicate row for {list(identity_keys)!r}"
    seen: dict[tuple, int] = {}
    for row in list(rows):
        key = tuple(str(row.get(column)) for column in identity_keys)
        seen[key] = seen.get(key, 0) + 1
    duplicates = {key: count for key, count in seen.items() if count > 1}
    if not seen:
        return failed(label, "there are no rows to check")
    return passed(label, f"{len(seen)} distinct row(s)") if not duplicates else failed(
        label, f"duplicated: {duplicates}")


def no_stale_row_contamination(attributed: AttributedRows, *, name: str | None = None) -> Check:
    """No row shares the authored identity without belonging to this run."""
    label = name or "no stale row shares this run's identity"
    if attributed.stale:
        return failed(label, f"{len(attributed.stale)} stale row(s): "
                             f"{[dict(row) for row in attributed.stale][:2]}")
    return passed(label, f"{attributed.count} attributed row(s), 0 stale")


def updated_in_place(before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]], *,
                     identity_keys: Sequence[str], changed_fields: Sequence[str] = (),
                     name: str | None = None) -> Check:
    """A second run over the same subject updates its row instead of adding another one."""
    label = name or "the row was updated in place"
    before_index = {tuple(str(row.get(column)) for column in identity_keys): row for row in before}
    after_index = {tuple(str(row.get(column)) for column in identity_keys): row for row in after}
    added = [key for key in after_index if key not in before_index]
    if added:
        return failed(label, f"{len(added)} new row(s) instead of an update: {added[:3]}")
    removed = [key for key in before_index if key not in after_index]
    if removed:
        return failed(label, f"{len(removed)} row(s) disappeared: {removed[:3]}")
    unchanged = [key for key in after_index
                 if changed_fields and all(before_index[key].get(column) == after_index[key].get(column)
                                           for column in changed_fields)]
    if changed_fields and unchanged:
        return failed(label, f"the authored fields did not change for {unchanged[:3]}")
    return passed(label, f"{len(after_index)} row(s), no insert, "
                         f"changed {list(changed_fields)!r}")


def state_before_after(before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]], *,
                       identity_keys: Sequence[str], fields: Sequence[str], name: str | None = None
                       ) -> tuple[Check, dict[str, Any]]:
    """Report and check each field's transition for the authored identity."""
    label = name or "the state transitioned as authored"
    before_index = {tuple(str(row.get(column)) for column in identity_keys): row for row in before}
    after_index = {tuple(str(row.get(column)) for column in identity_keys): row for row in after}
    shared = [key for key in after_index if key in before_index]
    if not shared:
        return failed(label, "no row with the authored identity exists before and after"), {}
    transitions: dict[str, Any] = {}
    for key in shared:
        # keyed by the identity joined readably, so a report can show which row transitioned
        label_key = "|".join(str(part) for part in key)
        transitions[label_key] = {field_name: {"before": before_index[key].get(field_name),
                                               "after": after_index[key].get(field_name)}
                                  for field_name in fields}
    return passed(label, f"{len(shared)} row(s), fields {list(fields)!r}"), transitions


# ── store readers ────────────────────────────────────────────────────────────────────────────────────
@runtime_checkable
class StoreReader(Protocol):
    """Anything that can hand back the rows of a named collection."""

    def rows(self, collection: str) -> Sequence[Mapping[str, Any]]:
        ...


@dataclass
class RowsFromCallable:
    """Adapt an existing reader (a target's ``_rows``, in practice) without new coupling."""

    read: Callable[[str], Sequence[Mapping[str, Any]]]

    def rows(self, collection: str) -> Sequence[Mapping[str, Any]]:
        return list(self.read(collection) or [])


@dataclass
class DataTableStore:
    """Rows of an n8n DataTable, read through a caller-supplied GET.

    The caller supplies the transport (Breaker's existing n8n REST helper), so this class carries no
    credentials and assumes nothing about the instance.
    """

    get: Callable[[str], Any]
    route: str = "/data-tables/{collection}/rows?limit=250"
    rows_key: str = "data"

    def rows(self, collection: str) -> Sequence[Mapping[str, Any]]:
        payload = self.get(self.route.format(collection=collection))
        if isinstance(payload, Mapping):
            rows = payload.get(self.rows_key)
            return list(rows or [])
        return list(payload or [])


@dataclass
class AttributedStore:
    """A store plus the attribution to apply when reading from it."""

    store: Any
    attribution: RunAttribution

    def rows_for_run(self, collection: str, *, identity_keys: Sequence[str] = ()) -> AttributedRows:
        try:
            rows = list(self.store.rows(collection) or [])
        except Exception as error:  # noqa: BLE001 - an unreadable store is reported, never counted as empty
            return AttributedRows(unreadable=f"{type(error).__name__}: {error}",
                                  attribution={"collection": collection})
        return rows_written_by_this_run(rows, self.attribution, identity_keys=identity_keys)
