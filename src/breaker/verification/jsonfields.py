"""Validators for storage fields that are lists serialized into text columns.

The failure this exists to catch is a *double* serialization: one write path stores
``["KB-001"]`` as JSON text, a later path reads that text back and stores it again, and the column ends up
holding ``"\\"[\\\\\\"KB-001\\\\\\"]\\""``. Reading it once yields a string, reading it twice yields the
array, and every naive ``json.loads`` in the middle looks like it worked.

The rule this module enforces: **the column holds exactly one JSON serialization of the list, and reading
that text once produces an array.** So :func:`inspect_stored_list` reports how many parses were needed and
whether the first parse already produced the array, and the assertions refuse the second parse.

Historical regression fixture: Customer Support's ``knowledge_refs`` column stored
``"\\"[\\\\\\"KB-001\\\\\\"]\\""`` while the workflow's own terminal payload reported the array correctly.
"""
from __future__ import annotations

import json
from enum import StrEnum
from typing import Any, Mapping, Sequence

#: Columns Breaker has actually seen serialized into text. A field outside this list can still be checked;
#: it just has to be named explicitly, so no abstraction is invented for storage Breaker has never read.
CANONICAL_LIST_FIELDS = (
    "knowledge_refs",
    "candidate_ids",
    "external_ids",
    "tags",
    "shipped_ids",
    "scored_ids",
    "available_ids",
    "blocked_ids",
    "sink_ids",
    "effect_ids",
)


class StoredListState(StrEnum):
    MISSING = "MISSING"
    NULL = "NULL"
    EMPTY = "EMPTY"
    ARRAY = "ARRAY"
    JSON_TEXT_SINGLE = "JSON_TEXT_SINGLE"
    DOUBLE_ENCODED = "DOUBLE_ENCODED"
    NOT_A_LIST = "NOT_A_LIST"
    INVALID = "INVALID"


def _object_key(value: Any) -> str | None:
    if isinstance(value, Mapping):
        return value.get("__error__")
    return None


def inspect_stored_list(value: Any) -> dict[str, Any]:
    """Inspect a stored list field without assuming how it was written.

    Returns a record with ``state``, ``parsed`` (the best reading available), ``parses`` (how many JSON
    parses were needed to reach an array) and ``single_serialization`` (the property the assertions use).
    """
    if value is None:
        return {"state": str(StoredListState.NULL), "parsed": None, "parses": 0,
                "single_serialization": False, "reason": "the column is null"}
    if isinstance(value, (list, tuple)):
        return {"state": str(StoredListState.ARRAY), "parsed": list(value), "parses": 0,
                "single_serialization": True, "reason": "already an array"}
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {"state": str(StoredListState.EMPTY), "parsed": [], "parses": 0,
                    "single_serialization": True, "reason": "empty string"}
        first: Any
        try:
            first = json.loads(text)
        except json.JSONDecodeError as error:
            return {"state": str(StoredListState.INVALID), "parsed": None, "parses": 0,
                    "single_serialization": False, "reason": f"not JSON: {error.msg}"}
        if isinstance(first, list):
            items = [item for item in first if not _object_key(item)]
            return {"state": str(StoredListState.JSON_TEXT_SINGLE), "parsed": items, "parses": 1,
                    "single_serialization": True, "reason": "one serialization, parses to an array"}
        if isinstance(first, str):
            # a string inside a string: the classic double encoding
            inner: Any
            try:
                inner = json.loads(first)
            except json.JSONDecodeError:
                return {"state": str(StoredListState.NOT_A_LIST), "parsed": first, "parses": 1,
                        "single_serialization": False,
                        "reason": "a JSON string that does not contain JSON"}
            if isinstance(inner, list):
                return {"state": str(StoredListState.DOUBLE_ENCODED), "parsed": inner, "parses": 2,
                        "single_serialization": False,
                        "reason": "double encoded: the stored text is a JSON string holding the array"}
            return {"state": str(StoredListState.NOT_A_LIST), "parsed": inner, "parses": 2,
                    "single_serialization": False, "reason": f"parses to {type(inner).__name__}"}
        return {"state": str(StoredListState.NOT_A_LIST), "parsed": first, "parses": 1,
                "single_serialization": False,
                "reason": f"a single parse produced {type(first).__name__}, not a list"}
    return {"state": str(StoredListState.NOT_A_LIST), "parsed": value, "parses": 0,
            "single_serialization": False, "reason": f"stored as {type(value).__name__}"}


def valid_json_text(value: Any) -> dict[str, Any]:
    """Is this column valid JSON text at all?"""
    if not isinstance(value, str):
        return {"ok": value is None or isinstance(value, (list, tuple)),
                "reason": "not text" if not isinstance(value, (list, tuple)) else "already structured"}
    try:
        json.loads(value)
    except json.JSONDecodeError as error:
        return {"ok": False, "reason": f"invalid JSON: {error.msg}"}
    return {"ok": True, "reason": "valid JSON text"}


def assert_single_serialization(value: Any, *, field: str = "value") -> dict[str, Any]:
    """The column must hold exactly one JSON serialization of the list."""
    state = inspect_stored_list(value)
    ok = bool(state["single_serialization"])
    return {"ok": ok, "field": field, "state": state["state"], "parsed": state["parsed"],
            "parses": state["parses"],
            "reason": state["reason"] if ok else f"{field}: {state['reason']}"}


def assert_parsed_is_array(value: Any, *, field: str = "value") -> dict[str, Any]:
    state = inspect_stored_list(value)
    ok = isinstance(state["parsed"], list) and bool(state["single_serialization"])
    return {"ok": ok, "field": field, "state": state["state"], "parsed": state["parsed"],
            "reason": f"{field}: parsed value is {type(state['parsed']).__name__}"
                      if not ok else f"{field}: array"}


def assert_items_match_expected(value: Any, expected: Sequence[Any], *, field: str = "value",
                                exact: bool = False) -> dict[str, Any]:
    """The parsed items must match the expected set (order-insensitive unless ``exact``)."""
    state = inspect_stored_list(value)
    parsed = state["parsed"] if isinstance(state["parsed"], list) else []
    if exact:
        ok = list(parsed) == list(expected)
    else:
        ok = sorted(map(str, parsed)) == sorted(map(str, expected))
    return {"ok": bool(ok), "field": field, "state": state["state"], "parsed": parsed,
            "expected": list(expected), "exact": exact,
            "reason": f"{field}: {parsed!r} vs expected {list(expected)!r}"}


def canonical_list(value: Any) -> str:
    """The writer contract: exactly one serialization of a list, whatever came in.

    Accepts an array, JSON text of an array, or JSON text of a JSON string holding an array, and always
    returns one JSON serialization of the array. This is the function a workflow's own writer should be
    equivalent to; having it here lets a harness check stored state against the same contract the writer
    promises.
    """
    state = inspect_stored_list(value)
    if state["state"] == str(StoredListState.INVALID):
        raise ValueError(f"cannot canonicalize a list field: {state['reason']}")
    parsed = state["parsed"] if isinstance(state["parsed"], list) else []
    return json.dumps(parsed, ensure_ascii=False)
