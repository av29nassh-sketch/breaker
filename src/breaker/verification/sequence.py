"""Sequence-aware cases: authored dependencies instead of accidental execution order.

Breaker has repeatedly had cases where A creates state and B depends on it. Relying on "the pack happens to
list them in this order" works until a case is filtered, replayed or reordered — and then B runs against
whatever A left behind last time, which is how a replay can quietly prove the wrong thing.

The dependency information belongs in the case metadata or the contract, never in adapter code. A case
declares:

* ``depends_on`` — case ids that must have run and produced their state first;
* ``setup_case`` — a case that exists to create state for others, not to be judged on its own;
* ``shared_fixture_scope`` — the fixture group the case belongs to, so resets happen per group;
* ``reset_policy`` — when state may be cleared around this case (see :class:`ResetPolicy`).

Everything here is deterministic and side-effect free: it orders and validates, it does not run anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence


class ResetPolicy(StrEnum):
    """When state may be cleared around a case. Resets are never implicit."""

    NEVER = "NEVER"
    ONCE_PER_RUN = "ONCE_PER_RUN"
    PER_CASE = "PER_CASE"
    PER_FIXTURE_SCOPE = "PER_FIXTURE_SCOPE"

    @property
    def clears_before_case(self) -> bool:
        return self in (ResetPolicy.PER_CASE, ResetPolicy.PER_FIXTURE_SCOPE)


@dataclass(frozen=True)
class CaseSequence:
    """The authored sequencing metadata of one case."""

    case_id: str
    depends_on: tuple[str, ...] = ()
    setup_case: str | None = None
    shared_fixture_scope: str | None = None
    reset_policy: str = str(ResetPolicy.ONCE_PER_RUN)
    declared_index: int = 0
    notes: str = ""

    @property
    def is_setup_only(self) -> bool:
        """A case referenced as another case's setup is not judged on its own."""
        return bool(self.setup_case)

    def as_record(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "depends_on": list(self.depends_on),
                "setup_case": self.setup_case, "shared_fixture_scope": self.shared_fixture_scope,
                "reset_policy": self.reset_policy, "declared_index": self.declared_index,
                **({"notes": self.notes} if self.notes else {})}


def sequence_from_metadata(case: Mapping[str, Any], *, index: int = 0) -> CaseSequence:
    """Read the sequence block out of a case, a case pack entry or a contract case.

    Accepts either a nested ``sequence``/``sequencing`` block or the fields at the top level, because
    existing packs carry a flat shape and contracts carry a nested one. Nothing here knows about a
    particular workflow.
    """
    block: Mapping[str, Any] = {}
    for key in ("sequence", "sequencing", "case_sequence"):
        candidate = case.get(key)
        if isinstance(candidate, Mapping):
            block = candidate
            break
    merged = {**{key: case.get(key) for key in
                 ("depends_on", "setup_case", "shared_fixture_scope", "reset_policy", "sequence_index")},
              **block}
    depends = merged.get("depends_on") or ()
    if isinstance(depends, str):
        depends = (depends,)
    declarer = merged.get("setup_case") or merged.get("requires_setup_case")
    scope = merged.get("shared_fixture_scope") or merged.get("fixture_scope")
    return CaseSequence(
        case_id=str(case.get("case_id") or case.get("id") or ""),
        depends_on=tuple(str(item) for item in depends),
        setup_case=str(declarer) if declarer else None,
        shared_fixture_scope=str(scope) if scope else None,
        reset_policy=str(merged.get("reset_policy") or ResetPolicy.ONCE_PER_RUN),
        declared_index=int(merged.get("sequence_index", index) or index),
        notes=str(merged.get("sequence_notes") or ""),
    )


@dataclass
class SequenceValidation:
    ok: bool = True
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def as_record(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": list(self.errors), "warnings": list(self.warnings)}


def validate_sequence(cases: Sequence[CaseSequence | Mapping[str, Any]]) -> SequenceValidation:
    """Validate dependencies, cycles, reset conflicts and declared ordering."""
    resolved = [case if isinstance(case, CaseSequence) else sequence_from_metadata(case, index=index)
                for index, case in enumerate(cases)]
    ids = [case.case_id for case in resolved]
    errors: list[str] = []
    warnings: list[str] = []

    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        errors.append(f"duplicate case ids: {duplicates}")

    known = set(ids)
    for case in resolved:
        for dependency in case.depends_on:
            if dependency not in known:
                errors.append(f"{case.case_id}: depends_on references an unknown case {dependency!r}")
        if case.setup_case and case.setup_case not in known:
            errors.append(f"{case.case_id}: setup_case references an unknown case {case.setup_case!r}")
        if case.case_id in case.depends_on:
            errors.append(f"{case.case_id}: depends on itself")
        try:
            ResetPolicy(case.reset_policy)
        except ValueError:
            errors.append(f"{case.case_id}: unknown reset_policy {case.reset_policy!r}")

    # declared order must already respect dependencies, otherwise a filtered replay can be wrong
    position = {case.case_id: index for index, case in enumerate(resolved)}
    for case in resolved:
        for dependency in case.depends_on:
            if dependency in position and position[dependency] > position[case.case_id]:
                warnings.append(f"{case.case_id}: declared before its dependency {dependency} "
                                f"(resolve_order will fix the order)")

    # cycles
    graph = {case.case_id: set(case.depends_on) for case in resolved}
    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(node: str, path: list[str]) -> None:
        if node in permanent:
            return
        if node in temporary:
            errors.append(f"dependency cycle: {' -> '.join(path + [node])}")
            return
        temporary.add(node)
        for neighbour in sorted(graph.get(node, ())):
            visit(neighbour, path + [node])
        temporary.discard(node)
        permanent.add(node)

    for case_id in sorted(graph):
        visit(case_id, [])

    # reset policy conflicts inside one fixture scope
    scopes: dict[str, list[CaseSequence]] = {}
    for case in resolved:
        if case.shared_fixture_scope:
            scopes.setdefault(str(case.shared_fixture_scope), []).append(case)
    for scope, members in scopes.items():
        policies = {member.reset_policy for member in members}
        if len(policies) > 1:
            errors.append(f"fixture scope {scope!r} mixes reset policies {sorted(policies)}")
        if ResetPolicy.PER_CASE in {ResetPolicy(policy) for policy in policies} and len(members) > 1:
            warnings.append(f"fixture scope {scope!r} clears per case, so its shared fixture is rebuilt "
                            f"for each of {len(members)} cases")

    return SequenceValidation(ok=not errors, errors=tuple(errors), warnings=tuple(warnings))


def resolve_order(cases: Sequence[CaseSequence | Mapping[str, Any]]) -> list[CaseSequence]:
    """A deterministic order that satisfies every declared dependency.

    Ties are broken by the authored index and then by case id, so the order is stable across runs and
    filterings. Raises on a cycle or an unknown dependency, because silently dropping either would make a
    replay prove the wrong thing.
    """
    resolved = [case if isinstance(case, CaseSequence) else sequence_from_metadata(case, index=index)
                for index, case in enumerate(cases)]
    validation = validate_sequence(resolved)
    fatal = [error for error in validation.errors
             if not error.startswith("duplicate case ids")]
    if fatal:
        raise ValueError("cannot order cases: " + "; ".join(fatal))

    remaining = {case.case_id: case for case in resolved}
    ordered: list[CaseSequence] = []
    satisfied: set[str] = set()
    while remaining:
        ready = [case for case in remaining.values()
                 if all(dependency in satisfied for dependency in case.depends_on)]
        if not ready:
            raise ValueError("cannot order cases: no case is ready, the graph has a cycle")
        ready.sort(key=lambda case: (case.declared_index, case.case_id))
        chosen = ready[0]
        ordered.append(chosen)
        satisfied.add(chosen.case_id)
        remaining.pop(chosen.case_id)
    return ordered


def dependency_chain(case_id: str, cases: Sequence[CaseSequence | Mapping[str, Any]]) -> list[str]:
    """The prerequisites of a case, in the order they must run (useful for replay provenance)."""
    by_id = {case.case_id: case for case in
             (item if isinstance(item, CaseSequence) else sequence_from_metadata(item, index=index)
              for index, item in enumerate(cases))}
    chain: list[str] = []
    seen: set[str] = set()

    def walk(node: str) -> None:
        if node in seen:
            return
        seen.add(node)
        case = by_id.get(node)
        if case is None:
            return
        # the setup case creates the state the chain depends on, so it comes first; the declared
        # dependencies follow depth-first, and each is appended after its own prerequisites
        if case.setup_case:
            walk(case.setup_case)
        for dependency in case.depends_on:
            walk(dependency)
        if node != case_id:
            chain.append(node)

    walk(case_id)
    return chain


def group_by_fixture_scope(cases: Sequence[CaseSequence | Mapping[str, Any]]
                           ) -> list[dict[str, Any]]:
    """Group cases by fixture scope, with the reset action each group implies."""
    resolved = [case if isinstance(case, CaseSequence) else sequence_from_metadata(case, index=index)
                for index, case in enumerate(cases)]
    groups: dict[str, list[CaseSequence]] = {}
    ungrouped: list[CaseSequence] = []
    for case in resolved:
        if case.shared_fixture_scope:
            groups.setdefault(str(case.shared_fixture_scope), []).append(case)
        else:
            ungrouped.append(case)
    out: list[dict[str, Any]] = []
    for scope, members in sorted(groups.items()):
        policy = str(members[0].reset_policy)
        out.append({
            "shared_fixture_scope": scope,
            "cases": [member.case_id for member in members],
            "reset_policy": policy,
            "reset_action": _reset_action(ResetPolicy(policy), members),
        })
    if ungrouped:
        for policy in sorted({str(case.reset_policy) for case in ungrouped}):
            members = [case for case in ungrouped if str(case.reset_policy) == policy]
            out.append({
                "shared_fixture_scope": None,
                "cases": [member.case_id for member in members],
                "reset_policy": policy,
                "reset_action": _reset_action(ResetPolicy(policy), members),
            })
    return out


def reset_plan(cases: Sequence[CaseSequence | Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Per case, whether state is cleared before it — derived from the declared policy, never implied."""
    resolved = [case if isinstance(case, CaseSequence) else sequence_from_metadata(case, index=index)
                for index, case in enumerate(cases)]
    plan: list[dict[str, Any]] = []
    seen_scopes: set[str] = set()
    run_reset_done = False
    for case in resolve_order(resolved) if resolved else []:
        policy = ResetPolicy(case.reset_policy)
        clear = False
        reason = ""
        if policy == ResetPolicy.NEVER:
            reason = "the case declares that state is never cleared"
        elif policy == ResetPolicy.ONCE_PER_RUN:
            clear = not run_reset_done
            reason = "the run clears state once, before the first case" if clear else \
                     "state was already cleared for this run"
            run_reset_done = True
        elif policy == ResetPolicy.PER_CASE:
            clear = True
            reason = "the case declares a clear before it runs"
        elif policy == ResetPolicy.PER_FIXTURE_SCOPE:
            scope = str(case.shared_fixture_scope or case.case_id)
            clear = scope not in seen_scopes
            reason = (f"first case of fixture scope {scope!r}" if clear else
                      f"fixture scope {scope!r} is already built")
            seen_scopes.add(scope)
        plan.append({"case_id": case.case_id, "reset_policy": str(policy), "clear_state": clear,
                     "reason": reason, "shared_fixture_scope": case.shared_fixture_scope})
    return plan


def _reset_action(policy: ResetPolicy, members: Sequence[CaseSequence]) -> str:
    if policy == ResetPolicy.NEVER:
        return "none"
    if policy == ResetPolicy.ONCE_PER_RUN:
        return "clear state once before the first case of the group"
    if policy == ResetPolicy.PER_CASE:
        return f"clear state before each of the {len(members)} case(s)"
    return "clear state once per fixture scope"
