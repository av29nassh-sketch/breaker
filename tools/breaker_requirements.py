"""Candidate-bound requirement declarations and an honest coverage report for any n8n workflow (offline, no n8n contact).

A workflow owner declares what the workflow is *required* to accomplish; Breaker never invents a requirement or an
expected result. Each requirement names the supplied test cases that are its evidence. Coverage is then computed from
what those cases actually did, so the report can say which requirements were verified, simulated, failed, blocked, not
tested, or need a human or a real integration.

    {"schema_version": 1,
     "candidate": {"name": "Order triage", "version": "1.2.0", "workflow_sha256": "<optional 64 hex>"},
     "triggers": [{"id": "T1", "node": "Order In", "kind": "webhook", "statement": "..."}],
     "requirements": [{"id": "R1", "kind": "required_effect", "statement": "...", "cases": ["lead"],
                       "nodes": ["Call CRM"], "tables": [], "destination": {"type": "http_api", "node": "Call CRM"},
                       "verification": "execution"}]}

It reuses what exists: Core's ``ProductionContract`` (the declaration is projected onto its field names, so a gap is a
``ContractGap`` path), Core's ``profile_from_n8n_workflow`` (observed triggers), the cases format and the front door's
execution evidence, and optionally a control registry file (rows are linked by the contract fields they require;
none ships with this repository). Nothing here books
a verdict, promotes a control or produces a readiness PASS: every status is capped at SIMULATED evidence.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
from collections import Counter

_ROOT = pathlib.Path(__file__).resolve().parent
OPS_ROOT = _ROOT.parent
REGISTRY_FILE = "breaker_control_registry.json"  # optional; absent means no links


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_pf = _load("breaker_effect_preflight_requirements", "breaker_effect_preflight.py")
PREFIX = _pf.PREFIX

OBSERVED, SIMULATED, FAILED = "OBSERVED_IN_DISPOSABLE_RUN", "SIMULATED_ONLY", "FAILED_IN_DISPOSABLE_RUN"
VERIFIED = OBSERVED  # kept as the internal name of the strongest status; the word "verified" is no longer part of any status
BLOCKED, NOT_TESTED, REQUIRES = "BLOCKED", "NOT_TESTED", "REQUIRES_HUMAN_OR_REAL_INTEGRATION"
MOCKED = "MOCKED_OFFLINE_RESULT"
STATUSES = (OBSERVED, SIMULATED, FAILED, MOCKED, BLOCKED, NOT_TESTED, REQUIRES)
MEANING = {
    OBSERVED: "the linked cases conformed in a real n8n execution of a disposable neutralised copy, and the evidence is self-consistent "
              "(the execution id matches its own read-back, the run succeeded). It covers the workflow's own logic and disposable "
              "state only. It is not verification of a real integration, not client data, and not production readiness",
    SIMULATED: "as above, but the evidence rests on an integration replaced by a stub you supplied; the stub's answer was assumed, "
               "not observed",
    FAILED: "a linked case failed an assertion that names this requirement's own nodes or tables, in a real disposable execution "
            "whose id matches its read-back. It shows the neutralised copy did not meet your declared expectation",
    MOCKED: "the only execution behind this was a fake n8n inside a test. It shows the reporting pipeline works; it says nothing "
            "about the workflow",
    BLOCKED: "Breaker refused or could not safely run the linked cases; nothing was executed for this requirement",
    NOT_TESTED: "no admissible execution evidence exists for this requirement (not executed, no linked case, inconclusive, "
                "inconsistent evidence, a failure it cannot attribute, or cases that do not assert on what it names)",
    REQUIRES: "you declared that this needs a real integration or a human; Breaker cannot establish it by simulation",
}
CEILING = ("Every status is capped at SIMULATED evidence from a disposable neutralised copy. None is a production or readiness "
           "PASS, none is closure-grade evidence accepted by Core, none promotes any control, and none "
           "says anything about real integrations, credentials, real data or live behaviour.")

#: The kinds of evidence a requirement can rest on. Breaker produces only the first four; the last two it never produces.
MOCKED_OFFLINE, REAL_RUN, STUBBED, READBACK = ("MOCKED_OFFLINE", "REAL_DISPOSABLE_EXECUTION", "SIMULATED_STUBBED_INTEGRATION",
                                               "INDEPENDENT_READBACK_OF_DISPOSABLE_STATE")
CLIENT_REAL, CORE_GRADE = "REAL_CLIENT_INTEGRATION", "CORE_CLOSURE_GRADE"
EVIDENCE_KINDS = {
    MOCKED_OFFLINE: "a fake n8n inside a test; proves nothing about a workflow",
    REAL_RUN: "a real n8n execution of a disposable, neutralised, inactive copy",
    STUBBED: "an external call replaced by an answer the author supplied",
    READBACK: "rows read back over REST from a table this run created",
    CLIENT_REAL: "the real integration or client system behaving correctly: never produced by Breaker",
    CORE_GRADE: "closure-grade evidence accepted by Core: never produced here; this report is not ingested into any readiness record",
}
ORIGINS = ("MOCKED_OFFLINE", "REAL_DISPOSABLE_N8N", "NOT_RUN")

#: requirement kind -> the Core ProductionContract fields it supplies
KINDS = {"business_outcome": ("intended_business_outcome", "successful_end_state"), "business_path": ("business_paths",),
         "required_effect": ("outputs",), "must_not_happen": ("must_not_happen",), "input_rule": ("inputs",)}
VERIFICATION = ("execution", "real_integration", "human")
DEST_TYPES = {"data_table": PREFIX + "dataTable", "http_api": PREFIX + "httpRequest", "email": PREFIX + "emailSend", "other": None}
TRIGGER_KINDS = ("webhook", "http", "schedule", "manual", "subworkflow", "event")
_ID = re.compile(r"[A-Za-z0-9_.-]{1,40}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class RequirementsError(ValueError):
    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _keys(obj, allowed, label, problems):
    for key in obj:
        if key not in allowed:
            problems.append(f"{label} has unknown key {key!r}")


def _names(value, label, known, problems, what="node"):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value) or len(set(value)) != len(value):
        problems.append(f"{label} must be a list of unique {what} names")
        return []
    for name in value:
        if name not in known:
            problems.append(f"{label} names unknown {what} {name!r}")
    return value


def parse(doc, definition, loaded, workflow_sha256, observed_triggers=()):
    """Validate a declaration against the exact workflow and its loaded cases. Returns (declaration | None, problems)."""
    problems = []
    if not isinstance(doc, dict):
        return None, ["requirements root must be an object"]
    _keys(doc, {"schema_version", "candidate", "triggers", "requirements"}, "requirements", problems)
    if doc.get("schema_version") != 1 or isinstance(doc.get("schema_version"), bool):
        problems.append("requirements schema_version must equal 1")
    candidate = doc.get("candidate")
    if not isinstance(candidate, dict):
        problems.append("candidate must be an object with name and version")
        candidate = {}
    _keys(candidate, {"name", "version", "workflow_sha256"}, "candidate", problems)
    for field in ("name", "version"):
        if not isinstance(candidate.get(field), str) or not candidate[field].strip():
            problems.append(f"candidate.{field} must be a non-empty string")
    bound = candidate.get("workflow_sha256")
    if bound is not None:
        if not isinstance(bound, str) or not _SHA.match(bound):
            problems.append("candidate.workflow_sha256 must be 64 lowercase hex characters")
        elif bound != workflow_sha256:
            problems.append("the requirements were written for a different version of the workflow "
                            "(candidate.workflow_sha256 does not match the file you passed)")
    nodes = {n["name"]: n for n in (definition.get("nodes") or []) if isinstance(n, dict) and isinstance(n.get("name"), str)}
    case_ids = {c.id for c in loaded.cases} if loaded is not None else None
    tables = set(loaded.tables) if loaded is not None else set()
    table_of_node = {node: logical for logical, spec in (loaded.tables.items() if loaded is not None else ())
                     for node in spec.nodes}

    triggers, seen = [], set()
    raw_triggers = doc.get("triggers", [])
    if not isinstance(raw_triggers, list):
        problems.append("triggers must be a list")
        raw_triggers = []
    for i, row in enumerate(raw_triggers):
        label = f"triggers[{i}]"
        if not isinstance(row, dict):
            problems.append(f"{label} must be an object")
            continue
        _keys(row, {"id", "node", "kind", "statement"}, label, problems)
        tid = row.get("id")
        if not isinstance(tid, str) or not _ID.match(tid) or tid in seen:
            problems.append(f"{label} id is invalid or duplicated")
        seen.add(tid)
        node = row.get("node")
        if node not in nodes or nodes[node].get("type") not in _pf.ENTRY:
            problems.append(f"{label} node must be an existing entry (trigger) node")
        kind = row.get("kind")
        if kind not in TRIGGER_KINDS:
            problems.append(f"{label} kind must be one of {', '.join(TRIGGER_KINDS)}")
        elif observed_triggers and kind.upper() not in observed_triggers:
            problems.append(f"{label} kind {kind!r} does not match the triggers Breaker observed in the workflow "
                            f"({', '.join(sorted(observed_triggers))})")
        if not isinstance(row.get("statement"), str) or not row["statement"].strip():
            problems.append(f"{label} statement must be a non-empty string")
        triggers.append(dict(row))

    items = []
    raw = doc.get("requirements")
    if not isinstance(raw, list) or not raw:
        problems.append("requirements must be a non-empty list")
        raw = []
    if len(raw) > 500:
        problems.append("at most 500 requirements are allowed")
    ids = set()
    for i, row in enumerate(raw):
        label = f"requirements[{i}]"
        if not isinstance(row, dict):
            problems.append(f"{label} must be an object")
            continue
        _keys(row, {"id", "kind", "statement", "cases", "nodes", "tables", "destination", "verification"}, label, problems)
        rid = row.get("id")
        if not isinstance(rid, str) or not _ID.match(rid):
            problems.append(f"{label} id is invalid")
        elif rid in ids:
            problems.append(f"duplicate requirement id {rid!r}")
        ids.add(rid)
        if row.get("kind") not in KINDS:
            problems.append(f"{label} kind must be one of {', '.join(KINDS)}")
        if not isinstance(row.get("statement"), str) or not row["statement"].strip() or len(row["statement"]) > 500:
            problems.append(f"{label} statement must be a non-empty string of at most 500 characters")
        verification = row.get("verification", "execution")
        if verification not in VERIFICATION:
            problems.append(f"{label} verification must be one of {', '.join(VERIFICATION)}")
        linked = _names(row.get("cases", []), f"{label} cases", case_ids if case_ids is not None else set(), problems, "case") \
            if "cases" in row else []
        want_nodes = _names(row.get("nodes", []), f"{label} nodes", nodes, problems) if "nodes" in row else []
        want_tables = _names(row.get("tables", []), f"{label} tables", tables, problems, "declared table") if "tables" in row else []
        dest = row.get("destination")
        if dest is not None:
            if not isinstance(dest, dict):
                problems.append(f"{label} destination must be an object")
            else:
                _keys(dest, {"type", "node"}, f"{label} destination", problems)
                dtype, dnode = dest.get("type"), dest.get("node")
                if dtype not in DEST_TYPES:
                    problems.append(f"{label} destination.type must be one of {', '.join(DEST_TYPES)}")
                elif dtype == "other":
                    if verification == "execution":
                        problems.append(f"{label} a destination of type 'other' cannot be simulated: set verification to "
                                        "real_integration or human")
                elif dnode not in nodes:
                    problems.append(f"{label} destination.node must name an existing node")
                elif nodes[dnode].get("type") != DEST_TYPES[dtype]:
                    problems.append(f"{label} destination.type {dtype!r} does not match node {dnode!r} "
                                    f"({str(nodes[dnode].get('type')).replace(PREFIX, '')})")
                if dtype == "data_table" and loaded is not None and dnode in nodes and dnode not in table_of_node:
                    problems.append(f"{label} destination node {dnode!r} is not covered by a declared test table, so its "
                                    "writes cannot be read back independently")
                if dtype != "other" and dnode in table_of_node:
                    want_tables = sorted(set(want_tables) | {table_of_node[dnode]})
                if dtype != "other" and isinstance(dnode, str) and dnode in nodes and dnode not in want_nodes \
                        and nodes[dnode].get("type") != DEST_TYPES["data_table"]:
                    want_nodes = want_nodes + [dnode]
        elif row.get("kind") == "required_effect":
            problems.append(f"{label} a required_effect must declare its destination (type and node, or type 'other')")
        items.append({"id": rid, "kind": row.get("kind"), "statement": row.get("statement"), "cases": linked,
                      "nodes": want_nodes, "tables": want_tables, "destination": copy.deepcopy(dest),
                      "verification": verification})
    if problems:
        return None, problems
    return {"candidate": {"name": candidate["name"], "version": candidate["version"]}, "triggers": triggers,
            "requirements": items}, []


def candidate_block(declaration, workflow_sha256, definition_digest, requirements_bytes, cases_sha256, binding_asserted=False,
                    cases_file_sha256=None):
    return {"name": declaration["candidate"]["name"], "version": declaration["candidate"]["version"],
            "workflow_sha256": workflow_sha256, "source_definition_digest": definition_digest,
            "requirements_sha256": hashlib.sha256(requirements_bytes).hexdigest(), "cases_sha256": cases_sha256,
            "cases_file_sha256": cases_file_sha256,
            "binding_asserted_by_declaration": bool(binding_asserted),
            "binding": ("the declaration asserted this workflow hash and it matched" if binding_asserted else
                        "the hash is recorded but the declaration did not assert it (candidate.workflow_sha256 absent), so a changed "
                        "workflow would not have been refused")}


def to_contract(declaration):
    """The declaration projected onto Core ``ProductionContract`` field names, validated by Core itself."""
    from breaker.readiness.contract import ProductionContract
    by = {}
    for item in declaration["requirements"]:
        for field in KINDS[item["kind"]]:
            by.setdefault(field, []).append(item["statement"])
    data = {"identity": {"workflow_name": declaration["candidate"]["name"], "version": declaration["candidate"]["version"]}}
    if declaration["triggers"]:
        first = declaration["triggers"][0]
        data["trigger"] = {"kind": first["kind"].upper(), "node": first["node"], "statement": first["statement"]}
    for field, statements in by.items():
        data[field] = statements[0] if field in ("intended_business_outcome", "successful_end_state") else statements
    return ProductionContract.from_mapping(data, source="requirements declaration",
                                           contract_id=declaration["candidate"]["name"],
                                           contract_version=declaration["candidate"]["version"])


def registry_rows(path=None):
    path = pathlib.Path(path) if path else OPS_ROOT / REGISTRY_FILE
    if not path.is_file():
        return None, None
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    rows = next((v for v in data.values() if isinstance(v, list) and v and isinstance(v[0], dict) and "id" in v[0]), None)
    return rows, hashlib.sha256(raw).hexdigest()


def link_controls(declaration, contract, rows, has_ai=False):
    """Registry rows whose required contract fields the declaration supplies. A link, never a promotion.

    AI rows (``AI-*``) are linked only when Core's profile found an AI surface in the workflow."""
    if rows is None:
        return {}, {"available": False}, {}
    rows = [r for r in rows if has_ai or not str(r["id"]).startswith("AI-")]
    supplied = {f for f in ("intended_business_outcome", "successful_end_state", "business_paths", "outputs",
                            "must_not_happen", "inputs", "trigger", "identity") if contract.has(f)}
    per_req, linked, gaps = {}, {}, {}
    for item in declaration["requirements"]:
        fields = set(KINDS[item["kind"]])
        ids = sorted(r["id"] for r in rows if fields & {f.split(".")[0] for f in r["required_contract_fields"]})
        per_req[item["id"]] = ids
        for cid in ids:
            linked.setdefault(cid, []).append(item["id"])
    if declaration["triggers"]:
        per_req["triggers"] = sorted(r["id"] for r in rows if "trigger" in {f.split(".")[0] for f in r["required_contract_fields"]})
        for cid in per_req["triggers"]:
            linked.setdefault(cid, []).append("triggers")
    by_id = {r["id"]: r for r in rows}
    for cid in linked:
        missing = sorted({f for f in by_id[cid]["required_contract_fields"] if not contract.has(f)})
        if missing:
            gaps[cid] = missing
    summary = {"available": True, "supplied_contract_fields": sorted(supplied), "linked_control_count": len(linked),
               "controls_with_other_contract_fields_still_missing": len(gaps)}
    return per_req, summary, {"links": {cid: {"wording": by_id[cid]["checklist_wording"], "requirements": reqs,
                                              "still_missing_contract_fields": gaps.get(cid, [])}
                                        for cid, reqs in sorted(linked.items())}}


def case_labels(case):
    """Failed-assertion label -> the node it names, rebuilt from the case's own assertions with the runner's exact wording, so a
    node called ``Check: Stock`` or text inside an expected value can never be mistaken for another node."""
    labels = {f"must_run {n}: node did not run": n for n in case.must_run}
    labels.update({f"must_not_run {n}: node ran": n for n in case.must_not_run})
    for a in case.output_assertions:
        labels[f"output {a['node']}[{a.get('item', 0)}].{a['path']} == {a['equals']!r}"] = a["node"]
    return labels


def _assertion_index(loaded):
    index = {}
    for case in (loaded.cases if loaded is not None else ()):
        index[case.id] = {"positive": {a["node"] for a in case.output_assertions} | set(case.must_run),
                          "negative": set(case.must_not_run),
                          "tables": {a["table"] for a in case.table_assertions}, "labels": case_labels(case)}
    return index


_FAILED_TABLE = re.compile(r"^table ([a-z][a-z0-9_]{0,23}) (?:count|equals|contains) ")


def failed_targets(labels, known):
    """The nodes and ``table <logical>`` names the failed-assertion labels point at. A label that is not exactly one of the case's
    own assertions (or a table assertion) points at nothing, so it can never be attributed to a requirement."""
    found = set()
    for label in labels:
        label = str(label)
        if label in known:
            found.add(known[label])
        else:
            match = _FAILED_TABLE.match(label)
            if match:
                found.add(f"table {match.group(1)}")
    return found


def admissible(ev):
    """Whether a case's execution evidence is self-consistent. An execution id by itself is never enough: the read-back the
    runner took must carry the same id, report a successful run, and come from a group that executed."""
    return bool(str(ev.get("execution_id") or "").strip()
                and ev.get("read_back_execution_id") == ev.get("execution_id")
                and ev.get("execution_status") == "success" and ev.get("group_status") == "EXECUTED")


def coverage(declaration, loaded, node_types, evidence, run_state, observed, origin="NOT_RUN", integrity=()):
    """One row per declared requirement.

    ``evidence`` maps case id -> the runner's own record for that case; ``run_state`` is NOT_RUN, BLOCKED or RAN; ``origin`` says
    what executed it (MOCKED_OFFLINE for any fake backend or transport, REAL_DISPOSABLE_N8N only for the guarded real wiring);
    ``integrity`` lists reasons the run itself was not clean (a failed cleanup, a changed instance): a positive claim is not made
    from such a run."""
    index = _assertion_index(loaded)
    empty = {"positive": set(), "negative": set(), "tables": set(), "labels": {}}
    stub_types = (PREFIX + "httpRequest", PREFIX + "emailSend")
    rows = []
    for item in declaration["requirements"]:
        linked = [{"case": cid, "status": evidence.get(cid, {}).get("status", "NOT_RUN"),
                   "execution_id": evidence.get(cid, {}).get("execution_id")} for cid in item["cases"]]
        statuses = [r["status"] for r in linked]
        positive = set().union(*(index.get(c, empty)["positive"] for c in item["cases"]))
        negative = set().union(*(index.get(c, empty)["negative"] for c in item["cases"]))
        tables = set().union(*(index.get(c, empty)["tables"] for c in item["cases"]))
        named = set(item["nodes"]) | {f"table {t}" for t in item["tables"]}
        uncovered = [n for n in item["nodes"] if n not in positive and n not in negative]
        uncovered += [f"table {t}" for t in item["tables"] if t not in tables]
        failed_cases = [cid for cid in item["cases"] if evidence.get(cid, {}).get("status") == "PRODUCT_FAIL"]
        known = {cid: index.get(cid, empty).get("labels", {}) for cid in item["cases"]}
        hits = {cid: failed_targets(evidence[cid].get("failed_assertions", ()), known[cid]) for cid in failed_cases}
        attributed = [cid for cid in failed_cases if hits[cid] & named]
        stubbed = sorted(n for n in item["nodes"] if node_types.get(n) in stub_types and n in positive)
        readback = bool(item["tables"]) and all(evidence.get(c, {}).get("table_readback") for c in item["cases"])
        reasons, held = [], []
        if attributed and origin == "MOCKED_OFFLINE":
            status, reasons = MOCKED, [f"a fake n8n reported a failed assertion on {', '.join(attributed)}"]
        elif attributed:
            bad = [c for c in attributed if not admissible(evidence[c])]
            if bad:
                status, reasons = NOT_TESTED, [f"case {', '.join(bad)} reported a failure whose execution evidence is not "
                                               "self-consistent (id, read-back and run status disagree), so it is not relied on"]
            else:
                status = FAILED
                reasons = [f"case {c} failed {sorted(hits[c] & named)} (execution "
                           f"{evidence[c]['execution_id']})" for c in attributed]
                held = [REAL_RUN] + ([READBACK] if readback else [])
        elif run_state == "BLOCKED" and item["cases"] or "BLOCKED" in statuses:
            status, reasons = BLOCKED, ["the run or a linked case was blocked: nothing was executed for this requirement"]
        elif item["verification"] != "execution":
            status, reasons = REQUIRES, [f"declared verification: {item['verification']}"]
        elif not item["cases"]:
            status, reasons = NOT_TESTED, ["no linked case"]
        elif run_state == "NOT_RUN" or "NOT_RUN" in statuses:
            status, reasons = NOT_TESTED, ["linked cases were not executed (check-only run)"]
        elif failed_cases:
            status = NOT_TESTED
            reasons = [f"linked case {c} failed on {sorted(hits[c]) or 'assertions Breaker cannot read'}, "
                       f"which this requirement does not name; the failure is not attributed to it, and its own evidence is not "
                       f"separable" for c in failed_cases]
        elif any(s != "CONFORMS" for s in statuses):
            status = NOT_TESTED
            reasons = [f"linked case(s) inconclusive: {', '.join(r['case'] for r in linked if r['status'] != 'CONFORMS')}"]
        elif uncovered:
            status, reasons = NOT_TESTED, [f"linked cases make no assertion on: {', '.join(uncovered)}"]
        elif origin == "MOCKED_OFFLINE":
            status, reasons = MOCKED, ["a fake n8n reported the linked cases as conforming"]
        elif not all(admissible(evidence[c]) for c in item["cases"]):
            status, reasons = NOT_TESTED, ["execution evidence is not self-consistent (execution id, read-back id, run status or "
                                           "group state disagree), so it is not relied on"]
        elif integrity:
            status, reasons = NOT_TESTED, ["the run was not clean, so no positive claim is made from it: " + "; ".join(integrity[:3])]
        elif stubbed:
            status, reasons = SIMULATED, [f"the evidence is the supplied stub's answer for: {', '.join(stubbed)}"]
            held = [REAL_RUN, STUBBED] + ([READBACK] if readback else [])
        else:
            status, reasons = OBSERVED, ["linked cases conformed in a real disposable execution; assertions cover every node and "
                                         "table the requirement names"]
            held = [REAL_RUN] + ([READBACK] if readback else [])
        if status == MOCKED:
            held = [MOCKED_OFFLINE]
        row = {"id": item["id"], "kind": item["kind"], "statement": item["statement"], "status": status, "reasons": reasons,
               "cases": linked, "required_nodes": item["nodes"], "required_tables": item["tables"],
               "destination": item["destination"], "verification": item["verification"],
               "evidence_held": held, "evidence_not_held": [k for k in (REAL_RUN, CLIENT_REAL, CORE_GRADE) if k not in held]}
        if status == REQUIRES and linked:
            row["simulation_support"] = [f"{r['case']}: {r['status']}" for r in linked]
        rows.append(row)
    named_all = {n for item in declaration["requirements"] for n in item["nodes"]} | \
                {i["destination"]["node"] for i in declaration["requirements"] if i["destination"] and i["destination"].get("node")}
    undeclared_effects = sorted(n for n, t in node_types.items()
                                if t in (PREFIX + "httpRequest", PREFIX + "emailSend", PREFIX + "dataTable") and n not in named_all)
    declared_triggers = {t["node"] for t in declaration["triggers"]}
    undeclared_triggers = sorted(n for n in observed.get("entry_candidates", []) if n not in declared_triggers)
    return {"rows": rows, "counts": {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES},
            "undeclared_effect_nodes": undeclared_effects, "undeclared_trigger_nodes": undeclared_triggers}


def build(declaration, loaded, definition, evidence, run_state, observed, candidate, rows=None, registry_sha=None,
          origin="NOT_RUN", integrity=()):
    from breaker.readiness.profile import profile_from_n8n_workflow
    has_ai = bool(profile_from_n8n_workflow(definition).ai_surfaces)
    node_types = {n["name"]: n["type"] for n in (definition.get("nodes") or []) if isinstance(n, dict) and "name" in n}
    contract = to_contract(declaration)
    cov = coverage(declaration, loaded, node_types, evidence, run_state, observed, origin, integrity)
    per_req, summary, links = link_controls(declaration, contract, rows, has_ai)
    for row in cov["rows"]:
        row["related_controls"] = per_req.get(row["id"], [])
    return {"candidate": candidate, "execution_origin": origin, "evidence_ceiling": "SIMULATED", "ceiling_statement": CEILING,
            "evidence_kinds": EVIDENCE_KINDS, "status_meanings": MEANING, "triggers": declaration["triggers"], **cov,
            "core_evidence": "not ingested and not closure-grade: this report is not a Core claim, verdict or readiness record; "
                             "Core would derive SYNTHETIC_FIXTURE provenance from a SIMULATED environment",
            "controls": {**summary, "registry_sha256": registry_sha, "statement": "links show which registry rows each requirement "
                         "supplies a contract field for; no control status was changed or promoted", **links},
            "readiness_claim": "NONE"}


def render(coverage_doc):
    c = coverage_doc["candidate"]
    lines = ["## Requirement coverage", "",
             f"Candidate: **{c['name']}** version {c['version']}  workflow sha256 `{c['workflow_sha256'][:16]}...`  "
             f"requirements `{c['requirements_sha256'][:12]}...`", "", f"Binding: {c['binding']}.", "",
             f"EXECUTION ORIGIN: {coverage_doc['execution_origin']}"
             + (" (a fake n8n inside a test: nothing below says anything about the workflow)"
                if coverage_doc["execution_origin"] == "MOCKED_OFFLINE" else ""), "", coverage_doc["ceiling_statement"], ""]
    counts = coverage_doc["counts"]
    lines += ["| Status | Requirements |", "|---|---|"] + [f"| {s} | {counts[s]} |" for s in STATUSES] + [""]
    for row in coverage_doc["rows"]:
        lines.append(f"- `{row['id']}` ({row['kind']}): **{row['status']}**: {row['statement']}")
        lines.append(f"  - {'; '.join(row['reasons'])}")
        if row["cases"]:
            lines.append("  - cases: " + ", ".join(f"{r['case']} {r['status']}" + (f" (execution {r['execution_id']})" if r["execution_id"] else "")
                                                   for r in row["cases"]))
        lines.append("  - evidence held: " + (", ".join(row["evidence_held"]) or "none") + "; not held: " + ", ".join(row["evidence_not_held"]))
        if row.get("simulation_support"):
            lines.append("  - simulation support only: " + "; ".join(row["simulation_support"]))
        if row["related_controls"]:
            lines.append("  - registry rows this supplies contract fields for: " + ", ".join(row["related_controls"][:12])
                         + (" ..." if len(row["related_controls"]) > 12 else ""))
    lines.append("")
    if coverage_doc["undeclared_effect_nodes"]:
        lines.append("Effects in the workflow that no requirement names (Breaker does not invent requirements): "
                     + ", ".join(coverage_doc["undeclared_effect_nodes"]))
    if coverage_doc["undeclared_trigger_nodes"]:
        lines.append("Triggers in the workflow that no declaration names: " + ", ".join(coverage_doc["undeclared_trigger_nodes"]))
    lines += ["", f"Core: {coverage_doc['core_evidence']}.", "", "Kinds of evidence:", ""] +              [f"- {k}: {v}" for k, v in coverage_doc["evidence_kinds"].items()]
    lines += ["", "What each status means:", ""] + [f"- {s}: {coverage_doc['status_meanings'][s]}" for s in STATUSES] + [""]
    return "\n".join(lines)
