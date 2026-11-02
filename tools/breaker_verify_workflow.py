"""One front door for testing any n8n workflow with the generic S1-S4 pipeline.

    python breaker_verify_workflow.py WORKFLOW.json --cases CASES.json --out-root <scratch dir>

Default mode is offline and touches nothing: it inventories the workflow, classifies every node's external effects with
the S1 preflight, validates the cases, and writes a report that says what Breaker can and cannot test. Only with
``--run`` (plus the operator's own arming string, credentials and a verified mechanism record) does it execute the
disposable neutralised copy through the existing guarded runner. A workflow the preflight refuses (Code nodes, unknown
integrations, host access, unbound Data Tables, ...) gets a BLOCKED report and no n8n object is ever created.

Results are always one of CONFORMS, PRODUCT_FAIL, BLOCKED, INCONCLUSIVE or NOT VERIFIED. Nothing here books a control
verdict or claims a pass: simulated results are conformance of the workflow's own logic against stubs you supplied.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timezone

_ROOT = pathlib.Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cli = _load("breaker_s4_run_front", "breaker_s4_run.py")  # the existing operator CLI: guarded backend, probe, runner, evidence
be, sim, probe, neutralise, cases_mod = cli.be, cli.sim, cli.probe, cli.neutralise, cli.cases_mod
pf = sim._pf
tables_mod = cases_mod.tables_mod
reqs = cli._load("breaker_requirements_front", "breaker_requirements.py")
table_probe = cli._load("breaker_table_probe_front", "breaker_table_probe.py")

STATUSES = ("CONFORMS", "PRODUCT_FAIL", "BLOCKED", "INCONCLUSIVE", "NOT VERIFIED")
LEGEND = {
    "CONFORMS": "every supplied case matched its declared expectation, in simulation only",
    "PRODUCT_FAIL": "at least one declared expectation did not hold in the workflow's own logic",
    "BLOCKED": "Breaker refused or could not safely run it; nothing was executed for the blocked part",
    "INCONCLUSIVE": "something ran but the evidence cannot support a verdict (bad read-back, failed cleanup, ...)",
    "NOT VERIFIED": "nothing was executed or asserted for this item",
}
LABELS = {"fixture_class": "USER_SUPPLIED_WORKFLOW", "subject_kind": "WORKFLOW_UNDER_TEST_SIMULATION",
          "claim_scope": "simulation conformance only; stubbed integrations are not verified; not production evidence",
          "readiness_record": "NOT_FOR_INGESTION_INTO_ANY_READINESS_RECORD"}
DISCLAIMER = ("Simulation conformance only. The run uses a neutralised, disposable copy in which external calls are replaced "
              "by stubs you supplied. It does not show that the original workflow, its credentials or any real integration "
              "works, and it can never be promoted to a readiness PASS.")
CODE_TYPES = {pf.PREFIX + n for n in ("code", "function", "functionItem")}
BLOCKER_TEXT = {
    "CODE_NODE": "Code nodes cannot be run safely yet (execution safety is unproven; Code-node support is deferred)",
    "DATA_TABLE_NEEDS_DECLARATION": "a Data Table node must be declared under 'tables' in the cases file (its columns, and a "
                                    "static table reference); Breaker then runs it against a disposable table it creates",
    "CREDENTIALED_NODE_NO_SAFE_STAND_IN": "the node holds credentials and has no safe stand-in",
    "HOST_ACCESS_OR_UNCLASSIFIED_CALL": "the node can reach the host or another workflow",
    "UNSUPPORTED_NODE_TYPE": "the node type is not in the classifier's table, so its effects are not established",
    "WORKFLOW_LEVEL": "a workflow-level setting makes it unsafe to run",
}


def blocker_category(node_type, reason):
    if node_type in CODE_TYPES:
        return "CODE_NODE"
    if node_type == pf.DATA_TABLE:
        return "DATA_TABLE_NEEDS_DECLARATION"
    if reason.startswith("holds credentials"):
        return "CREDENTIALED_NODE_NO_SAFE_STAND_IN"
    if node_type in pf.KNOWN_UNSAFE:
        return "HOST_ACCESS_OR_UNCLASSIFIED_CALL"
    return "UNSUPPORTED_NODE_TYPE"


def short(node_type):
    return node_type[len(pf.PREFIX):] if str(node_type).startswith(pf.PREFIX) else str(node_type)


def inventory(definition, declared_table_nodes=()):
    """Node census and S1 verdicts for any definition; never raises on odd input.

    ``declared_table_nodes`` are the Data Table nodes the cases file declares test tables for; only those are acceptable."""
    nodes = [n for n in (definition.get("nodes") or []) if isinstance(n, dict)] if isinstance(definition, dict) else []
    result = pf.evaluate(definition if isinstance(definition, dict) else {}, rebindable_nodes=declared_table_nodes)
    types = collections.Counter(str(n.get("type") or "?") for n in nodes)
    rows = [{"name": v.name, "type": short(v.node_type), "s1": v.disposition.value, "reason": v.reason}
            for v in result.nodes.values()]
    blockers = collections.OrderedDict()
    for v in result.nodes.values():
        if v.disposition.value == "BLOCK":
            key = blocker_category(v.node_type, v.reason)
            entry = blockers.setdefault(key, {"category": key, "meaning": BLOCKER_TEXT[key], "nodes": [], "types": collections.Counter()})
            entry["nodes"].append(v.name)
            entry["types"][short(v.node_type)] += 1
    for reason in result.workflow_reasons:
        entry = blockers.setdefault("WORKFLOW_LEVEL", {"category": "WORKFLOW_LEVEL", "meaning": BLOCKER_TEXT["WORKFLOW_LEVEL"], "nodes": [], "types": collections.Counter()})
        entry["nodes"].append(reason)
    blocker_list = [{"category": b["category"], "meaning": b["meaning"], "count": len(b["nodes"]),
                     "node_types": dict(b["types"]), "nodes": b["nodes"][:25], "more": max(0, len(b["nodes"]) - 25)}
                    for b in blockers.values()]
    entries = [v.name for v in result.nodes.values() if v.node_type in pf.ENTRY]
    data_tables = [{"name": name, "operation": (node.get("parameters") or {}).get("operation"),
                    "static_reference": tables_mod.static_source_id(node) is not None,
                    "declared": name in set(declared_table_nodes)}
                   for name, node in tables_mod.data_table_nodes(definition).items()]
    credentials = sorted({t for n in nodes for t in (n.get("credentials") or {})})
    return {"node_count": len(nodes), "node_types": {short(k): c for k, c in sorted(types.items())},
            "credential_types": credentials, "entry_candidates": entries,
            "external_effects": [{"name": r["name"], "type": r["type"]} for r in rows if r["s1"] == "SUBSTITUTE"],
            "blockers": blocker_list, "nodes": rows, "_result": result, **({"data_tables": data_tables} if data_tables else {})}


def _read_workflow(path):
    raw = pathlib.Path(path).read_bytes()
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as exc:
        return raw, None, f"workflow file is not valid JSON ({type(exc).__name__})"
    unwrapped = False
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
        data, unwrapped = data[0], True
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list) or not isinstance(data.get("connections"), dict):
        return raw, None, "file is not an n8n workflow export (needs 'nodes' and 'connections')"
    return raw, (data, unwrapped), None


def declared_nodes(cases_doc):
    """Data Table node names the cases file declares test tables for (best effort; the loader validates the rest)."""
    declared = cases_doc.get("tables") if isinstance(cases_doc, dict) else None
    names = []
    for declaration in (declared.values() if isinstance(declared, dict) else ()):
        listed = declaration.get("nodes") if isinstance(declaration, dict) else None
        names += [n for n in (listed if isinstance(listed, list) else ()) if isinstance(n, str)]
    return names


def _observed_triggers(definition):
    """Trigger kinds Core's profile reads from the graph (empty when it cannot tell, so nothing is compared)."""
    from breaker.readiness.profile import profile_from_n8n_workflow
    kinds = {str(k) for k in profile_from_n8n_workflow(definition).trigger_kinds}
    return set() if "UNKNOWN" in kinds else kinds


def _load_requirements(path, definition, loaded, report, context):
    try:
        raw = pathlib.Path(path).read_bytes()
        doc = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError) as exc:
        report["problems"].append(f"requirements file cannot be read as JSON ({type(exc).__name__}: {exc})")
        return
    declaration, problems = reqs.parse(doc, definition, loaded, report["workflow"]["sha256"], _observed_triggers(definition))
    if problems:
        report["requirements_problems"] = problems
        return
    cases_sha = hashlib.sha256(pathlib.Path(context["cases_path"]).read_bytes()).hexdigest() if context.get("cases_path") else None
    context["requirements"] = {"declaration": declaration, "bytes": raw, "cases_sha256": cases_sha}
    report["candidate"] = reqs.candidate_block(declaration, report["workflow"]["sha256"],
                                               pf_digest(definition), raw, cases_sha,
                                               binding_asserted=isinstance(doc.get("candidate"), dict)
                                               and doc["candidate"].get("workflow_sha256") is not None,
                                               cases_file_sha256=context.get("cases_file_sha256"))


def pf_digest(definition):
    return neutralise.canonical_digest(dict(definition))


def attach_requirements(report, context):
    """Candidate-bound requirement coverage from whatever evidence this report holds (none yet, or a finished run)."""
    held = context.get("requirements")
    if not held:
        return
    state = "BLOCKED" if report["overall"]["status"] == "BLOCKED" else ("RAN" if report.get("mode") == "SIMULATED_RUN" else "NOT_RUN")
    rows, sha = reqs.registry_rows()
    report["requirement_coverage"] = reqs.build(
        held["declaration"], context["loaded"], context["definition"], context.get("case_evidence", {}), state,
        context["inventory"], report["candidate"], rows, sha, context.get("execution_origin", "NOT_RUN"),
        list(report.get("warnings", ())) if state == "RAN" else [])


def analyse(workflow_path, cases_path, entry_override, run_dir, label, requirements_path=None):
    """Everything that can be established offline. Returns (report, context)."""
    report = {"tool": "breaker_verify_workflow", "report_version": 1, "label": label, "mode": "CHECK_ONLY",
              "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "status_legend": LEGEND, "disclaimer": DISCLAIMER, "problems": [], "warnings": [],
              "cases_file_supplied": bool(cases_path)}
    context = {"cases_path": None, "loaded": None, "inventory": None}
    raw, parsed, problem = _read_workflow(workflow_path)
    report["workflow"] = {"file": pathlib.Path(workflow_path).name, "sha256": hashlib.sha256(raw).hexdigest()}
    if problem:
        report["problems"].append(problem)
        return finish_check(report, None, context), context
    definition, unwrapped = parsed
    report["workflow"].update({"name": definition.get("name"), "active": bool(definition.get("active")),
                               "unwrapped_single_item_list": unwrapped})
    cases_doc = None
    if cases_path:
        try:
            cases_doc = json.loads(pathlib.Path(cases_path).read_text(encoding="utf-8-sig"))
            if not isinstance(cases_doc, dict):
                raise ValueError("root must be an object")
        except (OSError, UnicodeError, ValueError) as exc:
            report["problems"].append(f"cases file cannot be read as a JSON object ({type(exc).__name__}: {exc})")
            cases_doc = None
    inv = inventory(definition, declared_nodes(cases_doc))
    context["inventory"] = inv
    report["inventory"] = {k: v for k, v in inv.items() if k != "_result"}

    entries = inv["entry_candidates"]
    chosen_entry = entry_override
    if cases_doc is not None:
        declared = cases_doc.get("entry_node")
        if chosen_entry and declared and chosen_entry != declared:
            report["problems"].append(f"--entry {chosen_entry!r} conflicts with the cases file's entry_node {declared!r}")
        chosen_entry = chosen_entry or declared
    if not chosen_entry and len(entries) == 1:
        chosen_entry = entries[0]
    report["entry"] = {"candidates": entries, "chosen": chosen_entry}
    if not chosen_entry:
        report["problems"].append("no entry node could be chosen: " + (
            f"the workflow has {len(entries)} entry nodes {entries}; name one with --entry or entry_node in the cases file"
            if entries else "the workflow has no recognised entry node (manual, webhook, execute-workflow or schedule trigger)"))

    if cases_doc is not None and not report["problems"]:
        block = cases_doc.get("workflow")
        if isinstance(block, dict) and block.get("sha256") not in (None, report["workflow"]["sha256"]):
            report["problems"].append("the cases file was written for a different version of the workflow "
                                      "(its workflow.sha256 does not match the file you passed)")
        else:
            staged_dir = run_dir / "inputs"
            staged_dir.mkdir(parents=True, exist_ok=False)
            staged_wf = staged_dir / "workflow.json"
            staged_bytes = json.dumps(definition, ensure_ascii=False, sort_keys=True).encode("utf-8") if unwrapped else raw
            staged_wf.write_bytes(staged_bytes)
            staged = dict(cases_doc, workflow={"path": "workflow.json", "sha256": hashlib.sha256(staged_bytes).hexdigest()},
                          entry_node=chosen_entry)
            staged.setdefault("schema_version", 1)
            staged_cases = staged_dir / "cases.json"
            staged_cases.write_text(json.dumps(staged, indent=2, ensure_ascii=False), encoding="utf-8")
            try:
                context["loaded"] = cases_mod.load_cases(staged_cases)
                context["cases_path"] = staged_cases
                report["cases"] = {"supplied": len(context["loaded"].cases), "ids": [c.id for c in context["loaded"].cases]}
                if context["loaded"].tables:
                    report["tables"] = {logical: {"nodes": list(spec.nodes), "columns": [name for name, _ in spec.columns],
                                                  "default_seed_rows": len(spec.seed)}
                                        for logical, spec in context["loaded"].tables.items()}
            except cases_mod.CasesError as exc:
                report["cases_problems"] = exc.problems
    if requirements_path:
        if cases_path and pathlib.Path(cases_path).is_file():  # the file as the author wrote it; cases_sha256 is the staged copy
            context["cases_file_sha256"] = hashlib.sha256(pathlib.Path(cases_path).read_bytes()).hexdigest()
        context["definition"] = definition
        context["requirements_path"] = requirements_path
        if not report["problems"]:
            _load_requirements(requirements_path, definition, context["loaded"], report, context)
    report = finish_check(report, inv, context)
    attach_requirements(report, context)
    return report, context


def coverage_hint(inv, loaded):
    named = set()
    for case in loaded.cases:
        named.update(case.must_run)
        named.update(case.must_not_run)
        named.update(a["node"] for a in case.output_assertions)
    skip = {inv_row["name"] for inv_row in inv["nodes"] if inv_row["type"] in ("stickyNote",)} | {loaded.entry_node}
    return sorted(r["name"] for r in inv["nodes"] if r["name"] not in named and r["name"] not in skip)


def finish_check(report, inv, context):
    """Capabilities, needs, NOT VERIFIED list and the offline overall status."""
    caps, why, needs = [], [], []
    blockers = inv["blockers"] if inv else []
    caps.append({"capability": "Node inventory and external-effect classification", "status": "SUPPORTED" if inv else "BLOCKED",
                 "detail": "every node classified by type; unknown types are refused, never guessed" if inv else "; ".join(report["problems"])})
    if inv:
        entry = report["entry"]["chosen"]
        caps.append({"capability": "Entry node", "status": "SUPPORTED" if entry else "NEEDS_INPUT",
                     "detail": entry or "; ".join(p for p in report["problems"] if "entry" in p)})
        for blocker in blockers:
            why.append(f"{blocker['count']} node(s) blocked [{blocker['category']}]: {blocker['meaning']}")
        code = [b for b in blockers if b["category"] == "CODE_NODE"]
        tables = [b for b in blockers if b["category"] == "DATA_TABLE_NEEDS_DECLARATION"]
        other = [b for b in blockers if b["category"] not in ("CODE_NODE", "DATA_TABLE_NEEDS_DECLARATION")]
        present = inv.get("data_tables", [])
        caps.append({"capability": "Code nodes", "status": "BLOCKED" if code else "NOT_PRESENT",
                     "detail": f"{code[0]['count']} Code node(s); deferred, never bypassed" if code else "none in this workflow"})
        if not present:
            caps.append({"capability": "Data Tables / database read-back", "status": "NOT_PRESENT",
                         "detail": "none in this workflow"})
        elif tables:
            caps.append({"capability": "Data Tables / database read-back", "status": "NEEDS_INPUT",
                         "detail": f"{len(present)} Data Table node(s), {tables[0]['count']} not declared; "
                                   "declare them under 'tables' in the cases file"})
        else:
            caps.append({"capability": "Data Tables / database read-back", "status": "SIMULATED_ONLY",
                         "detail": f"{len(present)} Data Table node(s) run against disposable tables this run creates and "
                                   "deletes; your real tables are never touched. Needs --table-mechanism-record to run"})
        caps.append({"capability": "Other integrations and host access", "status": "BLOCKED" if other else "NOT_PRESENT",
                     "detail": ", ".join(f"{b['category']}: {b['node_types']}" for b in other) if other else "none in this workflow"})
        ext = inv["external_effects"]
        caps.append({"capability": "External HTTP/email calls", "status": "SIMULATED_ONLY" if ext else "NOT_PRESENT",
                     "detail": ("replaced by stubs you supply: " + ", ".join(e["name"] for e in ext)) if ext else "none in this workflow"})
        hard = [b for b in blockers if b["category"] != "DATA_TABLE_NEEDS_DECLARATION"]
        if tables:
            needs.append("for each Data Table node: a 'tables' declaration in the cases file (logical name, the node names that "
                         "use it, its columns, optional seed rows), a static table reference in the node, and only the row "
                         "operations get, insert or upsert (node version 1.1)")
        if hard:
            needs.append("nothing you supply unblocks the other blocked nodes: they must be absent from the file, "
                         "or Breaker needs new support for them (not planned for Code nodes yet)")
        if not blockers:
            if context["loaded"] is None:
                for e in ext:
                    needs.append(f"a stub (the JSON that node should return) for {e['name']!r} ({e['type']}), in the cases file")
            if not entry:
                needs.append("the entry node: --entry or entry_node in the cases file")
            if not report["cases_file_supplied"]:
                needs.append("test cases (a cases file): for each case an input object and your declared expectations "
                             "(output_assertions, must_run, must_not_run); Breaker does not invent expected behaviour")
    for problem in report["problems"]:
        why.append(problem)
    if report.get("cases_problems"):
        why.extend(f"cases file: {p}" for p in report["cases_problems"])
    if report.get("requirements_problems"):
        why.extend(f"requirements file: {p}" for p in report["requirements_problems"])
    blocked = bool(report["problems"] or blockers or report.get("cases_problems") or report.get("requirements_problems")
                   or (inv and not report["entry"]["chosen"]))
    executable = bool(inv) and not blocked and context["loaded"] is not None
    caps.append({"capability": "Simulated execution on a disposable neutralised copy",
                 "status": "BLOCKED" if blocked else ("SUPPORTED" if executable else "NEEDS_INPUT"),
                 "detail": "; ".join(why[:3]) if blocked else ("ready: run with --run after approval" if executable else "supply test cases")})
    caps.append({"capability": "Verification of real integrations, credentials or production behaviour", "status": "NOT_SUPPORTED",
                 "detail": "Breaker simulates; it does not call real services"})
    report["capabilities"], report["needs_from_you"] = caps, needs
    if blocked:
        status = "BLOCKED"
    else:
        status = "NOT VERIFIED"
        why = ["no test cases were supplied, so no behaviour was checked" if context["loaded"] is None
               else "the cases validated, but nothing has been executed yet (use --run after approval)"]
    report["overall"] = {"status": status, "why": why}
    report["not_verified"] = not_verified(report, inv, context)
    if inv and context["loaded"] is not None:
        report["uncovered_nodes"] = coverage_hint(inv, context["loaded"])
    return report


def not_verified(report, inv, context):
    items = []
    if inv:
        for e in inv["external_effects"]:
            items.append(f"{e['name']} ({e['type']}): real behaviour NOT VERIFIED; it is replaced by a stub in simulation")
        if inv["credential_types"]:
            items.append("credentials and authentication (" + ", ".join(inv["credential_types"]) + "): NOT VERIFIED; credentials are stripped from the test copy")
    if inv and inv.get("data_tables"):
        items.append("your real Data Tables, their data and their schema: NOT VERIFIED; the run used disposable tables seeded "
                     "with the rows you declared, and a passing table assertion shows only that the workflow's own logic wrote "
                     "what you expected there")
    items.append("production behaviour (timing, rate limits, real data, live triggers, activation): NOT VERIFIED")
    items.append("the original workflow itself: only a neutralised copy is ever executed")
    if inv and context["loaded"] is not None:
        items.append("any node or behaviour not named by your case assertions: NOT VERIFIED (see uncovered_nodes)")
    return items


def overall_from(result, instance_changes):
    statuses = [c.status for g in result.groups for c in g.cases]
    warnings = []
    for g in result.groups:
        if g.clone_id and g.cleanup != "DELETED":
            warnings.append(f"cleanup {g.cleanup} for disposable workflow {g.clone_id}: remove it manually after checking its name")
    for g in result.groups:
        for t in getattr(g, "tables", ()):
            if t["cleanup"] != "DELETED":
                warnings.append(f"cleanup {t['cleanup']} for disposable table {t['table_name']} ({t['table_id']}): remove it "
                                f"manually after checking its name starts with breaker_sim_")
    if instance_changes:
        warnings.append("the instance changed during the run: " + "; ".join(instance_changes[:5]))
    if result.status == "BLOCKED":
        return "BLOCKED", list(result.reasons), warnings
    if "PRODUCT_FAIL" in statuses:
        return "PRODUCT_FAIL", [f"{statuses.count('PRODUCT_FAIL')} case(s) did not meet a declared expectation"], warnings
    if statuses and all(s == "BLOCKED" for s in statuses):
        return "BLOCKED", [r for g in result.groups for r in g.reasons] or ["every case was blocked"], warnings
    if (not statuses or any(s in ("BLOCKED", "INCONCLUSIVE") for s in statuses) or warnings
            or any(g.status not in ("EXECUTED",) for g in result.groups)):
        return "INCONCLUSIVE", ["some cases were blocked or inconclusive, cleanup failed, or the instance changed"], warnings
    return "CONFORMS", [f"{statuses.count('CONFORMS')} case(s) matched their declared expectations (simulation only)"], warnings


def run_simulation(report, context, *, backend, transport, mechanism, run_dir, snapshot=None):
    """Execute through the existing runner. Backend and transport are injected, so tests use fakes."""
    before = snapshot() if snapshot else None
    # Real only when it is the guarded backend and transport; anything else (any fake) is labelled as mocked.
    context["execution_origin"] = ("REAL_DISPOSABLE_N8N" if isinstance(backend, be.N8nBackend)
                                   and isinstance(transport, be.GuardedTransport) else "MOCKED_OFFLINE")
    result = sim.simulate(context["cases_path"], backend=backend, transport=transport, mechanism=mechanism,
                          out_root=run_dir / "evidence", run_id=report["label"], labels=LABELS)
    context["case_evidence"] = {
        c.case_id: {"status": c.status, "execution_id": c.execution_id, "failed_assertions": list(c.failed_assertions),
                    "read_back_execution_id": (c.read_back or {}).get("execution_id"),
                    "execution_status": (c.read_back or {}).get("execution_status"), "group_status": g.status,
                    "table_readback": bool((c.read_back or {}).get("simulated_sandbox_data"))}
        for g in result.groups for c in g.cases}
    changes = be.diff_snapshots(before, snapshot()) if snapshot else []
    status, why, warnings = overall_from(result, changes)
    report["mode"] = "SIMULATED_RUN"
    for capability in report["capabilities"]:
        if capability["capability"].startswith("Simulated execution"):
            capability["detail"] = "executed in this run (see Cases)"
    report["overall"] = {"status": status, "why": why}
    report["warnings"].extend(warnings)
    report["instance_unchanged"] = not changes if snapshot else None
    report["cases"]["results"] = [
        {"id": c.case_id, "status": c.status, "detail": c.detail, "execution_id": c.execution_id,
         "failed_assertions": list(c.failed_assertions), "nodes_run": (c.read_back or {}).get("nodes_run")}
        for g in result.groups for c in g.cases]
    report["cases"]["counts"] = dict(collections.Counter(r["status"] for r in report["cases"]["results"]))
    report["disposable_copies"] = [{"workflow_id": g.clone_id, "cleanup": g.cleanup, "group_status": g.status,
                                    "transformed_digest": g.transformed_definition_digest} for g in result.groups]
    if any(getattr(g, "tables", ()) for g in result.groups):  # absent for a workflow without Data Tables
        report["disposable_tables"] = [{"group": i, **t} for i, g in enumerate(result.groups) for t in getattr(g, "tables", ())]
    report["evidence"] = {"run_dir": str(result.run_dir), "source_sha256": result.source_sha256,
                          "mechanism_execution_id": (result.mechanism_verification or {}).get("execution_id"),
                          "readiness_verdicts_booked": 0}
    if report.get("table_mechanism_execution_id"):
        report["evidence"]["table_mechanism_execution_id"] = report["table_mechanism_execution_id"]
    report["not_verified"] = not_verified(report, context["inventory"], context)
    attach_requirements(report, context)
    return report


def render_markdown(report):
    o = report["overall"]
    lines = [f"# Breaker report: {report.get('workflow', {}).get('name') or report['workflow']['file']}", "",
             f"**Overall: {o['status']}** ({report['mode'].replace('_', ' ').lower()})", ""]
    lines += [f"- {w}" for w in o["why"]] + [""]
    wf = report["workflow"]
    lines += [f"Workflow file: `{wf['file']}`  sha256 `{wf['sha256'][:16]}...`  label `{report['label']}`", ""]
    if "inventory" in report:
        inv = report["inventory"]
        lines += ["## What Breaker found", "",
                  f"- {inv['node_count']} nodes: " + ", ".join(f"{k} x{v}" for k, v in inv["node_types"].items()),
                  f"- entry nodes: {', '.join(inv['entry_candidates']) or 'none'}; chosen: {report['entry']['chosen'] or 'NOT CHOSEN'}",
                  "- external effects (replaced by stubs in simulation): " + (", ".join(f"{e['name']} ({e['type']})" for e in inv["external_effects"]) or "none"),
                  "- credential types present: " + (", ".join(inv["credential_types"]) or "none"), ""]
        if inv["blockers"]:
            lines += ["## Why it is BLOCKED", ""]
            for b in inv["blockers"]:
                names = ", ".join(b["nodes"][:8]) + (f" (+{b['count'] - 8} more)" if b["count"] > 8 else "")
                lines.append(f"- **{b['category']}** x{b['count']} {b['node_types']}: {b['meaning']}. Nodes: {names}")
            lines.append("")
    if report["problems"] or report.get("cases_problems"):
        lines += ["## Input problems", ""] + [f"- {p}" for p in report["problems"]] + [f"- cases file: {p}" for p in report.get("cases_problems", [])] + [""]
    lines += ["## Capabilities", ""] + [f"- {c['capability']}: **{c['status']}**; {c['detail']}" for c in report["capabilities"]] + [""]
    if report["needs_from_you"]:
        lines += ["## What you need to supply", ""] + [f"- {n}" for n in report["needs_from_you"]] + [""]
    if report.get("cases", {}).get("results"):
        lines += ["## Cases", ""]
        for r in report["cases"]["results"]:
            extra = f"; failed: {'; '.join(r['failed_assertions'])}" if r["failed_assertions"] else ""
            lines.append(f"- `{r['id']}`: **{r['status']}** ({r['detail']}{extra}; execution {r['execution_id']})")
        lines.append("")
        lines += ["Disposable copies: " + ", ".join(f"{d['workflow_id']} -> {d['cleanup']}" for d in report["disposable_copies"])]
        if report.get("disposable_tables"):
            lines.append("Disposable tables: " + ", ".join(
                f"{t['table_name']} ({t['table_id']}) -> {t['cleanup']}" for t in report["disposable_tables"]))
        lines.append("")
    if report.get("requirement_coverage"):
        lines += [reqs.render(report["requirement_coverage"])]
    if report.get("requirements_problems"):
        lines += ["## Requirements file problems", ""] + [f"- {p}" for p in report["requirements_problems"]] + [""]
    if report["warnings"]:
        lines += ["## Warnings", ""] + [f"- {w}" for w in report["warnings"]] + [""]
    lines += ["## NOT VERIFIED", ""] + [f"- {n}" for n in report["not_verified"]]
    if report.get("uncovered_nodes"):
        lines += ["", "Nodes no case asserts on: " + ", ".join(report["uncovered_nodes"][:30])]
    lines += ["", "## Scope", "", report["disclaimer"], ""]
    return "\n".join(lines)


def write_report(report, run_dir):
    with (run_dir / "report.json").open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    with (run_dir / "report.md").open("x", encoding="utf-8") as handle:
        handle.write(render_markdown(report))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="breaker_verify_workflow")
    parser.add_argument("workflow", help="n8n workflow JSON (an export, or a one-item list)")
    parser.add_argument("--cases", help="cases file (schema v1 without the 'workflow' block); omit for an inventory-only report")
    parser.add_argument("--entry", help="entry node name when the workflow has several")
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--label", default=datetime.now(timezone.utc).strftime("t%Y%m%dT%H%M%SZ"))
    parser.add_argument("--run", action="store_true", help="execute for real (needs arming, credentials, --base-url, --mechanism-record)")
    parser.add_argument("--base-url")
    parser.add_argument("--mechanism-record")
    parser.add_argument("--requirements", help="candidate-bound requirements declaration (see breaker_requirements.py); adds a coverage report")
    parser.add_argument("--protect", action="append", default=[], help="workflow id whose definition digest is checked before and after")
    parser.add_argument("--protect-table", action="append", default=[],
                        help="existing Data Table id whose rows are digested before and after (read-only); the backend can never write it")
    parser.add_argument("--table-mechanism-record", help="record from breaker_table_probe.py (needed when the cases declare tables)")
    parser.add_argument("--expect-n8n-version", help="n8n application version the run must be on (required with --run; checked by a live read)")
    parser.add_argument("--n8n-image-evidence", help="only when the instance does not expose its version: '<image tag> <sha256:image id> [started-at]' from docker inspect, which must support --expect-n8n-version")
    parser.add_argument("--table-project", help="project id for disposable tables, if the instance requires one")
    args = parser.parse_args(argv)
    run_dir = None
    try:
        out_root = cli.assert_scratch(args.out_root)
        if not cli.re.fullmatch(r"[A-Za-z0-9_-]{1,40}", args.label):
            raise cli.OperatorError("label must be 1-40 characters of letters, digits, '_' or '-'")
        fresh = out_root / args.label
        fresh.mkdir(parents=True, exist_ok=False)
        run_dir = fresh  # only a folder this run created may receive a stopped-report
        report, context = analyse(args.workflow, args.cases, args.entry, run_dir, args.label, args.requirements)
        if args.run and report["overall"]["status"] != "BLOCKED" and context["loaded"] is not None:
            backend, transport, mechanism, snapshot = real_wiring(args, run_dir, report, context)
            report = run_simulation(report, context, backend=backend, transport=transport, mechanism=mechanism,
                                    run_dir=run_dir, snapshot=snapshot)
        elif args.run:
            report["warnings"].append("--run was requested but nothing was executed: " + report["overall"]["status"])
        write_report(report, run_dir)
        print(f"overall: {report['overall']['status']}")
        for line in report["overall"]["why"][:6]:
            print(f"  - {line}")
        print(f"report: {run_dir / 'report.md'}")
        return 0 if report["overall"]["status"] == "CONFORMS" else 1
    except (cli.OperatorError, ValueError, RuntimeError, FileExistsError, OSError) as exc:
        print(f"stopped ({type(exc).__name__}): {exc}", file=sys.stderr)
        write_stopped(run_dir, args, exc)
        return 2
    except Exception as exc:  # a tool defect must never look like a verdict
        print(f"stopped (tool error {type(exc).__name__}): no verdict was produced", file=sys.stderr)
        return 2


def write_stopped(run_dir, args, exc):
    """A refusal leaves a record in the label folder. It is not a verdict; the journal says whether anything was created."""
    if run_dir is None or not pathlib.Path(run_dir).is_dir():
        return
    journal = pathlib.Path(run_dir) / "created.jsonl"
    record = {"stopped": True, "verdict": None, "error_type": type(exc).__name__, "message": str(exc), "label": args.label,
              "created_journal_present": journal.exists(), "created_journal_events": (journal.read_text(encoding="utf-8").count(chr(10)) if journal.exists() else 0),
              "note": "no verdict was produced; a missing or empty journal means this tool created nothing"}
    try:
        with (pathlib.Path(run_dir) / "stopped.json").open("x", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
    except OSError:
        pass


def check_instance_identity(transport, records):
    """Read-only MCP discovery before any create: the live server must be the one every mechanism record was observed on."""
    info = transport.preflight()
    live = info.get("serverInfo")
    missing = sorted(be.TRANSPORT_OPERATIONS - set(info.get("tools") or ()))
    if missing:
        raise cli.OperatorError(f"the instance does not offer the required MCP tools: {missing}")
    for label, rec in records:
        recorded = rec.get("server_info")
        if not (isinstance(recorded, dict) and recorded.get("name") and recorded.get("version")):
            raise cli.OperatorError(f"the {label} has no server identity; re-run its probe before relying on it")
        if live != recorded:
            raise cli.OperatorError(f"the instance's server identity ({live!r}) differs from the {label} ({recorded!r}); "
                                    "the mechanism was verified on another build, so re-run the probe")
    return {"mcp_server_info": live, "mcp_protocol_version": info.get("protocolVersion"),
            "tools_checked": sorted(be.TRANSPORT_OPERATIONS),
            "mcp_scope": "MCP server identity only: it says nothing about the n8n application build"}


IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


def parse_image_evidence(text, expected):
    """``<image tag>  <sha256 image id>  [started-at]`` as printed by ``docker inspect --format '{{.Config.Image}}  {{.Image}}  {{.State.StartedAt}}'``."""
    parts = str(text or "").split()
    if len(parts) not in (2, 3):
        raise cli.OperatorError("--n8n-image-evidence must be '<image tag> <sha256:image id> [started-at]'")
    tag, image_id = parts[0], parts[1]
    if tag.rpartition(":")[2] != expected or ":" not in tag:
        raise cli.OperatorError(f"the image tag {tag!r} does not end in :{expected}; the evidence does not support that version")
    if not IMAGE_ID.fullmatch(image_id):
        raise cli.OperatorError("--n8n-image-evidence has no sha256 image id")
    return {"image_tag": tag, "image_id": image_id, "container_started_at": parts[2] if len(parts) == 3 else None}


def check_application_version(base_url, expected, image_evidence=None):
    """The n8n application version against the operator's --expect-n8n-version. A live read decides when the instance exposes
    it; when its public settings omit it, container-image evidence supplied by the operator may stand in, and is labelled so."""
    if not (isinstance(expected, str) and expected.strip()):
        raise cli.OperatorError("--run needs --expect-n8n-version (the n8n application version you are testing against); "
                                "no mechanism record attests the application build")
    expected = expected.strip()
    try:
        live = be.read_application_version(base_url)
    except be.VersionNotExposed:
        if not image_evidence:
            raise
        evidence = parse_image_evidence(image_evidence, expected)
        return {"application_version": None, "application_version_confirmed_live": False, "application_version_expected": expected,
                "application_version_basis": "operator-asserted with container image evidence; the instance does not expose its "
                                             "version, so Breaker did not read it from the application and did not verify it",
                "container_image_evidence": evidence}
    if live != expected:
        raise cli.OperatorError(f"the n8n application version is {live!r}, not the expected {expected!r}; nothing was created")
    return {"application_version": live, "application_version_confirmed_live": True, "application_version_expected": expected,
            "application_version_basis": "operator-asserted via --expect-n8n-version and confirmed by a live read; "
                                         "not attested by any mechanism record"}


def real_wiring(args, run_dir, report, context):
    if not (args.base_url and args.mechanism_record):
        raise cli.OperatorError("--run needs --base-url and --mechanism-record (from a verified mechanism probe)")
    origin = be.approved_origin(args.base_url)
    required = f"run:{origin}:{args.label}"
    groups = cases_mod.group_by_stubs(context["loaded"])
    specs = context["loaded"].tables
    if specs and not args.table_mechanism_record:
        raise cli.OperatorError("the cases declare Data Table test tables: --run also needs --table-mechanism-record "
                                "(from a verified breaker_table_probe.py run)")
    # The client's own table ids are protected outright: the backend can neither own nor write them.
    protected_tables = list(args.protect_table) + [spec.source_id for spec in specs.values()]
    backend = be.N8nBackend(expected_base_url=args.base_url, approval=required, protected_ids=args.protect,
                            journal_path=run_dir / "created.jsonl", max_creates=len(groups),
                            max_tables=len(groups) * len(specs), protected_table_ids=protected_tables,
                            table_project_id=args.table_project)
    if not backend.armed:
        raise cli.OperatorError(f"disarmed: set BREAKER_S4_APPROVAL to exactly {required!r} (only after you approved this run)")
    record = json.loads(pathlib.Path(args.mechanism_record).read_text(encoding="utf-8"))
    mechanism = probe.mechanism_from_record(record, neutralise.SET_RAW_JSON, backend.expected_base_url)
    if specs:
        table_record = table_probe.table_mechanism_from_record(
            json.loads(pathlib.Path(args.table_mechanism_record).read_text(encoding="utf-8")), backend.expected_base_url)
        report["table_mechanism_execution_id"] = table_record["execution_id"]
    application = check_application_version(backend.expected_base_url, getattr(args, "expect_n8n_version", None),
                                            getattr(args, "n8n_image_evidence", None))
    transport = be.make_transport(backend, len(context["loaded"].cases))
    records = [("mechanism record", record)]
    if specs:
        records.append(("table mechanism record", json.loads(pathlib.Path(args.table_mechanism_record).read_text(encoding="utf-8"))))
    report["instance_identity"] = {**application, **check_instance_identity(transport, records)}
    return backend, transport, mechanism, lambda: backend.snapshot(
        digest_ids=list(args.protect), include_tables=bool(specs), table_digest_ids=list(args.protect_table))


if __name__ == "__main__":
    sys.exit(main())
