"""Offline tests for candidate-bound requirement declarations and the honest coverage report. No network, no n8n."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib
import socket
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "requirements"
W3 = ROOT / "fixtures" / "simulate" / "w3-mini"
B = "n8n-nodes-base."


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


front = load("front_requirements_under_test", ROOT / "tools" / "breaker_verify_workflow.py")
reqs = front.reqs
base = load("front_requirements_base", ROOT / "tests" / "test_breaker_verify_workflow.py")
env = load("front_requirements_env", ROOT / "tests" / "test_breaker_simulate_tables.py")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


class LeadTransport(env.TableTransport):
    """A faithful stand-in for the lead-intake fixture: upsert by email, then get the row."""

    def run_table_node(self, node, item):
        params = node["parameters"]
        table = self.backend.tables[params["dataTableId"]["value"]]
        self.touched.append(params["dataTableId"]["value"])
        if params["operation"] == "upsert":
            row = {"email": item["email"], "status": params["columns"]["value"]["status"]}
            hit = [r for r in table["rows"] if r["email"] == item["email"]]
            if hit:
                hit[0].update(row)
            else:
                table["rows"].append(row | {"id": len(table["rows"]) + 1})
            return item
        return dict(next(r for r in table["rows"] if r["email"] == item["email"]))


def w3_run(tmp_path, label="w3", requirements=None, run=True):
    run_dir = tmp_path / "scratch" / label
    run_dir.mkdir(parents=True)
    report, context = front.analyse(W3 / "workflow.json", W3 / "cases.json", None, run_dir, label,
                                    requirements or FIX / "w3-mini" / "requirements.json")
    if not run:
        return report, context
    backend = base.sim_tests.FakeBackend()
    transport = base.MiniFake(backend, base.W3_ROUTE)
    return front.run_simulation(report, context, backend=backend, transport=transport, mechanism=base.mechanism(),
                                run_dir=run_dir), context


def lead_run(tmp_path, label="lead", run=True, **backend_knobs):
    run_dir = tmp_path / "scratch" / label
    run_dir.mkdir(parents=True)
    report, context = front.analyse(FIX / "lead-intake" / "workflow.json", FIX / "lead-intake" / "cases.json", None, run_dir,
                                    label, FIX / "lead-intake" / "requirements.json")
    if not run:
        return report, context
    backend = env.TableBackend(**backend_knobs)
    return front.run_simulation(report, context, backend=backend, transport=LeadTransport(backend),
                                mechanism=env.MECHANISM, run_dir=run_dir), context


def pretend_real(report, context):
    """Test-only: recompute coverage as if the same case evidence had come from the guarded real wiring. Fakes are never real."""
    context["execution_origin"] = "REAL_DISPOSABLE_N8N"
    front.attach_requirements(report, context)
    return report


def status_of(report):
    return {r["id"]: r["status"] for r in report["requirement_coverage"]["rows"]}


# ---- finish line: two structurally different workflows, one report shape --------------------------------------------------
def test_router_with_stubbed_integrations_shows_every_kind_of_status(tmp_path):
    report, context = w3_run(tmp_path)
    pretend_real(report, context)
    cov = report["requirement_coverage"]
    assert status_of(report) == {"R1": reqs.SIMULATED, "R2": reqs.VERIFIED, "R3": reqs.SIMULATED, "R4": reqs.REQUIRES,
                                 "R5": reqs.NOT_TESTED, "R6": reqs.FAILED}
    failed = next(r for r in cov["rows"] if r["id"] == "R6")
    assert failed["cases"][0]["execution_id"] and "failed ['Queue Ticket']" in failed["reasons"][0]
    assert failed["evidence_held"] == [reqs.REAL_RUN] and reqs.CLIENT_REAL in failed["evidence_not_held"]
    requires = next(r for r in cov["rows"] if r["id"] == "R4")
    assert requires["verification"] == "real_integration" and not requires.get("simulation_support")
    assert report["overall"]["status"] == "PRODUCT_FAIL"
    assert cov["readiness_claim"] == "NONE" and cov["evidence_ceiling"] == "SIMULATED"
    assert sum(cov["counts"].values()) == 6 and cov["counts"][reqs.SIMULATED] == 2


def test_data_table_workflow_is_observed_on_disposable_state_and_human_items_stay_open(tmp_path):
    report, context = lead_run(tmp_path)
    pretend_real(report, context)
    cov = report["requirement_coverage"]
    assert report["overall"]["status"] == "CONFORMS"
    assert status_of(report) == {"R1": reqs.VERIFIED, "R2": reqs.VERIFIED, "R3": reqs.VERIFIED, "R4": reqs.REQUIRES,
                                 "R5": reqs.NOT_TESTED}
    r1 = next(r for r in cov["rows"] if r["id"] == "R1")
    assert r1["required_tables"] == ["leads"]  # a table destination forces an independent read-back assertion
    assert cov["undeclared_effect_nodes"] == ["Find Lead"] and cov["undeclared_trigger_nodes"] == []
    assert [d["cleanup"] for d in report["disposable_tables"]] == ["DELETED"]


def test_candidate_is_bound_to_the_exact_workflow_requirements_and_cases(tmp_path):
    report, context = w3_run(tmp_path)
    candidate = report["requirement_coverage"]["candidate"]
    assert report["candidate"] == candidate
    assert candidate["workflow_sha256"] == hashlib.sha256((W3 / "workflow.json").read_bytes()).hexdigest()
    assert candidate["requirements_sha256"] == hashlib.sha256((FIX / "w3-mini" / "requirements.json").read_bytes()).hexdigest()
    assert candidate["source_definition_digest"] and candidate["cases_sha256"] and candidate["name"] == "W3 mini router"


def test_check_only_run_reports_not_tested_never_a_result(tmp_path):
    report, _ = w3_run(tmp_path, run=False)
    cov = report["requirement_coverage"]
    assert report["overall"]["status"] == "NOT VERIFIED"
    assert set(status_of(report).values()) == {reqs.NOT_TESTED, reqs.REQUIRES}
    assert all("not executed" in r["reasons"][0] or r["id"] in ("R4", "R5") for r in cov["rows"])


def test_no_requirements_means_no_candidate_or_coverage_fields(tmp_path):
    run_dir = tmp_path / "scratch" / "plain"
    run_dir.mkdir(parents=True)
    report, context = front.analyse(W3 / "workflow.json", W3 / "cases.json", None, run_dir, "plain")
    assert not ({"candidate", "requirement_coverage", "requirements_problems"} & set(report))


# ---- the report never states more than the evidence supports ---------------------------------------------------------------
def test_no_status_or_wording_can_read_as_a_pass(tmp_path):
    for report, _ in (w3_run(tmp_path, "a"), lead_run(tmp_path, "b")):
        cov = report["requirement_coverage"]
        assert {r["status"] for r in cov["rows"]} <= set(reqs.STATUSES)
        text = reqs.render(cov)
        assert "readiness PASS" in text and "capped at SIMULATED" in text
        assert all(r["status"] not in ("PASS", "CONFORMS", "READY") for r in cov["rows"])
        front.write_report(report, pathlib.Path(report["evidence"]["run_dir"]).parents[1])


def test_a_requirement_is_only_verified_when_its_cases_assert_on_what_it_names(tmp_path):
    doc = json.loads((FIX / "w3-mini" / "requirements.json").read_text(encoding="utf-8"))
    doc["requirements"][1]["nodes"] = ["Triage"]  # R2 now names a node the linked case never asserts on
    path = tmp_path / "req.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    report, _ = w3_run(tmp_path, requirements=path)
    r2 = next(r for r in report["requirement_coverage"]["rows"] if r["id"] == "R2")
    assert r2["status"] == reqs.NOT_TESTED and "Triage" in r2["reasons"][0]


def test_unlinked_requirement_is_not_tested_and_invented_requirements_do_not_appear(tmp_path):
    report, _ = w3_run(tmp_path)
    ids = [r["id"] for r in report["requirement_coverage"]["rows"]]
    assert ids == ["R1", "R2", "R3", "R4", "R5", "R6"]  # exactly what was declared, nothing added by Breaker


# ---- precedence, driven directly -------------------------------------------------------------------------------------------
def declaration(**item):
    base_item = {"id": "R", "kind": "business_path", "statement": "s", "cases": ["c"], "nodes": [], "tables": [],
                 "destination": None, "verification": "execution"}
    return {"candidate": {"name": "n", "version": "1"}, "triggers": [], "requirements": [{**base_item, **item}]}


class Case:
    def __init__(self, cid="c", must_run=(), must_not_run=(), outputs=(), tables=()):
        self.id, self.must_run, self.must_not_run = cid, tuple(must_run), tuple(must_not_run)
        self.output_assertions = tuple({"node": n, "item": 0, "path": "p", "equals": 1} for n in outputs)
        self.table_assertions = tuple({"table": t} for t in tables)


class Loaded:
    def __init__(self, *cases):
        self.cases, self.tables = tuple(cases), {}


NODES = {"Stub": B + "httpRequest", "Mail": B + "emailSend", "Logic": B + "if", "Other": B + "if", "Store": B + "dataTable"}
REAL, MOCK = "REAL_DISPOSABLE_N8N", "MOCKED_OFFLINE"


def cover(decl, loaded, evidence, state="RAN", origin=REAL):
    return reqs.coverage(decl, loaded, NODES, evidence, state, {"entry_candidates": []}, origin)["rows"][0]


def ev(status="CONFORMS", eid="e1", failed=(), **override):
    """A case record whose execution evidence is self-consistent, unless an override breaks it."""
    record = {"status": status, "execution_id": eid, "failed_assertions": list(failed), "read_back_execution_id": eid,
              "execution_status": "success", "group_status": "EXECUTED", "table_readback": False}
    record.update(override)
    return {"c": record}


RUN_LOGIC = {"nodes": ["Logic"]}
LOGIC_FAIL = ["must_run Logic: node did not run"]


@pytest.mark.parametrize("item,loaded,evidence,state,origin,expected", [
    ({"nodes": ["Stub"]}, Loaded(Case(must_run=["Stub"])), ev(), "RAN", REAL, reqs.SIMULATED),
    ({"nodes": ["Mail"]}, Loaded(Case(outputs=["Mail"])), ev(), "RAN", REAL, reqs.SIMULATED),
    ({"nodes": ["Stub"]}, Loaded(Case(must_not_run=["Stub"])), ev(), "RAN", REAL, reqs.OBSERVED),
    (RUN_LOGIC, Loaded(Case(must_run=["Logic"])), ev(), "RAN", REAL, reqs.OBSERVED),
    (RUN_LOGIC, Loaded(Case(must_run=["Other"])), ev(), "RAN", REAL, reqs.NOT_TESTED),
    ({"tables": ["leads"]}, Loaded(Case(tables=[])), ev(), "RAN", REAL, reqs.NOT_TESTED),
    ({"tables": ["leads"]}, Loaded(Case(tables=["leads"])), ev(), "RAN", REAL, reqs.OBSERVED),
    (RUN_LOGIC, Loaded(Case(must_run=["Logic"])), ev("PRODUCT_FAIL", failed=LOGIC_FAIL), "RAN", REAL, reqs.FAILED),
    (RUN_LOGIC, Loaded(Case(must_run=["Logic"])), ev("INCONCLUSIVE"), "RAN", REAL, reqs.NOT_TESTED),
    (RUN_LOGIC, Loaded(Case(must_run=["Logic"])), ev("BLOCKED", None), "RAN", REAL, reqs.BLOCKED),
    (RUN_LOGIC, Loaded(Case(must_run=["Logic"])), {}, "BLOCKED", REAL, reqs.BLOCKED),
    (RUN_LOGIC, Loaded(Case(must_run=["Logic"])), {}, "NOT_RUN", "NOT_RUN", reqs.NOT_TESTED),
    ({"cases": []}, Loaded(), {}, "RAN", REAL, reqs.NOT_TESTED),
    ({"verification": "human"}, Loaded(Case(must_run=["Logic"])), ev(), "RAN", REAL, reqs.REQUIRES),
    ({"verification": "real_integration"}, Loaded(Case()), {}, "NOT_RUN", "NOT_RUN", reqs.REQUIRES),
    ({"verification": "human", **RUN_LOGIC}, Loaded(Case(must_run=["Logic"])), ev("PRODUCT_FAIL", failed=LOGIC_FAIL), "RAN", REAL, reqs.FAILED),
    ({"verification": "human"}, Loaded(Case()), {}, "BLOCKED", REAL, reqs.BLOCKED),
    ({"verification": "human", "cases": []}, Loaded(), {}, "BLOCKED", REAL, reqs.REQUIRES),  # nothing of its was blocked
    ({"cases": []}, Loaded(), {}, "BLOCKED", REAL, reqs.NOT_TESTED),
])
def test_status_precedence(item, loaded, evidence, state, origin, expected):
    assert cover(declaration(**item), loaded, evidence, state, origin)["status"] == expected


def test_human_requirement_keeps_its_simulation_support_visible_but_never_upgrades():
    row = cover(declaration(verification="human"), Loaded(Case(must_run=["Logic"])), ev())
    assert row["status"] == reqs.REQUIRES and row["simulation_support"] == ["c: CONFORMS"]


# ---- honesty: whose evidence is it, and is it self-consistent --------------------------------------------------------------
@pytest.mark.parametrize("status,failed", [("CONFORMS", ()), ("PRODUCT_FAIL", LOGIC_FAIL)])
def test_a_fake_n8n_can_never_yield_an_observed_failed_or_simulated_status(status, failed):
    row = cover(declaration(**RUN_LOGIC), Loaded(Case(must_run=["Logic"])), ev(status, failed=failed), "RAN", MOCK)
    assert row["status"] == reqs.MOCKED and row["evidence_held"] == [reqs.MOCKED_OFFLINE]
    assert reqs.CLIENT_REAL in row["evidence_not_held"] and reqs.CORE_GRADE in row["evidence_not_held"]
    stub = cover(declaration(nodes=["Stub"]), Loaded(Case(must_run=["Stub"])), ev(), "RAN", MOCK)
    assert stub["status"] == reqs.MOCKED


def test_a_mocked_front_door_run_is_labelled_everywhere_and_holds_no_stronger_status(tmp_path):
    for report, _ in (w3_run(tmp_path, "a"), lead_run(tmp_path, "b")):
        cov = report["requirement_coverage"]
        assert cov["execution_origin"] == "MOCKED_OFFLINE"
        assert not ({r["status"] for r in cov["rows"]} & {reqs.OBSERVED, reqs.SIMULATED, reqs.FAILED})
        assert reqs.MOCKED in {r["status"] for r in cov["rows"]}
        md = front.render_markdown(report)
        assert "EXECUTION ORIGIN: MOCKED_OFFLINE" in md and "nothing below says anything about the workflow" in md


def test_only_the_guarded_real_wiring_counts_as_real(tmp_path):
    be = front.be
    backend = be.N8nBackend(expected_base_url="http://127.0.0.1:5678", approval="x")

    class Raw:
        endpoint = "http://127.0.0.1:5678/mcp-server/http"

    for n, (pair, expected) in enumerate((((backend, be.GuardedTransport(Raw(), backend)), "REAL_DISPOSABLE_N8N"),
                                           ((env.TableBackend(), Raw()), "MOCKED_OFFLINE"),
                                           ((backend, Raw()), "MOCKED_OFFLINE"))):
        report, context = w3_run(tmp_path, label=f"o{n}", run=False)
        # the backend is disarmed, so nothing is contacted; only the origin it is judged as matters here
        front.run_simulation(report, context, backend=pair[0], transport=pair[1], mechanism=base.mechanism(),
                             run_dir=tmp_path / "scratch" / f"o{n}")
        assert context["execution_origin"] == expected, n


@pytest.mark.parametrize("break_it", [
    {"execution_id": None},
    {"execution_id": "   "},
    {"read_back_execution_id": "other"},
    {"read_back_execution_id": None},
    {"execution_status": "error"},
    {"execution_status": None},
    {"group_status": "BLOCKED"},
])
def test_an_execution_id_alone_never_makes_evidence_admissible(break_it):
    loaded = Loaded(Case(must_run=["Logic"]))
    conform = cover(declaration(**RUN_LOGIC), loaded, ev(**break_it))
    assert conform["status"] in (reqs.NOT_TESTED, reqs.BLOCKED) and conform["evidence_held"] == []
    failing = cover(declaration(**RUN_LOGIC), loaded, ev("PRODUCT_FAIL", failed=LOGIC_FAIL, **break_it))
    assert failing["status"] in (reqs.NOT_TESTED, reqs.BLOCKED) and failing["status"] != reqs.FAILED


def test_a_made_up_execution_id_with_a_matching_read_back_still_needs_the_real_origin():
    row = cover(declaration(**RUN_LOGIC), Loaded(Case(must_run=["Logic"])), ev(eid="999999"), "RAN", MOCK)
    assert row["status"] == reqs.MOCKED  # an id that looks real is still a fake run's id


def test_a_shared_case_failure_is_attributed_only_to_requirements_that_name_the_failed_thing():
    loaded = Loaded(Case(must_run=["Logic", "Other"]))
    evidence = ev("PRODUCT_FAIL", failed=["must_run Other: node did not run"])
    own = cover(declaration(nodes=["Other"]), loaded, evidence)
    unrelated = cover(declaration(nodes=["Logic"]), loaded, evidence)
    nothing_named = cover(declaration(), loaded, evidence)
    assert own["status"] == reqs.FAILED
    assert unrelated["status"] == reqs.NOT_TESTED and "does not name" in unrelated["reasons"][0]
    assert nothing_named["status"] == reqs.NOT_TESTED
    for row in (unrelated, nothing_named):
        assert row["status"] not in (reqs.FAILED, reqs.OBSERVED, reqs.SIMULATED)


def test_a_failure_in_a_label_breaker_cannot_read_is_never_attributed():
    row = cover(declaration(**RUN_LOGIC), Loaded(Case(must_run=["Logic"])), ev("PRODUCT_FAIL", failed=["something odd"]))
    assert row["status"] == reqs.NOT_TESTED and "cannot read" in row["reasons"][0]


def test_runner_failure_labels_are_read_back_to_the_nodes_and_tables_they_name(tmp_path):
    doc = json.loads((FIX / "lead-intake" / "cases.json").read_text(encoding="utf-8"))
    first = doc["cases"][0]
    first["output_assertions"] = [{"node": "Find Lead", "item": 0, "path": "status", "equals": "NOPE"}]
    first["must_run"] = ["Save Lead"]
    first["must_not_run"] = ["Done"]
    first["table_assertions"] = [{"table": "leads", "count": 5}]
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps(doc), encoding="utf-8")
    run_dir = tmp_path / "scratch" / "labels"
    run_dir.mkdir(parents=True)
    report, context = front.analyse(FIX / "lead-intake" / "workflow.json", cases, None, run_dir, "labels")
    backend = env.TableBackend()
    front.run_simulation(report, context, backend=backend, transport=LeadTransport(backend), mechanism=env.MECHANISM,
                         run_dir=run_dir)
    labels = context["case_evidence"]["new-lead-added-alongside-existing"]["failed_assertions"]
    case = next(c for c in context["loaded"].cases if c.id == "new-lead-added-alongside-existing")
    assert len(labels) == 3 and reqs.failed_targets(labels, reqs.case_labels(case)) == {"Find Lead", "Done", "table leads"}


def test_stub_dependent_evidence_is_never_observed_and_never_claims_the_real_integration():
    loaded = Loaded(Case(must_run=["Stub"]))
    row = cover(declaration(nodes=["Stub"]), loaded, ev())
    assert row["status"] == reqs.SIMULATED
    assert reqs.STUBBED in row["evidence_held"] and reqs.CLIENT_REAL in row["evidence_not_held"]
    with_table = cover(declaration(nodes=["Stub"], tables=["leads"]), Loaded(Case(must_run=["Stub"], tables=["leads"])),
                       ev(table_readback=True))
    assert with_table["status"] == reqs.SIMULATED and reqs.READBACK in with_table["evidence_held"]
    not_read_back = cover(declaration(tables=["leads"]), Loaded(Case(tables=["leads"])), ev(table_readback=False))
    assert reqs.READBACK not in not_read_back["evidence_held"]


def test_the_report_separates_the_six_kinds_of_evidence(tmp_path):
    report, context = w3_run(tmp_path)
    pretend_real(report, context)
    cov = report["requirement_coverage"]
    assert set(cov["evidence_kinds"]) == {reqs.MOCKED_OFFLINE, reqs.REAL_RUN, reqs.STUBBED, reqs.READBACK, reqs.CLIENT_REAL,
                                          reqs.CORE_GRADE}
    for row in cov["rows"]:
        assert reqs.CLIENT_REAL not in row["evidence_held"] and reqs.CORE_GRADE not in row["evidence_held"]
    text = reqs.render(cov)
    assert "evidence held:" in text and "not held:" in text and "not closure-grade" in text


def test_core_would_still_treat_this_environment_as_a_synthetic_fixture():
    from breaker.readiness.model import EvidenceClass, EvidenceProvenance
    from breaker.readiness.provenance import derive_provenance
    assert derive_provenance(evidence_class=EvidenceClass.DYNAMIC, environment=front.sim.__dict__.get("ENVIRONMENT", "SIMULATED")) \
        == EvidenceProvenance.SYNTHETIC_FIXTURE


def test_a_declaration_without_a_hash_is_recorded_as_not_binding(tmp_path):
    doc = json.loads((FIX / "w3-mini" / "requirements.json").read_text(encoding="utf-8"))
    doc["candidate"].pop("workflow_sha256")
    path = tmp_path / "nohash.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    report, _ = w3_run(tmp_path, requirements=path, run=False)
    candidate = report["candidate"]
    assert candidate["binding_asserted_by_declaration"] is False and "would not have been refused" in candidate["binding"]
    bound, _ = w3_run(tmp_path, label="bound", run=False)
    assert bound["candidate"]["binding_asserted_by_declaration"] is True


# ---- declaration validation ---------------------------------------------------------------------------------------------------
def good_doc():
    return json.loads((FIX / "lead-intake" / "requirements.json").read_text(encoding="utf-8"))


def parse(doc):
    run_dir = None
    wf = json.loads((FIX / "lead-intake" / "workflow.json").read_text(encoding="utf-8"))
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        report, context = front.analyse(FIX / "lead-intake" / "workflow.json", FIX / "lead-intake" / "cases.json", None,
                                        pathlib.Path(tmp), "x")
        loaded = context["loaded"]
    sha = hashlib.sha256((FIX / "lead-intake" / "workflow.json").read_bytes()).hexdigest()
    return reqs.parse(doc, wf, loaded, sha, {"SUBWORKFLOW"})


def test_the_fixture_declarations_are_valid():
    decl, problems = parse(good_doc())
    assert problems == [] and len(decl["requirements"]) == 5


@pytest.mark.parametrize("mutate,fragment", [
    (lambda d: d["candidate"].update(workflow_sha256="0" * 64), "different version of the workflow"),
    (lambda d: d["candidate"].update(workflow_sha256="XYZ"), "64 lowercase hex"),
    (lambda d: d.pop("candidate"), "candidate must be an object"),
    (lambda d: d.update(schema_version=2), "schema_version"),
    (lambda d: d.update(extra=1), "unknown key"),
    (lambda d: d["requirements"][0].update(kind="vibes"), "kind must be one of"),
    (lambda d: d["requirements"][0].update(cases=["no-such-case"]), "unknown case"),
    (lambda d: d["requirements"][0].update(nodes=["Ghost"]), "unknown node"),
    (lambda d: d["requirements"][1].update(tables=["nope"]), "unknown declared table"),
    (lambda d: d["requirements"][1].update(id="R1"), "duplicate requirement id"),
    (lambda d: d["requirements"][0].update(destination={"type": "http_api", "node": "Save Lead"}), "does not match node"),
    (lambda d: d["requirements"][3].update(verification="execution"), "cannot be simulated"),
    (lambda d: d["requirements"][0].pop("destination"), "must declare its destination"),
    (lambda d: d["requirements"][0].update(verification="whenever"), "verification must be one of"),
    (lambda d: d["requirements"][0].update(statement="  "), "statement"),
    (lambda d: d["triggers"][0].update(node="Save Lead"), "entry (trigger) node"),
    (lambda d: d["triggers"][0].update(kind="webhook"), "does not match the triggers Breaker observed"),
    (lambda d: d.update(requirements=[]), "non-empty list"),
])
def test_declaration_problems_are_named(mutate, fragment):
    doc = good_doc()
    mutate(doc)
    decl, problems = parse(doc)
    assert decl is None and any(fragment in p for p in problems), problems


def test_a_stale_declaration_blocks_the_run_before_anything_executes(tmp_path):
    doc = json.loads((FIX / "w3-mini" / "requirements.json").read_text(encoding="utf-8"))
    doc["candidate"]["workflow_sha256"] = "1" * 64
    path = tmp_path / "stale.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    report, context = w3_run(tmp_path, requirements=path, run=False)
    assert report["overall"]["status"] == "BLOCKED" and "requirement_coverage" not in report
    assert any("different version" in p for p in report["requirements_problems"])
    assert report["capabilities"][-2]["status"] == "BLOCKED"


def test_unreadable_requirements_file_is_a_problem_not_a_crash(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    report, _ = w3_run(tmp_path, requirements=path, run=False)
    assert report["overall"]["status"] == "BLOCKED" and any("cannot be read" in p for p in report["problems"])


def test_blocked_workflow_reports_every_requirement_blocked_or_requiring_humans(tmp_path):
    wf = tmp_path / "wf.json"
    wf.write_text(json.dumps({"name": "code", "nodes": [
        {"id": "a", "name": "In", "type": B + "executeWorkflowTrigger", "parameters": {}},
        {"id": "b", "name": "Calc", "type": B + "code", "parameters": {}}],
        "connections": {"In": {"main": [[{"node": "Calc", "type": "main", "index": 0}]]}}}), encoding="utf-8")
    req = tmp_path / "req.json"
    req.write_text(json.dumps({"schema_version": 1, "candidate": {"name": "code", "version": "1"},
                               "requirements": [
                                   {"id": "A", "kind": "business_outcome", "statement": "computes", "cases": ["c"]},
                                   {"id": "B", "kind": "required_effect", "statement": "a human checks", "destination":
                                    {"type": "other"}, "verification": "human"}]}), encoding="utf-8")
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps({"schema_version": 1, "entry_node": "In", "cases": [{"id": "c", "input": {}, "must_run": ["Calc"]}]}),
                     encoding="utf-8")
    run_dir = tmp_path / "scratch" / "blk"
    run_dir.mkdir(parents=True)
    report, _ = front.analyse(wf, cases, None, run_dir, "blk", req)
    assert report["overall"]["status"] == "BLOCKED"
    assert status_of(report) == {"A": reqs.BLOCKED, "B": reqs.REQUIRES}


# ---- Core contract and the optional control registry -------------------------------------------------------------------------------
def test_declaration_projects_onto_core_contract_fields_and_reports_gaps():
    decl, _ = parse(good_doc())
    contract = reqs.to_contract(decl)
    assert contract.has("outputs") and contract.has("business_paths") and contract.has("must_not_happen")
    assert contract.has("inputs") and contract.has("trigger.kind")
    assert not contract.has("recovery_objectives") and not contract.has("business_key_dedup")  # never defaulted or guessed


def test_missing_registry_file_degrades_to_no_links_not_a_failure(tmp_path):
    rows, sha = reqs.registry_rows(tmp_path / "absent.json")
    assert rows is None and sha is None
    decl, _ = parse(good_doc())
    assert reqs.link_controls(decl, reqs.to_contract(decl), None) == ({}, {"available": False}, {})


def test_markdown_report_carries_the_coverage_section_and_ceiling(tmp_path):
    report, _ = lead_run(tmp_path)
    md = front.render_markdown(report)
    assert "## Requirement coverage" in md and "MOCKED_OFFLINE_RESULT" in md and "REQUIRES_HUMAN_OR_REAL_INTEGRATION" in md
    assert "Effects in the workflow that no requirement names" in md and "Disposable tables:" in md
    assert "client table" not in md.lower() or env.CLIENT_TABLE not in md


# ---- combined-branch review fix: an unclean run supports no positive claim -----------------------------------------------------
@pytest.mark.parametrize("item,loaded", [({"nodes": ["Logic"]}, Loaded(Case(must_run=["Logic"]))),
                                         ({"nodes": ["Stub"]}, Loaded(Case(must_run=["Stub"])))])
def test_an_unclean_run_supports_no_positive_claim(item, loaded):
    clean = reqs.coverage(declaration(**item), loaded, NODES, ev(), "RAN", {"entry_candidates": []}, REAL, [])["rows"][0]
    dirty = reqs.coverage(declaration(**item), loaded, NODES, ev(), "RAN", {"entry_candidates": []}, REAL,
                          ["cleanup FAILED for disposable table x"])["rows"][0]
    assert clean["status"] in (reqs.OBSERVED, reqs.SIMULATED)
    assert dirty["status"] == reqs.NOT_TESTED and "not clean" in dirty["reasons"][0] and dirty["evidence_held"] == []


def test_a_failure_is_still_reported_from_an_unclean_run():
    row = reqs.coverage(declaration(**RUN_LOGIC), Loaded(Case(must_run=["Logic"])), NODES, ev("PRODUCT_FAIL", failed=LOGIC_FAIL),
                        "RAN", {"entry_candidates": []}, REAL, ["instance changed"])["rows"][0]
    assert row["status"] == reqs.FAILED


def test_front_door_passes_cleanup_failures_into_the_coverage(tmp_path):
    run_dir = tmp_path / "scratch" / "dirty"
    run_dir.mkdir(parents=True)
    report, context = front.analyse(FIX / "lead-intake" / "workflow.json", FIX / "lead-intake" / "cases.json", None, run_dir,
                                    "dirty", FIX / "lead-intake" / "requirements.json")
    backend = env.TableBackend(fail_delete_table=True)
    front.run_simulation(report, context, backend=backend, transport=LeadTransport(backend), mechanism=env.MECHANISM,
                         run_dir=run_dir)
    pretend_real(report, context)
    assert report["overall"]["status"] == "INCONCLUSIVE" and report["warnings"]
    statuses = status_of(report)
    assert reqs.OBSERVED not in statuses.values() and statuses["R1"] == reqs.NOT_TESTED


# ---- attribution is exact, not parsed from text ----------------------------------------------------------------------------------
def test_a_node_with_a_colon_in_its_name_is_not_confused_with_a_shorter_name():
    nodes = dict(NODES, **{"Check": B + "if", "Check: Stock": B + "if"})
    loaded = Loaded(Case(must_run=["Check", "Check: Stock"]))
    evidence = ev("PRODUCT_FAIL", failed=["must_run Check: Stock: node did not run"])
    run = lambda name: reqs.coverage(declaration(nodes=[name]), loaded, nodes, evidence, "RAN", {"entry_candidates": []}, REAL)["rows"][0]
    assert run("Check: Stock")["status"] == reqs.FAILED
    other = run("Check")
    assert other["status"] == reqs.NOT_TESTED and other["status"] != reqs.FAILED  # the failure belongs to the other node


def test_text_inside_an_expected_value_cannot_redirect_a_failure_to_another_node():
    case = Case(outputs=["Real"])
    labels = reqs.case_labels(case)
    forged = "output Real[0].p == 'x'[0].p == 1"  # not one of the case's own assertion labels
    assert reqs.failed_targets([forged], labels) == set()
    assert reqs.failed_targets(list(labels), labels) == {"Real"}


def test_a_table_label_only_counts_for_the_exact_logical_table():
    known = {}
    assert reqs.failed_targets(["table leads count == 5"], known) == {"table leads"}
    assert reqs.failed_targets(["table leads_old count == 5"], known) == {"table leads_old"}
    assert reqs.failed_targets(["table leads whatever"], known) == set()


def test_requirements_without_cases_still_produce_an_honest_not_tested_report(tmp_path):
    run_dir = tmp_path / "scratch" / "nocases"
    run_dir.mkdir(parents=True)
    report, context = front.analyse(W3 / "workflow.json", None, None, run_dir, "nocases", FIX / "w3-mini" / "requirements.json")
    statuses = set(status_of(report).values()) if "requirement_coverage" in report else None
    assert statuses is None or statuses <= {reqs.NOT_TESTED, reqs.REQUIRES, reqs.BLOCKED}
    assert report["overall"]["status"] in ("NOT VERIFIED", "BLOCKED")


def test_candidate_records_both_the_authors_cases_file_and_the_staged_copy(tmp_path):
    report, _ = w3_run(tmp_path, run=False)
    candidate = report["candidate"]
    assert candidate["cases_file_sha256"] == hashlib.sha256((W3 / "cases.json").read_bytes()).hexdigest()
    assert candidate["cases_sha256"] and candidate["cases_sha256"] != candidate["cases_file_sha256"]  # staged copy gets a computed workflow block
