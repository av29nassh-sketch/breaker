"""Regenerate site/demo-data.js from the real tool, offline.

Every offline scenario below runs this repository's own front door: the BLOCKED ones through the CLI exactly as a user
would, the run-shaped ones through ``run_simulation`` with the fake n8n backend the test suite uses (so they are labelled
MOCKED_OFFLINE, as the tool itself labels them). The one real-instance run is a recorded, sanitised report kept in
site/data/recorded-real-run.json; this script does not contact n8n.

usage: python scripts/build_demo_data.py
"""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
FIX = ROOT / "fixtures" / "requirements" / "lead-intake"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def summarise(report, origin):
    out = {"overall": report["overall"]["status"], "why": report["overall"]["why"][:4], "warnings": report.get("warnings", []),
           "origin": origin, "cases": [], "cleanup": []}
    for c in (report.get("cases") or {}).get("results") or []:
        out["cases"].append({"id": c["id"], "status": c["status"], "failed": c.get("failed_assertions") or []})
    for g in report.get("disposable_copies") or []:
        out["cleanup"].append({"what": "disposable workflow", "cleanup": g["cleanup"]})
    for t in report.get("disposable_tables") or []:
        out["cleanup"].append({"what": "disposable table " + t["table_name"].split("_")[0] + "_sim_…", "cleanup": t["cleanup"]})
    cov = report.get("requirement_coverage")
    if cov:
        out["requirements"] = [{"id": r["id"], "kind": r.get("kind"), "status": r["status"]} for r in cov["rows"]]
        out["ceiling"] = cov["evidence_ceiling"]
        out["readiness_claim"] = cov["readiness_claim"]
    return out


def cli(workflow, cases, requirements=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "scratch-demo"
        argv = [sys.executable, str(ROOT / "tools" / "breaker_verify_workflow.py"), str(workflow), "--cases", str(cases),
                "--out-root", str(root), "--label", "demo"]
        if requirements:
            argv += ["--requirements", str(requirements)]
        subprocess.run(argv, capture_output=True, text=True, env={"PYTHONPATH": str(ROOT / "src"), "SYSTEMROOT": "C:\\Windows"},
                       check=False)
        return json.loads((root / "demo" / "report.json").read_text(encoding="utf-8"))


def variant(tmp, change):
    wf = json.loads((FIX / "workflow.json").read_text(encoding="utf-8"))
    change(wf)
    path = pathlib.Path(tmp) / "workflow.json"
    path.write_text(json.dumps(wf), encoding="utf-8")
    return path


def code_node(wf):
    wf["nodes"].append({"id": "n9", "name": "Custom Logic", "type": "n8n-nodes-base.code", "typeVersion": 2,
                        "position": [880, 0], "parameters": {"jsCode": "return items;"}})
    wf["connections"]["Done"] = {"main": [[{"node": "Custom Logic", "type": "main", "index": 0}]]}


def update_op(wf):
    next(n for n in wf["nodes"] if n["name"] == "Save Lead")["parameters"]["operation"] = "update"


def edited(wf):
    next(n for n in wf["nodes"] if n["name"] == "Save Lead")["parameters"]["columns"]["value"]["status"] = "CONTACTED2"


def main():
    data = {"generated_by": "scripts/build_demo_data.py", "scenarios": {}}
    data["scenarios"]["dry"] = summarise(cli(FIX / "workflow.json", FIX / "cases.json", FIX / "requirements.json"), "NOT_RUN")
    with tempfile.TemporaryDirectory() as tmp:
        data["scenarios"]["code_node"] = summarise(cli(variant(tmp, code_node), FIX / "cases.json"), "NOT_RUN")
    with tempfile.TemporaryDirectory() as tmp:
        data["scenarios"]["update_op"] = summarise(cli(variant(tmp, update_op), FIX / "cases.json"), "NOT_RUN")
    with tempfile.TemporaryDirectory() as tmp:
        data["scenarios"]["tampered"] = summarise(cli(variant(tmp, edited), FIX / "cases.json", FIX / "requirements.json"), "NOT_RUN")

    tests = load("demo_front_tables", ROOT / "tests" / "test_breaker_verify_workflow_tables.py")
    env, front = tests.env, tests.front
    for key, knobs, change in (("mocked_fail", {}, "fail"), ("mocked_cleanup", {"fail_delete_table": True}, None)):
        with tempfile.TemporaryDirectory() as tmp:
            cases = env.default_cases()
            if change == "fail":
                cases[0]["table_assertions"] = [{"table": "leads", "count": 5}]
            report, context, run_dir = tests.check(pathlib.Path(tmp), doc=tests.cases_doc(cases=cases))
            backend = env.TableBackend(**knobs)
            report = front.run_simulation(report, context, backend=backend, transport=env.TableTransport(backend),
                                          mechanism=env.MECHANISM, run_dir=run_dir)
            data["scenarios"][key] = summarise(report, "MOCKED_OFFLINE")

    real = json.loads((ROOT / "site" / "data" / "recorded-real-run.json").read_text(encoding="utf-8"))
    data["scenarios"]["real_run"] = real
    (ROOT / "site" / "demo-data.js").write_text("window.BREAKER_DEMO = " + json.dumps(data, indent=1) + ";\n", encoding="utf-8")
    print("wrote site/demo-data.js:", ", ".join(f"{k}={v['overall']}" for k, v in data["scenarios"].items()))


if __name__ == "__main__":
    main()
