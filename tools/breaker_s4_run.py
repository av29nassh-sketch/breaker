"""Operator CLI for the S4.0 gates. Every real gate is disarmed unless the operator arms it for that gate alone.

  plan   print what each gate would do and the exact approval string each one needs; contacts nothing
  gate0  read-only preflight: MCP discovery, a snapshot of every workflow, offline checks; creates nothing
  probe  gate 1: the mechanism probe (one disposable workflow, two executions, identity-checked delete)
  e2e    gate 2: the generic runner on the w3-mini fixture, using the record the probe produced

Arming: BREAKER_S4_APPROVAL must equal ``<gate>:<approved local origin>:<run label>`` exactly. It is a safeguard against
running the wrong thing, never a substitute for the operator's own approval of that gate. Evidence goes only to a
scratch directory and is never ingested into a readiness record.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
OPS_ROOT = _ROOT.parent
FIXTURE = OPS_ROOT / "fixtures" / "simulate" / "w3-mini" / "cases.json"
PROTECTED_DEFAULT = ()  # ponytail: no built-in ids in the public build; pass --protect <workflow id> for yours
SYNTHETIC_CHECK = "SYNTHETIC-S4-0-DELIBERATE-FAIL"
LABELS = {"fixture_class": "DELIBERATE_FAILING_FIXTURE", "subject_kind": "SYNTHETIC_TEST_FIXTURE",
          "claim_scope": "mechanism demonstration only; not a client defect and not a result for any control",
          "readiness_record": "NOT_FOR_INGESTION_INTO_ANY_READINESS_RECORD"}
EXPECTED_CASES = {"urgent": "CONFORMS", "normal": "CONFORMS", "deliberate-fail": "PRODUCT_FAIL"}
GATE1_MAX_CREATES, GATE1_MAX_EXECUTIONS = 2, 3  # the operator's Gate 1 caps, enforced in code
GATE2_MAX_CREATES, GATE2_MAX_EXECUTIONS = 1, 3  # Gate 2: one disposable workflow, one execution per synthetic case
CAPS = {"gate1": (GATE1_MAX_CREATES, GATE1_MAX_EXECUTIONS), "gate2": (GATE2_MAX_CREATES, GATE2_MAX_EXECUTIONS)}
REQUIRED_TOOLS ={"test_workflow", "get_workflow_execution"}


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


be = _load("breaker_n8n_backend_s4", "breaker_n8n_backend.py")
probe = _load("breaker_mechanism_probe_s4", "breaker_mechanism_probe.py")
cases_mod = probe._sim._cases
neutralise = probe._neutralise
sim = probe._sim
evidence = _load("breaker_sim_evidence_s4", "breaker_sim_evidence.py")


class OperatorError(RuntimeError):
    pass


def approval_for(gate, base_url, label):
    if gate not in ("gate0", "gate1", "gate2", "tableprobe"):
        raise OperatorError(f"unknown gate {gate!r}")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", str(label)):
        raise OperatorError("run label must be 1-32 characters of letters, digits, '_' or '-'")
    return f"{gate}:{be.approved_origin(base_url)}:{label}"


def assert_scratch(out_root):
    path = pathlib.Path(out_root)
    if not path.is_absolute() or not path.name.startswith("scratch") or {"artifacts", "readiness", "mission"} & set(path.parts):
        raise OperatorError("evidence must go to an absolute directory named scratch*, outside artifacts/readiness/mission")
    return path


def _git(*args):
    try:
        return subprocess.run(["git", "-C", str(OPS_ROOT), *args], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _write(path, payload):
    with pathlib.Path(path).open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _offline_checks():
    loaded = cases_mod.load_cases(FIXTURE)
    classification = probe._pf.evaluate(loaded.definition)
    candidate = probe.build_probe_definition(neutralise.SET_RAW_JSON, "preview")
    return {"fixture_source_sha256": loaded.workflow_sha256, "fixture_cases": [c.id for c in loaded.cases],
            "fixture_classification": {n: v.disposition.value for n, v in classification.nodes.items()},
            "fixture_blocked": classification.blocked,
            "probe_definition_problems": probe.strict_problems(candidate, neutralise.SET_RAW_JSON, "preview")}


def run_gate0(backend, transport, run_dir, protected):
    info = transport.preflight()
    missing = sorted(REQUIRED_TOOLS - set(info["tools"]))
    snapshot = backend.snapshot(digest_ids=list(protected))
    offline = _offline_checks()
    report = {"gate": "gate0", "base_url": backend.expected_base_url, "mcp": info, "missing_tools": missing,
              "ops_commit": _git("rev-parse", "HEAD"),
              "tracked_changes": bool(_git("status", "--porcelain", "--untracked-files=no")),
              "protected_present": {i: i in snapshot["workflows"] for i in protected}, "workflow_count": len(snapshot["workflows"]),
              "snapshot": snapshot, "offline": offline}
    ok = not missing and not offline["fixture_blocked"] and not offline["probe_definition_problems"]
    report["ok"] = ok
    _write(run_dir / "gate0.json", report)
    return report


def run_probe_gate(backend, transport, run_dir, protected):
    info = transport.preflight()
    before = backend.snapshot(digest_ids=list(protected))
    report = probe.run_probe(backend=backend, transport=transport, mechanism=neutralise.SET_RAW_JSON, out_root=run_dir,
                             server_info=info.get("serverInfo"))
    after = backend.snapshot(digest_ids=list(protected))
    differences = be.diff_snapshots(before, after)
    summary = {"gate": "gate1", "probe_status": report["status"], "stopped_because": report["stopped_because"],
               "cleanup": report["cleanup"], "snapshot_differences": differences,
               "ok": report["status"] == "VERIFIED" and report["cleanup"] == "DELETED" and not differences}
    _write(run_dir / "gate1-summary.json", summary)
    return summary


def run_e2e_gate(backend, transport, run_dir, protected, record_path):
    record = json.loads(pathlib.Path(record_path).read_text(encoding="utf-8"))
    mechanism = probe.mechanism_from_record(record, neutralise.SET_RAW_JSON, backend.expected_base_url)
    before = backend.snapshot(digest_ids=list(protected))
    result = sim.simulate(FIXTURE, backend=backend, transport=transport, mechanism=mechanism, out_root=run_dir,
                          check_ids={"deliberate-fail": SYNTHETIC_CHECK}, labels=LABELS)
    after = backend.snapshot(digest_ids=list(protected))
    differences = be.diff_snapshots(before, after)
    statuses = {c.case_id: c.status for g in result.groups for c in g.cases}
    ingested = evidence.ingest(result.run_dir)
    summary = {"gate": "gate2", "run_status": result.status, "reasons": list(result.reasons), "case_statuses": statuses,
               "cleanup": [g.cleanup for g in result.groups], "snapshot_differences": differences,
               "scratch_ingest": {"accepted": list(ingested.accepted), "rejected": list(ingested.rejected),
                                  "provenance": sorted({str(r.provenance) for r in ingested.book.records})},
               "ok": (result.status == "COMPLETED" and statuses == EXPECTED_CASES and not differences
                      and all(g.cleanup == "DELETED" for g in result.groups))}
    _write(run_dir / "gate2-summary.json", summary)
    return summary


def build_real(args, gate):
    required = approval_for(gate, args.base_url, args.run_label)
    backend = be.N8nBackend(expected_base_url=args.base_url, approval=required, protected_ids=args.protect,
                            journal_path=None, max_creates=CAPS.get(gate, (None, None))[0])
    if not backend.armed:
        raise OperatorError(f"disarmed: set BREAKER_S4_APPROVAL to exactly {required!r} in your shell to arm {gate} "
                            f"(only after you have approved {gate})")
    return backend, required


def describe(args):
    return {gate: {"approval_env_value": approval_for(gate, args.base_url, args.run_label)} for gate in ("gate0", "gate1", "gate2")} | {
        "mcp_endpoint": be.mcp_endpoint_for(args.base_url), "rest_base": be.approved_origin(args.base_url),
        "protected_ids": list(args.protect), "evidence_root": str(assert_scratch(args.out_root)),
        "offline": _offline_checks(), "contacts_n8n": False}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="breaker_s4_run")
    parser.add_argument("command", choices=("plan", "gate0", "probe", "e2e"))
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--run-label", required=True)
    parser.add_argument("--protect", action="append", help="additional workflow id to protect (the defaults always apply)")
    parser.add_argument("--mechanism-record")
    args = parser.parse_args(argv)
    args.protect = list(dict.fromkeys([*PROTECTED_DEFAULT, *(args.protect or [])]))
    try:
        out_root = assert_scratch(args.out_root)
        if args.command == "plan":
            print(json.dumps(describe(args), indent=2, sort_keys=True))
            return 0
        gate = {"gate0": "gate0", "probe": "gate1", "e2e": "gate2"}[args.command]
        backend, _ = build_real(args, gate)
        run_dir = out_root / f"{gate}-{args.run_label}"
        run_dir.mkdir(parents=True, exist_ok=False)
        backend.journal_path = run_dir / "created.jsonl"
        transport = be.make_transport(backend, CAPS.get(gate, (None, None))[1])
        if args.command == "gate0":
            report = run_gate0(backend, transport, run_dir, args.protect)
        elif args.command == "probe":
            report = run_probe_gate(backend, transport, run_dir, args.protect)
        else:
            if not args.mechanism_record:
                raise OperatorError("e2e needs --mechanism-record from a VERIFIED probe")
            report = run_e2e_gate(backend, transport, run_dir, args.protect, args.mechanism_record)
        print(json.dumps({k: v for k, v in report.items() if k != "snapshot"}, indent=2, sort_keys=True, default=str))
        return 0 if report.get("ok") else 1
    except (OperatorError, ValueError, RuntimeError) as exc:  # refusals, missing credentials, transport failures
        print(f"stopped ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
