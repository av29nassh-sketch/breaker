"""Evidence serialization and Core ingestion adapter for simulated runs."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

ENVIRONMENT = "SIMULATED"


def _execution_rows(result):
    rows = []
    for group in result.groups:
        for case in group.cases:
            if case.execution_id:
                rows.append({"execution_id": case.execution_id, "group": group.stub_hash,
                             "case_id": case.case_id,
                             "transformed_definition_digest": group.transformed_definition_digest})
    return rows


def build_campaign_document(result, check_ids):
    executions = _execution_rows(result)
    verdicts = []
    for group in result.groups:
        for case in group.cases:
            if case.status == "PRODUCT_FAIL" and case.case_id in check_ids:
                # No provenance or campaign is declared: Core derives SYNTHETIC_FIXTURE from the SIMULATED
                # environment, and a producer must never assert more (or borrow another scenario's name).
                verdicts.append({"check_id": check_ids[case.case_id], "status": "FAIL",
                                 "execution_ids": [case.execution_id] if case.execution_id else [],
                                 "detail": case.detail, "observed": dict(case.observed),
                                 "read_back": case.read_back or {}})
    assert all(row.get("status") != "PASS" for row in verdicts)
    identity = any(group.status == "EXECUTED" for group in result.groups)
    candidate = {"preflight_identity_pass": identity, "source_sha256": result.source_sha256,
                 "source_definition_digest": result.source_definition_digest,
                 "transformed_definition_digests": [group.transformed_definition_digest for group in result.groups
                                                   if group.transformed_definition_digest],
                 "run_id": result.run_id, "mechanism_verification": result.mechanism_verification,
                 "labels": result.labels}
    return {"environment": ENVIRONMENT, "campaign_requested": "simulate", "candidate": candidate,
            "campaigns": {"simulate": {"executions": executions}}, "verdicts": verdicts}


def _case_json(case):
    return {"case_id": case.case_id, "status": case.status, "detail": case.detail,
            "execution_id": case.execution_id, "failed_assertions": list(case.failed_assertions),
            "observed": case.observed, "read_back": case.read_back, "expected": case.expected}


def write_run_files(result, check_ids):
    unmapped = [{"case_id": case.case_id, "failed_assertions": list(case.failed_assertions),
                 "execution_id": case.execution_id}
                for group in result.groups for case in group.cases
                if case.status == "PRODUCT_FAIL" and case.case_id not in check_ids]
    report = {"run_id": result.run_id, "run_dir": str(result.run_dir), "status": result.status,
              "reasons": list(result.reasons), "source_sha256": result.source_sha256,
              "source_definition_digest": result.source_definition_digest,
              "mechanism_verification": result.mechanism_verification,
              "node_classification": result.node_classification,
              "groups": [{"stub_hash": group.stub_hash, "case_ids": list(group.case_ids), "status": group.status,
                          "reasons": list(group.reasons),
                          "transformed_definition_digest": group.transformed_definition_digest,
                          "manifest": group.manifest, "clone_id": group.clone_id, "cleanup": group.cleanup,
                          "cases": [_case_json(case) for case in group.cases]} for group in result.groups],
              "labels": result.labels, "unmapped_failures": unmapped,
              "policy": "SIMULATED evidence can never be a promotable PASS."}
    run_path = Path(result.run_dir) / "run.json"
    with run_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    campaigns = Path(result.run_dir) / "campaigns"
    campaigns.mkdir(parents=True, exist_ok=False)
    with (campaigns / "simulate.json").open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(build_campaign_document(result, check_ids), indent=2,
                                sort_keys=True, ensure_ascii=False))


def ingest(run_dir, candidate_hash=None):
    root = Path(run_dir)
    report = json.loads((root / "run.json").read_text(encoding="utf-8"))
    identity = candidate_hash if candidate_hash is not None else report["source_definition_digest"]
    core_ingest = importlib.import_module("breaker.readiness.ingest")
    return core_ingest.ingest_campaigns(root / "campaigns", root=root, candidate_hash=identity)
