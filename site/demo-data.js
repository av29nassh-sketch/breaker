window.BREAKER_DEMO = {
 "generated_by": "scripts/build_demo_data.py",
 "scenarios": {
  "dry": {
   "overall": "NOT VERIFIED",
   "why": [
    "the cases validated, but nothing has been executed yet (use --run after approval)"
   ],
   "warnings": [],
   "origin": "NOT_RUN",
   "cases": [],
   "cleanup": [],
   "requirements": [
    {
     "id": "R1",
     "kind": "required_effect",
     "status": "NOT_TESTED"
    },
    {
     "id": "R2",
     "kind": "must_not_happen",
     "status": "NOT_TESTED"
    },
    {
     "id": "R3",
     "kind": "business_path",
     "status": "NOT_TESTED"
    },
    {
     "id": "R4",
     "kind": "required_effect",
     "status": "REQUIRES_HUMAN_OR_REAL_INTEGRATION"
    },
    {
     "id": "R5",
     "kind": "input_rule",
     "status": "NOT_TESTED"
    }
   ],
   "ceiling": "SIMULATED",
   "readiness_claim": "NONE"
  },
  "code_node": {
   "overall": "BLOCKED",
   "why": [
    "1 node(s) blocked [CODE_NODE]: Code nodes cannot be run safely yet (execution safety is unproven; Code-node support is deferred)"
   ],
   "warnings": [],
   "origin": "NOT_RUN",
   "cases": [],
   "cleanup": []
  },
  "update_op": {
   "overall": "BLOCKED",
   "why": [
    "cases file: Data Table node 'Save Lead': operation 'update' has no probed mechanism (probed: get, insert, upsert)",
    "cases file: case[0] seed names undeclared table 'leads'",
    "cases file: case[0] table_assertions[0] names an undeclared table",
    "cases file: case[1] seed names undeclared table 'leads'"
   ],
   "warnings": [],
   "origin": "NOT_RUN",
   "cases": [],
   "cleanup": []
  },
  "tampered": {
   "overall": "BLOCKED",
   "why": [
    "requirements file: the requirements were written for a different version of the workflow (candidate.workflow_sha256 does not match the file you passed)"
   ],
   "warnings": [],
   "origin": "NOT_RUN",
   "cases": [],
   "cleanup": []
  },
  "mocked_fail": {
   "overall": "PRODUCT_FAIL",
   "why": [
    "1 case(s) did not meet a declared expectation"
   ],
   "warnings": [],
   "origin": "MOCKED_OFFLINE",
   "cases": [
    {
     "id": "new-lead",
     "status": "PRODUCT_FAIL",
     "failed": [
      "table leads count == 5"
     ]
    },
    {
     "id": "known-lead",
     "status": "CONFORMS",
     "failed": []
    },
    {
     "id": "reset-proof",
     "status": "CONFORMS",
     "failed": []
    }
   ],
   "cleanup": [
    {
     "what": "disposable workflow",
     "cleanup": "DELETED"
    },
    {
     "what": "disposable table breaker_sim_\u2026",
     "cleanup": "DELETED"
    }
   ]
  },
  "mocked_cleanup": {
   "overall": "INCONCLUSIVE",
   "why": [
    "some cases were blocked or inconclusive, cleanup failed, or the instance changed"
   ],
   "warnings": [
    "cleanup FAILED: RuntimeError for disposable table breaker_sim_63cd4f63_0_leads (tbl-1): remove it manually after checking its name starts with breaker_sim_"
   ],
   "origin": "MOCKED_OFFLINE",
   "cases": [
    {
     "id": "new-lead",
     "status": "CONFORMS",
     "failed": []
    },
    {
     "id": "known-lead",
     "status": "CONFORMS",
     "failed": []
    },
    {
     "id": "reset-proof",
     "status": "CONFORMS",
     "failed": []
    }
   ],
   "cleanup": [
    {
     "what": "disposable workflow",
     "cleanup": "DELETED"
    },
    {
     "what": "disposable table breaker_sim_\u2026",
     "cleanup": "FAILED: RuntimeError"
    }
   ]
  },
  "real_run": {
   "overall": "CONFORMS",
   "why": [
    "2 case(s) matched their declared expectations (simulation only)"
   ],
   "warnings": [],
   "origin": "REAL_DISPOSABLE_N8N",
   "recorded": "2026-10-22, local n8n 2.35.4 (Docker), Breaker Stable 2 build",
   "cases": [
    {
     "id": "new-lead-added-alongside-existing",
     "status": "CONFORMS",
     "failed": [],
     "nodes_run": [
      "Done",
      "Find Lead",
      "Intake",
      "Save Lead"
     ]
    },
    {
     "id": "existing-lead-updated-no-carryover",
     "status": "CONFORMS",
     "failed": [],
     "nodes_run": [
      "Done",
      "Find Lead",
      "Intake",
      "Save Lead"
     ]
    }
   ],
   "executions": 2,
   "readback": {
    "new-lead-added-alongside-existing": [
     {
      "email": "new@example.invalid",
      "status": "CONTACTED"
     },
     {
      "email": "old@example.invalid",
      "status": "NEW"
     }
    ],
    "existing-lead-updated-no-carryover": [
     {
      "email": "vip@example.invalid",
      "status": "CONTACTED"
     }
    ]
   },
   "cleanup": [
    {
     "what": "disposable workflow",
     "cleanup": "DELETED"
    },
    {
     "what": "disposable table breaker_sim_\u2026",
     "cleanup": "DELETED"
    }
   ],
   "instance_unchanged": true,
   "requirements": [
    {
     "id": "R1",
     "kind": "required_effect",
     "status": "OBSERVED_IN_DISPOSABLE_RUN"
    },
    {
     "id": "R2",
     "kind": "must_not_happen",
     "status": "OBSERVED_IN_DISPOSABLE_RUN"
    },
    {
     "id": "R3",
     "kind": "business_path",
     "status": "OBSERVED_IN_DISPOSABLE_RUN"
    },
    {
     "id": "R4",
     "kind": "required_effect",
     "status": "REQUIRES_HUMAN_OR_REAL_INTEGRATION"
    },
    {
     "id": "R5",
     "kind": "input_rule",
     "status": "NOT_TESTED"
    }
   ],
   "ceiling": "SIMULATED",
   "readiness_claim": "NONE",
   "identity": {
    "mcp_server": "n8n MCP Server 1.1.0 (MCP identity only)",
    "application_version": "2.35.4, operator-asserted from docker inspect; not verified by Breaker"
   },
   "note": "Sanitised: instance-specific ids and paths removed."
  }
 }
};
