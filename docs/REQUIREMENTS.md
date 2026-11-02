# Requirements coverage

Say what a workflow must accomplish, and see per requirement what Breaker actually exercised. Pass a declaration with
`--requirements REQ.json` to `tools/breaker_verify_workflow.py`. Code: `tools/breaker_requirements.py`. Example:
`fixtures/requirements/lead-intake/requirements.json`.

## Rules

- Requirements and expected results come only from the declaration and the cases you supply; Breaker adds none.
- The declaration is bound to the exact workflow: `candidate.workflow_sha256` (optional, checked when present), and the report records the workflow digest, the declaration hash and the cases hash. A changed workflow needs new declarations.
- A requirement names the cases that are its evidence (`cases`) and the `nodes` / `tables` that evidence must assert on. A linked case that does not assert on them gives NOT_TESTED, not a pass.
- `candidate.workflow_sha256` is optional; without it the hash is recorded but the report says the binding was not asserted and a changed workflow would not have been refused.
- A `required_effect` declares its destination (`data_table`, `http_api`, `email`, or `other`). The type is checked against the real node; a table destination forces an independent table assertion; `other` cannot be simulated and must say `real_integration` or `human`.
- Every status is capped at SIMULATED evidence. Nothing here is a readiness PASS.

## Statuses (precedence top to bottom)

No status contains the word "verified": none of them is production evidence.

1. FAILED_IN_DISPOSABLE_RUN: a linked case failed an assertion that names this requirement's own nodes or tables, in a real disposable execution whose id matches its read-back and whose run succeeded. A case failing on something the requirement does not name is NOT attributed to it.
2. MOCKED_OFFLINE_RESULT: the only execution was a fake n8n inside a test (any backend/transport that is not the guarded real wiring). Shows the pipeline works, nothing about the workflow.
3. BLOCKED: the run or a linked case was blocked (Code node, unsupported integration, stale input).
4. REQUIRES_HUMAN_OR_REAL_INTEGRATION: declared `verification` is `real_integration` or `human`; simulation support is listed but never upgrades it.
5. NOT_TESTED: no linked case, not executed (check-only), inconclusive, a failure it cannot attribute, evidence whose execution id, read-back id, run status and group state do not agree, or cases that do not assert on what the requirement names.
6. SIMULATED_ONLY: conformed in a real disposable execution, but the evidence is a supplied stub's answer.
7. OBSERVED_IN_DISPOSABLE_RUN: conformed in a real disposable execution with self-consistent evidence and assertions covering every named node and table. Scope: the workflow's own logic and disposable state.

An execution id alone proves nothing: the runner's read-back must carry the same id, report a successful run, and come from a group that executed.

## Kinds of evidence (each row lists what it holds and does not hold)

| Kind | Meaning | Produced by Breaker? |
|---|---|---|
| MOCKED_OFFLINE | a fake n8n inside a test | only in tests |
| REAL_DISPOSABLE_EXECUTION | real n8n run of a disposable, neutralised, inactive copy | yes, with `--run` |
| SIMULATED_STUBBED_INTEGRATION | an external call replaced by an answer the author supplied | yes |
| INDEPENDENT_READBACK_OF_DISPOSABLE_STATE | rows read over REST from a table this run created | yes, for declared tables |
| REAL_CLIENT_INTEGRATION | the real system behaving correctly | never |

The execution origin (MOCKED_OFFLINE or REAL_DISPOSABLE_N8N) is printed at the top of the coverage section. The report without `--requirements` is unchanged.

## Requirement kinds

`business_outcome`, `business_path`, `required_effect` (with a `destination`: `data_table`, `http_api`, `email`, `other`),
`must_not_happen`, `input_rule`. Triggers name the entry nodes and what calls them. See the example declaration for the
exact shape.
