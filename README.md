# Breaker

**Test your n8n workflows before your client does.**

Breaker runs a disposable copy of an n8n workflow against the test cases you declare, reads the results back on its own,
deletes everything it created, and reports exactly what was proven and what was not. Your real workflows and Data
Tables are never written.

- Python standard library only. No dependencies.
- Talks only to an n8n running on your own machine, and only after you arm it for one specific run.
- Refuses what it can't test safely (Code nodes, unsupported Data Table operations, a workflow that changed since its
  requirements were written) before creating anything.

**Interactive demo:** https://av29nassh-sketch.github.io/breaker/ (or open [`site/index.html`](site/index.html) locally) to watch real Breaker runs,
including the ones it refuses.

## Quick start (offline, touches nothing)

```bash
git clone https://github.com/av29nassh-sketch/breaker breaker && cd breaker
export PYTHONPATH=src            # PowerShell: $env:PYTHONPATH = "src"
python tools/breaker_verify_workflow.py fixtures/requirements/lead-intake/workflow.json \
  --cases fixtures/requirements/lead-intake/cases.json \
  --requirements fixtures/requirements/lead-intake/requirements.json \
  --out-root "$PWD/../scratch-breaker" --label first-look
```

`--out-root` must be an absolute directory whose name starts with `scratch`. The report is written to
`<out-root>/<label>/report.md` and `report.json`. Without `--run`, nothing contacts n8n.

## Running against your local n8n

1. **Probe the mechanism once per n8n build.** Two small probes create one throwaway workflow each, run it, check the
   result, and delete it:
   ```bash
   export N8N_BASE_URL=http://127.0.0.1:5678
   # Set N8N_API_KEY and MCP_N8N_API_KEY yourself. Never commit or paste them.
   export BREAKER_S4_APPROVAL="gate1:http://127.0.0.1:5678:p1"
   python tools/breaker_s4_run.py probe --base-url http://127.0.0.1:5678 --out-root "$PWD/../scratch-breaker" --run-label p1
   export BREAKER_S4_APPROVAL="tableprobe:http://127.0.0.1:5678:tp1"
   python tools/breaker_table_probe.py --base-url http://127.0.0.1:5678 --out-root "$PWD/../scratch-breaker" --label tp1
   ```
2. **Run your cases:**
   ```bash
   export BREAKER_S4_APPROVAL="run:http://127.0.0.1:5678:r1"
   python tools/breaker_verify_workflow.py my-workflow.json --cases my-cases.json --requirements my-requirements.json \
     --out-root "$PWD/../scratch-breaker" --label r1 --run --base-url http://127.0.0.1:5678 \
     --mechanism-record <path>/mechanism-record.json --table-mechanism-record <path>/table-mechanism-record.json \
     --expect-n8n-version <your n8n version>
   ```
   If your instance does not expose its version, add `--n8n-image-evidence "<docker image tag> <sha256 image id>"`
   (from `docker inspect`). The report then marks the version as operator-asserted and not verified.

`BREAKER_S4_APPROVAL` must equal `<gate>:<local origin>:<label>` exactly. It is a guard against running the wrong
thing, not a substitute for deciding to run it. Use a new label for every run; a label folder is never reused.

## What a run does

1. **Preflight:** classifies every node; blocks Code nodes, undeclared or unsupported Data Table use, and requirements
   bound to a different workflow file.
2. **Instance checks:** loopback origin only; MCP server identity and n8n version match the probe records.
3. **Disposable copy:** outbound nodes are stubbed; Data Table nodes are rebound to fresh tables created for this run.
4. **Per case:** the table is reset to that case's seed, the copy is executed, and rows are read back over REST
   independently of the workflow's own output.
5. **Cleanup:** the copy and the tables are deleted by id, checked against the run's journal. Nothing is deleted by
   name prefix.
6. **Compare:** a snapshot of every workflow and table before and after must match.
7. **Report:** each case and each requirement gets a status that says what evidence it holds and lacks.

## Files you write

- `cases.json`: entry node, declared tables (columns, the nodes that use them), and cases with input, seed rows,
  nodes that must run, output assertions and table assertions. See `fixtures/requirements/lead-intake/cases.json`.
- `requirements.json` (optional): the business promises, each bound to cases and to the exact workflow hash. See
  `fixtures/requirements/lead-intake/requirements.json` and [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Honest limits

- **Code nodes are blocked.** Their execution can't yet be isolated.
- **Data Tables:** node v1.1, static table reference, row operations `get`, `insert` and `upsert` only.
- **Real integrations are not tested.** Email, CRM and API calls are stubbed; requirements about them are reported as
  `REQUIRES_HUMAN_OR_REAL_INTEGRATION`.
- **Evidence ceiling: SIMULATED.** Every report carries `readiness_claim: NONE`. A passing run says the disposable copy
  behaved as declared, not that the workflow is production-ready.
- **Local n8n only**, reached at a loopback address.

## Tests

```bash
python -m pytest -q
```

The suite (about 600 tests) runs offline. `conftest.py` installs a guard before anything is imported: network,
DNS, Docker and other subprocess calls are refused and recorded, credentials in the environment are withheld, and
the session fails if anything tried. It is a Python-level guard, not operating-system isolation; see
[docs/OFFLINE_TESTS.md](docs/OFFLINE_TESTS.md).

## Layout

| Path | What |
|---|---|
| `tools/breaker_verify_workflow.py` | the front door (CLI) |
| `tools/` | preflight, neutraliser, runner, guarded n8n backend, probes, requirements coverage |
| `src/breaker/` | engine modules the tools use (workflow profile, contract, provenance, MCP transport) |
| `fixtures/` | sample workflows, cases and requirements |
| `site/` | the interactive explainer (static, no dependencies); `scripts/build_demo_data.py` regenerates its data |

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Breaker is not affiliated with n8n GmbH; "n8n" is
used only to name the platform it tests.
