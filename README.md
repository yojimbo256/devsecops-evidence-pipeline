# devsecops-evidence-pipeline

A small CI/CD security pipeline plus a Python tool that turns scanner output into
NIST SP 800-53 mapped POA&M evidence.

Most pipelines stop at "the scan found 12 things." This one carries the results
through to what an authorizing official actually asks for: which controls are
affected, how bad it is, and when each item has to be fixed.

## What's in the repo

| Piece | Purpose |
|---|---|
| `app/` | Tiny FastAPI service with input validation. Gives the pipeline something real to build and ship. |
| `Dockerfile` | Slim base image, non-root user, health check. |
| `.github/workflows/ci.yml` | Tests, Bandit (SAST), pip-audit (dependencies), image build, Trivy (image scan), evidence build, severity gate. |
| `evidence/` | The tool. Parses scanner JSON, maps findings to controls, writes the POA&M and summary. |
| `tests/` | Unit tests for the parsers, mapping, report building and CLI exit codes. |
| `docs/sample-output/` | Example output generated from the test fixtures. |

## How the pipeline flows

```
push / PR
   |
   +-- pytest
   +-- bandit        -> reports/bandit.json
   +-- pip-audit     -> reports/pip-audit.json
   +-- docker build
   +-- trivy         -> reports/trivy.json
   |
   +-- python -m evidence ...  -> poam.csv, summary.md, findings.json
                               -> exit 1 if anything >= critical
```

The scanners run with `exit-code: 0` / `|| true` on purpose. The evidence step is
the single gate, so the build fails in one place with one clear rule.

## Using the evidence tool

```bash
python -m evidence \
  --bandit reports/bandit.json \
  --pip-audit reports/pip-audit.json \
  --trivy reports/trivy.json \
  --gitleaks reports/gitleaks.json \
  --out evidence-out \
  --fail-on high
```

Any combination of inputs works; at least one is required. Outputs:

- `poam.csv`: one row per finding (POAM ID, controls, weakness, severity,
  location, detected date, scheduled completion, milestone, status)
- `summary.md`: counts by severity and by control, with the worst severity per control
- `findings.json`: the same data, machine-readable

Options:

- `--fail-on {info,low,medium,high,critical}`: exit 1 if any finding is at or
  above that level, so a pipeline can use it as a gate
- `--as-of YYYY-MM-DD`: report date (default: today), useful for reproducible output
- `--pip-audit-severity LEVEL`: pip-audit reports no severity, so this sets one (default: high)

### Design decisions

- **Stable IDs.** A POAM ID is a hash of source, rule and location, so the same
  finding keeps the same ID from run to run and can be tracked over time.
- **Deduplication.** Repeated findings collapse into one row.
- **Secrets stay out.** The gitleaks parser keeps only the rule and location. The
  secret value never reaches the CSV, summary or JSON, and a test checks this.
- **Deadlines by severity.** Defaults are 15 / 30 / 90 / 180 days for
  critical / high / medium / low. Edit `DEFAULT_SLA_DAYS` in `evidence/controls.py`
  to match your program's rules.
- **Readable mapping.** The finding-to-control mapping is a plain dictionary in
  `evidence/controls.py`, so a reviewer can audit or change it without reading logic.

## Limitations

- The control mappings are judgment calls, not an official crosswalk. Treat the
  output as a starting point for an ISSO or assessor to review.
- pip-audit has no severity data, so its findings use the configured default.
- This produces POA&M-style rows, not a complete OSCAL document.
- Gitleaks is supported by the tool but is not wired into the workflow.

## Run it locally

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q

python -m evidence \
  --bandit tests/fixtures/bandit.json \
  --pip-audit tests/fixtures/pip_audit.json \
  --trivy tests/fixtures/trivy.json \
  --gitleaks tests/fixtures/gitleaks.json \
  --out evidence-out --as-of 2026-11-16
```

## License

MIT
