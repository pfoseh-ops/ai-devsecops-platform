1# Copilot instructions for ai-devsecops-starter

Purpose: quick, actionable guidance for Copilot sessions interacting with this repository.

---

1) Build, test, and lint commands

- Primary local setup:
  - python -m venv .venv  # activate with .venv\Scripts\activate (Windows) or source .venv/bin/activate (mac/linux)
  - pip install -r requirements.txt

- Makefile shortcuts (repo root):
  - make install       -> pip install -r requirements.txt
  - make run           -> uvicorn src.app.main:app --reload --host 0.0.0.0 --port 8000
  - make test          -> pytest -q
  - make scan          -> python -m src.ai_guard.scan --target . --output reports/devsecops-report.md
  - make docker        -> docker compose up --build
  - make scan-insecure -> python -m src.ai_guard.scan --target examples/insecure --output reports/insecure-report.md --fail-on high

- CI (GitHub Actions): .github/workflows/devsecops.yml uses Python 3.12, runs install, pytest, scan, docker build, and uploads reports/devsecops-report.md as an artifact.

- Running a single test or specific test function:
  - pytest tests/test_app.py::test_health
  - pytest -k "analyze_high_risk"  # example using -k to filter

- Running the scanner with severity gating:
  - python -m src.ai_guard.scan --target <path> --output <out.md> --fail-on high

---

2) High-level architecture (big picture)

- A small FastAPI service (src/app) exposing:
  - GET /health — returns status, service name, timestamp
  - POST /analyze — demo analyzer that scans a text prompt for risk keywords and returns structured JSON (input, risk, signals, recommendation)

- DevSecOps scanner (src/ai_guard/scan.py): deterministic, rule-based scans across Terraform (.tf), Kubernetes (.yaml/.yml), and Dockerfile artifacts. Produces a Markdown report to reports/*.md and can exit non-zero when findings meet `--fail-on` threshold.

- CI pipeline (.github/workflows/devsecops.yml): installs deps, runs pytest, runs scanner with --fail-on critical, builds a Docker image, and uploads the report.

- Packaging and run targets: Dockerfile and docker-compose.yml for containerized local runs; Makefile exposes common tasks.

- Example insecure artifacts under examples/insecure/ used to demo failing scans.

---

3) Key conventions and repo-specific patterns

- Scanner file discovery:
  - iter_files() skips .git, .venv, __pycache__, node_modules, reports
  - Only scans files with suffixes {.tf, .yaml, .yml, .json, Dockerfile} (see allowed_suffixes)
  - examples/insecure/ is excluded by default unless targeted explicitly

- Severity ordering and gating:
  - SEVERITY_ORDER = {"low":1, "medium":2, "high":3, "critical":4}
  - --fail-on accepts low/medium/high/critical; scanner raises exit code 1 if any finding >= threshold

- Rule ID / messaging pattern:
  - Findings are dataclasses with fields (severity, file, rule, message, recommendation)
  - Common rule prefixes: TF-*, K8S-*, DOCKER-*, SECRET-*, COST-*

- Kubernetes checks:
  - Flags unpinned images ("latest" or untagged), missing runAsNonRoot, privileged containers, missing resources.requests/limits, and missing liveness/readiness probes

- Dockerfile checks:
  - Warns if no non-root USER is set or if base image uses :latest

- Terraform checks:
  - Detects missing public access block for S3, internet-open SSH/RDP, hardcoded passwords, and expensive GPU instances

- API contract expectations (tests rely on this):
  - /health returns JSON with status == "healthy"
  - /analyze accepts {"prompt": "..."} and returns keys: input, risk ("low"|"high"), signals (list), recommendation

- Reports and artifacts:
  - Reports written to reports/*.md (created if missing). CI uploads reports/devsecops-report.md

- Python version:
  - CI uses Python 3.12; prefer matching local dev venv for parity.

---

Reference files to check when updating instructions:
- README.md (usage and local run examples)
- Makefile (task shortcuts)
- .github/workflows/devsecops.yml (CI expectations and Python version)
- src/ai_guard/scan.py (rules, scanning behavior, fail-on semantics)
- src/app/main.py and tests/test_app.py (API surface and tests)

---

If you want additions (e.g., IDE setup, pre-commit hooks, or mapping scanner rules to external policy IDs), say which area to cover.
