# AI-Powered DevSecOps Starter Platform 🚀

Updated: this branch adds CI steps (SAST, SCA, DAST) and consolidated reporting. See `ai-devsecops-starter/devsecops-workflow.yml` for the workflow content to place under `.github/workflows/devsecops.yml`.


This repo is a ground-up starter project that demonstrates a unified DevSecOps workflow from planning to production.

It includes:

- A small FastAPI service
- Docker build support
- Automated tests
- AI-style security/compliance scanner
- Terraform examples
- Kubernetes manifests
- GitHub Actions CI/CD workflow
- Automated DevSecOps report generation

The scanner works without paid AI APIs. It uses deterministic rules first, then you can optionally plug in an LLM later.

---

## Architecture

```text
Developer Push
   ↓
GitHub Actions
   ↓
Test → Security Scan → Compliance Scan → Build Docker Image
   ↓
Generate DevSecOps Report
   ↓
Deploy-ready Kubernetes/Terraform artifacts
```

---

## Local Setup

### 1. Clone repo

```bash
git clone https://github.com/YOUR_USERNAME/ai-devsecops-starter.git
cd ai-devsecops-starter
```

### 2. Create Python virtual environment

```bash
python -m venv .venv
source .venv/bin/activate   # Mac/Linux
# .venv\Scripts\activate    # Windows PowerShell
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
uvicorn src.app.main:app --reload --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000/health
```

---

## Run With Docker

```bash
docker compose up --build
```

Open:

```text
http://localhost:8000/health
```

---

## Run Tests

```bash
pytest -q
```

---

## Run DevSecOps Scan

```bash
python -m src.ai_guard.scan --target . --output reports/devsecops-report.md
```

Then open:

```text
reports/devsecops-report.md
```

---

## Demo a Failed Compliance Scan

This repo includes intentionally bad examples under `examples/insecure/`.

```bash
python -m src.ai_guard.scan --target examples/insecure --output reports/insecure-report.md --fail-on high
```

You should see violations such as:

- Public S3 bucket risk
- Kubernetes container running as privileged
- Missing CPU/memory limits
- Image using `latest` tag

---

## GitHub Actions

The workflow is located here:

```text
.github/workflows/devsecops.yml
```

It runs:

1. Python dependency install
2. Unit tests
3. DevSecOps scan
4. Docker build
5. Report artifact upload

---

## How This Maps to Enterprise DevSecOps

| Stage | What This Repo Demonstrates |
|---|---|
| Plan | Security/compliance rules defined before deployment |
| Code | FastAPI app + tests |
| Build | Docker image build |
| Secure | Automated scan of Terraform and Kubernetes artifacts |
| Deploy | Kubernetes deployment/service manifests |
| Operate | Health endpoint and resource limits |
| Feedback | Markdown report generated for engineers/security teams |

---

## Next Enhancements

Good next steps:

- Add OpenAI/Azure OpenAI explanation layer
- Add Checkov or tfsec
- Add Trivy image scanning
- Add Argo CD app manifests
- Push Docker image to AWS ECR
- Deploy to EKS
- Add Prometheus/Grafana dashboards
- Add cost optimization recommendations

---

## Suggested Resume Bullet

Designed a prototype AI-powered DevSecOps workflow integrating CI/CD, Kubernetes, Terraform, policy-based compliance scanning, and automated risk reporting to shift security left, reduce deployment risk, and standardize cloud operations across teams.
