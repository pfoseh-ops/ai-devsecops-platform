# AI-Powered DevSecOps Starter Platform 🚀




A production-style DevSecOps platform demonstrating automated security testing, CI/CD orchestration, containerized application delivery, Infrastructure-as-Code validation, and consolidated security reporting across the software delivery lifecycle.

## Key Capabilities

- FastAPI application with hardened security headers
- Dockerized application deployment
- GitHub Actions CI/CD pipeline
- Automated unit testing with Pytest
- SAST scanning with Bandit
- SCA and IaC scanning with Trivy
- DAST scanning with OWASP ZAP
- Terraform infrastructure examples
- Kubernetes deployment manifests
- Consolidated DevSecOps report generation
- Automated artifact publishing in GitHub Actions

The platform uses deterministic policy and rule-based scanning by default and can optionally be extended with LLM-powered analysis in future iterations.

## Security Controls

- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Resource-Policy
- Cache-Control

---

## Architecture

```text
Developer Push
   ↓
GitHub Actions CI/CD
   ↓
Unit Tests
   ↓
SAST (Bandit)
   ↓
SCA & IaC Scan (Trivy)
   ↓
Docker Build Validation
   ↓
DAST (OWASP ZAP)
   ↓
Generate Security Reports & Artifacts
   ↓
Deploy-ready Kubernetes/Terraform Assets
```

---

## Local Setup

### 1. Clone repo

```bash
git clone https://github.com/pfoseh-ops/ai-devsecops-starter.git
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

1. Python dependency installation
2. Unit testing
3. SAST with Bandit
4. SCA and IaC scanning with Trivy
5. Docker image build validation
6. DAST with OWASP ZAP
7. Consolidated report generation
8. Artifact publishing

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

## Future Enhancements

Planned improvements:

- Checkov/tfsec
- Trivy image scanning
- SBOM generation with Syft/CycloneDX
- Argo CD GitOps manifests
- Automated container publishing to AWS ECR
- Amazon EKS deployment automation
- Prometheus/Grafana
- OPA/Kyverno
- OpenAI/Azure OpenAI explanation layer

---

## Suggested Resume Bullet

Designed and implemented a production-style DevSecOps platform integrating GitHub Actions CI/CD, SAST, SCA, DAST, Docker, Kubernetes, Terraform, and automated security reporting to shift security left and standardize secure delivery workflows.
