from fastapi import FastAPI, Request
from pydantic import BaseModel
from datetime import datetime, timezone
import re

app = FastAPI(title="AI DevSecOps Demo API", version="1.0.0")

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response

class PromptRequest(BaseModel):
    prompt: str

@app.get("/")
def root():
    return {"message": "AI DevSecOps Demo API", "status": "ok"}

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "ai-devsecops-demo",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/analyze")
def analyze(request: PromptRequest):
    """
    Demo endpoint. Balances precise phrase matching with weighted token indicators
    so multiple weak signals can combine into higher risk while reducing false positives.
    """
    prompt = request.prompt.strip()
    # normalize: lower-case and collapse whitespace
    text = re.sub(r"\s+", " ", prompt.lower()).strip()

    findings = []
    total_score = 0
    base_score = 5
    total_score += base_score

    # precise patterns with higher weight
    pattern_defs = [
        (r"\bhardcoded secrets?\b", "hardcoded_secret", 40),
        (r"aws[_\- ]?access[_\- ]?key", "hardcoded_secret", 40),
        (r"0\.0\.0\.0/0", "public_cloud_exposure", 35),
        (r"\bpublic (?:cloud|bucket|s3|access)\b", "public_cloud_exposure", 30),
        (r"\bpublic[-_ ]?bucket\b", "public_cloud_exposure", 30),
        (r"wildcard\s+(?:iam|policy|permissions)", "iam_policy_wildcard", 35),
        (r"\binsecure\s+iam\b", "iam_policy_wildcard", 30),
        (r"overly\s+permissive\s+iam", "iam_policy_wildcard", 35),
        (r"wildcard\s+policy", "iam_policy_wildcard", 30),
        (r"\biam\s+policies?\b", "iam_policy_wildcard", 30),
        (r"administrator\s*access|administratoraccess", "privileged_account", 30),
        (r"\bprivileged[- ]?account\b", "privileged_account", 25),
        (r"\bfull access\b", "iam_policy_wildcard", 25),
        (r"dockerfile.*privileged", "insecure_docker_config", 20),
    ]

    for pat, sig, w in pattern_defs:
        try:
            if re.search(pat, text, flags=re.IGNORECASE):
                if sig not in findings:
                    findings.append(sig)
                total_score += w
        except re.error:
            continue

    # weaker keyword indicators (lower weight) that can combine
    keyword_defs = {
        "public": ("public_cloud_exposure", 20),
        "privileged": ("privileged_account", 25),
        "root": ("privileged_account", 25),
        "password": ("hardcoded_secret", 30),
        "admin": ("privileged_account", 20),
        "wildcard": ("iam_policy_wildcard", 15),
    }

    for kw, (sig, w) in keyword_defs.items():
        if re.search(r"\b" + re.escape(kw) + r"\b", text, flags=re.IGNORECASE):
            # only add keyword-derived weight if the exact precise pattern didn't already add the same signal
            if sig not in findings:
                findings.append(sig)
                total_score += w
            else:
                # if signal already present from patterns, add a smaller bonus instead of full weight
                total_score += int(w * 0.25)

    # cap score
    score = max(0, min(100, int(total_score)))

    # risk level thresholds
    if score >= 70:
        risk = "high"
    elif score >= 30:
        risk = "medium"
    else:
        risk = "low"

    frameworks = ["CIS", "SOC2", "NIST"] if findings else []

    # build actionable recommendation
    rec_parts = []
    if "public_cloud_exposure" in findings:
        rec_parts.append("Restrict public access to resources, apply network controls, and review bucket/object ACLs")
    if "hardcoded_secret" in findings:
        rec_parts.append("Rotate exposed secrets, remove them from source control, and adopt a secret management solution")
    if "iam_policy_wildcard" in findings:
        rec_parts.append("Enforce least-privilege IAM policies and remove wildcard permissions (e.g., '*') from roles/policies")
    if "privileged_account" in findings:
        rec_parts.append("Avoid use of root/privileged accounts; use RBAC and scoped service accounts")
    if "insecure_docker_config" in findings:
        rec_parts.append("Harden container images and IaC templates; set resource limits and avoid privileged containers")

    recommendation = ". ".join(rec_parts)
    if recommendation and not recommendation.endswith("."):
        recommendation += "."
    if not recommendation:
        recommendation = "No immediate actions detected. Continue regular security hygiene and code review."

    return {
        "input": prompt,
        "risk": risk,
        "score": score,
        "signals": findings,
        "frameworks": frameworks,
        "recommendation": recommendation,
    }
