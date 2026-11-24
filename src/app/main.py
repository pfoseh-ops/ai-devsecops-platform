import os
import re
import secrets
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator

from src.app.security import RequestBoundaryMiddleware

MAX_PROMPT_LENGTH = 10_000


class PromptRequest(BaseModel):
    prompt: str = Field(
        min_length=1,
        max_length=MAX_PROMPT_LENGTH,
        description="Nonblank text, at most 10,000 characters before trimming. Do not submit live secrets.",
    )

    @field_validator("prompt")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Prompt must contain non-whitespace characters")
        return value.strip()


class RootResponse(BaseModel):
    message: str
    status: Literal["ok"]


class HealthResponse(BaseModel):
    status: Literal["healthy"]
    service: str
    timestamp: datetime


class AnalyzeResponse(BaseModel):
    risk: Literal["low", "medium", "high"]
    score: int = Field(ge=0, le=100)
    signals: list[str]
    frameworks: list[str]
    recommendation: str


class ErrorResponse(BaseModel):
    detail: str


class ValidationIssue(BaseModel):
    loc: list[str | int]
    msg: str
    type: str


class ValidationResponse(BaseModel):
    detail: list[ValidationIssue]


def root():
    return {"message": "AI DevSecOps Demo API", "status": "ok"}


def health():
    return {
        "status": "healthy",
        "service": "ai-devsecops-demo",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


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

    # Targeted phrase heuristics, not semantic analysis or a complete scanner.
    for signal, weight in additional_risks(text):
        if signal not in findings:
            findings.append(signal)
            total_score += weight

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
        rec_parts.append(
            "Rotate exposed secrets, remove them from source control, and adopt a secret management solution"
        )
    if "iam_policy_wildcard" in findings:
        rec_parts.append(
            "Enforce least-privilege IAM policies and remove wildcard permissions (e.g., '*') from roles/policies"
        )
    if "privileged_account" in findings:
        rec_parts.append("Avoid use of root/privileged accounts; use RBAC and scoped service accounts")
    if "insecure_docker_config" in findings:
        rec_parts.append(
            "Harden container images and IaC templates; set resource limits and avoid privileged containers"
        )
    if "exposed_credentials" in findings:
        rec_parts.append("Revoke or rotate exposed credentials, restrict access, and investigate their use")
    if "disabled_security_monitoring" in findings:
        rec_parts.append("Enable audit logging and security monitoring, protect log storage, and verify alert delivery")

    recommendation = ". ".join(rec_parts)
    if recommendation and not recommendation.endswith("."):
        recommendation += "."
    if not recommendation:
        recommendation = "No immediate actions detected. Continue regular security hygiene and code review."

    return {
        "risk": risk,
        "score": score,
        "signals": findings,
        "frameworks": frameworks,
        "recommendation": recommendation,
    }


def additional_risks(text: str):
    sensitive = r"(?:credentials?|secrets?|api[- ]?keys?|access[- ]?tokens?)"
    exposed = r"(?:expos(?:e|ed|ing)|leak(?:ed|ing)?|published|publicly accessible)"
    controls = r"(?:(?:audit|security|access)\s+)?(?:logging|logs|monitoring|alerts?|cloudtrail)"
    disabled = r"(?:disable(?:d)?|turn(?:ed)?\s+off|switch(?:ed)?\s+off|stop(?:ped)?)"
    patterns = [
        (
            rf"\b{exposed}\s+{sensitive}\b|\b{sensitive}\s+(?:(?:are|were|have been)\s+)?{exposed}\b",
            "exposed_credentials",
            40,
        ),
        (
            rf"\b{disabled}\s+(?:(?:all|the)\s+)?{controls}\b|\b{controls}\s+(?:(?:is|are|was|were|has been)\s+)?(?:{disabled}|off)\b",
            "disabled_security_monitoring",
            35,
        ),
    ]
    # Keep negation local to a clause so a safe clause cannot hide a later risk.
    for pattern, signal, weight in patterns:
        for clause in re.split(r"[.!?;\n]|\bbut\b", text):
            for match in re.finditer(pattern, clause):
                prefix = clause[: match.start()]
                suffix = clause[match.end() :]
                if re.search(r"\b(?:no|not|never|without|avoid|prevent|don['’]t|do not)\s+(?:\w+\s+){0,2}$", prefix):
                    continue
                if re.match(r"\s+(?:is|are|was|were)\s+(?:not|never)\b", suffix):
                    continue
                yield signal, weight
                break


def create_app() -> FastAPI:
    api_key = os.getenv("API_KEY", "")
    environment = os.getenv("ENVIRONMENT", "local").lower()
    if environment not in {"local", "test", "production"}:
        raise RuntimeError("ENVIRONMENT must be local, test, or production")
    if (environment == "production" or api_key) and len(api_key.encode()) < 32:
        raise RuntimeError("API_KEY must contain at least 32 bytes when authentication is enabled")

    application = FastAPI(
        title="AI DevSecOps Demo API",
        version="1.1.0",
        responses={500: {"model": ErrorResponse}},
        description="Deterministic text risk indicators; not a complete security scanner or compliance assessment.",
    )
    key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def authorize(key: str | None = Depends(key_header)):
        if api_key and (key is None or not secrets.compare_digest(key.encode(), api_key.encode())):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Never serialize input, body, ctx, or attacker-controlled field names.
        issues = []
        for error in exc.errors():
            location = [
                part if part in {"body", "prompt"} or isinstance(part, int) else "field" for part in error["loc"]
            ]
            messages = {
                "missing": "Field required",
                "string_too_short": "Prompt must not be empty",
                "string_too_long": "Prompt must contain at most 10000 characters",
                "string_type": "Prompt must be a string",
                "value_error": "Prompt must contain non-whitespace characters",
                "json_invalid": "Invalid JSON body",
            }
            issues.append(
                {"loc": location, "type": error["type"], "msg": messages.get(error["type"], "Invalid request body")}
            )
        return JSONResponse(status_code=422, content={"detail": issues})

    application.add_api_route("/", root, response_model=RootResponse)
    application.add_api_route("/health", health, response_model=HealthResponse)
    application.add_api_route(
        "/analyze",
        analyze,
        methods=["POST"],
        response_model=AnalyzeResponse,
        dependencies=[Depends(authorize)] if api_key else [],
        responses={
            422: {"model": ValidationResponse},
            **{code: {"model": ErrorResponse} for code in (401, 413, 429, 500)},
        },
    )
    application.add_middleware(RequestBoundaryMiddleware)
    return application


app = create_app()
