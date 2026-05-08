from fastapi import FastAPI, Request
from pydantic import BaseModel
from datetime import datetime, timezone

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
    Demo endpoint. In a real AI platform, this could call an LLM or model endpoint.
    """
    prompt = request.prompt.strip()
    risk_words = ["public", "root", "privileged", "secret", "password", "open"]
    findings = [word for word in risk_words if word in prompt.lower()]
    risk = "high" if findings else "low"
    return {
        "input": prompt,
        "risk": risk,
        "signals": findings,
        "recommendation": "Review security/compliance controls before deployment." if findings else "No obvious risk terms detected.",
    }
