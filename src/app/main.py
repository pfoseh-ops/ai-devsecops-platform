from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime, timezone

app = FastAPI(title="AI DevSecOps Demo API", version="1.0.0")

class PromptRequest(BaseModel):
    prompt: str

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
