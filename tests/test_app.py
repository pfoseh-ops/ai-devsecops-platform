from fastapi.testclient import TestClient
from src.app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_analyze_low_risk():
    response = client.post("/analyze", json={"prompt": "deploy normal service"})
    assert response.status_code == 200
    assert response.json()["risk"] == "low"

def test_analyze_high_risk():
    response = client.post("/analyze", json={"prompt": "public privileged root password"})
    assert response.status_code == 200
    assert response.json()["risk"] == "high"
