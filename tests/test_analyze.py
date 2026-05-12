import pytest
from fastapi.testclient import TestClient
from src.app.main import app

client = TestClient(app)


def test_analyze_known_prompt():
    payload = {
        "prompt": "Detect hardcoded secrets, insecure IAM policies, and public cloud exposure"
    }
    r = client.post("/analyze", json=payload)
    assert r.status_code == 200
    data = r.json()

    # required fields
    for key in ("input", "risk", "score", "signals", "recommendation"):
        assert key in data, f"Missing field: {key}"

    # types and values
    assert isinstance(data["score"], int)
    assert data["risk"] in ("low", "medium", "high")
    assert isinstance(data["signals"], list)

    # expected signals
    expected = {"hardcoded_secret", "public_cloud_exposure", "iam_policy_wildcard"}
    assert expected.issubset(set(data["signals"])), f"Signals missing: {expected - set(data['signals'])}"

    # frameworks
    assert isinstance(data.get("frameworks", []), list)
    for fw in ("CIS", "SOC2", "NIST"):
        assert fw in data.get("frameworks", []), f"Expected framework {fw} not present"


def test_analyze_no_findings():
    payload = {"prompt": "This is a benign message with no secrets or policy issues"}
    r = client.post("/analyze", json=payload)
    assert r.status_code == 200
    data = r.json()

    assert "score" in data and isinstance(data["score"], int)
    assert data["risk"] in ("low", "medium", "high")
    assert isinstance(data["signals"], list)
    assert data["signals"] == [] or len(data["signals"]) == 0
