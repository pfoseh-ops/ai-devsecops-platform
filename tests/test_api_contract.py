import asyncio
import json
import logging

import pytest
from fastapi.testclient import TestClient

from src.app.main import MAX_PROMPT_LENGTH, create_app
from src.app.security import MAX_BODY_BYTES, REQUESTS_PER_MINUTE, RequestBoundaryMiddleware


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("API_KEY", raising=False)
    with TestClient(create_app()) as session:
        yield session


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"prompt": ""},
        {"prompt": " \t\n"},
        {"prompt": "\u2003\u00a0"},
        {"prompt": None},
        {"prompt": 123},
        {"prompt": ["secret-value"]},
        {"prompt": "x" * (MAX_PROMPT_LENGTH + 1)},
    ],
)
def test_invalid_prompts(client, payload):
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "prompt"]
    assert all(set(issue) == {"loc", "type", "msg"} for issue in response.json()["detail"])
    assert "secret-value" not in response.text


@pytest.mark.parametrize(
    "prompt",
    ["deploy normal service", "  deploy normal service  ", "x" * MAX_PROMPT_LENGTH, "\U0001f512" * MAX_PROMPT_LENGTH],
    ids=["normal", "padded", "max-ascii", "max-unicode"],
)
def test_valid_prompts_and_boundary(client, prompt):
    response = client.post(
        "/analyze", content=json.dumps({"prompt": prompt}), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    assert set(response.json()) == {"risk", "score", "signals", "frameworks", "recommendation"}


def test_combined_risks(client):
    response = client.post(
        "/analyze",
        json={
            "prompt": "A public S3 bucket contains exposed credentials and secrets. Disable logging and security monitoring."
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert set(result["signals"]) == {"public_cloud_exposure", "exposed_credentials", "disabled_security_monitoring"}
    assert result["risk"] == "high"
    assert result["score"] == 100
    assert "rotate" in result["recommendation"]
    assert "monitoring" in result["recommendation"]


@pytest.mark.parametrize(
    "prompt",
    [
        "leaked credentials",
        "Secrets were exposed",
        "API keys are publicly accessible",
        "published access tokens",
        "EXPOSED\nCREDENTIALS",
        "Expose credentials",
        "leaking secrets",
    ],
)
def test_exposed_credential_variations(client, prompt):
    assert "exposed_credentials" in client.post("/analyze", json={"prompt": prompt}).json()["signals"]


@pytest.mark.parametrize(
    "prompt",
    [
        "Disable logging",
        "Turn off security monitoring",
        "audit logging has been disabled",
        "Security monitoring is off",
        "Stop audit logs",
        "CloudTrail was turned off",
        "switch off security alerts",
        "Disable all logging",
    ],
)
def test_disabled_control_variations(client, prompt):
    assert "disabled_security_monitoring" in client.post("/analyze", json={"prompt": prompt}).json()["signals"]


@pytest.mark.parametrize(
    "prompt",
    [
        "Rotate credentials and enable logging",
        "No exposed credentials",
        "Credentials are not exposed",
        "Secrets remain encrypted",
        "Do not disable logging",
        "Never turn off security monitoring",
        "Avoid disabling logging",
        "Logging is not disabled",
        "Enable security monitoring",
        "Disable verbose debug output",
        "Exposed credentials are not present",
        "Prevent leaked secrets",
        "Don't disable logging",
        "Don’t turn off security monitoring",
    ],
)
def test_new_rules_false_positives(client, prompt):
    assert client.post("/analyze", json={"prompt": prompt}).json()["signals"] == []


def test_safe_clause_does_not_suppress_later_risk(client):
    data = client.post("/analyze", json={"prompt": "No exposed credentials, but disable audit logging"}).json()
    assert data["signals"] == ["disabled_security_monitoring"]


def test_existing_rules_preserved(client):
    data = client.post("/analyze", json={"prompt": "hardcoded secrets in a public bucket"}).json()
    assert set(data["signals"]) == {"hardcoded_secret", "public_cloud_exposure"}
    assert data["risk"] == "high"


def test_sensitive_values_absent_in_responses_and_logs(client, caplog):
    secret = "sensitive-test-value-9248"
    with caplog.at_level(logging.INFO, logger="src.app.security"):
        responses = [
            client.post("/analyze", json={"prompt": f"exposed credentials {secret}"}),
            client.post("/analyze", json={"prompt": {secret: secret}}),
            client.post("/analyze", content='{"prompt":"' + secret),
        ]
    for response in responses:
        assert secret not in response.text
        assert response.headers["Cache-Control"] == "no-store"
    assert secret not in caplog.text
    assert "request_complete" in caplog.text


def test_body_limit(client):
    response = client.post("/analyze", content=b"x" * (MAX_BODY_BYTES + 1))
    assert response.status_code == 413
    assert response.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("headers", [[], [(b"content-length", b"1")]])
def test_streamed_body_limit_ignores_untrusted_length(headers):
    async def exercise():
        invoked = False
        messages = iter(
            [
                {"type": "http.request", "body": b"x" * MAX_BODY_BYTES, "more_body": True},
                {"type": "http.request", "body": b"x", "more_body": False},
            ]
        )
        sent = []

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        async def downstream(scope, receive, send):
            nonlocal invoked
            invoked = True

        await RequestBoundaryMiddleware(downstream)(
            {"type": "http", "path": "/analyze", "method": "POST", "headers": headers}, receive, send
        )
        assert not invoked
        assert sent[0]["status"] == 413

    asyncio.run(exercise())


def test_rate_limit_and_health_exemption(client, monkeypatch):
    monkeypatch.setattr("src.app.security.monotonic", lambda: 100)
    for _ in range(REQUESTS_PER_MINUTE):
        assert client.post("/analyze", json={"prompt": "hello"}).status_code == 200
    response = client.post("/analyze", json={"prompt": "hello"})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"
    assert client.get("/health").status_code == 200
    monkeypatch.setattr("src.app.security.monotonic", lambda: 161)
    assert client.post("/analyze", json={"prompt": "hello"}).status_code == 200


def test_production_requires_key(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    for value in ("", "too-short"):
        monkeypatch.setenv("API_KEY", value)
        with pytest.raises(RuntimeError, match="API_KEY"):
            create_app()


def test_authentication(monkeypatch):
    key = "test-key-" + "x" * 32
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("API_KEY", key)
    with TestClient(create_app()) as client:
        for headers in ({}, {"X-API-Key": "wrong"}):
            assert client.post("/analyze", json={"prompt": "hello"}, headers=headers).status_code == 401
        assert client.post("/analyze", json={"prompt": "hello"}, headers={"X-API-Key": key}).status_code == 200
        assert client.get("/health").status_code == 200


def test_error_response_is_sanitized(client, caplog):
    def broken():
        raise RuntimeError("sensitive-internal-value")

    client.app.add_api_route("/broken", broken)
    with caplog.at_level(logging.ERROR):
        response = client.get("/broken")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert response.headers["Cache-Control"] == "no-store"
    assert "sensitive-internal-value" not in caplog.text


def test_openapi_matches_responses(client):
    schema = client.get("/openapi.json").json()
    assert not schema["paths"]["/analyze"]["post"].get("security")
    models = schema["components"]["schemas"]
    for path, model in [("/", "RootResponse"), ("/health", "HealthResponse")]:
        assert set(client.get(path).json()) == set(models[model]["properties"])
    assert set(client.post("/analyze", json={"prompt": "hello"}).json()) == set(models["AnalyzeResponse"]["properties"])
    assert models["PromptRequest"]["properties"]["prompt"]["maxLength"] == MAX_PROMPT_LENGTH
    responses = schema["paths"]["/analyze"]["post"]["responses"]
    assert {"200", "401", "413", "422", "429", "500"} <= set(responses)
    assert responses["422"]["content"]["application/json"]["schema"]["$ref"].endswith("/ValidationResponse")
    assert set(models["ValidationIssue"]["properties"]) == {"loc", "msg", "type"}
