import json
import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient

from scripts import sync_api_secret
from src.app.main import create_app

ROOT = Path(__file__).resolve().parents[1]


def test_secret_sync_uses_manager_and_stdin(monkeypatch):
    marker = "synthetic-test-key-" + "x" * 32
    calls = []

    def fake_tool(arguments, *, payload=None):
        calls.append((arguments, payload))
        return json.dumps({"SecretString": marker}) if arguments[0] == "aws" else "configured"

    monkeypatch.setattr(sync_api_secret, "run_tool", fake_tool)
    sync_api_secret.sync_secret("example-secret-arn", "approved-context")
    assert calls[0][0][:3] == ["aws", "secretsmanager", "get-secret-value"]
    assert "AWSCURRENT" in calls[0][0]
    assert "--server-side" in calls[1][0]
    assert "approved-context" in calls[1][0]
    assert marker not in " ".join(calls[1][0])
    manifest = json.loads(calls[1][1])
    assert manifest["stringData"] == {"api-key": marker}
    assert manifest["metadata"]["namespace"] == "ai-devsecops"


@pytest.mark.parametrize("value", [None, "short", "x" * 32 + "\n"])
def test_secret_sync_rejects_invalid_values(monkeypatch, value):
    calls = []

    def fake_tool(arguments, **kwargs):
        calls.append(arguments)
        return json.dumps({"SecretString": value})

    monkeypatch.setattr(sync_api_secret, "run_tool", fake_tool)
    with pytest.raises(RuntimeError):
        sync_api_secret.sync_secret("example", "test")
    assert len(calls) == 1  # Kubernetes is never called.


def test_tool_failure_does_not_echo_secret(monkeypatch):
    monkeypatch.setattr(sync_api_secret.shutil, "which", lambda name: "/tools/" + name)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stdout="secret-marker", stderr="secret-marker"))
    with pytest.raises(RuntimeError) as exc:
        sync_api_secret.run_tool(["aws", "secretsmanager"])
    assert "secret-marker" not in str(exc.value)


def test_app_logs_exclude_headers_queries_paths_and_body(monkeypatch, caplog):
    marker = "synthetic-credential-marker-" + "x" * 32
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("API_KEY", marker)
    with caplog.at_level(logging.INFO, logger="src.app.security"), TestClient(create_app()) as client:
        response = client.post("/analyze?token=" + marker, json={"prompt": marker},
                               headers={"X-API-Key": marker, "Authorization": "Bearer " + marker})
        assert response.status_code == 200
        assert client.get("/unknown/" + marker).status_code == 404
    records = [record.getMessage() for record in caplog.records if record.name == "src.app.security"]
    assert records
    assert all(marker not in record for record in records)


def test_server_logging_configuration_disables_access_log():
    config = json.loads((ROOT / "config/logging.json").read_text())
    assert config["loggers"]["uvicorn.access"]["handlers"] == []
    assert config["loggers"]["uvicorn.access"]["propagate"] is False
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert '"--no-access-log"' in dockerfile
    assert '"--no-proxy-headers"' in dockerfile


def test_deployment_has_only_secret_references_and_gateway_network_access():
    deployment = list(yaml.safe_load_all((ROOT / "k8s/deployment.yaml").read_text()))[0]
    assert deployment["metadata"]["namespace"] == "ai-devsecops"
    for container in deployment["spec"]["template"]["spec"]["containers"]:
        assert container["image"].startswith("ghcr.io/pfoseh-ops/")
    env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    key = next(item for item in env if item["name"] == "API_KEY")
    assert "value" not in key
    assert key["valueFrom"]["secretKeyRef"] == {"name": "ai-devsecops-api", "key": "api-key"}
    policy = yaml.safe_load((ROOT / "k8s/network-policy.yaml").read_text())
    peer = policy["spec"]["ingress"][0]["from"][0]
    assert "namespaceSelector" in peer and "podSelector" in peer
    assert policy["spec"]["egress"] == []
