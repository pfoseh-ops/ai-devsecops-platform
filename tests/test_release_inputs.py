from pathlib import Path
import shutil
import yaml

from scripts.check_release_inputs import check_inputs


def test_placeholder_inputs_are_blocked(tmp_path):
    for source in Path("k8s").glob("*.yaml"):
        shutil.copyfile(source, tmp_path / source.name)
    deployment_path = tmp_path / "deployment.yaml"
    docs = list(yaml.safe_load_all(deployment_path.read_text()))
    docs[0]["spec"]["template"]["spec"]["containers"][0]["image"] = "REPLACE_WITH_RELEASE_IMAGE"
    deployment_path.write_text(yaml.safe_dump_all(docs))
    for filename in ("ingress.yaml", "network-policy.yaml"):
        path = tmp_path / filename
        doc = yaml.safe_load(path.read_text())
        doc["metadata"]["annotations"] = {"readiness-test": "replace-with-test-value"}
        path.write_text(yaml.safe_dump(doc))
    blockers = check_inputs(tmp_path)
    assert any("immutable" in item for item in blockers)
    assert any("ingress.yaml" in item for item in blockers)
    assert any("network-policy.yaml" in item for item in blockers)


def test_resolved_syntax_does_not_require_network(tmp_path):
    for source in Path("k8s").glob("*.yaml"):
        shutil.copyfile(source, tmp_path / source.name)
    for path in tmp_path.glob("*.yaml"):
        text = path.read_text().replace(":REPLACE_WITH_RELEASE_TAG", "@sha256:" + "a" * 64)
        text = text.replace("replace-with-approved-gateway", "test-gateway")
        text = text.replace("replace-with-gateway-namespace", "test-gateway")
        text = text.replace("replace-with-gateway-name", "test-gateway")
        text = text.replace("api.example.invalid", "api.test.example.org")
        path.write_text(text)
    assert check_inputs(tmp_path) == []  # Syntax only; synthetic digest is NOT approved.
    path = tmp_path / "deployment.yaml"
    path.write_text(path.read_text().replace("ghcr.io/pfoseh-ops/", "ghcr.io/other-owner/"))
    assert any("immutable" in item for item in check_inputs(tmp_path))


def test_missing_files_fail_closed(tmp_path):
    assert len(check_inputs(tmp_path)) == 4
