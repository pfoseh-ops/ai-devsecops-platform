from copy import deepcopy

import pytest

from scripts.summarize_image_scan import summarize


@pytest.fixture
def evidence():
    scan = {
        "Trivy": {"Version": "test"}, "CreatedAt": "2026-11-24T00:00:00Z",
        "Metadata": {"DiffIDs": ["sha256:layer"], "ImageID": "sha256:config",
                     "ImageConfig": {"os": "linux", "architecture": "amd64"},
                     "OS": {"Family": "alpine", "Name": "test"}},
        "Results": [{"Packages": [{"Name": "example"}], "Vulnerabilities": [
            {"VulnerabilityID": "CVE-test", "Severity": "HIGH", "PkgName": "one", "FixedVersion": "2"},
            {"VulnerabilityID": "CVE-test", "Severity": "HIGH", "PkgName": "two"},
            {"VulnerabilityID": "TEMP-test", "Severity": "LOW", "PkgName": "one"},
        ]}],
    }
    sbom = {"bomFormat": "CycloneDX", "components": [{"name": "example"}],
            "metadata": {"component": {"properties": [
                {"name": "aquasecurity:trivy:ImageID", "value": "sha256:config"},
                {"name": "aquasecurity:trivy:DiffID", "value": "sha256:layer"},
            ]}}}
    return (scan, sbom,
            {"image_id": "sha256:index", "os": "linux", "architecture": "amd64", "diff_ids": ["sha256:layer"]})


def test_occurrences_are_distinct_from_unique_ids(evidence, monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "source-commit")
    result = summarize(*evidence)
    assert result["vulnerability_occurrences"] == 3
    assert result["unique_vulnerability_ids"] == 2
    assert result["unique_cve_ids"] == 1
    assert result["severity_occurrences"] == {"HIGH": 2, "LOW": 1}
    assert result["occurrences_with_reported_fix"] == 1
    assert result["source_commit"] == "source-commit"


def test_no_matches_do_not_clear_manual_release_blockers(evidence):
    evidence[0]["Results"][0]["Vulnerabilities"] = []
    result = summarize(*evidence)
    assert result["vulnerability_occurrences"] == 0
    assert result["release_decision"] == "NO GO"
    assert "SQLite/OpenSSL" in result["manual_review"]


@pytest.mark.parametrize("invalid", ["layers", "platform", "packages", "sbom", "sbom_identity"])
def test_invalid_or_unrelated_evidence_fails_closed(evidence, invalid):
    scan, sbom, identity = deepcopy(evidence)
    if invalid == "layers":
        identity["diff_ids"] = ["sha256:different-image"]
    elif invalid == "platform":
        identity["architecture"] = "arm64"
    elif invalid == "packages":
        scan["Results"] = []
    elif invalid == "sbom":
        sbom["components"] = []
    else:
        sbom["metadata"]["component"]["properties"][0]["value"] = "sha256:unrelated"
    with pytest.raises(ValueError):
        summarize(scan, sbom, identity)
