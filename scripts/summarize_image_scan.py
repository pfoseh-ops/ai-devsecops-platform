"""Summarize image evidence without converting scanner success into release approval."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path


def summarize(scan, sbom, identity):
    metadata = scan["Metadata"]
    if not identity["diff_ids"] or metadata["DiffIDs"] != identity["diff_ids"]:
        raise ValueError("Scanned image layers do not match the built image")
    config = metadata["ImageConfig"]
    if (config["os"], config["architecture"]) != (identity["os"], identity["architecture"]):
        raise ValueError("Scanned image platform does not match the built image")
    if not any(result.get("Packages") for result in scan["Results"]):
        raise ValueError("Runtime package inventory is missing")
    if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
        raise ValueError("CycloneDX component inventory is missing")
    properties = sbom.get("metadata", {}).get("component", {}).get("properties", [])
    image_ids = [p["value"] for p in properties if p["name"] == "aquasecurity:trivy:ImageID"]
    layers = [p["value"] for p in properties if p["name"] == "aquasecurity:trivy:DiffID"]
    if image_ids != [metadata["ImageID"]] or sorted(layers) != sorted(identity["diff_ids"]):
        raise ValueError("SBOM identity does not match the scanned image")
    vulnerabilities = [v for result in scan["Results"] for v in result.get("Vulnerabilities", [])]
    ids = {v["VulnerabilityID"] for v in vulnerabilities}
    return {
        "release_decision": "NO GO",
        "manual_review": "Five SQLite/OpenSSL dispositions and deployment controls remain open; see docs/sqlite-openssl-dispositions.md",
        "source_commit": os.environ.get("GITHUB_SHA", "local-uncommitted-or-unspecified"),
        "image_id": identity["image_id"],
        "image_config_digest": metadata["ImageID"],
        "platform": f'{identity["os"]}/{identity["architecture"]}',
        "layers_verified": True,
        "scanner_version": scan["Trivy"]["Version"],
        "scan_created_at": scan["CreatedAt"],
        "os": metadata["OS"],
        "vulnerability_occurrences": len(vulnerabilities),
        "unique_vulnerability_ids": len(ids),
        "unique_cve_ids": sum(vid.startswith("CVE-") for vid in ids),
        "severity_occurrences": dict(sorted(Counter(v["Severity"] for v in vulnerabilities).items())),
        "occurrences_with_reported_fix": sum(bool(v.get("FixedVersion")) for v in vulnerabilities),
        "sbom_components": len(sbom["components"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    directory = parser.parse_args().reports
    names = ("runtime-image-scan.json", "runtime-image-sbom.cdx.json", "runtime-image.json")
    inputs = [json.loads((directory / name).read_text(encoding="utf-8-sig")) for name in names]
    summary = summarize(*inputs)
    summary["database_metadata"] = json.loads((directory / "runtime-trivy-db.json").read_text())
    summary["evidence_sha256"] = {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in (*names, "runtime-trivy-db.json", "runtime-trivy-version.txt")
    }
    (directory / "runtime-image-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    text = (
        "## Runtime image scan and SBOM\n\n"
        "**Production readiness: NO GO.** Zero scanner matches do not close manual CVE reviews.\n\n"
        f"- Source commit: `{summary['source_commit']}`\n"
        f"- Local image identity: `{summary['image_id']}` (not an approved registry digest)\n"
        f"- Scanned configuration: `{summary['image_config_digest']}`\n"
        f"- Platform: `{summary['platform']}`; scanned/built layers verified.\n"
        f"- Vulnerability occurrences: {summary['vulnerability_occurrences']}; "
        f"unique IDs: {summary['unique_vulnerability_ids']}; unique CVEs: {summary['unique_cve_ids']}.\n"
        f"- Severity occurrence counts: `{json.dumps(summary['severity_occurrences'], sort_keys=True)}`\n"
        f"- CycloneDX components: {summary['sbom_components']}.\n\n"
        "Full package/layer findings, SBOM, database timestamps and hashes are in the "
        "`runtime-image-security` workflow artifact. Findings are not suppressed by severity or fix availability. "
        "This vulnerability scan does not replace secret scanning or manual advisory review.\n"
    )
    (directory / "runtime-image-summary.md").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
