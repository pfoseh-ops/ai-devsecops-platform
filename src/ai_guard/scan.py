import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List
import yaml

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

@dataclass
class Finding:
    severity: str
    file: str
    rule: str
    message: str
    recommendation: str


def iter_files(target: Path) -> Iterable[Path]:
    skip = {".git", ".venv", "__pycache__", "node_modules", "reports"}
    allowed_suffixes = {".tf", ".yaml", ".yml", ".json", ".Dockerfile"}
    scanning_insecure_examples = "examples" in target.parts and "insecure" in target.parts
    for path in target.rglob("*"):
        if any(part in skip for part in path.parts):
            continue
        if not scanning_insecure_examples and "examples" in path.parts and "insecure" in path.parts:
            continue
        if path.is_file() and (path.suffix in allowed_suffixes or path.name == "Dockerfile"):
            yield path


def scan_terraform(path: Path, text: str) -> List[Finding]:
    findings: List[Finding] = []
    # Existing checks
    if 'resource "aws_s3_bucket_public_access_block"' not in text and 'resource "aws_s3_bucket"' in text:
        findings.append(Finding(
            "high", str(path), "TF-AWS-S3-001",
            "S3 bucket exists without an aws_s3_bucket_public_access_block resource.",
            "Add aws_s3_bucket_public_access_block with block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets set to true."
        ))
    if re.search(r'0\.0\.0\.0/0', text) and re.search(r'from_port\s*=\s*(22|3389)', text):
        findings.append(Finding(
            "critical", str(path), "TF-NET-001",
            "SSH/RDP appears open to the internet.",
            "Restrict admin access to VPN, bastion, or approved corporate CIDR ranges."
        ))
    if re.search(r'instance_type\s*=\s*"(p\d|g\d|trn|inf)', text):
        findings.append(Finding(
            "medium", str(path), "COST-GPU-001",
            "GPU/accelerator instance detected. These are expensive if left idle.",
            "Tag workloads, enable schedules, monitor utilization, and use autoscaling/spot where appropriate."
        ))
    if re.search(r'password\s*=\s*"[^"$]', text, re.IGNORECASE):
        findings.append(Finding(
            "critical", str(path), "SECRET-001",
            "Possible hardcoded password found in Terraform.",
            "Move secrets to AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, or HashiCorp Vault."
        ))

    # IAM and policy checks
    # Detect creation of long-lived access keys
    if 'resource "aws_iam_access_key"' in text or re.search(r'resource\s+"aws_iam_access_key"', text):
        findings.append(Finding(
            "critical", str(path), "IAM-KEY-001",
            "Long-lived IAM access key resource detected.",
            "Avoid creating long-lived IAM access keys in IaC; prefer IAM Roles, instance profiles, or short-lived credentials."
        ))

    # Detect AdministratorAccess attachments
    if 'AdministratorAccess' in text or 'arn:aws:iam::aws:policy/AdministratorAccess' in text:
        findings.append(Finding(
            "high", str(path), "IAM-ADMIN-001",
            "Attachment of AdministratorAccess policy detected.",
            "Avoid attaching AdministratorAccess; apply least-privilege policies scoped to required actions and resources."
        ))

    # Detect wildcard Action and Resource in policies
    if (re.search(r'"Action"\s*:\s*"\*"', text) or re.search(r'Action\s*=\s*"\*"', text)) and (
        re.search(r'"Resource"\s*:\s*"\*"', text) or re.search(r'Resource\s*=\s*"\*"', text)
    ):
        findings.append(Finding(
            "critical", str(path), "IAM-WILD-001",
            "IAM policy contains wildcard Action and Resource.",
            "Avoid using '*' for Action and Resource; scope permissions to the minimum necessary."
        ))

    # Detect S3 bucket policy with wildcard Principal
    if 'resource "aws_s3_bucket_policy"' in text:
        if re.search(r'"Principal"\s*:\s*"\*"', text) or re.search(r'Principal\s*=\s*"\*"', text) or re.search(r'"Principal"\s*:\s*\{\s*"\*"', text):
            findings.append(Finding(
                "high", str(path), "TF-AWS-S3-POL-001",
                "S3 bucket policy uses a wildcard Principal '*'.",
                "Restrict S3 bucket policies to specific principals or roles; avoid anonymous or public access in bucket policies."
            ))

    return findings


def scan_kubernetes(path: Path, text: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception:
        return findings

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "Unknown")
        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", "unnamed")
        spec = doc.get("spec", {}) or {}

        # Service-level checks (handle without pod_spec)
        if kind == "Service":
            svc_type = spec.get("type", "ClusterIP")
            if svc_type in {"NodePort", "LoadBalancer"}:
                lb_ranges = spec.get("loadBalancerSourceRanges") or []
                if not lb_ranges:
                    findings.append(Finding(
                        "high", str(path), "K8S-SVC-001",
                        f"Service/{name} exposes type {svc_type} without loadBalancerSourceRanges.",
                        "Restrict load balancer or nodeport exposure to approved CIDR ranges when exposing services externally."
                    ))
            # done with service doc
            continue

        pod_spec = None
        if kind in {"Deployment", "StatefulSet", "DaemonSet"}:
            pod_spec = spec.get("template", {}).get("spec", {})
        elif kind == "Pod":
            pod_spec = spec

        if not pod_spec:
            continue

        containers = pod_spec.get("containers", []) or []
        for container in containers:
            cname = container.get("name", "container")
            image = container.get("image", "")
            security_context = container.get("securityContext", {}) or {}
            resources = container.get("resources", {}) or {}

            if image.endswith(":latest") or ":" not in image:
                findings.append(Finding(
                    "high", str(path), "K8S-IMG-001",
                    f"{kind}/{name}/{cname} uses an unpinned or latest image tag.",
                    "Use immutable image tags or digests, such as app:v1.2.3 or image@sha256:..."
                ))
            if security_context.get("privileged") is True:
                findings.append(Finding(
                    "critical", str(path), "K8S-SEC-001",
                    f"{kind}/{name}/{cname} runs as privileged.",
                    "Avoid privileged containers unless absolutely required and approved by security."
                ))
            if security_context.get("runAsNonRoot") is not True:
                findings.append(Finding(
                    "medium", str(path), "K8S-SEC-002",
                    f"{kind}/{name}/{cname} does not enforce runAsNonRoot.",
                    "Set securityContext.runAsNonRoot: true and use a non-root container user."
                ))
            if not resources.get("limits") or not resources.get("requests"):
                findings.append(Finding(
                    "high", str(path), "K8S-RES-001",
                    f"{kind}/{name}/{cname} is missing CPU/memory requests or limits.",
                    "Define resource requests and limits to improve reliability, cost control, and scheduling."
                ))
            if "readinessProbe" not in container:
                findings.append(Finding(
                    "medium", str(path), "K8S-REL-001",
                    f"{kind}/{name}/{cname} is missing readinessProbe.",
                    "Add readinessProbe so Kubernetes only routes traffic to ready pods."
                ))
            if "livenessProbe" not in container:
                findings.append(Finding(
                    "medium", str(path), "K8S-REL-002",
                    f"{kind}/{name}/{cname} is missing livenessProbe.",
                    "Add livenessProbe so Kubernetes can restart unhealthy pods."
                ))

            # Additional container-level hardening checks
            sc = container.get("securityContext", {}) or {}
            if sc.get("allowPrivilegeEscalation") is True:
                findings.append(Finding(
                    "critical", str(path), "K8S-SEC-003",
                    f"{kind}/{name}/{cname} allows privilege escalation.",
                    "Set securityContext.allowPrivilegeEscalation to false unless explicitly required and reviewed."
                ))

            caps = sc.get("capabilities", {}) or {}
            added_caps = caps.get("add", []) or []
            dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE"}
            if any((str(cap).upper() in dangerous_caps) for cap in added_caps):
                findings.append(Finding(
                    "critical", str(path), "K8S-SEC-CAP-001",
                    f"{kind}/{name}/{cname} adds potentially dangerous capabilities: {added_caps}",
                    "Remove unnecessary capabilities; prefer fine-grained capabilities and use PodSecurityPolicies or OPA Gatekeeper to enforce."
                ))
        # pod/container loops end here

        # Pod-level checks
        if pod_spec.get("hostNetwork") is True:
            findings.append(Finding(
                "critical", str(path), "K8S-SEC-HOSTNET",
                f"{kind}/{name} sets hostNetwork: true.",
                "Avoid hostNetwork unless required; it gives containers broad network access to the host."
            ))
        if pod_spec.get("hostPID") is True:
            findings.append(Finding(
                "critical", str(path), "K8S-SEC-HOSTPID",
                f"{kind}/{name} sets hostPID: true.",
                "Avoid hostPID unless required; it exposes host process namespace."
            ))
        volumes = pod_spec.get("volumes", []) or []
        for vol in volumes:
            if "hostPath" in vol:
                findings.append(Finding(
                    "high", str(path), "K8S-SEC-004",
                    f"{kind}/{name} uses hostPath volume: {vol.get('hostPath')}",
                    "Avoid hostPath volumes; prefer PVCs or other remote storage, and restrict hostPath usage via policies."
                ))

        # Service checks
        if kind == "Service":
            svc_type = spec.get("type", "ClusterIP")
            if svc_type in {"NodePort", "LoadBalancer"}:
                lb_ranges = spec.get("loadBalancerSourceRanges") or []
                if not lb_ranges:
                    findings.append(Finding(
                        "high", str(path), "K8S-SVC-001",
                        f"Service/{name} exposes type {svc_type} without loadBalancerSourceRanges.",
                        "Restrict load balancer or nodeport exposure to approved CIDR ranges when exposing services externally."
                    ))

    return findings


def scan_dockerfile(path: Path, text: str) -> List[Finding]:
    findings = []
    if re.search(r'^USER\s+root\b', text, re.MULTILINE) or 'USER ' not in text:
        findings.append(Finding(
            "medium", str(path), "DOCKER-SEC-001",
            "Dockerfile does not clearly run as a non-root user.",
            "Create a non-root user and set USER before starting the application."
        ))
    if re.search(r'FROM\s+[^\n:]+:latest', text):
        findings.append(Finding(
            "high", str(path), "DOCKER-IMG-001",
            "Dockerfile uses latest base image tag.",
            "Pin the base image version to improve repeatability and supply-chain control."
        ))
    return findings


def ai_style_summary(findings: List[Finding]) -> str:
    if not findings:
        return "No high-risk issues were detected. The deployment artifacts look acceptable for a starter baseline."
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    return (
        f"The scan found {critical} critical, {high} high, and {medium} medium findings. "
        "Prioritize internet-exposed access, privileged containers, hardcoded secrets, public storage, and missing resource controls before production deployment."
    )


def write_report(findings: List[Finding], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# AI DevSecOps Scan Report",
        "",
        "## Executive Summary",
        "",
        ai_style_summary(findings),
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No findings detected. ✅")
    else:
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER[x.severity], reverse=True):
            lines += [
                f"### {f.severity.upper()} — {f.rule}",
                "",
                f"**File:** `{f.file}`",
                "",
                f"**Issue:** {f.message}",
                "",
                f"**Recommended Fix:** {f.recommendation}",
                "",
            ]
    output.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="AI-style DevSecOps scanner")
    parser.add_argument("--target", default=".", help="Directory to scan")
    parser.add_argument("--output", default="reports/devsecops-report.md", help="Report output path")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None)
    args = parser.parse_args()

    target = Path(args.target).resolve()
    findings: List[Finding] = []

    for path in iter_files(target):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix == ".tf":
            findings.extend(scan_terraform(path, text))
        if path.suffix in {".yaml", ".yml"}:
            findings.extend(scan_kubernetes(path, text))
        if path.name == "Dockerfile":
            findings.extend(scan_dockerfile(path, text))

    write_report(findings, Path(args.output))
    print(ai_style_summary(findings))
    print(f"Report written to {args.output}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            raise SystemExit(1)

if __name__ == "__main__":
    main()
