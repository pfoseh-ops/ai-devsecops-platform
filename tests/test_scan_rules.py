from pathlib import Path

import pytest

from src.ai_guard.scan import scan_kubernetes, scan_terraform

# Kubernetes rule tests

def test_k8s_bad_privilege_and_caps_and_host_settings():
    yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  hostNetwork: true
  hostPID: true
  volumes:
    - name: hostvol
      hostPath:
        path: /var/lib/data
  containers:
    - name: bad
      image: ubuntu:latest
      securityContext:
        allowPrivilegeEscalation: true
        capabilities:
          add: ["SYS_ADMIN"]
      # no resources, no probes
"""
    findings = scan_kubernetes(Path("bad.yaml"), yaml)
    rules = {f.rule for f in findings}
    assert "K8S-SEC-003" in rules
    assert "K8S-SEC-CAP-001" in rules
    assert "K8S-SEC-HOSTNET" in rules
    assert "K8S-SEC-HOSTPID" in rules
    assert "K8S-SEC-004" in rules


def test_k8s_service_exposed_without_source_ranges():
    yaml = """
apiVersion: v1
kind: Service
metadata:
  name: public-svc
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
"""
    findings = scan_kubernetes(Path("svc.yaml"), yaml)
    rules = {f.rule for f in findings}
    assert "K8S-SVC-001" in rules


def test_k8s_safe_example_no_findings():
    yaml = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe-deploy
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:v1.2.3
          securityContext:
            runAsNonRoot: true
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "200m"
              memory: "256Mi"
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
"""
    findings = scan_kubernetes(Path("safe.yaml"), yaml)
    # Ensure no critical rules triggered
    rules = {f.rule for f in findings}
    assert not any(r.startswith("K8S-SEC-") and r != "K8S-SEC-002" for r in rules)


# Terraform IAM rule tests

def test_tf_detect_iam_access_key():
    tf = 'resource "aws_iam_access_key" "bad" { user = "alice" }'
    findings = scan_terraform(Path("iam.tf"), tf)
    rules = {f.rule for f in findings}
    assert "IAM-KEY-001" in rules


def test_tf_detect_admin_policy_attachment():
    tf = '''resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.example.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}'''
    findings = scan_terraform(Path("admin.tf"), tf)
    rules = {f.rule for f in findings}
    assert "IAM-ADMIN-001" in rules


def test_tf_detect_wildcard_action_and_resource():
    tf = '''resource "aws_iam_policy" "wild" {
  policy = <<POLICY
{
  "Statement": [
    {
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}'''
    findings = scan_terraform(Path("wild.tf"), tf)
    rules = {f.rule for f in findings}
    assert "IAM-WILD-001" in rules


def test_tf_detect_s3_bucket_policy_with_wildcard_principal():
    tf = '''resource "aws_s3_bucket_policy" "bad" {
  bucket = aws_s3_bucket.example.id
  policy = <<POL
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::example/*"]
    }
  ]
}
POL
}'''
    findings = scan_terraform(Path("s3pol.tf"), tf)
    rules = {f.rule for f in findings}
    assert "TF-AWS-S3-POL-001" in rules


def test_tf_safe_example_no_iam_findings():
    tf = '''resource "aws_s3_bucket" "good" {}

resource "aws_s3_bucket_public_access_block" "good_block" {
  bucket = aws_s3_bucket.good.id
}
'''
    findings = scan_terraform(Path("safe.tf"), tf)
    rules = {f.rule for f in findings}
    # Only the S3 public access check should not trigger because public access block exists
    assert not any(r.startswith("IAM-") for r in rules)
    assert not ("TF-AWS-S3-001" in rules)
