"""Operator-only AWS Secrets Manager -> Kubernetes sync. Never run during tests/builds.

Requires AWS CLI and kubectl authenticated with narrowly scoped operator roles.
No secret value is passed in argv, printed, or written to a temporary file.
"""
import argparse
import json
import shutil
import subprocess
import sys


def run_tool(arguments, *, payload=None):
    executable = shutil.which(arguments[0])
    if executable is None:
        raise RuntimeError("Required operator tool is unavailable")
    # Fixed executable names, argument arrays, shell=False; never log tool output.
    result = subprocess.run(  # nosec B603
        [executable, *arguments[1:]], input=payload, capture_output=True,
        text=True, timeout=60, check=False,
    )
    if result.returncode:
        raise RuntimeError("Operator command failed; inspect permissions without enabling secret output")
    return result.stdout


def sync_secret(secret_id, context):
    response = json.loads(run_tool([
        "aws", "secretsmanager", "get-secret-value", "--secret-id", secret_id,
        "--version-stage", "AWSCURRENT", "--output", "json", "--no-cli-pager",
    ]))
    key = response.get("SecretString")
    if not isinstance(key, str) or len(key.encode()) < 32 or key != key.strip() or "\n" in key or "\r" in key:
        raise RuntimeError("Secret must be a single-line raw API key of at least 32 bytes")
    manifest = {
        "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
        "metadata": {"name": "ai-devsecops-api", "namespace": "ai-devsecops"},
        "stringData": {"api-key": key},
    }
    run_tool([
        "kubectl", "--context", context, "apply", "--server-side",
        "--field-manager=devsecops-secret-sync", "-f", "-",
    ], payload=json.dumps(manifest))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-id", required=True, help="AWS Secrets Manager ARN; not the secret value")
    parser.add_argument("--context", required=True, help="Explicit approved kubectl context")
    args = parser.parse_args()
    try:
        sync_secret(args.secret_id, args.context)
    except Exception:
        # JSON/parser/tool exceptions may embed sensitive stdout or request payloads.
        print("Secret synchronization failed; no credential details logged.", file=sys.stderr)
        return 1
    print("Secret synchronized. Restart workloads through the approved rotation procedure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
