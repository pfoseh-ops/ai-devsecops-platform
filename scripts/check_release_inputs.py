"""Read-only checks for release placeholders; passing is NOT production approval."""
import argparse
import re
from pathlib import Path

import yaml

MARKER = re.compile(r"replace[-_]|example\.invalid|your_username", re.IGNORECASE)
IMAGE = re.compile(r"ghcr\.io/pfoseh-ops/ai-devsecops-platform@sha256:[0-9a-f]{64}\Z")


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


def check_inputs(directory):
    blockers = []
    for filename in ("namespace.yaml", "deployment.yaml", "ingress.yaml", "network-policy.yaml"):
        try:
            documents = list(yaml.safe_load_all((directory / filename).read_text(encoding="utf-8")))
            if any(MARKER.search(value) for doc in documents for value in strings(doc)):
                blockers.append(f"{filename}: unresolved environment placeholder")
            if filename == "deployment.yaml":
                deployment = next(doc for doc in documents if doc.get("kind") == "Deployment")
                for container in deployment["spec"]["template"]["spec"]["containers"]:
                    if not IMAGE.fullmatch(container["image"]):
                        blockers.append(f"{filename}: use the proposed repository with an immutable sha256 digest")
        except (OSError, yaml.YAMLError, KeyError, TypeError, AttributeError, StopIteration):
            blockers.append(f"{filename}: missing or invalid configuration")
    return blockers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("k8s"))
    args = parser.parse_args()
    blockers = check_inputs(args.directory)
    for blocker in blockers:
        print("BLOCKED:", blocker)
    if blockers:
        return 1
    print("Input syntax checks passed; owner approval and live verification are still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
