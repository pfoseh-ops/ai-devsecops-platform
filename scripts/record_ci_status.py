"""Persist GitHub step outcomes without hiding failed checks."""
import json
import os
from pathlib import Path


def main():
    directory = Path("reports")
    directory.mkdir(exist_ok=True)
    job = os.environ["GITHUB_JOB"]
    steps = json.loads(os.environ["CI_STEPS_JSON"])
    (directory / f"{job}-status.json").write_text(
        json.dumps(steps, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
